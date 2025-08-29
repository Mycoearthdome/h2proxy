#!/usr/bin/env python3
"""
h2-capable Twisted HTTP/2 -> HTTP/1.1 streaming proxy with ipset Cloudflare whitelist.

Improvements over earlier version:
- Proper SETTINGS handling
- Flow-control-aware sending (connection & stream windows)
- WindowUpdated handling and resume logic
- Priority bookkeeping (simple weight/dependency)
- Server-push that fetches and streams body to promised streams
- Uses Twisted Agent to fetch upstream resources asynchronously
- Journald logging integration with fallback
- ipset management for Cloudflare whitelist
"""
from __future__ import annotations
import sys
import time
import urllib.request
from ipaddress import ip_network, ip_address
from typing import Dict, Optional, Deque, Tuple, List
from collections import deque
import logging
import subprocess
import signal
import re

from twisted.internet import reactor, task, defer
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.web import server, http
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS, ResponseDone
from twisted.internet.task import cooperate
from twisted.internet.defer import Deferred
from twisted.web.iweb import IBodyProducer
from twisted.python.failure import Failure

import h2.connection
import h2.events
import h2.config
import h2.settings

from OpenSSL import SSL

# ---------- Configuration ----------
CLOUDFLARE_IPS_URL = "https://www.cloudflare.com/ips-v4"
IPSET_NAME = "cloudflare_whitelist"
LISTEN_PORT = 443
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
IP_REFRESH_INTERVAL = 60 * 60
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# Operational limits
MAX_CONCURRENT_STREAMS_DEFAULT = 200
INITIAL_WINDOW_SIZE_DEFAULT = 256 * 1024  # 256 KiB per stream
MAX_FRAME_SIZE = 65536

# ---------- Logging (journald if available) ----------
logger = logging.getLogger("h2proxy")
logger.setLevel(logging.INFO)
try:
    from systemd.journal import JournalHandler
    jh = JournalHandler()
    jh.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(jh)
    logger.info("Using systemd journal for logging")
except Exception:
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(sh)
    logger.info("systemd.journal not available; logging to stdout")

# ---------- ipset helpers ----------
def run_cmd(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def refresh_ipset():
    try:
        with urllib.request.urlopen(CLOUDFLARE_IPS_URL, timeout=15) as resp:
            text = resp.read().decode()
            nets = [line.strip() for line in text.splitlines() if line.strip()]
    except Exception as e:
        logger.error("Failed to fetch Cloudflare IPs: %s", e)
        return

    if not run_cmd(["ipset", "flush", IPSET_NAME]):
        logger.warning("Failed to flush ipset %s; continuing", IPSET_NAME)

    added = []
    for net in nets:
        if run_cmd(["ipset", "add", IPSET_NAME, net, "-exist"]):
            added.append(net)
    logger.info("Refreshed ipset %s: %d entries added", IPSET_NAME, len(added))
    # For auditability, log the list size and sample first/last
    if added:
        logger.debug("Sample Cloudflare networks: %s ... %s", added[0], added[-1])

def setup_ipset_and_rule():
    run_cmd(["ipset", "create", IPSET_NAME, "hash:net", "-exist"])
    refresh_ipset()
    # ensure iptables rule exists
    check = subprocess.run(
        ["iptables", "-C", "INPUT", "-p", "tcp", "--dport", str(LISTEN_PORT),
         "-m", "set", "!", "--match-set", IPSET_NAME, "src", "-j", "DROP"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    if check.returncode != 0:
        run_cmd(["iptables", "-I", "INPUT", "-p", "tcp", "--dport", str(LISTEN_PORT),
                 "-m", "set", "!", "--match-set", IPSET_NAME, "src", "-j", "DROP"])
        logger.info("Inserted iptables rule to DROP non-cloudflare sources on port %d", LISTEN_PORT)
    else:
        logger.info("iptables rule already present")

def cleanup_ipset_and_rule():
    run_cmd(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(LISTEN_PORT),
             "-m", "set", "!", "--match-set", IPSET_NAME, "src", "-j", "DROP"])
    run_cmd(["ipset", "destroy", IPSET_NAME])
    logger.info("Cleaned up ipset and iptables rule")

def ipset_contains_peer(ip: str) -> bool:
    try:
        res = subprocess.run(["ipset", "test", IPSET_NAME, ip],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

# ---------- Flow control & stream metadata ----------
class StreamMeta:
    def __init__(self, stream_id: int):
        self.stream_id = stream_id
        self.buffer: Deque[bytes] = deque()  # outgoing bytes waiting to be sent for this stream
        self.wait_deferreds: List[Deferred] = []  # deferreds waiting for WINDOW_UPDATE
        self.weight = 16
        self.depends_on = 0
        self.exclusive = False
        self.closed = False

    def enqueue(self, data: bytes):
        if data:
            self.buffer.append(data)

    def pop_chunk(self, size: int) -> Optional[bytes]:
        if not self.buffer:
            return None
        # concatenates from buffer up to size
        out = bytearray()
        while self.buffer and len(out) < size:
            chunk = self.buffer.popleft()
            need = size - len(out)
            if len(chunk) <= need:
                out.extend(chunk)
            else:
                out.extend(chunk[:need])
                self.buffer.appendleft(chunk[need:])
        return bytes(out)

# ---------- Twisted Agent for upstream fetching (used for server push) ----------
_agent_pool = None
def get_agent():
    global _agent_pool
    if _agent_pool is None:
        _agent_pool = Agent(reactor, BrowserLikePolicyForHTTPS())
    return _agent_pool

# ---------- Upstream response body receiver for pushed streams ----------
class UpstreamBodyReceiver(Protocol):
    def __init__(self, proxy_conn: "H2ProxyProtocol", promised_stream_id: int):
        self.proxy_conn = proxy_conn
        self.stream_id = promised_stream_id
        self.bytes_received = 0

    def dataReceived(self, data):
        self.bytes_received += len(data)
        # enqueue data to stream meta and attempt to send respecting flow control
        meta = self.proxy_conn.stream_meta.get(self.stream_id)
        if meta is None:
            return
        meta.enqueue(data)
        # try to drain
        self.proxy_conn.maybe_send_queued_data()

    def connectionLost(self, reason):
        # when upstream push body finishes, mark end_stream
        # we'll attempt to send zero-length end_stream once windows allow
        logger.debug("Push body finished for promised stream %d; scheduling end_stream", self.stream_id)
        meta = self.proxy_conn.stream_meta.get(self.stream_id)
        if meta:
            meta.closed = True
            # try to send remaining buffer and end_stream
            self.proxy_conn.maybe_send_queued_data()

# ---------- Upstream streaming client for regular (non-pushed) requests ----------
class UpstreamStreamingClient(Protocol):
    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_id: int):
        self.h2_protocol = h2_protocol
        self.stream_id = stream_id
        self.header_buffer = b""
        self.body_started = False
        self.response_headers = {}
        self.status_code = 200

    def dataReceived(self, data):
        # Received bytes from the upstream server; forward to the h2 stream respecting flow control
        if not self.body_started:
            self.header_buffer += data
            if b"\r\n\r\n" in self.header_buffer:
                header_part, remaining = self.header_buffer.split(b"\r\n\r\n", 1)
                lines = header_part.split(b"\r\n")
                try:
                    parts = lines[0].decode(errors="ignore").split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        self.status_code = int(parts[1])
                except Exception:
                    self.status_code = 200
                link_headers = []
                for line in lines[1:]:
                    if b":" in line:
                        k, v = line.split(b":", 1)
                        key = k.decode(errors="ignore").strip().lower()
                        val = v.decode(errors="ignore").strip()
                        self.response_headers[key] = val
                        if key == "link":
                            link_headers.append(val)

                # build H2 response headers
                h2_headers = [
                    (":status", str(self.status_code)),
                    ("cache-control", "public, max-age=31536000"),
                    ("strict-transport-security", "max-age=31536000; includeSubDomains"),
                    ("x-content-type-options", "nosniff"),
                    ("x-frame-options", "DENY"),
                    ("referrer-policy", "no-referrer"),
                ]
                for k, v in self.response_headers.items():
                    if k not in ("connection", "transfer-encoding", "server"):
                        h2_headers.append((k, v))
                self.h2_protocol.h2_conn.send_headers(self.stream_id, h2_headers)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())

                # server push for Link: rel=preload
                for link in link_headers:
                    try:
                        self.h2_protocol.initiate_push(self.stream_id, link)
                    except Exception as e:
                        logger.debug("Push initiation failed: %s", e)

                self.body_started = True
                if remaining:
                    # enqueue remaining to stream meta
                    meta = self.h2_protocol.stream_meta.get(self.stream_id)
                    if meta is None:
                        meta = StreamMeta(self.stream_id)
                        self.h2_protocol.stream_meta[self.stream_id] = meta
                    meta.enqueue(remaining)
                    self.h2_protocol.maybe_send_queued_data()
        else:
            meta = self.h2_protocol.stream_meta.get(self.stream_id)
            if meta is None:
                meta = StreamMeta(self.stream_id)
                self.h2_protocol.stream_meta[self.stream_id] = meta
            meta.enqueue(data)
            self.h2_protocol.maybe_send_queued_data()

    def connectionLost(self, reason):
        # mark stream closed & attempt to flush remaining bytes with end_stream
        meta = self.h2_protocol.stream_meta.get(self.stream_id)
        if meta:
            meta.closed = True
            self.h2_protocol.maybe_send_queued_data()

# ---------- H2 Protocol implementation (Twisted HTTPChannel subclass) ----------
class H2ProxyProtocol(http.HTTPChannel):
    def __init__(self):
        super().__init__()
        config = h2.config.H2Configuration(client_side=False)
        self.h2_conn = h2.connection.H2Connection(config=config)
        # stream metadata map
        self.stream_meta: Dict[int, StreamMeta] = {}
        # per-connection list of deferreds waiting for WINDOW_UPDATE (simple approach)
        self.waiters: List[Deferred] = []
        self.transport = None
        # track remote settings
        self.remote_settings = {}
        self.max_concurrent_streams = MAX_CONCURRENT_STREAMS_DEFAULT

    def connectionMade(self):
        super().connectionMade()
        self.h2_conn.initiate_connection()
        # server settings: push a few tuned settings
        settings = {
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: INITIAL_WINDOW_SIZE_DEFAULT,
            h2.settings.SettingCodes.MAX_FRAME_SIZE: MAX_FRAME_SIZE,
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams,
        }
        self.h2_conn.update_settings(settings)
        self.transport.write(self.h2_conn.data_to_send())
        logger.debug("Sent initial SETTINGS: %s", settings)

    def dataReceived(self, data):
        # called when TLS layer provides bytes; feed them to h2 and handle events
        events = self.h2_conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.handle_request(event)
            elif isinstance(event, h2.events.DataReceived):
                # forward request body chunks to upstream if upstream connected
                sid = event.stream_id
                client = self.stream_clients.get(sid)
                if client and getattr(client, "transport", None):
                    client.transport.write(event.data)
                else:
                    self.stream_buffers.setdefault(sid, []).append(event.data)
                # acknowledge to grow window on client side
                self.h2_conn.acknowledge_received_data(event.flow_controlled_length, sid)
            elif isinstance(event, h2.events.StreamEnded):
                sid = event.stream_id
                client = getattr(self, "stream_clients", {}).get(sid)
                if client and getattr(client, "transport", None):
                    try:
                        client.transport.loseConnection()
                    except Exception:
                        pass
            elif isinstance(event, h2.events.WindowUpdated):
                # resume any waiting senders
                logger.debug("WindowUpdated: stream %s", getattr(event, "stream_id", None))
                self._wake_waiters()
            elif isinstance(event, h2.events.RemoteSettingsChanged):
                logger.info("Remote SETTINGS changed: %s", event.changed_settings)
                # adapt to remote limits if needed
                if h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS in event.changed_settings:
                    self.max_concurrent_streams = event.changed_settings[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS]
            elif isinstance(event, h2.events.PriorityUpdated):
                sid = event.stream_id
                meta = self.stream_meta.get(sid)
                if not meta:
                    meta = StreamMeta(sid)
                    self.stream_meta[sid] = meta
                meta.weight = event.weight
                meta.depends_on = event.depends_on
                meta.exclusive = event.exclusive
            elif isinstance(event, h2.events.SettingsAcknowledged):
                logger.debug("Settings acknowledged by peer")
            elif isinstance(event, h2.events.StreamReset):
                # cleanup
                sid = event.stream_id
                logger.debug("StreamReset received for %s", sid)
                if sid in self.stream_meta:
                    del self.stream_meta[sid]
            else:
                logger.debug("Unhandled h2 event: %s", type(event))
        # finally, write any data to transport
        self.transport.write(self.h2_conn.data_to_send())

    # store ephemeral per-request data structures
    stream_clients: Dict[int, UpstreamStreamingClient] = {}
    stream_buffers: Dict[int, List[bytes]] = {}

    def handle_request(self, event: h2.events.RequestReceived):
        peer_ip = self.transport.getPeer().host
        if not ipset_contains_peer(peer_ip):
            logger.warning("Rejected connection from non-cloudflare IP (peer=%s)", peer_ip)
            self.transport.abortConnection()
            return

        headers = {k.decode(): v.decode() for k, v in event.headers}
        method = headers.get(":method", "GET")
        path = headers.get(":path", "/")
        authority = headers.get(":authority") or headers.get("host") or UPSTREAM_HOST

        # Build HTTP/1.1 request text
        req_lines = [f"{method} {path} HTTP/1.1\r\n", f"Host: {authority}\r\n"]
        # forward other headers except :pseudo and hop-by-hop
        for k, v in headers.items():
            if not k.startswith(":") and k.lower() not in ("connection", "keep-alive", "proxy-connection", "upgrade", "te"):
                req_lines.append(f"{k}: {v}\r\n")
        req_lines.append("\r\n")
        request_bytes = "".join(req_lines).encode("utf-8", "ignore")

        # Create stream meta
        meta = StreamMeta(event.stream_id)
        self.stream_meta[event.stream_id] = meta

        # Connect to upstream
        endpoint = TCP4ClientEndpoint(reactor, UPSTREAM_HOST, UPSTREAM_PORT)
        upstream_client = UpstreamStreamingClient(self, event.stream_id)
        self.stream_clients[event.stream_id] = upstream_client

        def _on_connect(proto):
            try:
                proto.transport.write(request_bytes)
                # if any buffered request body from DataReceived earlier, flush to upstream
                for chunk in self.stream_buffers.pop(event.stream_id, []):
                    proto.transport.write(chunk)
            except Exception as e:
                logger.error("Error sending request to upstream: %s", e)

        d = connectProtocol(endpoint, upstream_client)
        d.addCallback(_on_connect)

    # ---- Flow / send helpers ----
    def _wake_waiters(self):
        # call all waiters (deferred callbacks) to resume senders
        waiters = list(self.waiters)
        self.waiters.clear()
        for d in waiters:
            try:
                d.callback(None)
            except Exception:
                pass

    def wait_for_window(self) -> Deferred:
        d = Deferred()
        self.waiters.append(d)
        return d

    def maybe_send_queued_data(self):
        """
        Try to send any queued data for streams, respecting priorities and windows.
        Basic scheduler: choose non-empty stream metas ordered by weight descending.
        """
        # build list of ready streams
        ready = [meta for meta in self.stream_meta.values() if meta.buffer]
        if not ready:
            # also handle streams that are closed (no more incoming data) to send end_stream
            for meta in list(self.stream_meta.values()):
                if meta.closed and not meta.buffer:
                    # send end_stream if not yet done
                    try:
                        self.h2_conn.send_data(meta.stream_id, b"", end_stream=True)
                        self.transport.write(self.h2_conn.data_to_send())
                        del self.stream_meta[meta.stream_id]
                    except Exception:
                        pass
            return

        # prioritize by weight (higher first)
        ready.sort(key=lambda m: m.weight, reverse=True)

        # Attempt to send chunks for each stream in priority order
        for meta in ready:
            # send while windows permit and meta has buffer
            while meta.buffer:
                conn_win = self.h2_conn.local_flow_control_window(None)
                stream_win = self.h2_conn.local_flow_control_window(meta.stream_id)
                allowed = min(conn_win, stream_win, MAX_FRAME_SIZE)
                if allowed <= 0:
                    # must wait for WINDOW_UPDATE
                    # register waiter and return
                    d = self.wait_for_window()
                    # schedule resume when window updated
                    d.addCallback(lambda _: self.maybe_send_queued_data())
                    return
                chunk = meta.pop_chunk(allowed)
                if not chunk:
                    break
                try:
                    self.h2_conn.send_data(meta.stream_id, chunk)
                    self.transport.write(self.h2_conn.data_to_send())
                except Exception as e:
                    logger.error("Failed to send data on stream %s: %s", meta.stream_id, e)
                    return
            # if meta closed and no buffer left, end stream
            if meta.closed and not meta.buffer:
                try:
                    self.h2_conn.send_data(meta.stream_id, b"", end_stream=True)
                    self.transport.write(self.h2_conn.data_to_send())
                    del self.stream_meta[meta.stream_id]
                except Exception:
                    pass

    # ---- Server push ----
    def initiate_push(self, orig_stream_id: int, link_header_value: str):
        """
        Parse Link header value(s), for each rel=preload resource create a promised stream,
        push headers and fetch body from upstream to stream it.
        """
        links = re.findall(r'<([^>]+)>;\s*rel=preload', link_header_value)
        for url in links:
            # Only support absolute-path or absolute-URL; for simplicity, if URL starts with '/', treat as origin path
            if url.startswith("/"):
                path = url
            else:
                # try parse path portion
                try:
                    from urllib.parse import urlparse
                    p = urlparse(url)
                    path = p.path or "/"
                except Exception:
                    path = url
            promised_stream_id = self.h2_conn.get_next_available_stream_id()
            push_headers = [
                (":method", "GET"),
                (":path", path),
                (":scheme", "https"),
                (":authority", UPSTREAM_HOST),
            ]
            try:
                self.h2_conn.push_stream(orig_stream_id, promised_stream_id, push_headers)
                self.transport.write(self.h2_conn.data_to_send())
                logger.debug("PUSH_PROMISE sent for %s -> promised stream %d", path, promised_stream_id)
                # prepare stream meta for promised
                meta = StreamMeta(promised_stream_id)
                self.stream_meta[promised_stream_id] = meta
                # fetch resource from upstream using Twisted Agent (http)
                self._fetch_and_push_body(path, promised_stream_id)
            except Exception as e:
                logger.debug("Failed to send push promise for %s: %s", path, e)

    def _fetch_and_push_body(self, path: str, promised_stream_id: int):
        """
        Fetch 'http://UPSTREAM_HOST:UPSTREAM_PORT{path}' using Agent and stream bytes into promised stream meta.
        """
        agent = get_agent()
        url = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}{path}"
        d = agent.request(b"GET", url.encode("ascii"))
        def on_response(response):
            # send headers for promise response
            status = response.code
            headers = [(":status", str(status))]
            # forward some headers
            for name, values in response.headers.getAllRawHeaders():
                try:
                    headers.append((name.decode(), b", ".join(values).decode()))
                except Exception:
                    pass
            try:
                self.h2_conn.send_headers(promised_stream_id, headers)
                self.transport.write(self.h2_conn.data_to_send())
            except Exception as e:
                logger.debug("Failed to send push response headers for %d: %s", promised_stream_id, e)
            # deliver body via protocol that enqueues chunks
            from twisted.internet import protocol
            class PushReceiver(Protocol):
                def dataReceived(inner_self, data):
                    meta = self.stream_meta.get(promised_stream_id)
                    if meta is None:
                        meta = StreamMeta(promised_stream_id)
                        self.stream_meta[promised_stream_id] = meta
                    meta.enqueue(data)
                    self.maybe_send_queued_data()
                def connectionLost(inner_self, reason):
                    meta = self.stream_meta.get(promised_stream_id)
                    if meta:
                        meta.closed = True
                        self.maybe_send_queued_data()
            return response.deliverBody(PushReceiver())
        d.addCallback(on_response)
        d.addErrback(lambda f: logger.error("Failed to fetch push resource %s: %s", path, f))

# ---------- TLS context factory with ALPN=h2 ----------
def make_h2_alpn_context(certfile=CERT_FILE, keyfile=KEY_FILE):
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    ctx.set_options(SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
    try:
        ctx.set_cipher_list(b"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5")
    except Exception:
        pass
    try:
        ctx.set_alpn_protos([b"h2"])
    except Exception:
        def _alpn_select(conn, protos):
            return b"h2" if b"h2" in protos else None
        try:
            ctx.set_alpn_select_callback(_alpn_select)
        except Exception:
            pass
    ctx.use_privatekey_file(keyfile)
    ctx.use_certificate_file(certfile)
    class CF:
        def getContext(self):
            return ctx
    return CF()

# ---------- signals & lifecycle ----------
def graceful_shutdown(signum, frame):
    logger.info("shutdown signal %s received — cleaning ipset and exiting", signum)
    try:
        cleanup_ipset_and_rule()
    finally:
        reactor.stop()

# ---------- main ----------
if __name__ == "__main__":
    # ensure ipset & iptables rule
    setup_ipset_and_rule()
    # schedule periodic ipset refresh
    task.LoopingCall(refresh_ipset).start(IP_REFRESH_INTERVAL)
    signal.signal(signal.SIGTERM, graceful_shutdown)
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGHUP, lambda s, f: refresh_ipset())
    # start TLS listener (ALPN=h2)
    contextFactory = make_h2_alpn_context(CERT_FILE, KEY_FILE)
    reactor.listenSSL(LISTEN_PORT, server.Site(H2ProxyProtocol()), contextFactory)
    logger.info("h2proxy listening on :%d -> upstream %s:%d", LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT)
    reactor.run()
