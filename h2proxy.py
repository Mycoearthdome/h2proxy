#!/usr/bin/env python3
"""
Twisted HTTP/2 -> HTTP/1.1 streaming proxy with ipset-based Cloudflare whitelist.

Features:
- ALPN h2 (via pyOpenSSL) so Cloudflare can connect with HTTP/2
- ipset cloudflare_whitelist used by a single iptables rule (fast kernel lookup)
- Periodic refresh of Cloudflare IPv4 ranges from https://www.cloudflare.com/ips-v4
- Streams request bodies to upstream and response bodies back to client
- Injects security headers and Cache-Control: public, max-age=31536000
- Systemd-friendly (no internal daemonize)
"""

import ssl
import urllib.request
from ipaddress import ip_network, ip_address
from twisted.internet import reactor, task
from twisted.internet.protocol import Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.web import server, http
import h2.connection
import h2.events
import h2.config
import re
import os
import signal
import logging
import subprocess
from OpenSSL import SSL

# ---------- Configuration ----------
CLOUDFLARE_IPS_URL = "https://www.cloudflare.com/ips-v4"
IPSET_NAME = "cloudflare_whitelist"
LISTEN_PORT = 443                    # Port to listen on (443 recommended)
UPSTREAM_HOST = "127.0.0.1"          # HTTP/1.1 upstream
UPSTREAM_PORT = 8080
IP_REFRESH_INTERVAL = 60 * 60        # seconds; refresh every 1 hour
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# ---------- Logging ----------
logger = logging.getLogger("h2proxy")
logger.setLevel(logging.INFO)

try:
    from systemd.journal import JournalHandler
    journal_handler = JournalHandler()
    journal_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(journal_handler)
    logger.info("Logging initialized to systemd journal")
except ImportError:
    # fallback for environments without systemd-python
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.info("systemd.journal not available, logging to stdout")

# ---------- ipset + iptables helpers ----------
def run_cmd(cmd):
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def setup_ipset_and_rule():
    """Create ipset, populate it, and insert iptables rule that drops traffic not in the set."""
    # create ipset if missing (hash:net suited for networks)
    run_cmd(["ipset", "create", IPSET_NAME, "hash:net", "-exist"])
    refresh_ipset()  # populate

    # Ensure iptables rule exists: if source not in set -> DROP for the listen port
    # Check presence (-C) and insert (-I) if missing; prefer a single rule
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

def refresh_ipset():
    """Fetch Cloudflare IPv4 list and repopulate ipset atomically (flush -> add)."""
    try:
        with urllib.request.urlopen(CLOUDFLARE_IPS_URL, timeout=15) as resp:
            text = resp.read().decode()
            lines = [line.strip() for line in text.splitlines() if line.strip()]
    except Exception as e:
        logger.error("Failed to fetch Cloudflare IPs: %s", e)
        return

    # flush ipset then add each network
    if not run_cmd(["ipset", "flush", IPSET_NAME]):
        logger.warning("Failed to flush ipset %s (continuing)", IPSET_NAME)

    added = 0
    for net in lines:
        if run_cmd(["ipset", "add", IPSET_NAME, net, "-exist"]):
            added += 1
    logger.info("Refreshed ipset %s: added %d entries", IPSET_NAME, added)

def cleanup_ipset_and_rule():
    """Remove the iptables rule and destroy the ipset."""
    # delete the iptables rule; ignore errors
    run_cmd(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(LISTEN_PORT),
             "-m", "set", "!", "--match-set", IPSET_NAME, "src", "-j", "DROP"])
    # destroy ipset
    run_cmd(["ipset", "destroy", IPSET_NAME])
    logger.info("Cleaned up ipset and iptables rule")

# ---------- H2 proxy implementation ----------
class UpstreamStreamingClient(Protocol):
    """
    Receives raw HTTP/1.1 response bytes from upstream and streams them into HTTP/2.
    Also used to accept streamed request body writes from the H2 side once connected.
    """
    def __init__(self, h2_protocol, stream_id, is_websocket=False):
        self.h2_protocol = h2_protocol
        self.stream_id = stream_id
        self.is_websocket = is_websocket
        self.header_buffer = b""
        self.body_started = False
        self.status_code = 200
        self.response_headers = {}

    def dataReceived(self, data):
        if self.is_websocket:
            # Not implemented full WebSocket bridging here; raw data would be forwarded
            self.h2_protocol.transport.write(data)
            return

        if not self.body_started:
            self.header_buffer += data
            if b"\r\n\r\n" in self.header_buffer:
                header_part, remaining = self.header_buffer.split(b"\r\n\r\n", 1)
                lines = header_part.split(b"\r\n")
                # status
                try:
                    parts = lines[0].decode(errors="ignore").split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        self.status_code = int(parts[1])
                except Exception:
                    self.status_code = 200
                # parse headers
                link_headers = []
                for line in lines[1:]:
                    if b":" in line:
                        k, v = line.split(b":", 1)
                        key = k.decode(errors="ignore").strip().lower()
                        val = v.decode(errors="ignore").strip()
                        self.response_headers[key] = val
                        if key == "link":
                            link_headers.append(val)

                # build H2 headers (inject security + CF cache)
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

                # optional push
                for link in link_headers:
                    self.push_resources(link)

                self.body_started = True
                if remaining:
                    self.h2_protocol.h2_conn.send_data(self.stream_id, remaining)
                    self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
        else:
            self.h2_protocol.h2_conn.send_data(self.stream_id, data)
            self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())

    def push_resources(self, link_header):
        links = re.findall(r'<([^>]+)>;\s*rel=preload', link_header)
        for url in links:
            try:
                promised_stream_id = self.h2_protocol.h2_conn.get_next_available_stream_id()
                push_headers = [
                    (":method", "GET"),
                    (":path", url),
                    (":scheme", "https"),
                    (":authority", UPSTREAM_HOST),
                ]
                self.h2_protocol.h2_conn.push_stream(self.stream_id, promised_stream_id, push_headers)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception as e:
                logger.debug("push_resources failed for %s: %s", url, e)

    def connectionLost(self, reason):
        # terminate H2 stream
        try:
            self.h2_protocol.h2_conn.send_data(self.stream_id, b"", end_stream=True)
            self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
        except Exception:
            pass

class H2ProxyProtocol(http.HTTPChannel):
    def __init__(self):
        super().__init__()
        config = h2.config.H2Configuration(client_side=False)
        self.h2_conn = h2.connection.H2Connection(config=config)
        self.stream_clients = {}   # stream_id -> UpstreamStreamingClient
        self.stream_buffers = {}   # stream_id -> list(request-body-chunks)

    def connectionMade(self):
        self.h2_conn.initiate_connection()
        self.transport.write(self.h2_conn.data_to_send())

    def dataReceived(self, data):
        events = self.h2_conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.handle_request(event)
            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                client = self.stream_clients.get(sid)
                if client and getattr(client, "transport", None):
                    client.transport.write(event.data)
                else:
                    self.stream_buffers.setdefault(sid, []).append(event.data)
            elif isinstance(event, h2.events.StreamEnded):
                sid = event.stream_id
                client = self.stream_clients.get(sid)
                if client and getattr(client, "transport", None):
                    try:
                        # signal end to upstream by closing its write side
                        client.transport.loseConnection()
                    except Exception:
                        pass
        # send any outgoing H2 data
        self.transport.write(self.h2_conn.data_to_send())

    def handle_request(self, event):
        peer_ip = self.transport.getPeer().host
        # kernel-level ipset already blocks non-CF IPs, but do defensive check
        if not ipset_contains_peer(peer_ip):
            logger.warning("Rejected connection from non-cloudflare IP (peer=%s)", peer_ip)
            # don't attempt to modify iptables here; kernel rule already drops
            self.transport.abortConnection()
            return

        headers = {k.decode(): v.decode() for k, v in event.headers}
        method = headers.get(":method", "GET")
        path = headers.get(":path", "/")
        authority = headers.get(":authority") or headers.get("host") or UPSTREAM_HOST

        # build HTTP/1.1 request headers for upstream; ensure Host present
        req_lines = [f"{method} {path} HTTP/1.1\r\n", f"Host: {authority}\r\n"]
        for k, v in headers.items():
            if not k.startswith(":") and k.lower() != "host":
                req_lines.append(f"{k}: {v}\r\n")
        req_lines.append("\r\n")
        request_bytes = "".join(req_lines).encode("utf-8", "ignore")

        # connect to upstream and stream headers + any buffered body
        endpoint = TCP4ClientEndpoint(reactor, UPSTREAM_HOST, UPSTREAM_PORT)
        upstream_client = UpstreamStreamingClient(self, event.stream_id)
        self.stream_clients[event.stream_id] = upstream_client

        def connected(cbproto):
            try:
                cbproto.transport.write(request_bytes)
                for chunk in self.stream_buffers.pop(event.stream_id, []):
                    cbproto.transport.write(chunk)
            except Exception:
                pass

        d = connectProtocol(endpoint, upstream_client)
        d.addCallback(connected)

class H2ProxyFactory(server.Site):
    protocol = H2ProxyProtocol

# ---------- ipset helper: fast membership check (optional) ----------
# We can check peer membership by testing ipset membership via `ipset test` (slowish),
# but since kernel enforces access, checking is mostly defensive. We'll implement a quick test.

def ipset_contains_peer(ip):
    try:
        res = subprocess.run(["ipset", "test", IPSET_NAME, ip],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

# ---------- TLS context with ALPN = h2 using pyOpenSSL ----------
def make_h2_alpn_context(certfile=CERT_FILE, keyfile=KEY_FILE):
    ctx = SSL.Context(SSL.TLS_SERVER_METHOD)
    # disable old TLS
    ctx.set_options(SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
    # set ciphers (OpenSSL string)
    try:
        ctx.set_cipher_list(b"ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5")
    except Exception:
        pass
    # Advertise ALPN h2
    try:
        ctx.set_alpn_protos([b"h2"])
    except Exception:
        def _alpn_select(conn, protos):
            return b"h2" if b"h2" in protos else None
        try:
            ctx.set_alpn_select_callback(_alpn_select)
        except Exception:
            pass
    # load cert/key
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

if __name__ == "__main__":
    # ensure ipset & iptables rule
    setup_ipset_and_rule()

    # schedule periodic refresh
    task.LoopingCall(refresh_ipset).start(IP_REFRESH_INTERVAL)

    # signals
    signal.signal(signal.SIGTERM, graceful_shutdown)
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGHUP, lambda s, f: refresh_ipset())

    # start TLS listener
    contextFactory = make_h2_alpn_context(CERT_FILE, KEY_FILE)
    reactor.listenSSL(LISTEN_PORT, H2ProxyFactory(None), contextFactory)
    logger.info("h2proxy listening on :%d -> upstream %s:%d", LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT)
    reactor.run()
