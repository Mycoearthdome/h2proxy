#!/usr/bin/env python3
# Hardened HTTP/2 -> HTTP/1.1 streaming proxy
# RFC 7540 compliant with Cloudflare IP whitelisting, metrics, and diagnostics

from __future__ import annotations
import sys, time, logging, signal, ipaddress, subprocess, urllib.parse
from typing import Dict, List, Optional, Tuple, Set

from twisted.internet import reactor, task
from twisted.internet.threads import deferToThread
from twisted.internet.protocol import Protocol, Factory
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.http_headers import Headers
from twisted.internet.defer import Deferred
from twisted.protocols.policies import TimeoutMixin
from twisted.web.server import Site
from twisted.web.wsgi import WSGIResource

import h2.connection
import h2.events
import h2.config
import h2.settings
import h2.errors

import ssl as pyssl
import urllib.request
from collections import deque

# ---------- Configuration ----------
IPSET_NAME = "cloudflare_whitelist"
LISTEN_PORT = 443
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
IP_REFRESH_INTERVAL = 3600

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

MAX_CONCURRENT_STREAMS_DEFAULT = 200
INITIAL_WINDOW_SIZE_DEFAULT = 256 * 1024
MAX_FRAME_SIZE_DEFAULT = 65536
MAX_BUFFER_PER_STREAM = 4 * 1024 * 1024
CONNECTION_IDLE_TIMEOUT = 300
STREAM_INACTIVITY_TIMEOUT = 120
STREAM_BODY_TIMEOUT = 60
METRICS_PORT = 9100
UPSTREAM_TIMEOUT = 30  # seconds

LOG_LEVEL = logging.INFO
logger = logging.getLogger("h2proxy")
logger.setLevel(LOG_LEVEL)
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(sh)

# ---------- Metrics ----------
USE_PROMETHEUS_CLIENT = False
metrics = {
    "requests_total": 0,
    "active_streams": 0,
    "bytes_in_total": 0,
    "bytes_out_total": 0,
    "streams_reset_total": 0,
    "ipset_refresh_count": 0
}
try:
    from prometheus_client import Counter, Gauge, Histogram, make_wsgi_app
    USE_PROMETHEUS_CLIENT = True
    PROM_REQUESTS = Counter("h2proxy_requests_total", "Total requests proxied")
    PROM_ACTIVE = Gauge("h2proxy_active_streams", "Active streams")
    PROM_BYTES_IN = Counter("h2proxy_bytes_in_total", "Bytes received")
    PROM_BYTES_OUT = Counter("h2proxy_bytes_out_total", "Bytes sent")
    PROM_RST = Counter("h2proxy_streams_reset", "Streams reset")
    PROM_STREAM_LATENCY = Histogram("h2proxy_stream_latency_seconds", "Stream duration")
except Exception:
    USE_PROMETHEUS_CLIENT = False

def safe_increment(metric_name, n=1):
    def _inc():
        old = metrics.get(metric_name, 0)
        new = old + n

        if metric_name == "active_streams":
            if new < 0:
                new = 0
            metrics[metric_name] = new
            if USE_PROMETHEUS_CLIENT:
                try:
                    PROM_ACTIVE.set(new)
                except Exception:
                    pass
            return

        if metric_name in ("requests_total", "bytes_in_total", "bytes_out_total", "streams_reset_total", "ipset_refresh_count"):
            if n > 0:
                metrics[metric_name] = new
                if USE_PROMETHEUS_CLIENT:
                    try:
                        if metric_name == "requests_total": PROM_REQUESTS.inc(n)
                        elif metric_name == "bytes_in_total": PROM_BYTES_IN.inc(n)
                        elif metric_name == "bytes_out_total": PROM_BYTES_OUT.inc(n)
                        elif metric_name == "streams_reset_total": PROM_RST.inc(n)
                    except Exception:
                        pass
            else:
                metrics[metric_name] = max(0, old + n)
        else:
            metrics[metric_name] = max(0, new)

    try:
        reactor.callFromThread(_inc)
    except Exception:
        _inc()

def incr_bytes_out(n: int): safe_increment("bytes_out_total", n)
def incr_bytes_in(n: int): safe_increment("bytes_in_total", n)
def incr_streams_reset(): safe_increment("streams_reset_total", 1)

# ---------- OS cmd helper ----------
def run_cmd_blocking(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

# ---------- IPCollector ----------
class IPCollector:
    CF_IPS_V4 = "https://www.cloudflare.com/ips-v4"
    CF_IPS_V6 = "https://www.cloudflare.com/ips-v6"

    def __init__(self):
        self.valid_ips: Set[str] = set()

    def _fetch_ips_blocking(self) -> List[str]:
        urls = [self.CF_IPS_V4, self.CF_IPS_V6]
        all_ips: List[str] = []
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=10) as resp:
                    text = resp.read().decode("utf-8")
                lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
                all_ips.extend(lines)
            except Exception as e:
                logger.warning("Failed to fetch %s: %s", url, e)
        return all_ips

    def refresh_ipset_blocking(self) -> bool:
        ips = self._fetch_ips_blocking()
        if not ips:
            logger.warning("No Cloudflare IP ranges fetched; skipping ipset update")
            return False

        tmp_set = IPSET_NAME + "_tmp"
        try:
            subprocess.run(["ipset", "create", tmp_set, "hash:net"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        for cidr in ips:
            try:
                subprocess.run(["ipset", "add", tmp_set, cidr, "-exist"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        try:
            subprocess.run(["ipset", "swap", tmp_set, IPSET_NAME], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset", "destroy", tmp_set], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning("ipset swap/destroy failed: %s", e)
            return False

        self.valid_ips = set(ips)
        safe_increment("ipset_refresh_count", 1)
        logger.info("Refreshed ipset %s with %d entries", IPSET_NAME, len(self.valid_ips))
        return True

    def refresh_ipset(self):
        return deferToThread(self.refresh_ipset_blocking)

    def is_valid_ip(self, ip: str) -> bool:
        try:
            res = subprocess.run(["ipset", "test", IPSET_NAME, ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if res.returncode == 0:
                return True
        except Exception:
            pass
        try:
            ipaddr = ipaddress.ip_address(ip)
            for net in self.valid_ips:
                if ipaddr in ipaddress.ip_network(net):
                    return True
        except Exception:
            pass
        return False

# ---------- IPSet helpers ----------
# instantiate a collector for the program to share
ip_collector = IPCollector()


def refresh_ipset_async(retries=3, delay=2):
    """
    Use the IPCollector.refresh_ipset to update ipset (runs in threadpool).
    If it fails, schedule retries with exponential backoff.
    """
    def _attempt(attempt=1):
        d = ip_collector.refresh_ipset()
        def _on_done(res):
            # success or failure handled by collector; nothing else to do
            return res
        def _on_err(err):
            logger.warning("refresh_ipset attempt %d failed: %s", attempt, err)
            if attempt < retries:
                reactor.callLater(delay * (2 ** (attempt - 1)), _attempt, attempt + 1)
            else:
                logger.error("Failed to refresh ipset after %d attempts", attempt)
        d.addCallbacks(_on_done, _on_err)
    _attempt()

def setup_ipset_and_rule():
    def _bootstrap():
        run_cmd_blocking(["ipset","create",IPSET_NAME,"hash:net","-exist"])
        try:
            subprocess.run(["iptables","-C","INPUT","-p","tcp","--dport",str(LISTEN_PORT),
                            "-m","set","!","--match-set",IPSET_NAME,"src","-j","DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception: pass
        try:
            subprocess.run(["iptables","-I","INPUT","-p","tcp","--dport",str(LISTEN_PORT),
                            "-m","set","!","--match-set",IPSET_NAME,"src","-j","DROP"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception: pass
    deferToThread(_bootstrap)
    refresh_ipset_async()

def cleanup_ipset_and_rule():
    def _cleanup():
        try: run_cmd_blocking(["iptables","-D","INPUT","-p","tcp","--dport",str(LISTEN_PORT),
                               "-m","set","!","--match-set",IPSET_NAME,"src","-j","DROP"])
        except Exception: pass
        try: run_cmd_blocking(["ipset","destroy",IPSET_NAME])
        except Exception: pass
    deferToThread(_cleanup)

# ---------- Active H2 protocols ----------
_active_h2_protocols: Set["H2ProxyProtocol"] = set()

# ---------- Stream metadata ----------
class StreamMeta:
    __slots__ = (
        'stream_id', 'protocol_ref', 'chunks', 'buffered_bytes',
        'last_activity', 'closed', 'inactivity_call', 'body_timeout_call',
        'start_time', 'weight', 'depends_on', 'exclusive', 'method'
    )

    CHUNK_SIZE = 16 * 1024  # 16 KB per chunk

    def __init__(self, stream_id: int, proto, method: Optional[str] = None):
        self.stream_id = stream_id
        self.protocol_ref = proto
        self.chunks = deque()
        self.buffered_bytes = 0
        self.last_activity = time.time()
        self.closed = False
        self.inactivity_call = None
        self.body_timeout_call = None
        self.start_time = time.time()
        self.weight = None
        self.depends_on = None
        self.exclusive = None
        self.method = method

    def enqueue(self, data: bytes):
        if not data:
            return
        if self.buffered_bytes + len(data) > MAX_BUFFER_PER_STREAM:
            logger.warning("Stream %d buffer exceeded %d bytes, resetting",
                           self.stream_id, MAX_BUFFER_PER_STREAM)
            self.reset_stream(h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
            return
        # Break into fixed-size chunks
        for i in range(0, len(data), self.CHUNK_SIZE):
            chunk = memoryview(data[i:i+self.CHUNK_SIZE])
            self.chunks.append(chunk)
            self.buffered_bytes += len(chunk)
        self.last_activity = time.time()
        self.reset_inactivity_timer()

    def pop_chunk(self, max_size: int) -> Optional[bytes]:
        if not self.chunks:
            return None
        chunk = self.chunks.popleft()
        if len(chunk) > max_size:
            # split chunk
            self.chunks.appendleft(chunk[max_size:])
            chunk = chunk[:max_size]
        self.buffered_bytes -= len(chunk)
        self.last_activity = time.time()
        self.reset_inactivity_timer()
        return chunk.tobytes()

    def reset_inactivity_timer(self):
        if self.inactivity_call:
            try: self.inactivity_call.cancel()
            except Exception: pass
        self.inactivity_call = reactor.callLater(STREAM_INACTIVITY_TIMEOUT, self.on_inactive)

    def set_body_timeout(self):
        if self.body_timeout_call:
            try: self.body_timeout_call.cancel()
            except Exception: pass
        self.body_timeout_call = reactor.callLater(STREAM_BODY_TIMEOUT, self.on_body_timeout)

    def cancel_timers(self):
        if self.inactivity_call:
            try: self.inactivity_call.cancel()
            except Exception: pass
        if self.body_timeout_call:
            try: self.body_timeout_call.cancel()
            except Exception: pass

    def on_inactive(self):
        self.reset_stream(h2.errors.ErrorCodes.CANCEL, STREAM_INACTIVITY_TIMEOUT)

    def on_body_timeout(self):
        self.reset_stream(h2.errors.ErrorCodes.CANCEL, STREAM_BODY_TIMEOUT)

    def reset_stream(self, code, duration=None):
        try:
            code_int = int(code)
        except Exception:
            code_int = int(h2.errors.ErrorCodes.INTERNAL_ERROR)
        logger.warning("Stream %d reset: %s after %s sec; buffered_bytes=%d",
                       self.stream_id, code_int, duration, self.buffered_bytes)
        incr_streams_reset()
        try:
            self.protocol_ref.h2_conn.reset_stream(self.stream_id, error_code=code_int)
            self.protocol_ref.transport.write(self.protocol_ref.h2_conn.data_to_send())
        except Exception:
            pass
        self.clear()

    def clear(self):
        safe_increment("active_streams", -1)
        self.cancel_timers()
        try: del self.protocol_ref.stream_meta[self.stream_id]
        except KeyError: pass
        if USE_PROMETHEUS_CLIENT:
            duration = time.time() - self.start_time
            try: PROM_STREAM_LATENCY.observe(duration)
            except Exception: pass

# ---------------------------------------------------------------------
# Upstream receiver and request
# ---------------------------------------------------------------------
class UpstreamStreamReceiver(Protocol, TimeoutMixin):
    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_meta: StreamMeta):
        self.h2_protocol = h2_protocol
        self.meta = stream_meta
        self.setTimeout(UPSTREAM_TIMEOUT)

    def dataReceived(self, data: bytes):
        if not self.meta or self.meta.closed:
            return
        self.meta.enqueue(data)
        # New data -> wake send-loop
        self.h2_protocol.maybe_send_queued_data()

    def connectionLost(self, reason):
        if self.meta and not self.meta.closed:
            self.meta.closed = True
            try:
                # send explicit end_stream empty DATA
                self.h2_protocol.h2_conn.send_data(self.meta.stream_id, b'', end_stream=True)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception as e:
                logger.debug("Failed to send END_STREAM for stream %d: %s", self.meta.stream_id, e)
        self.h2_protocol.maybe_send_queued_data()

    def timeoutConnection(self):
        logger.warning("Upstream timeout for stream %d", self.meta.stream_id)
        self.meta.reset_stream(h2.errors.ErrorCodes.CANCEL)
        try:
            self.transport.loseConnection()
        except Exception:
            pass

class UpstreamAgentRequest:
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_meta: StreamMeta,
                 method: str, path: str, headers: List[Tuple[str, str]]):
        self.h2_protocol = h2_protocol
        self.meta = stream_meta
        self.method = method if isinstance(method, bytes) else method.encode("ascii")
        # allow safe chars in origin-form
        self.path = urllib.parse.quote(path, safe="/?=&%:[]@!$&'()*+,;")
        self.headers = headers

    def start(self, attempt=1):
        url = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}{self.path}".encode("ascii")
        hdrs = Headers()
        for k, v in self.headers:
            kl = k.lower()
            # remove hop-by-hop and forbidden headers
            if kl in ("connection", "proxy-connection", "keep-alive", "transfer-encoding"):
                continue
            if kl in ("server", "x-powered-by"):
                continue
            hdrs.addRawHeader(kl, v)
        d = self.h2_protocol.agent.request(self.method, url, headers=hdrs)
        timeout_call = reactor.callLater(UPSTREAM_TIMEOUT, lambda: d.cancel())

        def on_response(resp):
            if timeout_call.active():
                timeout_call.cancel()
            status = resp.code
            h2_headers = [(":status", str(status))]
            raw_link_headers: List[str] = []

            for name, vals in resp.headers.getAllRawHeaders():
                lname = name.decode().lower()
                val = b", ".join(vals).decode()
                if lname in ("connection", "proxy-connection", "keep-alive", "transfer-encoding"):
                    continue
                h2_headers.append((lname, val))
                if lname == "link":
                    raw_link_headers.append(val)

            # Enforce some recommended headers if missing (security/caching)
            def ensure(hlist, key, val):
                if not any(k.lower() == key.lower() for k, _ in hlist):
                    hlist.append((key, val))
            ensure(h2_headers, "cache-control", "public, max-age=31536000")
            ensure(h2_headers, "x-content-type-options", "nosniff")
            ensure(h2_headers, "x-frame-options", "DENY")
            ensure(h2_headers, "referrer-policy", "no-referrer")

            # Send headers (pseudo-headers already first in h2_headers)
            try:
                normalized_headers = []
                for k, v in h2_headers:
                    normalized_headers.append((k, v))
                self.h2_protocol.h2_conn.send_headers(self.meta.stream_id, normalized_headers)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception as e:
                logger.debug("Failed to send H2 headers: %s", e)

            # Only consider Link pushes for GET responses
            if (self.meta.method and self.meta.method.upper() == "GET"):
                def parse_link_entries(link_value: str):
                    entries = []
                    cur = ""
                    inq = False
                    for ch in link_value:
                        if ch == '"':
                            inq = not inq
                        if ch == ',' and not inq:
                            entries.append(cur.strip())
                            cur = ""
                        else:
                            cur += ch
                    if cur.strip():
                        entries.append(cur.strip())

                    parsed = []
                    for ent in entries:
                        if '<' not in ent or '>' not in ent:
                            continue
                        url_part = ent[ent.find('<') + 1:ent.find('>')].strip()
                        params_part = ent[ent.find('>') + 1:].strip()
                        params = {}
                        for p in params_part.split(';'):
                            p = p.strip()
                            if not p:
                                continue
                            if '=' in p:
                                k, v = p.split('=', 1)
                                v = v.strip().strip('"')
                                params[k.lower()] = v
                            else:
                                params[p.lower()] = ""
                        parsed.append((url_part, params))
                    return parsed

                for raw_link in raw_link_headers:
                    for url_part, params in parse_link_entries(raw_link):
                        rel = params.get('rel', '').lower()
                        if 'preload' not in rel.split():
                            continue

                        parsed = urllib.parse.urlparse(url_part)
                        netloc_ok = False
                        if not parsed.netloc:
                            netloc_ok = True
                        else:
                            host_only = parsed.netloc.split(':', 1)[0]
                            if host_only == UPSTREAM_HOST:
                                netloc_ok = True

                        if not netloc_ok:
                            logger.debug("Skipping push for cross-origin Link target: %s", url_part)
                            continue

                        push_path = parsed.path or '/'
                        if parsed.query:
                            push_path += '?' + parsed.query

                        try:
                            self.h2_protocol.initiate_push(self.meta.stream_id, push_path)
                        except Exception as e:
                            logger.debug("initiate_push skipped/failed for %s: %s", push_path, e)

            resp.deliverBody(UpstreamStreamReceiver(self.h2_protocol, self.meta))
            return resp

        def on_error(f):
            if timeout_call.active():
                timeout_call.cancel()
            if attempt < self.MAX_RETRIES:
                logger.warning("Upstream fetch failed, retrying %d/%d: %s", attempt, self.MAX_RETRIES, f)
                reactor.callLater(self.RETRY_DELAY, lambda: self.start(attempt + 1))
            else:
                logger.error("Upstream fetch failed for stream %d: %s", self.meta.stream_id, f)
                if self.meta:
                    self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)

        d.addCallbacks(on_response, on_error)
        return d

# ---------------------------------------------------------------------
# H2 protocol implementation (server-side)
# ---------------------------------------------------------------------
class H2ProxyProtocol:
    def __init__(self, transport):
        self.transport = transport
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        self.h2_conn = h2.connection.H2Connection(config=cfg)
        self.stream_meta: Dict[int, StreamMeta] = {}
        self.waiters: List[Deferred] = []
        self.sending = False
        self.max_concurrent_streams = MAX_CONCURRENT_STREAMS_DEFAULT
        self.max_frame_size = MAX_FRAME_SIZE_DEFAULT
        # idle timer will be set in connection wrapper
        self._idle_call = None
        self.agent = Agent(reactor, BrowserLikePolicyForHTTPS())

        # Advertise sensible settings immediately
        try:
            self.h2_conn.initiate_connection()
            settings = {
                h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: INITIAL_WINDOW_SIZE_DEFAULT,
                h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: MAX_CONCURRENT_STREAMS_DEFAULT,
                h2.settings.SettingCodes.MAX_FRAME_SIZE: self.max_frame_size
            }
            self.h2_conn.update_settings(settings)
            # Note: data_to_send will be written by wrapper that created this instance
        except Exception:
            pass

    # Connection idle handler
    def on_connection_idle(self):
        # If there are active streams, extend idle timer; otherwise close
        if any(not s.closed for s in self.stream_meta.values()):
            self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)
            return
        # Graceful close
        try:
            self.shutdown(error=h2.errors.ErrorCodes.NO_ERROR)
        except Exception:
            try:
                self.transport.loseConnection()
            except Exception:
                pass

    def handle_request(self, event: h2.events.RequestReceived):
        safe_increment("requests_total", 1)
        try:
            if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                try:
                    self._idle_call.cancel()
                except Exception:
                    pass
        except Exception:
            pass
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # normalize header names to lowercase strings
        headers: List[Tuple[str, str]] = []
        for k, v in event.headers:
            key = k.decode() if isinstance(k, bytes) else k
            val = v.decode() if isinstance(v, bytes) else v
            headers.append((key.lower(), val))

        # fetch pseudo-headers
        method = next((v for k, v in headers if k == ":method"), None)
        path = next((v for k, v in headers if k == ":path"), None)
        scheme = next((v for k, v in headers if k == ":scheme"), None)
        authority = next((v for k, v in headers if k == ":authority"), None)

        # validate pseudo-headers per RFC 7540 §8.1.2.3
        if not method or not path or not scheme or not authority:
            try:
                self.h2_conn.reset_stream(event.stream_id, error_code=int(h2.errors.ErrorCodes.PROTOCOL_ERROR))
                self.transport.write(self.h2_conn.data_to_send())
            except Exception:
                pass
            return

        # Only handle GET/HEAD (as per original logic)
        if method.upper() not in ("GET", "HEAD"):
            try:
                hdrs = [(":status", "405"), ("content-length", "0")]
                self.h2_conn.send_headers(event.stream_id, hdrs, end_stream=True)
                self.transport.write(self.h2_conn.data_to_send())
                incr_streams_reset()
            except Exception:
                pass
            return

        # concurrency limit
        if len(self.stream_meta) >= self.max_concurrent_streams:
            try:
                hdrs = [(":status", "503"), ("content-length", "0")]
                self.h2_conn.send_headers(event.stream_id, hdrs, end_stream=True)
                self.transport.write(self.h2_conn.data_to_send())
                incr_streams_reset()
            except Exception:
                pass
            return

        meta = StreamMeta(event.stream_id, self, method=method)
        self.stream_meta[event.stream_id] = meta
        safe_increment("active_streams", 1)

        # Build upstream headers excluding pseudo-headers
        upstream_headers = [(k, v) for k, v in headers if not k.startswith(":")]
        UpstreamAgentRequest(self, meta, method, path, upstream_headers).start()

    def dataReceived(self, data: bytes):
        # reset idle timer
        try:
            if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                try:
                    self._idle_call.cancel()
                except Exception:
                    pass
        except Exception:
            pass
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # parse events from h2
        try:
            events = self.h2_conn.receive_data(data)
        except Exception:
            # protocol error: send GOAWAY and close
            self.shutdown(error=h2.errors.ErrorCodes.PROTOCOL_ERROR)
            return

        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.handle_request(event)

            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                incr_bytes_in(len(event.data))
                meta = self.stream_meta.get(sid)
                if meta:
                    # We do not support request body streaming (only GET/HEAD)
                    if meta.method and meta.method.upper() not in ("GET", "HEAD"):
                        meta.reset_stream(h2.errors.ErrorCodes.PROTOCOL_ERROR)
                    else:
                        meta.set_body_timeout()
                    # RFC 7540 §6.9: acknowledge received data to maintain flow-control
                    try:
                        self.h2_conn.acknowledge_received_data(len(event.data), sid)
                    except Exception:
                        # some h2 versions use different method; ignore if not present
                        pass

            elif isinstance(event, h2.events.StreamEnded):
                sid = event.stream_id
                meta = self.stream_meta.get(sid)
                if meta:
                    meta.closed = True
                try:
                    if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                        try:
                            self._idle_call.cancel()
                        except Exception:
                            pass
                except Exception:
                    pass
                self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

            elif isinstance(event, h2.events.WindowUpdated):
                # remote increased our outbound window: wake send loop
                self._wake_waiters()
                self.maybe_send_queued_data()

            elif isinstance(event, h2.events.RemoteSettingsChanged):
                changed = event.changed_settings
                if h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS in changed:
                    try:
                        self.max_concurrent_streams = int(changed[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS].new_value)
                    except Exception:
                        pass
                if h2.settings.SettingCodes.MAX_FRAME_SIZE in changed:
                    try:
                        self.max_frame_size = int(changed[h2.settings.SettingCodes.MAX_FRAME_SIZE].new_value)
                    except Exception:
                        pass

            elif isinstance(event, h2.events.SettingsReceived):
                # MUST ack peer settings (RFC 7540 §6.5.3)
                try:
                    # newer h2 versions use: self.h2_conn.acknowledge_settings()
                    # some accept the event; try both defensively
                    try:
                        self.h2_conn.acknowledge_settings(event)
                    except TypeError:
                        # fallback: call without args
                        self.h2_conn.acknowledge_settings()
                    self.transport.write(self.h2_conn.data_to_send())
                except Exception:
                    pass

            elif isinstance(event, h2.events.SettingsAcknowledged):
                logger.debug("Client acknowledged our SETTINGS")

            elif isinstance(event, h2.events.PingReceived):
                # reply with PING ACK (RFC 7540 §6.7)
                try:
                    # h2 provides ping_acknowledge or ping_reply depending on version
                    try:
                        self.h2_conn.ping_acknowledge(event.ping_data)
                    except AttributeError:
                        # fallback
                        self.h2_conn.ping(event.ping_data, ack=True)
                    self.transport.write(self.h2_conn.data_to_send())
                except Exception:
                    pass

            elif isinstance(event, h2.events.PriorityUpdated):
                sid = event.stream_id
                meta = self.stream_meta.get(sid)
                if meta is None:
                    meta = StreamMeta(sid, self)
                    self.stream_meta[sid] = meta
                meta.weight = event.weight
                meta.depends_on = event.depends_on
                meta.exclusive = event.exclusive

            elif isinstance(event, h2.events.StreamReset):
                sid = event.stream_id
                if sid in self.stream_meta:
                    try:
                        self.stream_meta[sid].clear()
                    except Exception:
                        pass
                try:
                    if self._idle_call and getattr(self._idle_call, "active", lambda: False)():
                        try:
                            self._idle_call.cancel()
                        except Exception:
                            pass
                except Exception:
                    pass
                self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # After processing events, try to send any queued frames
        self.maybe_send_queued_data()
        try:
            self.transport.write(self.h2_conn.data_to_send())
        except Exception:
            pass

    def _wake_waiters(self):
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
        Trigger sending of queued data if not already sending.
        """
        if getattr(self, "_sending_loop_active", False):
            return
        reactor.callLater(0, self._send_loop)

    def _send_loop(self):
        """
        Iteratively send buffered data for all active streams, respecting
        flow-control windows and frame size limits.
        """
        if getattr(self, "_sending_loop_active", False):
            return
        self._sending_loop_active = True

        try:
            # Collect active streams with data
            active_streams = [s for s in self.stream_meta.values()
                              if s.buffered_bytes > 0 and not s.closed]
            if not active_streams:
                return

            for meta in active_streams:
                while meta.buffered_bytes > 0:
                    conn_window = self.h2_conn.local_flow_control_window(meta.stream_id)
                    if conn_window <= 0:
                        # Wait asynchronously for WINDOW_UPDATE
                        d = self.wait_for_window()
                        d.addCallback(lambda _: self._send_loop())
                        return

                    frame_limit = min(self.max_frame_size, MAX_FRAME_SIZE_DEFAULT)
                    chunk_size = min(meta.buffered_bytes, frame_limit, conn_window)
                    chunk = meta.pop_chunk(chunk_size)
                    if not chunk:
                        break

                    try:
                        self.h2_conn.send_data(meta.stream_id, chunk)
                        incr_bytes_out(len(chunk))
                    except Exception as e:
                        logger.debug("Send failed for stream %d: %s", meta.stream_id, e)
                        meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)
                        break

            # Flush queued frames once at the end
            try:
                data_to_send = self.h2_conn.data_to_send()
                if data_to_send:
                    self.transport.write(data_to_send)
            except Exception:
                pass

        finally:
            self._sending_loop_active = False


    def initiate_push(self, parent_stream_id: int, link_path: str):
        parsed = urllib.parse.urlparse(link_path)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if parsed.netloc and parsed.netloc.split(':', 1)[0] != UPSTREAM_HOST:
            logger.debug("Refusing to push cross-origin resource: %s", link_path)
            return

        try:
            sid = self.h2_conn.get_next_available_stream_id()
            headers = [(":method", "GET"), (":path", path), (":scheme", "https"),
                       (":authority", parsed.netloc or UPSTREAM_HOST)]
            self.h2_conn.push_stream(parent_stream_id, sid, headers)
            self.transport.write(self.h2_conn.data_to_send())
        except Exception as e:
            logger.debug("Push failed for %s: %s", path, e)

    def shutdown(self, error=h2.errors.ErrorCodes.NO_ERROR):
        """Send GOAWAY and close connection gracefully (RFC 7540 §6.8)."""
        try:
            last_sid = max(self.stream_meta.keys()) if self.stream_meta else 0
            # Some h2 versions accept 'last_stream_id' arg name
            try:
                self.h2_conn.close_connection(error_code=int(error), last_stream_id=last_sid)
            except TypeError:
                # fallback if different signature
                self.h2_conn.close_connection(error_code=int(error))
            self.transport.write(self.h2_conn.data_to_send())
        except Exception:
            pass
        try:
            self.transport.loseConnection()
        except Exception:
            pass

# ---------- TLS Listener (wrapper) ----------
class H2ProtocolWrapper(Protocol):
    def connectionMade(self):
        # instantiate the core protocol implementation and register
        self.h2 = H2ProxyProtocol(self.transport)
        # set idle timer for the created H2ProxyProtocol
        try:
            self.h2._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.h2.on_connection_idle)
        except Exception:
            pass
        # add to global active set for graceful shutdown
        _active_h2_protocols.add(self.h2)
        try:
            # write initial frames (H2Connection.initiate_connection called in H2ProxyProtocol.__init__)
            self.transport.write(self.h2.h2_conn.data_to_send())
        except Exception:
            pass

    def connectionLost(self, reason=None):
        try:
            _active_h2_protocols.discard(self.h2)
        except Exception:
            pass

    def dataReceived(self, data):
        self.h2.dataReceived(data)

class H2Factory(Factory):
    def buildProtocol(self, addr):
        return H2ProtocolWrapper()

def start_tls_listener():
    ctx = pyssl.SSLContext(pyssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    # disable old TLS versions
    try:
        ctx.options |= pyssl.OP_NO_TLSv1 | pyssl.OP_NO_TLSv1_1
    except Exception:
        pass
    ctx.set_ciphers("ECDHE+AESGCM:!aNULL:!MD5:!3DES")
    try:
        ctx.set_alpn_protocols(["h2"])
    except Exception:
        pass
    reactor.listenSSL(LISTEN_PORT, H2Factory(), ctx)

# ---------- Metrics server ----------
def start_metrics_server():
    if USE_PROMETHEUS_CLIENT:
        app = make_wsgi_app()
        root = WSGIResource(reactor, reactor.getThreadPool(), app)
        reactor.listenTCP(METRICS_PORT, Site(root))

# ---------- Signal Handling ----------
def shutdown_all(*args):
    logger.info("Shutdown requested - sending GOAWAY to all active connections")
    # iterate snapshot
    for proto in list(_active_h2_protocols):
        try:
            proto.shutdown(error=h2.errors.ErrorCodes.NO_ERROR)
        except Exception:
            pass
    # cleanup ipset rules
    cleanup_ipset_and_rule()
    # stop reactor after a short grace to allow frames to flush
    reactor.callLater(0.5, reactor.stop)

signal.signal(signal.SIGINT, shutdown_all)
signal.signal(signal.SIGTERM, shutdown_all)

# ---------- Periodic Cloudflare IP refresh ----------
def start_periodic_ip_refresh():
    refresh_ipset_async()
    loop = task.LoopingCall(refresh_ipset_async)
    loop.start(IP_REFRESH_INTERVAL, now=False)

if __name__ == "__main__":
    setup_ipset_and_rule()
    start_periodic_ip_refresh()
    start_tls_listener()
    start_metrics_server()
    reactor.run()
