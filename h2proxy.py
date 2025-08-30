#!/usr/bin/env python3
# Hardened HTTP/2 -> HTTP/1.1 streaming proxy (modified: clamped metrics + event-driven send loop)

from __future__ import annotations
import sys, time, logging, signal, ipaddress, subprocess, urllib.parse
from typing import Dict, List, Optional, Tuple

from twisted.internet import reactor, task, defer
from twisted.internet.threads import deferToThread
from twisted.internet.protocol import Protocol, Factory
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web.http_headers import Headers
from twisted.internet.defer import Deferred
from twisted.protocols.policies import TimeoutMixin

import h2.connection, h2.events, h2.config, h2.settings
import ssl as pyssl

import os
import urllib.request

# ---------- Configuration ----------
CLOUDFLARE_IPS_URL = "https://www.cloudflare.com/ips-v4"
# ---------- IPSet helpers (dual-stack, kernel-backed, threaded fetch) ----------
# single canonical ipset name used by OS-level firewall
IPSET_NAME = "cloudflare_whitelist"
LISTEN_PORT = 443
UPSTREAM_HOST = "127.0.0.1"
UPSTREAM_PORT = 8080
IP_REFRESH_INTERVAL = 3600

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

MAX_CONCURRENT_STREAMS_DEFAULT = 200
INITIAL_WINDOW_SIZE_DEFAULT = 256 * 1024
MAX_FRAME_SIZE = 65536
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
    "requests_total":0,
    "active_streams":0,
    "bytes_in_total":0,
    "bytes_out_total":0,
    "streams_reset_total":0,
    "ipset_refresh_count":0
}
try:
    from prometheus_client import Counter, Gauge, start_http_server, Histogram, make_wsgi_app
    from twisted.web.wsgi import WSGIResource
    USE_PROMETHEUS_CLIENT = True
    PROM_REQUESTS = Counter("h2proxy_requests_total","Total requests proxied")
    PROM_ACTIVE = Gauge("h2proxy_active_streams","Active streams")
    PROM_BYTES_IN = Counter("h2proxy_bytes_in_total","Bytes received")
    PROM_BYTES_OUT = Counter("h2proxy_bytes_out_total","Bytes sent")
    PROM_RST = Counter("h2proxy_streams_reset","Streams reset")
    PROM_STREAM_LATENCY = Histogram("h2proxy_stream_latency_seconds","Stream duration")
except Exception:
    USE_PROMETHEUS_CLIENT = False

def safe_increment(metric_name, n=1):
    """
    Thread-safe metric update executed on the reactor thread.
    - active_streams is clamped to >= 0 and sets the Prometheus gauge to the exact value.
    - Counters are only incremented (ignore negative attempts).
    """
    def _inc():
        old = metrics.get(metric_name, 0)
        new = old + n

        if metric_name == "active_streams":
            # clamp
            if new < 0:
                new = 0
            metrics[metric_name] = new
            if USE_PROMETHEUS_CLIENT:
                try:
                    PROM_ACTIVE.set(new)
                except Exception:
                    pass
            return

        # for counters, avoid decrementing them via this function (only support positive increments)
        if metric_name in ("requests_total","bytes_in_total","bytes_out_total","streams_reset_total","ipset_refresh_count"):
            if n > 0:
                metrics[metric_name] = new
                if USE_PROMETHEUS_CLIENT:
                    try:
                        if metric_name == "requests_total": PROM_REQUESTS.inc(n)
                        elif metric_name == "bytes_in_total": PROM_BYTES_IN.inc(n)
                        elif metric_name == "bytes_out_total": PROM_BYTES_OUT.inc(n)
                        elif metric_name == "streams_reset_total": PROM_RST.inc(n)
                        # ipset_refresh_count is an internal counter; we don't map it to a Prom client metric here
                    except Exception:
                        pass
            else:
                # ignore negative adjustments to counters to prevent inconsistencies
                metrics[metric_name] = max(0, old + n)
        else:
            # generic fallback
            metrics[metric_name] = max(0, new)

    try:
        reactor.callFromThread(_inc)
    except Exception:
        # If reactor not running (unit tests/etc), run inline
        _inc()

def incr_bytes_out(n:int): safe_increment("bytes_out_total", n)
def incr_bytes_in(n:int): safe_increment("bytes_in_total", n)
def incr_streams_reset(): safe_increment("streams_reset_total", 1)

def run_cmd_blocking(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

class IPCollector:
    CF_IPS_V4 = "https://www.cloudflare.com/ips-v4"
    CF_IPS_V6 = "https://www.cloudflare.com/ips-v6"

    def __init__(self):
        # cached set of CIDR strings
        self.valid_ips = set()

    def _fetch_ips_blocking(self) -> List[str]:
        """Blocking fetch of both IPv4 and IPv6 Cloudflare lists."""
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
        """
        Blocking: fetch Cloudflare ranges and atomically update the kernel ipset.
        Returns True on success.
        """
        ips = self._fetch_ips_blocking()
        if not ips:
            logger.warning("No Cloudflare IP ranges fetched; skipping ipset update")
            return False

        # Build a temporary set, add members, then swap
        tmp_set = IPSET_NAME + "_tmp"
        try:
            subprocess.run(["ipset","create",tmp_set,"hash:net"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        for cidr in ips:
            try:
                subprocess.run(["ipset","add",tmp_set,cidr,"-exist"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        # swap into place
        try:
            subprocess.run(["ipset","swap",tmp_set,IPSET_NAME], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["ipset","destroy",tmp_set], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning("ipset swap/destroy failed: %s", e)
            return False

        # update memory cache of ip networks for fallback checks
        try:
            self.valid_ips = set(ips)
        except Exception:
            self.valid_ips = set(ips)

        safe_increment("ipset_refresh_count", 1)
        logger.info("Refreshed ipset %s with %d entries", IPSET_NAME, len(self.valid_ips))
        return True

    def refresh_ipset(self):
        """Schedule the blocking refresh on reactor threadpool."""
        return deferToThread(self.refresh_ipset_blocking)

    def is_valid_ip(self, ip: str) -> bool:
        """
        Prefer kernel ipset test (fast). If ipset isn't available or test fails, fall back
        to in-memory CIDR matching.
        """
        # Try kernel-level ipset test first
        try:
            res = subprocess.run(["ipset","test",IPSET_NAME,ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if res.returncode == 0:
                return True
        except Exception:
            # ipset not available/permission denied -> fall back
            pass

        # Fallback: check against cached CIDRs
        try:
            ipaddr = ipaddress.ip_address(ip)
            for net in self.valid_ips:
                try:
                    if ipaddr in ipaddress.ip_network(net):
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

# ---------- IPSet helpers ----------
# instantiate a collector for the program to share
ip_collector = IPCollector()


class IPWhitelistProxy(Protocol):
    def __init__(self, factory):
        self.factory = factory
        self.transport = None
        self.client_ip = None

    def connectionMade(self):
        peer = self.transport.getPeer()
        self.client_ip = peer.host
        if not ip_collector.is_valid_ip(self.client_ip):
            logger.warning(f"Connection rejected: {self.client_ip} not in Cloudflare ranges")
            self.transport.loseConnection()
            return
        logger.info(f"Accepted proxied client from {self.client_ip}")
        # Continue with normal H2 setup
        self.factory.active_connections.add(self)
        self.factory.protocol_instance = self
        self.factory.h2_conn.initiate_connection()
        self.factory._send_data()

    def connectionLost(self, reason):
        if self in self.factory.active_connections:
            self.factory.active_connections.remove(self)


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

def ipset_contains_peer(ip: str) -> bool:
    try:
        ipaddr = ipaddress.ip_address(ip)
        # Use the cached Cloudflare networks from the collector
        return any(ipaddr in ipaddress.ip_network(net) for net in ip_collector.valid_ips)
    except Exception:
        pass

    # Fallback: kernel ipset check
    try:
        res = subprocess.run(
            ["ipset", "test", IPSET_NAME, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False
        )
        return res.returncode == 0
    except Exception:
        return False

# ---------- Stream Metadata ----------
class StreamMeta:
    __slots__ = ('stream_id','protocol_ref','buffer','start','end','last_activity',
                 'closed','inactivity_call','body_timeout_call','start_time','weight',
                 'depends_on','exclusive')

    def __init__(self, stream_id:int, proto):
        self.stream_id = stream_id
        self.protocol_ref = proto
        self.buffer = bytearray()
        self.start = 0
        self.end = 0
        self.last_activity = time.time()
        self.closed = False
        self.inactivity_call = None
        self.body_timeout_call = None
        self.start_time = time.time()
        self.weight = None
        self.depends_on = None
        self.exclusive = None

    @property
    def buffered_bytes(self):
        return self.end - self.start

    def enqueue(self, data: bytes):
        if not data: return
        self.buffer += data
        self.end += len(data)
        self.last_activity = time.time()
        if self.buffered_bytes > MAX_BUFFER_PER_STREAM:
            # reset with ENHANCE_YOUR_CALM when buffer grows too large
            self.reset_stream(h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
            return
        if len(data) > 1024: self.reset_inactivity_timer()

    def pop_chunk(self, size:int) -> Optional[bytes]:
        if self.buffered_bytes==0: return None
        n = min(size,self.buffered_bytes)
        chunk = memoryview(self.buffer)[self.start:self.start+n].tobytes()
        self.start += n
        # Compact buffer if needed
        if self.start>=1024*1024 or self.start==self.end:
            self.buffer = self.buffer[self.start:]
            self.end -= self.start
            self.start = 0
        self.last_activity = time.time()
        self.reset_inactivity_timer()
        return chunk

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

    def on_inactive(self): self.reset_stream(h2.errors.ErrorCodes.CANCEL, STREAM_INACTIVITY_TIMEOUT)
    def on_body_timeout(self): self.reset_stream(h2.errors.ErrorCodes.CANCEL, STREAM_BODY_TIMEOUT)

    def reset_stream(self, code, duration=None):
        code_int = int(code) if isinstance(code,int) else code
        reason = getattr(h2.errors.ErrorCodes(code_int),"name",str(code_int))
        logger.warning("Stream %d reset: %s after %s seconds", self.stream_id, reason, duration)
        incr_streams_reset()
        try:
            self.protocol_ref.h2_conn.reset_stream(self.stream_id,error_code=code_int)
            self.protocol_ref.transport.write(self.protocol_ref.h2_conn.data_to_send())
        except Exception: pass
        self.clear()

    def clear(self):
        # decrement active_streams (clamped in safe_increment)
        safe_increment("active_streams",-1)
        self.buffer = bytearray()
        self.start = 0
        self.end = 0
        self.cancel_timers()
        try: del self.protocol_ref.stream_meta[self.stream_id]
        except KeyError: pass
        # Observe duration if Prometheus enabled
        if USE_PROMETHEUS_CLIENT:
            duration = time.time() - self.start_time
            try: PROM_STREAM_LATENCY.observe(duration)
            except Exception: pass

# ---------- Upstream via Twisted Agent ----------
class UpstreamStreamReceiver(Protocol, TimeoutMixin):
    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_meta: StreamMeta):
        self.h2_protocol = h2_protocol
        self.meta = stream_meta
        self.setTimeout(UPSTREAM_TIMEOUT)

    def dataReceived(self, data: bytes):
        if not self.meta or self.meta.closed: return
        self.meta.enqueue(data)
        # trigger the send loop only when new data arrives
        self.h2_protocol.maybe_send_queued_data()

    def connectionLost(self, reason):
        # Mark upstream closed and ensure client receives END_STREAM
        if self.meta and not self.meta.closed:
            self.meta.closed = True
            # if there's no buffered data, send an explicit END_STREAM immediately
            try:
                # Send an empty DATA frame with end_stream=True so the client sees the end.
                self.h2_protocol.h2_conn.send_data(self.meta.stream_id, b'', end_stream=True)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception as e:
                logger.debug("Failed to send END_STREAM for stream %d: %s", self.meta.stream_id, e)
        # Trigger the send loop to let it finalize any remaining work
        self.h2_protocol.maybe_send_queued_data()

    def timeoutConnection(self):
        logger.warning("Upstream timeout for stream %d", self.meta.stream_id)
        self.meta.reset_stream(h2.errors.ErrorCodes.CANCEL)
        self.transport.loseConnection()


class UpstreamAgentRequest:
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_meta: StreamMeta,
                 method: str, path: str, headers: List[Tuple[str,str]]):
        self.h2_protocol = h2_protocol
        self.meta = stream_meta
        self.method = method.encode("ascii")
        self.path = urllib.parse.quote(path, safe="/?=&")  # safe encoding
        self.headers = headers

    def start(self, attempt=1):
        url = f"http://{UPSTREAM_HOST}:{UPSTREAM_PORT}{self.path}".encode("ascii")
        hdrs = Headers()
        for k, v in self.headers:
            if k.lower() in ("connection","proxy-connection","keep-alive","transfer-encoding"): continue
            if k.lower() in ("server","x-powered-by"): continue
            hdrs.addRawHeader(k, v)
        d = self.h2_protocol.agent.request(self.method, url, headers=hdrs)

        # setup timeout
        timeout_call = reactor.callLater(UPSTREAM_TIMEOUT, lambda: d.cancel())

        def on_response(resp):
            if timeout_call.active():
                timeout_call.cancel()
            status = resp.code
            h2_headers = [(":status", str(status))]
            raw_link_headers = []

            for name, vals in resp.headers.getAllRawHeaders():
                lname = name.decode().lower()
                val = b", ".join(vals).decode()
                if lname in ("connection","proxy-connection","keep-alive","transfer-encoding"):
                    continue
                h2_headers.append((lname, val))
                if lname == "link":
                    raw_link_headers.append(val)

            # Security & caching defaults (keep your ensures)
            def ensure(hlist, key, val):
                if not any(k.lower()==key.lower() for k,_ in hlist):
                    hlist.append((key,val))
            ensure(h2_headers,"cache-control","public, max-age=31536000")
            ensure(h2_headers,"strict-transport-security","max-age=31536000; includeSubDomains")
            ensure(h2_headers,"x-content-type-options","nosniff")
            ensure(h2_headers,"x-frame-options","DENY")
            ensure(h2_headers,"referrer-policy","no-referrer")

            # Send headers to client
            try:
                self.h2_protocol.h2_conn.send_headers(self.meta.stream_id, h2_headers)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception as e:
                logger.debug("Failed to send H2 headers: %s", e)

            # --- Parse and validate Link headers for push ---
            # Only consider Link params that include rel=preload
            # Only allow pushes for same-origin (relative paths) or same host as UPSTREAM_HOST.
            def parse_link_entries(link_value: str):
                # Basic parser: split on comma not inside quotes (simple approximation)
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
                    # expect format: <url>; param1=..., param2="..."
                    if '<' not in ent or '>' not in ent:
                        continue
                    url_part = ent[ent.find('<')+1:ent.find('>')].strip()
                    params_part = ent[ent.find('>')+1:].strip()
                    params = {}
                    for p in params_part.split(';'):
                        p = p.strip()
                        if not p: continue
                        if '=' in p:
                            k, v = p.split('=',1)
                            v = v.strip().strip('"')
                            params[k.lower()] = v
                        else:
                            params[p.lower()] = ""
                    parsed.append((url_part, params))
                return parsed

            for raw_link in raw_link_headers:
                for url_part, params in parse_link_entries(raw_link):
                    rel = params.get('rel','').lower()
                    if 'preload' not in rel.split():
                        # only respect rel=preload entries for push
                        continue

                    # Validate target: allow relative URLs or same host as UPSTREAM_HOST
                    parsed = urllib.parse.urlparse(url_part)
                    # Accept if no netloc (relative) or netloc matches UPSTREAM_HOST (optionally port)
                    netloc_ok = False
                    if parsed.netloc == "" or parsed.netloc is None:
                        netloc_ok = True
                    else:
                        # strip possible port
                        host_only = parsed.netloc.split(':',1)[0]
                        if host_only == UPSTREAM_HOST:
                            netloc_ok = True

                    if not netloc_ok:
                        logger.debug("Skipping push for cross-origin Link target: %s", url_part)
                        continue

                    # construct path (path + maybe query + maybe fragment omitted)
                    push_path = parsed.path or '/'
                    if parsed.query:
                        push_path += '?' + parsed.query

                    try:
                        self.h2_protocol.initiate_push(self.meta.stream_id, push_path)
                    except Exception as e:
                        logger.debug("initiate_push skipped/failed for %s: %s", push_path, e)

            # deliver body to receiver
            resp.deliverBody(UpstreamStreamReceiver(self.h2_protocol, self.meta))
            return resp

        def on_error(f):
            if timeout_call.active():
                timeout_call.cancel()
            if attempt < self.MAX_RETRIES:
                logger.warning("Upstream fetch failed, retrying %d/%d: %s", attempt, self.MAX_RETRIES, f)
                reactor.callLater(self.RETRY_DELAY, lambda: self.start(attempt+1))
            else:
                logger.error("Upstream fetch failed for stream %d: %s", self.meta.stream_id, f)
                if self.meta: self.meta.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)

        d.addCallbacks(on_response, on_error)
        return d

# ---------- H2 Protocol ----------
class H2ProxyProtocol:
    def __init__(self, transport):
        self.transport = transport
        self.h2_conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
        self.stream_meta: Dict[int,StreamMeta] = {}
        self.waiters: List[Deferred] = []
        self.sending = False
        self.max_concurrent_streams = MAX_CONCURRENT_STREAMS_DEFAULT
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)
        # Removed tight LoopingCall(0.001) to avoid busy-polling.
        # The send-loop is driven by events: incoming upstream data, window updates, or explicit wakeups.
        self.agent = Agent(reactor, BrowserLikePolicyForHTTPS())

    def on_connection_idle(self):
        if any(not s.closed for s in self.stream_meta.values()):
            self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)
            return
        try: self.transport.loseConnection()
        except Exception: pass

    def handle_request(self, event: h2.events.RequestReceived):
        safe_increment("requests_total", 1)

        try:
            if self._idle_call.active():
                self._idle_call.cancel()
        except Exception:
            pass
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)


        headers = [(k.decode() if isinstance(k, bytes) else k,
                    v.decode() if isinstance(v, bytes) else v) for k,v in event.headers]
        method = next((v for k,v in headers if k==":method"), None)
        path = next((v for k,v in headers if k==":path"), None)
        if not method or not path:
            try:
                self.h2_conn.reset_stream(event.stream_id, error_code=h2.errors.ErrorCodes.PROTOCOL_ERROR)
                self.transport.write(self.h2_conn.data_to_send())
            except Exception: pass
            return

        if len(self.stream_meta) >= self.max_concurrent_streams:
            try:
                hdrs = [(":status","503"),("content-length","0")]
                self.h2_conn.send_headers(event.stream_id,hdrs,end_stream=True)
                self.transport.write(self.h2_conn.data_to_send())
                incr_streams_reset()
            except Exception: pass
            return

        meta = StreamMeta(event.stream_id, self)
        self.stream_meta[event.stream_id] = meta
        safe_increment("active_streams", 1)
        upstream_headers = [(k.lower(),v) for k,v in headers if not k.startswith(":")]
        UpstreamAgentRequest(self, meta, method, path, upstream_headers).start()

    def dataReceived(self, data: bytes):
        try:
            if self._idle_call.active(): self._idle_call.cancel()
        except Exception: pass
        self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)
        events = self.h2_conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                self.handle_request(event)
            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                incr_bytes_in(len(event.data))
                meta = self.stream_meta.get(sid)
                if meta: meta.set_body_timeout()
            elif isinstance(event, h2.events.StreamEnded):
                sid = event.stream_id
                meta = self.stream_meta.get(sid)
                if meta:
                    meta.closed = True
                # Reset idle timer since a new stream just finished
                try:
                    if self._idle_call.active():
                        self._idle_call.cancel()
                except Exception:
                    pass
                self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)
            elif isinstance(event, h2.events.WindowUpdated):
                self._wake_waiters()
                # wake send loop if waiting
                self.maybe_send_queued_data()
            elif isinstance(event, h2.events.RemoteSettingsChanged):
                if h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS in event.changed_settings:
                    self.max_concurrent_streams = event.changed_settings[h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS]
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
                    self.stream_meta[sid].clear()
                # Reset idle timer after stream reset
                try:
                    if self._idle_call.active():
                        self._idle_call.cancel()
                except Exception:
                    pass
                self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)

        # Try to send any queued data if possible
        self.maybe_send_queued_data()
        self.transport.write(self.h2_conn.data_to_send())

    def _wake_waiters(self):
        waiters = list(self.waiters)
        self.waiters.clear()
        for d in waiters:
            try: d.callback(None)
            except Exception: pass

    def wait_for_window(self) -> Deferred:
        d = Deferred()
        self.waiters.append(d)
        return d

    def maybe_send_queued_data(self):
        """
        Event-driven trigger to run the send loop.
        We set a 'sending' flag and schedule the _send_loop to run on next reactor tick.
        """
        if getattr(self, "sending", False):
            return
        self.sending = True
        reactor.callLater(0, self._send_loop)

    def _send_loop(self):
        # Clear sending flag at the end (in finally); if send-loop re-triggers maybe_send_queued_data
        try:
            active_streams = {s.stream_id:s for s in self.stream_meta.values() if s.buffered_bytes>0 and not s.closed}
            if not active_streams:
                return

            tree: Dict[int, List[StreamMeta]] = {}
            for meta in active_streams.values():
                parent = meta.depends_on or 0
                tree.setdefault(parent, [])
                if meta.exclusive and parent in tree:
                    existing = tree[parent]
                    for sib in existing:
                        sib.depends_on = meta.stream_id
                    tree[meta.stream_id] = existing
                    tree[parent] = [meta]
                else:
                    tree[parent].append(meta)

            def send_branch(parent_id, ratio=1.0):
                children = tree.get(parent_id, [])
                total_weight = sum((c.weight or 16) for c in children) or 1
                for child in children:
                    child_ratio = ratio * ((child.weight or 16) / total_weight)
                    while child.buffered_bytes > 0:
                        conn_window = self.h2_conn.local_flow_control_window(child.stream_id)
                        if conn_window <= 0:
                            # Wait for window update; schedule wakeup on window update
                            d = self.wait_for_window()
                            d.addCallback(lambda _: self._send_loop())
                            return False
                        chunk_size = min(child.buffered_bytes, MAX_FRAME_SIZE, conn_window)
                        chunk = child.pop_chunk(chunk_size)
                        if not chunk: break
                        try:
                            self.h2_conn.send_data(child.stream_id, chunk)
                            incr_bytes_out(len(chunk))
                        except Exception as e:
                            logger.debug("Send failed for stream %d: %s", child.stream_id, e)
                            child.reset_stream(h2.errors.ErrorCodes.INTERNAL_ERROR)
                            break
                        self.transport.write(self.h2_conn.data_to_send())
                    # Recurse into this child's children (priority tree)
                    send_branch(child.stream_id, child_ratio)
                return True

            send_branch(0)

        except Exception as e:
            logger.error("Error in _send_loop: %s", e)
        finally:
            # mark sending complete (allows future wakeups)
            self.sending = False

    def initiate_push(self, parent_stream_id:int, link_path:str):
        """
        Hardened push: only accept relative paths or paths that reference the UPSTREAM_HOST.
        `link_path` here should be a path (e.g. "/static/foo.js" or "/img/a.png?q=1").
        """
        # If the caller supplied a full URL, parse it; if it's already a path, parsed.path is that.
        parsed = urllib.parse.urlparse(link_path)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        # Disallow absolute cross-origin pushes
        if parsed.netloc and parsed.netloc.split(':',1)[0] != UPSTREAM_HOST:
            logger.debug("Refusing to push cross-origin resource: %s", link_path)
            return

        try:
            sid = self.h2_conn.get_next_available_stream_id()
            # Use scheme https and authority equal to the host client expects (use UPSTREAM_HOST)
            headers=[(":method","GET"),(":path",path),(":scheme","https"),
                     (":authority", parsed.netloc or UPSTREAM_HOST)]
            # push_stream can raise if server doesn't allow; guard it
            self.h2_conn.push_stream(parent_stream_id, sid, headers)
            self.transport.write(self.h2_conn.data_to_send())
        except Exception as e:
            logger.debug("Push failed for %s: %s", path, e)


# ---------- TLS Listener ----------
class H2ProtocolWrapper(Protocol):
    def connectionMade(self):
        self.h2 = H2ProxyProtocol(self.transport)
        self.h2.h2_conn.initiate_connection()
        self.transport.write(self.h2.h2_conn.data_to_send())
    def dataReceived(self, data): self.h2.dataReceived(data)

class H2Factory(Factory):
    def buildProtocol(self, addr): return H2ProtocolWrapper()

def start_tls_listener():
    ctx = pyssl.SSLContext(pyssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE,keyfile=KEY_FILE)
    ctx.options |= pyssl.OP_NO_TLSv1 | pyssl.OP_NO_TLSv1_1
    ctx.set_ciphers("ECDHE+AESGCM:!aNULL:!MD5:!3DES")
    ctx.set_alpn_protocols(["h2"])
    reactor.listenSSL(LISTEN_PORT,H2Factory(),ctx)

# ---------- Metrics server ----------
def start_metrics_server():
    if USE_PROMETHEUS_CLIENT:
        app = make_wsgi_app()
        root = WSGIResource(reactor, reactor.getThreadPool(), app)
        reactor.listenTCP(METRICS_PORT, Site(root))

# ---------- Signal Handling ----------
def shutdown(*args):
    cleanup_ipset_and_rule()
    reactor.stop()

signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)

# ---------- Periodic Cloudflare IP refresh ----------
def start_periodic_ip_refresh():
    # Immediate refresh first
    refresh_ipset_async()
    # Schedule hourly refresh
    loop = task.LoopingCall(refresh_ipset_async)
    loop.start(IP_REFRESH_INTERVAL, now=False)

if __name__=="__main__":
    setup_ipset_and_rule()
    start_periodic_ip_refresh()
    start_tls_listener()
    start_metrics_server()
    reactor.run()
