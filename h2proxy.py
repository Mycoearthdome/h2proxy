#!/usr/bin/env python3
# Hardened HTTP/2 -> HTTP/1.1 streaming proxy with safe _send_loop, retries, metrics, ALPN, push, and Cloudflare IP whitelist

# Please install the following.....
# sudo apt install python3-systemd ipset
# pip install prometheus-client

from __future__ import annotations
import sys, time, logging, signal, ipaddress, subprocess, urllib.parse
from typing import Dict, List, Optional, Tuple

from twisted.internet import reactor, task
from twisted.internet.threads import deferToThread
from twisted.internet.protocol import Protocol, Factory
from twisted.web.client import Agent, BrowserLikePolicyForHTTPS
from twisted.web.resource import Resource
from twisted.web.server import Site
from twisted.web.http_headers import Headers
from twisted.internet.defer import Deferred

import h2.connection, h2.events, h2.config, h2.settings
import ssl as pyssl

# ---------- Configuration ----------
CLOUDFLARE_IPS_URL = "https://www.cloudflare.com/ips-v4"
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
    reactor.callFromThread(lambda: metrics.update({metric_name: metrics.get(metric_name,0)+n}))
    if USE_PROMETHEUS_CLIENT:
        try:
            if metric_name=="requests_total": PROM_REQUESTS.inc(n)
            elif metric_name=="active_streams": PROM_ACTIVE.inc(n)
            elif metric_name=="bytes_in_total": PROM_BYTES_IN.inc(n)
            elif metric_name=="bytes_out_total": PROM_BYTES_OUT.inc(n)
            elif metric_name=="streams_reset_total": PROM_RST.inc(n)
        except Exception: pass

def incr_bytes_out(n:int): safe_increment("bytes_out_total", n)
def incr_bytes_in(n:int): safe_increment("bytes_in_total", n)
def incr_streams_reset(): safe_increment("streams_reset_total", 1)

# ---------- IPSet helpers ----------
_cloudflare_networks: List[ipaddress.IPv4Network] = []

def run_cmd_blocking(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

class IPCollector(Protocol):
    def __init__(self, deferred: Deferred):
        self.deferred = deferred
        self.body = b""

    def dataReceived(self, data: bytes):
        self.body += data

    def connectionLost(self, reason):
        body = self.body.decode(errors="ignore")
        nets = [line.strip() for line in body.splitlines() if line.strip()]

        def _do_update():
            new_set = IPSET_NAME + "_new"
            run_cmd_blocking(["ipset","create",new_set,"hash:net","-exist"])
            for net in nets: run_cmd_blocking(["ipset","add",new_set,net,"-exist"])
            run_cmd_blocking(["ipset","swap",new_set,IPSET_NAME])
            run_cmd_blocking(["ipset","destroy",new_set])
            global _cloudflare_networks
            _cloudflare_networks = [ipaddress.ip_network(n) for n in nets]
            safe_increment('ipset_refresh_count')
            return True

        d = deferToThread(_do_update)
        d.addBoth(lambda r: self.deferred.callback(True))

def refresh_ipset_async(retries=3, delay=2):
    agent = Agent(reactor, BrowserLikePolicyForHTTPS())
    def _do_refresh(attempt=1):
        d = agent.request(b"GET", CLOUDFLARE_IPS_URL.encode("ascii"))
        def on_response(resp):
            done = Deferred()
            resp.deliverBody(IPCollector(done))
            return done
        d.addCallback(on_response)
        def on_error(failure):
            if attempt < retries:
                reactor.callLater(delay*(2**(attempt-1)), _do_refresh, attempt+1)
            else: logger.error("Failed Cloudflare IP fetch: %s", failure)
        d.addErrback(on_error)
    _do_refresh()

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

def ipset_contains_peer(ip:str)->bool:
    try:
        ipaddr = ipaddress.ip_address(ip)
        return any(ipaddr in net for net in _cloudflare_networks)
    except Exception: pass
    try:
        res = subprocess.run(["ipset","test",IPSET_NAME,ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return res.returncode == 0
    except Exception: return False

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
        safe_increment("active_streams",-1)
        self.buffer = bytearray()
        self.start = 0
        self.end = 0
        self.cancel_timers()
        try: del self.protocol_ref.stream_meta[self.stream_id]
        except KeyError: pass
        if USE_PROMETHEUS_CLIENT:
            duration = time.time() - self.start_time
            try: PROM_STREAM_LATENCY.observe(duration)
            except Exception: pass
            try: PROM_ACTIVE.dec()
            except Exception: pass

# ---------- Upstream via Twisted Agent ----------
class UpstreamStreamReceiver(Protocol):
    def __init__(self, h2_protocol: "H2ProxyProtocol", stream_meta: StreamMeta):
        self.h2_protocol = h2_protocol
        self.meta = stream_meta

    def dataReceived(self, data: bytes):
        if not self.meta or self.meta.closed: return
        self.meta.enqueue(data)
        self.h2_protocol.maybe_send_queued_data()

    def connectionLost(self, reason):
        if self.meta: self.meta.closed = True
        self.h2_protocol.maybe_send_queued_data()

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

        def on_response(resp):
            status = resp.code
            h2_headers = [(":status", str(status))]
            link_headers = []
            for name, vals in resp.headers.getAllRawHeaders():
                lname = name.decode().lower()
                val = b", ".join(vals).decode()
                if lname in ("connection","proxy-connection","keep-alive","transfer-encoding"): continue
                h2_headers.append((lname, val))
                if lname == "link": link_headers.append(val)

            # Security & caching
            def ensure(hlist, key, val):
                if not any(k.lower()==key.lower() for k,_ in hlist):
                    hlist.append((key,val))
            ensure(h2_headers,"cache-control","public, max-age=31536000")
            ensure(h2_headers,"strict-transport-security","max-age=31536000; includeSubDomains")
            ensure(h2_headers,"x-content-type-options","nosniff")
            ensure(h2_headers,"x-frame-options","DENY")
            ensure(h2_headers,"referrer-policy","no-referrer")

            try:
                self.h2_protocol.h2_conn.send_headers(self.meta.stream_id, h2_headers)
                self.h2_protocol.transport.write(self.h2_protocol.h2_conn.data_to_send())
            except Exception as e:
                logger.debug("Failed to send H2 headers: %s", e)

            for link in link_headers:
                try: self.h2_protocol.initiate_push(self.meta.stream_id, link)
                except Exception: pass

            resp.deliverBody(UpstreamStreamReceiver(self.h2_protocol, self.meta))
            return resp

        def on_error(f):
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
        self._send_loop_task = task.LoopingCall(self._send_loop)
        self._send_loop_task.start(0.001, now=False)
        self.agent = Agent(reactor, BrowserLikePolicyForHTTPS())

    def on_connection_idle(self):
        if any(not s.closed for s in self.stream_meta.values()):
            self._idle_call = reactor.callLater(CONNECTION_IDLE_TIMEOUT, self.on_connection_idle)
            return
        try: self.transport.loseConnection()
        except Exception: pass

    def handle_request(self, event: h2.events.RequestReceived):
        safe_increment("requests_total")
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
                safe_increment("active_streams")
            elif isinstance(event, h2.events.DataReceived):
                sid = event.stream_id
                incr_bytes_in(len(event.data))
                meta = self.stream_meta.get(sid)
                if meta: meta.set_body_timeout()
            elif isinstance(event, h2.events.StreamEnded):
                sid = event.stream_id
                meta = self.stream_meta.get(sid)
                if meta: meta.closed=True
            elif isinstance(event, h2.events.WindowUpdated):
                self._wake_waiters()
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
                if sid in self.stream_meta: self.stream_meta[sid].clear()
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
        if getattr(self, "sending", False):
            return
        self.sending = True
        reactor.callLater(0, self._send_loop)

    def _send_loop(self):
        if getattr(self,"sending",False) is False: self.sending = True
        try:
            active_streams = {s.stream_id:s for s in self.stream_meta.values() if s.buffered_bytes>0 and not s.closed}
            if not active_streams: return

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
                total_weight = sum((c.weight or 16) for c in children)
                for child in children:
                    child_ratio = ratio * ((child.weight or 16) / total_weight)
                    while child.buffered_bytes > 0:
                        conn_window = self.h2_conn.local_flow_control_window(child.stream_id)
                        if conn_window <= 0:
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
                    send_branch(child.stream_id, child_ratio)
                return True

            send_branch(0)

        except Exception as e:
            logger.error("Error in _send_loop: %s", e)
        finally:
            self.sending = False

    def initiate_push(self, parent_stream_id:int, link_header:str):
        parsed = urllib.parse.urlparse(link_header.strip("<>"))
        path = parsed.path or "/"
        try:
            sid = self.h2_conn.get_next_available_stream_id()
            headers=[(":method","GET"),(":path",path),(":scheme","https"),
                     (":authority",parsed.netloc or UPSTREAM_HOST)]
            self.h2_conn.push_stream(parent_stream_id,sid,headers)
            self.transport.write(self.h2_conn.data_to_send())
        except Exception as e:
            logger.debug("Push failed: %s", e)

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