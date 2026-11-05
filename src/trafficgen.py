#!/usr/bin/env python3
"""trafficgen - realistic multi-source-IP traffic generator for FortiGate
(SD-WAN / application control / web filtering) monitoring.

Engine + CLI. The web GUI (webui.py) is the normal way to run tests.
"""
import argparse
import collections
import http.client
import ipaddress
import json
import os
import random
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

import yaml

CONFIG_PATH = os.environ.get("TRAFFICGEN_CONFIG", "/etc/trafficgen/config.yaml")
USER_PROFILES = "/etc/trafficgen/profiles.yaml"
DEFAULT_PROFILES = os.path.join(os.path.dirname(os.path.realpath(__file__)), "profiles.yaml")
STATE_DIR = os.environ.get("TRAFFICGEN_VARDIR", "/var/lib/trafficgen")
LOG_DIR = os.environ.get("TRAFFICGEN_LOGDIR", "/var/log/trafficgen")
UNIT = "trafficgen-run"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
THINK = {"low": (5, 20), "medium": (1, 8), "high": (0.2, 2)}

DEFAULT_CONFIG = {
    "mgmt_interface": "eth0",      # never used for test traffic
    "networks": [],                # source networks, managed in the GUI (see netconf.py)
    "duration_minutes": 10,        # 0 = run until stopped
    "threads_per_ip": 2,           # parallel 'sessions' per source IP
    "intensity": "medium",         # low | medium | high
    "tls_verify": False,           # False = work behind SSL deep inspection
    "disabled_apps": [],
    "ioc_feeds": False,            # fetch the Feodo C2 IP list (used only as DNS/connect targets)
    "ioc_connect": False,          # allow bare TCP connects to IOC IPs/ports (no payload is sent)
    "block_ips": ["208.91.112.55"],  # DNS answers that mean "FortiGuard block portal"
    "throughput": {                # bandwidth / packet-loss / CPS tester (see throughput.py)
        "tx_network": "",          # name of the source network the sender uses
        "base_port": 5201,         # UDP/TCP ports base..base+7 on the receiver
        "rx": {"mode": "isolated", "parent": "eth1", "vlan": "", "ip": "", "prefix": 24, "gateway": "", "count": 1},
    },
    "groups": {                    # relative weights of traffic groups; 0 = off
        "office365": 25, "collab": 20, "streaming": 20, "social": 10,
        "saas": 10, "web": 10, "updates": 3, "download": 2, "sdwan": 5,
        "webfilter": 0, "malware": 0, "ioc": 0,
    },
}


# --------------------------------------------------------------- helpers
def deep_merge(a, b):
    out = dict(a)
    for k, v in (b or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path=None):
    path = path or CONFIG_PATH
    cfg = DEFAULT_CONFIG
    if os.path.exists(path):
        with open(path) as f:
            cfg = deep_merge(DEFAULT_CONFIG, yaml.safe_load(f) or {})
    return cfg


def load_profiles():
    path = USER_PROFILES if os.path.exists(USER_PROFILES) else DEFAULT_PROFILES
    with open(path) as f:
        return yaml.safe_load(f)["apps"]


def sh(cmd, check=False):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def iface_info(iface):
    r = sh(["ip", "-j", "-4", "addr", "show", "dev", iface])
    if r.returncode != 0:
        sys.exit("Interface %s not found: %s" % (iface, r.stderr.strip()))
    addrs = json.loads(r.stdout)[0]["addr_info"]
    if not addrs:
        sys.exit("Interface %s has no IPv4 address" % iface)
    return addrs[0]["local"], addrs[0]["prefixlen"]


def log(msg):
    print("%s %s" % (datetime.now().strftime("%H:%M:%S"), msg), flush=True)


# ------------------------------------------------------------------- DNS
def _skip_name(buf, off):
    while True:
        ln = buf[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


class DNSError(OSError):
    def __init__(self, rcode):
        super().__init__("DNS rcode %d" % rcode)
        self.rcode = rcode


def dns_resolve(name, server, src_ip, timeout=2.0):
    """A-record lookup bound to src_ip; raises DNSError/OSError when nothing resolves."""
    rcode, ips = dns_query(name, server, src_ip, 1, timeout)
    if rcode or not ips:
        raise DNSError(rcode)
    return ips


def dns_query(name, server, src_ip, qtype=1, timeout=2.0):
    """Raw DNS query bound to src_ip. Returns (rcode, [A records])."""
    tid = random.randrange(65536)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    q += struct.pack(">HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.bind((src_ip, 0))
        s.sendto(q, (server, 53))
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != tid:
        raise OSError("bad DNS reply")
    rcode = data[3] & 0x0F
    qd, an = struct.unpack(">HH", data[4:8])
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        off = _skip_name(data, off)
        rtype, _c, _ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return rcode, ips


# ---------------------------------------------------------------- HTTP(S)
class _Conn:
    """Mixin: connect to a pre-resolved IP from a fixed source address."""

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout, self.source_address)
        if self._tls:
            sock = self._ctx.wrap_socket(sock, server_hostname=self.host)
        self.sock = sock


class _HTTP(_Conn, http.client.HTTPConnection):
    _tls = False


class _HTTPS(_Conn, http.client.HTTPSConnection):
    _tls = True


def http_get(url, ip, src_ip, ua, max_bytes, ctx, timeout=10):
    scheme, rest = url.split("://", 1)
    hostport, _, path = rest.partition("/")
    path = "/" + path
    host, _, port = hostport.partition(":")
    port = int(port) if port else (443 if scheme == "https" else 80)
    cls = _HTTPS if scheme == "https" else _HTTP
    c = cls(host, port, timeout=timeout, source_address=(src_ip, 0))
    c._ip, c._ctx = ip, ctx
    got, status, blocked = 0, 0, False
    try:
        c.request("GET", path, headers={"User-Agent": ua, "Accept": "*/*",
                                        "Accept-Language": "nl-NL,nl;q=0.9,en;q=0.8",
                                        "Accept-Encoding": "identity"})
        r = c.getresponse()
        status = r.status
        head = b""
        while got < max_bytes:
            chunk = r.read(min(65536, max_bytes - got))
            if not chunk:
                break
            if got < 4096:
                head += chunk[:4096]
            got += len(chunk)
        blocked = is_block_page(status, head.lower())
        eicar = b"eicar-standard-antivirus-test-file" in head.lower()
    finally:
        c.close()
    return status, got, blocked, eicar


BLOCK_MARKERS = (b"web page blocked", b"high security alert", b"you are not permitted to download",
                 b"fortiguard", b"fortigate", b"application control", b"blocked by", b"access denied by")


def is_block_page(status, text):
    """Heuristic for FortiGate replacement messages (web filter, AV, app control)."""
    if any(m in text for m in BLOCK_MARKERS):
        return True
    return status == 403 and b"block" in text


# ------------------------------------------------------- IOC-style probes
def tcp_connect(host, port, src_ip, timeout=4):
    """Bare TCP connect, closed immediately. No data is sent. Returns 'connected' | 'refused' | 'timeout'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.bind((src_ip, 0))
        s.connect((host, int(port)))
        return "connected"
    except ConnectionRefusedError:
        return "refused"
    except (socket.timeout, TimeoutError):
        return "timeout"
    except ConnectionResetError:
        return "reset"
    finally:
        s.close()


def dga_name():
    """Random algorithmically-generated-looking domain (will not exist)."""
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    lab = "".join(random.choice(letters) for _ in range(random.randint(10, 18)))
    return lab + random.choice([".com", ".net", ".org", ".info", ".biz", ".top", ".xyz", ".ru", ".cn"])


def tunnel_name(base):
    """Long hex-encoded subdomain, typical for DNS tunnelling."""
    return "%s.%s.%s" % (os.urandom(random.randint(20, 30)).hex(), os.urandom(8).hex(), base)


FEEDS = {"feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"}
_IP_RE = __import__("re").compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def load_feed(name, max_age=86400):
    """Return a cached list of indicators (IPs only), refreshed at most once a day."""
    path = os.path.join(STATE_DIR, "feed-%s.txt" % name)
    try:
        if time.time() - os.path.getmtime(path) < max_age:
            return [x for x in open(path).read().split() if x]
    except OSError:
        pass
    try:
        import urllib.request
        raw = urllib.request.urlopen(FEEDS[name], timeout=10).read().decode("utf-8", "replace")
        items = [ln.strip() for ln in raw.splitlines() if _IP_RE.match(ln.strip())]
        os.makedirs(STATE_DIR, exist_ok=True)
        open(path, "w").write("\n".join(items))
        return items
    except Exception:  # noqa - network/feed problems must never stop a test
        try:
            return [x for x in open(path).read().split() if x]
        except OSError:
            return []


# ------------------------------------------------------------ UDP / ping
def stun_probe(hostport, src_ip, burst_s=0):
    host, port = hostport.rsplit(":", 1)
    ip = socket.gethostbyname(host)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2)
    s.bind((src_ip, 0))
    try:
        req = struct.pack(">HHI", 1, 0, 0x2112A442) + os.urandom(12)
        s.sendto(req, (ip, int(port)))
        ok = True
        try:
            s.recvfrom(2048)
        except socket.timeout:
            ok = False
        sent = 20
        end = time.time() + burst_s       # RTP-like media burst (50 pps)
        while time.time() < end:
            s.sendto(os.urandom(172), (ip, int(port)))
            sent += 172
            time.sleep(0.02)
        return ok, sent
    finally:
        s.close()


def ping_probe(host, src_ip, count=4):
    r = sh(["ping", "-c", str(count), "-W", "2", "-I", src_ip, host])
    return r.returncode == 0


# ---------------------------------------------------------------- engine
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.c = collections.defaultdict(lambda: collections.Counter())

    def add(self, key, **kw):
        with self.lock:
            for k, v in kw.items():
                self.c[key][k] += v

    def snapshot(self):
        with self.lock:
            return {k: dict(v) for k, v in self.c.items()}


class Engine:
    """sources: list of {"ip":..., "dns":...}"""

    def __init__(self, cfg, apps, stop_evt, sources):
        self.cfg, self.stop, self.sources = cfg, stop_evt, sources
        disabled = set(cfg.get("disabled_apps") or [])
        self.feeds = {}
        self.apps = {}
        for n, a in apps.items():
            if n in disabled:
                continue
            if a.get("feed"):          # needs the feed switch and connects
                if not (cfg.get("ioc_feeds") and cfg.get("ioc_connect")):
                    continue
                self.feeds[a["feed"]] = load_feed(a["feed"])
                if not self.feeds[a["feed"]]:
                    continue
            if a.get("connect") and not cfg.get("ioc_connect"):
                continue
            self.apps[n] = a
        self.block_ips = set(cfg.get("block_ips") or [])
        self.stats = Stats()
        self.src_stats = Stats()
        self.recent = collections.deque(maxlen=300)
        self.ctx = ssl.create_default_context()
        if not cfg["tls_verify"]:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.reqlog = None
        self.loglock = threading.Lock()
        self.groups = collections.defaultdict(list)
        for name, a in self.apps.items():
            self.groups[a["group"]].append((name, a))
        self.active = [(g, w) for g, w in cfg["groups"].items() if w > 0 and g in self.groups]
        if not self.active:
            raise ValueError("No traffic group enabled.")
        self.started = time.time()
        self.finished = None

    def write(self, **rec):
        rec["ts"] = datetime.now().strftime("%H:%M:%S")
        with self.loglock:
            self.recent.append(rec)
            if self.reqlog:
                self.reqlog.write(json.dumps(rec) + "\n")

    def pick_app(self):
        g = random.choices([g for g, _ in self.active], [w for _, w in self.active])[0]
        apps = self.groups[g]
        return random.choices(apps, [a.get("weight", 1) for _, a in apps])[0]

    def account(self, src, name, **kw):
        self.stats.add(name, **kw)
        self.src_stats.add(src["ip"], **kw)

    def visit(self, src, name, app, cache, ua):
        ip_src = src["ip"]
        expect_block = app.get("expect") == "block"
        targets = [(k, t) for k in ("urls", "stun", "ping", "dns", "connect") for t in app.get(k, [])]
        if app.get("dga"):
            targets += [("dga", None)] * int(app["dga"])
        for base in app.get("tunnel", []):
            targets.append(("tunnel", base))
        if app.get("feed"):
            targets += [("feed", app["feed"])] * 3
        for kind, t in random.sample(targets, min(len(targets), random.randint(1, 3))):
            if self.stop.is_set():
                return
            t0 = time.time()
            try:
                if kind == "urls":
                    host = t.split("://", 1)[1].split("/")[0].split(":")[0]
                    ips = cache.get(host)
                    if not ips or ips[1] < time.time():
                        ips = (dns_resolve(host, src["dns"], ip_src), time.time() + 60)
                        cache[host] = ips
                    try:
                        st, n, blocked, eicar = http_get(t, random.choice(ips[0]), ip_src, ua,
                                                         app.get("max_bytes", 400000), self.ctx)
                    except (ConnectionResetError, ssl.SSLEOFError, http.client.RemoteDisconnected, BrokenPipeError):
                        if not expect_block:
                            raise
                        self.account(src, name, requests=1, blocked=1, ex_blocked=1)
                        self.write(src=ip_src, app=name, url=t, result="blocked", detail="connection reset",
                                   ms=int((time.time() - t0) * 1000))
                        continue
                    if expect_block:
                        res = "blocked" if blocked else ("missed" if st == 200 else "ok")
                        extra = {"ex_" + res: 1} if res in ("blocked", "missed") else {}
                    else:
                        res, extra = ("blocked" if blocked else "ok"), {}
                    self.account(src, name, requests=1, bytes=n, **{res: 1}, **extra)
                    self.write(src=ip_src, app=name, url=t, result=res, status=st, bytes=n,
                               ms=int((time.time() - t0) * 1000))
                elif kind in ("dns", "dga", "tunnel"):
                    qname = t if kind == "dns" else dga_name() if kind == "dga" else tunnel_name(t)
                    rc, ips = dns_query(qname, src["dns"], ip_src, 16 if kind == "tunnel" else 1)
                    # The *query* is the indicator; only a FortiGuard block-portal answer counts as blocked.
                    res = "blocked" if set(ips) & self.block_ips else "ok"
                    self.account(src, name, requests=1, **{res: 1})
                    self.write(src=ip_src, app=name, url="dns://" + qname, result=res, rcode=rc,
                               answer=",".join(ips[:2]), ms=int((time.time() - t0) * 1000))
                elif kind in ("connect", "feed"):
                    if kind == "feed":
                        host, port = random.choice(self.feeds[t]), random.choice([443, 8080, 80, 8443])
                    else:
                        host, port = t.rsplit(":", 1)
                    res = tcp_connect(host, port, ip_src)
                    self.account(src, name, requests=1, **{("ok" if res == "connected" else "error"): 1})
                    self.write(src=ip_src, app=name, url="tcp://%s:%s" % (host, port),
                               result="reached" if res == "connected" else res,
                               ms=int((time.time() - t0) * 1000))
                elif kind == "stun":
                    ok, n = stun_probe(t, ip_src, app.get("udp_burst_s", 0))
                    self.account(src, name, requests=1, bytes=n, ok=int(ok), error=int(not ok))
                    self.write(src=ip_src, app=name, url="udp://" + t, result="ok" if ok else "noreply", bytes=n)
                else:
                    ok = ping_probe(t, ip_src)
                    self.account(src, name, requests=1, ok=int(ok), error=int(not ok))
                    self.write(src=ip_src, app=name, url="icmp://" + t, result="ok" if ok else "loss")
            except (OSError, ssl.SSLError, http.client.HTTPException) as e:
                self.account(src, name, requests=1, error=1)
                self.write(src=ip_src, app=name, url=t, result="error", err=type(e).__name__ + ": " + str(e)[:80])

    def user(self, src):
        ua = random.choice(USER_AGENTS)
        cache = {}
        lo, hi = THINK[self.cfg["intensity"]]
        while not self.stop.is_set():
            name, app = self.pick_app()
            self.visit(src, name, app, cache, ua)
            self.stop.wait(random.uniform(lo, hi))

    def run(self, deadline):
        """Blocks until stop is set or the deadline passes."""
        os.makedirs(LOG_DIR, exist_ok=True)
        try:
            self.reqlog = open(os.path.join(LOG_DIR, "requests.log"), "a", buffering=1)
        except OSError:
            self.reqlog = None
        threads = []
        for src in self.sources:
            for _ in range(self.cfg["threads_per_ip"]):
                t = threading.Thread(target=self.user, args=(src,), daemon=True)
                t.start()
                threads.append(t)
                time.sleep(random.uniform(0, 0.1))
        while not self.stop.is_set() and (deadline is None or time.time() < deadline):
            self.stop.wait(0.5)
        self.stop.set()
        for t in threads:
            t.join(timeout=12)
        self.finished = time.time()
        if self.reqlog:
            self.reqlog.close()

    def totals(self):
        tot = collections.Counter()
        for c in self.stats.snapshot().values():
            tot.update(c)
        return dict(tot)

    def summary(self):
        snap = self.stats.snapshot()
        rows = sorted(snap.items(), key=lambda kv: -kv[1].get("requests", 0))
        g = lambda c, k: c.get(k, 0)
        out = ["%-18s %8s %8s %8s %8s %8s %10s" % ("app", "requests", "ok", "blocked", "missed", "error", "MB")]
        for n, c in rows:
            out.append("%-18s %8d %8d %8d %8d %8d %10.1f" % (n, g(c, "requests"), g(c, "ok"), g(c, "blocked"), g(c, "missed"), g(c, "error"), g(c, "bytes") / 1e6))
        t = self.totals()
        out.append("%-18s %8d %8d %8d %8d %8d %10.1f" % ("TOTAL", g(t, "requests"), g(t, "ok"), g(t, "blocked"), g(t, "missed"), g(t, "error"), g(t, "bytes") / 1e6))
        if g(t, "ex_blocked") + g(t, "ex_missed"):
            out.append("Malware detection rate: %d%% (%d blocked, %d missed)" % (
                100 * g(t, "ex_blocked") // (g(t, "ex_blocked") + g(t, "ex_missed")), g(t, "ex_blocked"), g(t, "ex_missed")))
        return "\n".join(out)


# ------------------------------------------------------------------- CLI
def cmd_run(args):
    import netconf
    cfg = load_config(args.config)
    if args.duration is not None:
        cfg["duration_minutes"] = args.duration
    if args.intensity:
        cfg["intensity"] = args.intensity
    if args.threads:
        cfg["threads_per_ip"] = args.threads
    if args.groups:
        wanted = set(args.groups.split(","))
        cfg["groups"] = {g: (max(w, 1) if g in wanted else 0) for g, w in cfg["groups"].items()}
    sources = netconf.sources(cfg)
    if not sources:
        sys.exit("No source networks configured. Configure them in the web GUI first.")
    stop = threading.Event()
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, lambda *_: stop.set())
    eng = Engine(cfg, load_profiles(), stop, sources)
    dur = cfg["duration_minutes"]
    log("start: %d source IPs x %d sessions, %s" % (len(sources), cfg["threads_per_ip"],
                                                  ("%d min" % dur) if dur else "until Ctrl-C"))
    eng.run(time.time() + dur * 60 if dur else None)
    print("\n" + eng.summary())


def cmd_apps(_):
    by = collections.defaultdict(list)
    for n, a in load_profiles().items():
        by[a["group"]].append(n)
    cfg = load_config()
    for g, names in sorted(by.items()):
        print("%-10s weight=%-3s %s" % (g, cfg["groups"].get(g, "-"), ", ".join(sorted(names))))


def cmd_passwd(args):
    import webui
    pw = open(args.file).read().strip() if args.file else __import__("getpass").getpass("New admin password: ")
    webui.set_password(pw)
    print("Admin password set.")


def main():
    ap = argparse.ArgumentParser(prog="trafficgen", description="Control the test via the web GUI; CLI is for debugging.")
    ap.add_argument("--config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run", help="run a test in the foreground using the configured networks")
    p.add_argument("-d", "--duration", type=int, help="minutes (0 = until Ctrl-C)")
    p.add_argument("-i", "--intensity", choices=list(THINK))
    p.add_argument("-t", "--threads", type=int)
    p.add_argument("-g", "--groups")
    p.set_defaults(fn=cmd_run)
    sub.add_parser("apps").set_defaults(fn=cmd_apps)
    p = sub.add_parser("passwd", help="set the web GUI admin password")
    p.add_argument("--file", help="read password from file")
    p.set_defaults(fn=cmd_passwd)
    args = ap.parse_args()
    if args.config:
        global CONFIG_PATH
        CONFIG_PATH = args.config
    args.fn(args)


if __name__ == "__main__":
    main()
