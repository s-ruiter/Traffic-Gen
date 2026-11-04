#!/usr/bin/env python3
"""trafficgen - realistic multi-source-IP traffic generator for FortiGate
(SD-WAN / application control / web filtering) monitoring.

Subcommands: run | start | stop | status | apps | wizard
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
DEFAULT_PROFILES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles.yaml")
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
    "source": {
        "interface": "eth0",
        "include_primary": True,   # primary IP of the interface is also a source
        "first": "",               # first extra source IP ("" = none)
        "count": 0,                # number of extra source IPs (first .. first+count-1)
        "keep_ips": False,         # keep alias IPs after the run
    },
    "duration_minutes": 10,        # 0 = run until stopped
    "threads_per_ip": 2,           # parallel 'sessions' per source IP
    "intensity": "medium",         # low | medium | high
    "tls_verify": False,           # False = work behind SSL deep inspection
    "dns_server": "",              # "" = first nameserver of /etc/resolv.conf
    "groups": {                    # relative weights of traffic groups; 0 = off
        "office365": 25, "collab": 20, "streaming": 20, "social": 10,
        "saas": 10, "web": 10, "updates": 3, "download": 2, "sdwan": 5,
        "webfilter": 0, "security": 0,
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


def dns_resolve(name, server, src_ip, timeout=2.0):
    """A-record lookup bound to src_ip (so DNS also shows the right source)."""
    tid = random.randrange(65536)
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    q += struct.pack(">HH", 1, 1)
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
    if not ips:
        raise OSError("no A record")
    return ips


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
        text = head.lower()
        blocked = status == 403 and (b"fortigate" in text or b"fortiguard" in text or b"blocked" in text) \
            or b"web page blocked" in text or b"fortinet" in text and b"block" in text
    finally:
        c.close()
    return status, got, blocked


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


class Engine:
    def __init__(self, cfg, apps, stop_evt):
        self.cfg, self.apps, self.stop = cfg, apps, stop_evt
        self.stats = Stats()
        self.dns = cfg["dns_server"] or self._resolv()
        self.ctx = ssl.create_default_context()
        if not cfg["tls_verify"]:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.reqlog = None
        self.loglock = threading.Lock()
        # weighted group -> apps
        self.groups = collections.defaultdict(list)
        for name, a in apps.items():
            self.groups[a["group"]].append((name, a))
        self.active = [(g, w) for g, w in cfg["groups"].items() if w > 0 and g in self.groups]
        if not self.active:
            sys.exit("No traffic group enabled (check 'groups' in config).")

    @staticmethod
    def _resolv():
        try:
            for ln in open("/etc/resolv.conf"):
                if ln.startswith("nameserver"):
                    return ln.split()[1]
        except OSError:
            pass
        return "1.1.1.1"

    def write(self, **rec):
        rec["ts"] = datetime.now().isoformat(timespec="seconds")
        if self.reqlog:
            with self.loglock:
                self.reqlog.write(json.dumps(rec) + "\n")

    def pick_app(self):
        g = random.choices([g for g, _ in self.active], [w for _, w in self.active])[0]
        apps = self.groups[g]
        return random.choices(apps, [a.get("weight", 1) for _, a in apps])[0]

    def visit(self, src, name, app, cache, ua):
        targets = []
        for kind in ("urls", "stun", "ping"):
            for t in app.get(kind, []):
                targets.append((kind, t))
        for kind, t in random.sample(targets, min(len(targets), random.randint(1, 3))):
            if self.stop.is_set():
                return
            t0 = time.time()
            try:
                if kind == "urls":
                    host = t.split("://", 1)[1].split("/")[0].split(":")[0]
                    ips = cache.get(host)
                    if not ips or ips[1] < time.time():
                        ips = (dns_resolve(host, self.dns, src), time.time() + 60)
                        cache[host] = ips
                    st, n, blocked = http_get(t, random.choice(ips[0]), src, ua,
                                              app.get("max_bytes", 400000), self.ctx)
                    res = "blocked" if blocked else "ok"
                    self.stats.add(name, requests=1, bytes=n, **{res: 1})
                    self.write(src=src, app=name, url=t, result=res, status=st, bytes=n,
                               ms=int((time.time() - t0) * 1000))
                elif kind == "stun":
                    ok, n = stun_probe(t, src, app.get("udp_burst_s", 0))
                    self.stats.add(name, requests=1, bytes=n, ok=int(ok), error=int(not ok))
                    self.write(src=src, app=name, url="udp://" + t, result="ok" if ok else "noreply", bytes=n)
                else:
                    ok = ping_probe(t, src)
                    self.stats.add(name, requests=1, ok=int(ok), error=int(not ok))
                    self.write(src=src, app=name, url="icmp://" + t, result="ok" if ok else "loss")
            except (OSError, ssl.SSLError, http.client.HTTPException) as e:
                self.stats.add(name, requests=1, error=1)
                self.write(src=src, app=name, url=t, result="error", err=type(e).__name__ + ":" + str(e)[:80])

    def user(self, src):
        ua = random.choice(USER_AGENTS)
        cache = {}
        lo, hi = THINK[self.cfg["intensity"]]
        while not self.stop.is_set():
            name, app = self.pick_app()
            self.visit(src, name, app, cache, ua)
            self.stop.wait(random.uniform(lo, hi))

    def run(self, ips, deadline):
        os.makedirs(LOG_DIR, exist_ok=True)
        try:
            self.reqlog = open(os.path.join(LOG_DIR, "requests.log"), "a", buffering=1)
        except OSError:
            self.reqlog = None
        threads = []
        for ip in ips:
            for _ in range(self.cfg["threads_per_ip"]):
                t = threading.Thread(target=self.user, args=(ip,), daemon=True)
                t.start()
                threads.append(t)
                time.sleep(random.uniform(0, 0.3))
        last = time.time()
        while not self.stop.is_set() and (deadline is None or time.time() < deadline):
            self.stop.wait(1)
            if time.time() - last >= 30:
                last = time.time()
                tot = sum(c["requests"] for c in self.stats.c.values())
                left = "" if deadline is None else " | %ds left" % max(0, deadline - time.time())
                log("running: %d requests so far%s" % (tot, left))
        self.stop.set()
        for t in threads:
            t.join(timeout=12)
        if self.reqlog:
            self.reqlog.close()

    def summary(self):
        rows = sorted(self.stats.c.items(), key=lambda kv: -kv[1]["requests"])
        out = ["%-18s %8s %8s %8s %8s %10s" % ("app", "requests", "ok", "blocked", "error", "MB")]
        tot = collections.Counter()
        for n, c in rows:
            out.append("%-18s %8d %8d %8d %8d %10.1f" % (n, c["requests"], c["ok"], c["blocked"], c["error"], c["bytes"] / 1e6))
            tot.update(c)
        out.append("%-18s %8d %8d %8d %8d %10.1f" % ("TOTAL", tot["requests"], tot["ok"], tot["blocked"], tot["error"], tot["bytes"] / 1e6))
        return "\n".join(out), {n: dict(c) for n, c in rows}


# ------------------------------------------------------------------- cmds
def source_ips(cfg):
    iface = cfg["source"]["interface"]
    primary, prefix = iface_info(iface)
    ips, extra = [], []
    if cfg["source"]["include_primary"]:
        ips.append(primary)
    if cfg["source"]["first"] and cfg["source"]["count"] > 0:
        first = ipaddress.IPv4Address(cfg["source"]["first"])
        extra = [str(first + i) for i in range(cfg["source"]["count"])]
        extra = [e for e in extra if e != primary]
    return ips + extra, extra, prefix


def cmd_run(args):
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
    apps = load_profiles()
    ips, extra, prefix = source_ips(cfg)
    iface = cfg["source"]["interface"]
    added = []
    for ip in extra:
        r = sh(["ip", "addr", "add", "%s/%d" % (ip, prefix), "dev", iface])
        if r.returncode == 0:
            added.append(ip)
            sh(["arping", "-q", "-c", "1", "-U", "-I", iface, ip])   # announce to switch/FortiGate
        elif "exists" not in r.stderr.lower():
            log("WARN cannot add %s: %s" % (ip, r.stderr.strip()))
    stop = threading.Event()
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, lambda *_: stop.set())
    eng = Engine(cfg, apps, stop)
    dur = cfg["duration_minutes"]
    deadline = time.time() + dur * 60 if dur else None
    log("start: %d source IPs x %d sessions, intensity=%s, duration=%s, groups=%s" % (
        len(ips), cfg["threads_per_ip"], cfg["intensity"],
        ("%d min" % dur) if dur else "until stopped", ",".join(g for g, _ in eng.active)))
    log("source IPs: " + ", ".join(ips))
    try:
        eng.run(ips, deadline)
    finally:
        if not cfg["source"]["keep_ips"]:
            for ip in added:
                sh(["ip", "addr", "del", "%s/%d" % (ip, prefix), "dev", iface])
    text, data = eng.summary()
    print("\n" + text)
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, "last-run.json"), "w") as f:
        json.dump({"finished": datetime.now().isoformat(timespec="seconds"), "sources": ips, "apps": data}, f, indent=1)


def cmd_start(args):
    if sh(["systemctl", "is-active", "--quiet", UNIT]).returncode == 0:
        sys.exit("Already running. Use 'trafficgen stop' first.")
    sh(["systemctl", "reset-failed", UNIT])
    cmd = ["systemd-run", "--unit", UNIT, "--collect", "-p", "KillSignal=SIGTERM", "-p", "TimeoutStopSec=30",
           "-p", "StandardOutput=append:%s/run.log" % LOG_DIR, "-p", "StandardError=inherit",
           sys.executable, os.path.abspath(__file__), "run"]
    for flag, val in (("-d", args.duration), ("-i", args.intensity), ("-t", args.threads), ("-g", args.groups)):
        if val is not None:
            cmd += [flag, str(val)]
    os.makedirs(LOG_DIR, exist_ok=True)
    r = sh(cmd)
    print(r.stderr.strip() or "Started in background. Follow with: trafficgen status  (log: %s/run.log)" % LOG_DIR)


def cmd_stop(_):
    sh(["systemctl", "stop", UNIT])
    print("Stopped.")


def cmd_status(_):
    active = sh(["systemctl", "is-active", UNIT]).stdout.strip()
    print("State:", active)
    p = os.path.join(LOG_DIR, "run.log")
    if os.path.exists(p):
        print("".join(open(p).readlines()[-15:]))


def cmd_apps(_):
    by = collections.defaultdict(list)
    for n, a in load_profiles().items():
        by[a["group"]].append(n)
    cfg = load_config()
    for g, names in sorted(by.items()):
        print("%-10s weight=%-3s %s" % (g, cfg["groups"].get(g, "-"), ", ".join(sorted(names))))


def ask(q, default):
    v = input("%s [%s]: " % (q, default)).strip()
    return v if v else str(default)


def cmd_wizard(_):
    cfg = load_config()
    print("trafficgen wizard - Enter keeps the default\n")
    s = cfg["source"]
    s["interface"] = ask("Interface", s["interface"])
    prim, prefix = iface_info(s["interface"])
    print("Primary IP: %s/%d" % (prim, prefix))
    s["first"] = ask("First extra source IP (empty = none)", s["first"] or "")
    s["count"] = int(ask("Number of extra source IPs", s["count"])) if s["first"] else 0
    cfg["duration_minutes"] = int(ask("Duration in minutes (0 = until stopped)", cfg["duration_minutes"]))
    cfg["threads_per_ip"] = int(ask("Sessions per source IP", cfg["threads_per_ip"]))
    cfg["intensity"] = ask("Intensity (low/medium/high)", cfg["intensity"])
    print("\nGroup weights (0 = off):", ", ".join(cfg["groups"]))
    for g in list(cfg["groups"]):
        cfg["groups"][g] = int(ask("  weight %s" % g, cfg["groups"][g]))
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    print("\nSaved to %s. Start with: trafficgen start" % CONFIG_PATH)


def main():
    ap = argparse.ArgumentParser(prog="trafficgen")
    ap.add_argument("--config")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("start", cmd_start)):
        p = sub.add_parser(name, help="run in foreground" if name == "run" else "run in background (systemd)")
        p.add_argument("-d", "--duration", type=int, help="minutes (0 = until stopped)")
        p.add_argument("-i", "--intensity", choices=list(THINK))
        p.add_argument("-t", "--threads", type=int, help="sessions per source IP")
        p.add_argument("-g", "--groups", help="comma list of groups to enable, e.g. streaming,collab")
        p.set_defaults(fn=fn)
    for name, fn in (("stop", cmd_stop), ("status", cmd_status), ("apps", cmd_apps), ("wizard", cmd_wizard)):
        sub.add_parser(name).set_defaults(fn=fn)
    args = ap.parse_args()
    if args.config:
        global CONFIG_PATH
        CONFIG_PATH = args.config
    args.fn(args)


if __name__ == "__main__":
    main()
