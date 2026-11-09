#!/usr/bin/env python3
"""Web GUI + JSON API for trafficgen (stdlib only, HTTPS with self-signed cert)."""
import collections
import hashlib
import hmac
import http.cookies
import json
import os
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

import netconf
import report
import throughput as tp
import trafficgen as tg

BASE = os.path.dirname(os.path.abspath(__file__))
WEBDIR = os.path.join(BASE, "web")
AUTH_FILE = os.environ.get("TRAFFICGEN_AUTH", "/etc/trafficgen/auth.json")
CERT = "/etc/trafficgen/tls/server.crt"
KEY = "/etc/trafficgen/tls/server.key"
SESSION_TTL = 12 * 3600
VERSION = "2.3"


# ----------------------------------------------------------------- auth
def _hash(pw, salt, it=200000):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, it).hex()


def set_password(pw):
    if len(pw) < 8:
        raise ValueError("Password must be at least 8 characters.")
    salt = secrets.token_bytes(16)
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    fd = os.open(AUTH_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"salt": salt.hex(), "hash": _hash(pw, salt)}, f)


def check_password(pw):
    try:
        a = json.load(open(AUTH_FILE))
    except (OSError, ValueError):
        return False
    return hmac.compare_digest(_hash(pw, bytes.fromhex(a["salt"])), a["hash"])


class Sessions:
    def __init__(self):
        self.s, self.fail, self.lock = {}, collections.defaultdict(list), threading.Lock()

    def new(self):
        t = secrets.token_urlsafe(32)
        with self.lock:
            self.s[t] = time.time() + SESSION_TTL
        return t

    def valid(self, t):
        with self.lock:
            e = self.s.get(t)
            if e and e > time.time():
                return True
            self.s.pop(t, None)
            return False

    def drop(self, t):
        with self.lock:
            self.s.pop(t, None)

    def locked(self, ip):
        now = time.time()
        with self.lock:
            self.fail[ip] = [x for x in self.fail[ip] if x > now - 300]
            return len(self.fail[ip]) >= 5

    def failed(self, ip):
        with self.lock:
            self.fail[ip].append(time.time())


SESS = Sessions()


# ------------------------------------------------------------ controller
def save_config(cfg):
    os.makedirs(os.path.dirname(tg.CONFIG_PATH), exist_ok=True)
    tmp = tg.CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        yaml.safe_dump(cfg, f, sort_keys=False)
    os.replace(tmp, tg.CONFIG_PATH)


class Controller:
    def __init__(self):
        self.lock = threading.RLock()
        self.engine = None
        self.stop_evt = None
        self.thread = None
        self.deadline = None
        self.series = collections.deque(maxlen=1800)
        self.apply_log = []
        threading.Thread(target=self._sampler, daemon=True).start()

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def _sampler(self):
        while True:
            time.sleep(1)
            e = self.engine
            if e and self.running:
                t = e.totals()
                self.series.append([round(time.time(), 1), t.get("requests", 0), t.get("bytes", 0),
                                    t.get("blocked", 0), t.get("error", 0)])

    def apply_network(self):
        cfg = tg.load_config()
        if not cfg["networks"]:
            netconf.teardown()
            self.apply_log = ["No networks configured."]
            return
        try:
            self.apply_log, _ = netconf.apply(cfg["networks"], cfg["mgmt_interface"])
        except ValueError as e:
            self.apply_log = [str(e)]

    def start(self, p):
        with self.lock:
            if self.running or TP.running:
                raise ValueError("A test is already running.")
            cfg = tg.load_config()
            for k in ("duration_minutes", "threads_per_ip"):
                if k in p:
                    cfg[k] = max(0, int(p[k]))
            if p.get("intensity") in tg.THINK:
                cfg["intensity"] = p["intensity"]
            if isinstance(p.get("groups"), dict):
                cfg["groups"] = {g: max(0, int(w)) for g, w in p["groups"].items()}
            cfg["threads_per_ip"] = min(max(cfg["threads_per_ip"], 1), 20)
            sources = netconf.sources(cfg)
            if not sources:
                raise ValueError("No source networks configured. Go to Settings > Network.")
            live = netconf.live_addrs()
            missing = [s["ip"] for s in sources if s["ip"] not in live.get(s["dev"], set())]
            if missing:
                raise ValueError("%d source IPs are not active. Click 'Apply' under Settings > Network first." % len(missing))
            self.stop_evt = threading.Event()
            self.engine = tg.Engine(cfg, tg.load_profiles(), self.stop_evt, sources)
            dur = cfg["duration_minutes"]
            self.deadline = time.time() + dur * 60 if dur else None
            self.series.clear()
            self.thread = threading.Thread(target=self.engine.run, args=(self.deadline,), daemon=True)
            self.thread.start()
            self.cfg_run = cfg

    def stop(self):
        with self.lock:
            if self.stop_evt:
                self.stop_evt.set()

    def state(self):
        e = self.engine
        s = {"running": self.running, "version": VERSION, "now": time.time(), "has_run": bool(e)}
        if e:
            s.update({
                "started": e.started, "finished": e.finished, "deadline": self.deadline,
                "sources": len(e.sources), "threads_per_ip": e.cfg["threads_per_ip"], "intensity": e.cfg["intensity"],
                "totals": e.totals(), "apps": e.stats.snapshot(), "src": e.src_stats.snapshot(),
                "series": list(self.series),
            })
        return s


CTRL = Controller()
TP = tp.Runner()


def _net_of(ip, prefix):
    import ipaddress
    return ipaddress.ip_network("%s/%d" % (ip, int(prefix)), strict=False)


def tp_validate_path(body, cfg):
    """Validate/normalise the throughput path settings (sender network + receiver)."""
    import ipaddress
    out = {"tx_network": str(body.get("tx_network", "")).strip(), "base_port": int(body.get("base_port", 5201))}
    if not 1024 <= out["base_port"] <= 65000:
        raise ValueError("Base port must be between 1024 and 65000.")
    rx = body.get("rx") or {}
    mode = rx.get("mode", "isolated")
    if mode not in ("isolated", "loopback"):
        raise ValueError("Receiver mode must be 'isolated' or 'loopback'.")
    out["rx"] = {"mode": mode, "parent": "", "vlan": "", "ip": "", "prefix": 24, "gateway": "", "count": 1}
    if mode == "loopback":
        return out
    parent = str(rx.get("parent", "")).strip()
    names = {i["name"] for i in netconf.interfaces()}
    if not parent or parent == cfg["mgmt_interface"] or "." in parent or parent not in names:
        raise ValueError("Receiver interface '%s' is invalid, missing or the management interface." % parent)
    txn = next((n for n in cfg["networks"] if n.get("name") == out["tx_network"]), None)
    if txn and txn["parent"] == parent:
        raise ValueError("The receiver must use a different interface than the sender network (%s). Add a third interface to the LXC in Proxmox." % parent)
    try:
        ip = str(ipaddress.IPv4Address(str(rx.get("ip", "")).strip()))
        prefix = int(rx.get("prefix", 24))
        net = _net_of(ip, prefix)
        gw = str(rx.get("gateway", "")).strip()
        if not gw:
            raise ValueError("The receiver gateway is required: the receiver must be able to answer the sender, which is in another network.")
        if ipaddress.IPv4Address(gw) not in net:
            raise ValueError("Receiver gateway must be inside %s." % net)
    except ipaddress.AddressValueError as e:
        raise ValueError("Receiver address is invalid: %s" % e)
    if not 8 <= prefix <= 30:
        raise ValueError("Receiver prefix must be between 8 and 30.")
    count = int(rx.get("count") or 1)
    if not 1 <= count <= 250:
        raise ValueError("The number of receiver IPs must be between 1 and 250.")
    last = ipaddress.IPv4Address(ip) + (count - 1)
    if last not in net:
        raise ValueError("Receiver IPs %s to %s do not fit in %s." % (ip, last, net))
    if gw and ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(gw) <= last:
        raise ValueError("The receiver gateway %s is inside the receiver IP range." % gw)
    for n in cfg["networks"]:
        if net.overlaps(_net_of(n["first"], n["prefix"])):
            raise ValueError("Receiver network %s overlaps with source network '%s'; it must be a different network so traffic crosses the FortiGate." % (net, n.get("name")))
    mnet = netconf.mgmt_network(cfg["mgmt_interface"])
    if mnet and net.overlaps(mnet):
        raise ValueError("Receiver network %s overlaps with the management network." % net)
    out["rx"].update({"parent": parent, "vlan": "", "ip": ip, "prefix": prefix, "gateway": gw, "count": count})
    return out


def _num(body, k, lo, hi, default, cast=float):
    v = cast(body.get(k, default))
    if not lo <= v <= hi:
        raise ValueError("%s must be between %s and %s." % (k, lo, hi))
    return v


def tp_params(kind, body, cfg):
    t = cfg["throughput"]
    p = {"base_port": t["base_port"], "rx": t["rx"], "tx_ip": ""}
    if t["rx"]["mode"] == "isolated":
        n = next((x for x in cfg["networks"] if x.get("name") == t["tx_network"]), None)
        if not n:
            raise ValueError("Choose a sender network first (Throughput > Path).")
        if not t["rx"]["ip"]:
            raise ValueError("Configure the receiver first (Throughput > Path).")
        if t["rx"]["parent"] == n["parent"]:
            raise ValueError("The receiver must use a different interface than the sender network (%s). Add a third interface to the LXC in Proxmox." % n["parent"])
        p["tx_ip"] = n["first"]
        p["tx_gw"] = n.get("gateway", "")
        if p["tx_ip"] not in netconf.live_addrs().get(netconf.dev_of(n), set()):
            raise ValueError("Sender IP %s is not active. Click 'Apply' under Settings > Network first." % p["tx_ip"])
    if kind == "udp":
        p.update(payload=_num(body, "payload", 16, 1472, 1400, int), rate_mbps=_num(body, "rate_mbps", 1, 1000, 100),
                 streams=_num(body, "streams", 0, 8, 0, int), duration=_num(body, "duration", 1, 3600, 10))
    elif kind == "tcp":
        p.update(streams=_num(body, "streams", 1, 32, 4, int), duration=_num(body, "duration", 1, 3600, 10))
    elif kind == "cps":
        p.update(rate=_num(body, "rate", 1, 50000, 1000), duration=_num(body, "duration", 1, 3600, 10),
                 ramp=bool(body.get("ramp")), step=_num(body, "step", 1, 50000, 500), steps=_num(body, "steps", 1, 20, 5, int),
                 req=_num(body, "req", 0, 65000, 0, int), resp=_num(body, "resp", 0, 65000, 0, int),
                 hold_ms=_num(body, "hold_ms", 0, 60000, 0, int), close="fin" if body.get("close") == "fin" else "rst",
                 max_fail_pct=_num(body, "max_fail_pct", 0, 100, 0.1))
        if (p["rate"] + (p["step"] * (p["steps"] - 1) if p["ramp"] else 0)) * p["hold_ms"] / 1000.0 > 100000:
            raise ValueError("Rate x hold time would keep more than 100000 connections open at once. Lower the rate or the hold time.")
        if p["req"] == 0 and p["resp"] > 0:
            raise ValueError("A response size needs a request size greater than 0.")
    elif kind == "concurrent":
        p.update(target=_num(body, "target", 100, 500000, 10000, int), rate=_num(body, "rate", 50, 20000, 2000),
                 hold_s=_num(body, "hold_s", 0, 3600, 30), heartbeat_s=_num(body, "heartbeat_s", 0, 300, 30),
                 fail_pct=_num(body, "fail_pct", 0.1, 50, 5))
        if 0 < p["heartbeat_s"] < 5:
            raise ValueError("The heartbeat interval must be 0 (off) or at least 5 seconds.")
        src_n = _num(body, "src_ips", 1, 250, 1, int)
        dst_n = int(t["rx"].get("count") or 1)
        if t["rx"]["mode"] == "isolated":
            net = next(x for x in cfg["networks"] if x.get("name") == t["tx_network"])
            if src_n > int(net["count"]):
                raise ValueError("'Source IPs to use' (%d) is more than the %d IPs of sender network '%s'." % (src_n, int(net["count"]), net["name"]))
            ips = netconf.ips_of(net)[:src_n]
            live = netconf.live_addrs().get(netconf.dev_of(net), set())
            if any(i not in live for i in ips):
                raise ValueError("Not all %d sender IPs are active. Click 'Apply' under Settings > Network first." % src_n)
            p["tx_ips"] = ips
        else:
            src_n, dst_n = 1, 1
            p["rx"] = dict(t["rx"], count=1)
        cap = tp.tuple_capacity(src_n, dst_n)
        if p["target"] > 0.9 * cap:
            raise ValueError("%d sessions do not fit: %d source IP(s) x %d receiver IP(s) x %d ports allow about %d concurrent sessions. "
                             "Use more source IPs or receiver IPs." % (p["target"], src_n, dst_n, tp.MAX_STREAMS, cap))
        if p["target"] > 50000 and not body.get("confirm"):
            raise ValueError("Confirmation required: more than 50,000 concurrent sessions can fill the FortiGate session table and affect other users.")
    elif kind == "rfc2544":
        sizes = body.get("sizes") or [64, 512, 1518]
        sizes = sorted({int(x) for x in sizes})
        if not sizes or any(not 64 <= x <= 1518 for x in sizes):
            raise ValueError("Frame sizes must be between 64 and 1518 bytes.")
        p.update(sizes=sizes, link_mbps=_num(body, "link_mbps", 10, 1000, 1000), trial_s=_num(body, "trial_s", 1, 120, 5),
                 loss_tol=_num(body, "loss_tol", 0, 100, 0), resolution=_num(body, "resolution", 0.1, 25, 1),
                 frame_loss=bool(body.get("frame_loss")))
    else:
        raise ValueError("Unknown test type.")
    return p


# ----------------------------------------------------------- HTTP layer
def config_view(cfg):
    return {k: cfg[k] for k in ("duration_minutes", "threads_per_ip", "intensity", "tls_verify", "groups",
                                "disabled_apps", "networks", "mgmt_interface", "ioc_feeds", "ioc_connect",
                                "block_ips")}


class H(BaseHTTPRequestHandler):
    server_version = "trafficgen"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # helpers
    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _token(self):
        c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return c["tg"].value if "tg" in c else ""

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 1_000_000:
            raise ValueError("Request te groot")
        return json.loads(self.rfile.read(n) or b"{}")

    def _authed(self):
        return SESS.valid(self._token())

    # routes
    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, open(os.path.join(WEBDIR, "index.html"), "rb").read(), "text/html; charset=utf-8")
        if u.path in ("/favicon.svg", "/favicon.ico"):
            return self._send(200, open(os.path.join(WEBDIR, "favicon.svg"), "rb").read(), "image/svg+xml")
        if not u.path.startswith("/api/"):
            return self._send(404, {"error": "not found"})
        if u.path == "/api/session":
            return self._send(200, {"authed": self._authed()})
        if not self._authed():
            return self._send(401, {"error": "login required"})
        try:
            cfg = tg.load_config()
            if u.path == "/api/state":
                return self._send(200, CTRL.state())
            if u.path == "/api/config":
                return self._send(200, config_view(cfg))
            if u.path == "/api/apps":
                groups = collections.defaultdict(list)
                for n, a in tg.load_profiles().items():
                    groups[a["group"]].append({"name": n, "weight": a.get("weight", 1),
                                               "targets": len(a.get("urls", [])) + len(a.get("stun", [])) + len(a.get("ping", []))})
                return self._send(200, groups)
            if u.path == "/api/interfaces":
                return self._send(200, {"interfaces": netconf.interfaces(), "mgmt": cfg["mgmt_interface"],
                                        "mgmt_net": str(netconf.mgmt_network(cfg["mgmt_interface"]) or "")})
            if u.path == "/api/network":
                return self._send(200, {"status": netconf.status(cfg), "log": CTRL.apply_log})
            if u.path in ("/api/tp/report.pdf", "/api/report.pdf"):
                tpr = u.path.startswith("/api/tp/")
                st = TP.state() if tpr else CTRL.state()
                if not (st.get("kind") if tpr else st.get("has_run")):
                    return self._send(404, {"error": "No results yet."})
                data = report.tp_report(st, VERSION) if tpr else report.traffic_report(st, VERSION)
                name = "traffic-gen-%s-%s.pdf" % ("throughput-" + st["kind"] if tpr else "traffic", time.strftime("%Y%m%d-%H%M"))
                return self._send(200, data, "application/pdf", {"Content-Disposition": 'attachment; filename="%s"' % name})
            if u.path == "/api/tp/state":
                return self._send(200, TP.state())
            if u.path == "/api/tp/config":
                return self._send(200, {"throughput": cfg["throughput"], "networks": [{"name": n.get("name"), "parent": n.get("parent"), "first": n.get("first"), "gateway": n.get("gateway"), "count": n.get("count")} for n in cfg["networks"]],
                                        "interfaces": [i["name"] for i in netconf.interfaces() if i["name"] != cfg["mgmt_interface"] and "." not in i["name"]]})
            if u.path == "/api/log":
                e = CTRL.engine
                n = int(parse_qs(u.query).get("n", ["60"])[0])
                return self._send(200, list(e.recent)[-n:][::-1] if e else [])
        except Exception as e:  # noqa
            return self._send(500, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        if self.headers.get("X-TG") != "1":
            return self._send(403, {"error": "forbidden"})
        ip = self.client_address[0]
        try:
            body = self._body()
            if u.path == "/api/login":
                if SESS.locked(ip):
                    return self._send(429, {"error": "Too many attempts, try again in 5 minutes."})
                if check_password(str(body.get("password", ""))):
                    t = SESS.new()
                    return self._send(200, {"ok": True}, extra={"Set-Cookie": "tg=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=%d" % (t, SESSION_TTL)})
                SESS.failed(ip)
                time.sleep(1)
                return self._send(401, {"error": "Incorrect password."})
            if not self._authed():
                return self._send(401, {"error": "login required"})
            if u.path == "/api/logout":
                SESS.drop(self._token())
                return self._send(200, {"ok": True}, extra={"Set-Cookie": "tg=; Path=/; Max-Age=0"})
            if u.path == "/api/start":
                CTRL.start(body)
                return self._send(200, {"ok": True})
            if u.path == "/api/stop":
                CTRL.stop()
                return self._send(200, {"ok": True})
            if u.path == "/api/config":
                cfg = tg.load_config()
                if "duration_minutes" in body:
                    cfg["duration_minutes"] = max(0, int(body["duration_minutes"]))
                if "threads_per_ip" in body:
                    cfg["threads_per_ip"] = min(max(int(body["threads_per_ip"]), 1), 20)
                if body.get("intensity") in tg.THINK:
                    cfg["intensity"] = body["intensity"]
                if isinstance(body.get("groups"), dict):
                    cfg["groups"] = {g: max(0, min(100, int(w))) for g, w in body["groups"].items()}
                if isinstance(body.get("disabled_apps"), list):
                    cfg["disabled_apps"] = [str(x) for x in body["disabled_apps"]]
                for k in ("tls_verify", "ioc_feeds", "ioc_connect"):
                    if k in body:
                        cfg[k] = bool(body[k])
                if isinstance(body.get("block_ips"), list):
                    import ipaddress
                    cfg["block_ips"] = [str(ipaddress.IPv4Address(str(x).strip())) for x in body["block_ips"] if str(x).strip()]
                save_config(cfg)
                return self._send(200, config_view(cfg))
            if u.path == "/api/tp/config":
                cfg = tg.load_config()
                cfg["throughput"] = tp_validate_path(body, cfg)
                save_config(cfg)
                return self._send(200, {"throughput": cfg["throughput"]})
            if u.path == "/api/tp/start":
                if CTRL.running:
                    return self._send(409, {"error": "Stop the running traffic test first."})
                cfg = tg.load_config()
                TP.start(str(body.get("kind", "")), tp_params(str(body.get("kind", "")), body.get("params") or {}, cfg), tg.LOG_DIR)
                return self._send(200, {"ok": True})
            if u.path == "/api/tp/stop":
                TP.stop()
                return self._send(200, {"ok": True})
            if u.path == "/api/tp/check":
                if TP.running or CTRL.running:
                    return self._send(409, {"error": "Stop the running test first."})
                return self._send(200, tp.check_env(tg.load_config()["throughput"]["rx"]))
            if u.path == "/api/network/apply":
                if CTRL.running or TP.running:
                    return self._send(409, {"error": "Stop the running test first."})
                nets, errs = netconf.validate(body.get("networks", []), tg.load_config()["mgmt_interface"])
                if errs:
                    return self._send(400, {"error": "\n".join(errs)})
                cfg = tg.load_config()
                cfg["networks"] = nets
                save_config(cfg)
                CTRL.apply_network()
                return self._send(200, {"log": CTRL.apply_log, "status": netconf.status(cfg), "networks": nets})
            if u.path == "/api/network/test":
                return self._send(200, netconf.test(tg.load_config()))
            if u.path == "/api/password":
                if not check_password(str(body.get("current", ""))):
                    return self._send(400, {"error": "Current password is incorrect."})
                set_password(str(body.get("new", "")))
                return self._send(200, {"ok": True})
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:  # noqa
            return self._send(500, {"error": str(e)})
        self._send(404, {"error": "not found"})


def main():
    cfg = tg.load_config()
    port = int(os.environ.get("TRAFFICGEN_PORT", "8443"))
    if not os.path.exists(AUTH_FILE):
        pw = secrets.token_urlsafe(9)
        set_password(pw)
        print("No admin password set; generated one: %s" % pw, flush=True)
    if cfg["networks"]:
        CTRL.apply_network()
        print("network: " + " | ".join(CTRL.apply_log), flush=True)
    srv = ThreadingHTTPServer(("0.0.0.0", port), H)
    srv.daemon_threads = True
    if os.path.exists(CERT) and os.path.exists(KEY):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(CERT, KEY)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        print("Listening on https://0.0.0.0:%d" % port, flush=True)
    else:
        print("WARNING: no TLS cert found, serving plain HTTP on :%d (login cookie is Secure and will not work)" % port, flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
