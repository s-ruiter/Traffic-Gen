#!/usr/bin/env python3
"""Throughput / packet-loss / connections-per-second tester (stdlib only).

A sender (bound to a configured source IP, routed through the FortiGate by netconf's
policy routing) talks to a receiver that lives in its own network namespace on a second
interface/VLAN.  The receiver is therefore reached *through* the firewall instead of via
the local loopback.  Tests: UDP stream, TCP throughput, RFC 2544 (throughput / frame loss /
latency) and TCP connections per second.  A "loopback" mode runs both ends on 127.0.0.1
as a self-test of the tool itself.
"""
import array
import collections
import ctypes
import errno
import json
import math
import multiprocessing as mp
import os
import selectors
import socket
import struct
import subprocess
import threading
import time

CTX = mp.get_context("fork")
MAGIC = 0x5447
HDR = struct.Struct("!HHIQ")          # magic, stream id, sequence, send timestamp (ns) = 16 bytes
HDR_LEN = HDR.size
RFC_OVERHEAD = 46                     # RFC 2544 frame = UDP payload + 8 UDP + 20 IP + 14 Eth + 4 FCS
RFC_SIZES = [64, 128, 256, 512, 1024, 1280, 1518]
CLONE_NEWNET = 0x40000000
RX_DEV = "tgrx0"
MAX_STREAMS = 8
SEC = 1_000_000_000


def mono():
    return time.monotonic_ns()


# ------------------------------------------------------------ plumbing helpers
def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _die_with_parent():
    try:
        _libc().prctl(1, 9)           # PR_SET_PDEATHSIG, SIGKILL
    except Exception:  # noqa
        pass


def enter_netns(pid):
    fd = os.open("/proc/%d/ns/net" % pid, os.O_RDONLY)
    try:
        if _libc().setns(fd, CLONE_NEWNET) != 0:
            e = ctypes.get_errno()
            raise OSError(e, "setns: " + os.strerror(e))
    finally:
        os.close(fd)


def run(cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("%s: %s" % (" ".join(cmd), (r.stderr or r.stdout).strip()))
    return r


class RxNet:
    """Isolated receiver network: a holder process in its own netns plus a VLAN/macvlan interface."""

    def __init__(self, rx):
        self.rx, self.holder, self.pid = rx, None, None

    def up(self):
        rx = self.rx
        self.holder = subprocess.Popen(["unshare", "-n", "sleep", "86400"], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, preexec_fn=_die_with_parent)
        self.pid = self.holder.pid
        mine = os.readlink("/proc/self/ns/net")
        for _ in range(40):
            try:
                if os.readlink("/proc/%d/ns/net" % self.pid) != mine:
                    break
            except OSError:
                pass
            time.sleep(0.05)
        else:
            raise RuntimeError("could not create a network namespace (is 'unshare -n' allowed in this LXC?)")
        try:
            run(["ip", "link", "del", RX_DEV], check=False)
            if rx.get("vlan"):
                run(["ip", "link", "add", "link", rx["parent"], "name", RX_DEV, "type", "vlan", "id", str(int(rx["vlan"]))])
            else:
                run(["ip", "link", "add", "link", rx["parent"], "name", RX_DEV, "type", "macvlan", "mode", "bridge"])
            run(["ip", "link", "set", RX_DEV, "netns", str(self.pid)])
            ns = ["nsenter", "-t", str(self.pid), "-n"]
            run(ns + ["ip", "link", "set", "lo", "up"])
            run(ns + ["ip", "addr", "add", "%s/%d" % (rx["ip"], int(rx["prefix"])), "dev", RX_DEV])
            run(ns + ["ip", "link", "set", RX_DEV, "up"])
            if rx.get("gateway"):
                run(ns + ["ip", "route", "add", "default", "via", rx["gateway"]])
            run(ns + ["arping", "-U", "-c", "1", "-I", RX_DEV, rx["ip"]], check=False)
        except Exception:
            self.down()
            raise

    def gateway_ping(self):
        gw = self.rx.get("gateway")
        if not gw:
            return None
        r = run(["nsenter", "-t", str(self.pid), "-n", "ping", "-c", "2", "-W", "1", "-I", self.rx["ip"], gw], check=False)
        return r.returncode == 0

    def down(self):
        if self.holder:
            try:
                self.holder.kill()
                self.holder.wait(timeout=3)
            except Exception:  # noqa
                pass
            self.holder = None
        run(["ip", "link", "del", RX_DEV], check=False)


# ------------------------------------------------------------ UDP receiver
class UdpStat:
    def __init__(self):
        self.t0 = None
        self.n = self.uniq = self.dup = self.reorder = self.bytes = 0
        self.maxseq = -1
        self.bm = bytearray(1 << 16)
        self.jit, self.prev = 0.0, None
        self.lmin, self.lmax, self.lsum = None, 0, 0
        self.ps = []

    def rx(self, ln, now, buf):
        magic, _sid, seq, ts = HDR.unpack_from(buf)
        if magic != MAGIC:
            return
        if self.t0 is None:
            self.t0 = now
        self.n += 1
        self.bytes += ln
        if seq > self.maxseq:
            self.maxseq = seq
        else:
            self.reorder += 1
        if seq < (1 << 27):
            if seq >= len(self.bm):
                self.bm.extend(bytes(max(seq + 1 - len(self.bm), 1 << 16)))
            if self.bm[seq]:
                self.dup += 1
            else:
                self.bm[seq] = 1
                self.uniq += 1
        else:
            self.uniq += 1
        tr = now - ts if now >= ts else 0
        if self.prev is not None:
            self.jit += (abs(tr - self.prev) - self.jit) / 16.0
        self.prev = tr
        self.lsum += tr
        if self.lmin is None or tr < self.lmin:
            self.lmin = tr
        if tr > self.lmax:
            self.lmax = tr
        i = (now - self.t0) // SEC
        while len(self.ps) <= i:
            self.ps.append([0, 0])
        self.ps[i][0] += 1
        self.ps[i][1] += ln

    def snap(self):
        return {"n": self.uniq, "bytes": self.bytes, "persec": [list(x) for x in self.ps]}

    def final(self):
        n = max(self.n, 1)
        return {"n": self.n, "uniq": self.uniq, "dup": self.dup, "reorder": self.reorder, "bytes": self.bytes,
                "jitter_ms": self.jit / 1e6, "lat_min_ms": (self.lmin or 0) / 1e6,
                "lat_avg_ms": self.lsum / n / 1e6, "lat_max_ms": self.lmax / 1e6, "persec": self.ps}


def _udp_rx(conn, ns_pid, bind_ip, port):
    _die_with_parent()
    try:
        if ns_pid:
            enter_netns(ns_pid)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)
        s.bind((bind_ip, port))
        s.settimeout(0.05)
    except Exception as e:  # noqa
        conn.send(("error", str(e)))
        return
    conn.send(("ready", None))
    buf = bytearray(65536)
    st, k = None, 0
    while True:
        try:
            ln = s.recv_into(buf)
        except (socket.timeout, OSError):
            ln = 0
        if ln >= HDR_LEN and st is not None:
            st.rx(ln, mono(), buf)
        k += 1
        if (ln == 0 or k & 255 == 0) and conn.poll():
            cmd = conn.recv()
            if cmd[0] == "arm":
                s.settimeout(0)
                try:
                    while True:
                        s.recv_into(buf)          # drop leftovers of the previous trial
                except (BlockingIOError, OSError):
                    pass
                s.settimeout(0.05)
                st = UdpStat()
                conn.send(("ok", None))
            elif cmd[0] == "snap":
                conn.send(("snap", st.snap() if st else None))
            elif cmd[0] == "collect":
                conn.send(("final", st.final() if st else None))
                st = None
            elif cmd[0] == "quit":
                return


def _udp_tx(conn, src, dst, port, sid, size, pps, dur):
    _die_with_parent()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
        if src:
            s.bind((src, 0))
        s.connect((dst, port))
    except OSError as e:
        conn.send(("error", str(e)))
        return
    buf = bytearray(b"\xa5") * max(size, HDR_LEN)
    pack, send = HDR.pack_into, s.send
    start = mono()
    end = start + int(dur * SEC)
    per, sent, errs, nxt = pps / 1e9, 0, 0, start + SEC
    while True:
        now = mono()
        if now >= end:
            break
        n = int((now - start) * per) + 1 - sent
        if n > 0:
            for _ in range(min(n, 256)):
                pack(buf, 0, MAGIC, sid, sent & 0xFFFFFFFF, mono())
                try:
                    send(buf)
                    sent += 1
                except OSError:
                    errs += 1
        else:
            time.sleep(0.0002)
        if now >= nxt:
            conn.send(("tick", sent))
            nxt += SEC
        if conn.poll() and conn.recv() == "stop":
            break
    conn.send(("done", {"sent": sent, "errors": errs, "elapsed": (mono() - start) / 1e9}))


# ------------------------------------------------------------ TCP receiver
def _tcp_rx(conn, ns_pid, bind_ip, ports):
    _die_with_parent()
    sel = selectors.DefaultSelector()
    try:
        if ns_pid:
            enter_netns(ns_pid)
        for p in ports:
            ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((bind_ip, p))
            ls.listen(4096)
            ls.setblocking(False)
            sel.register(ls, selectors.EVENT_READ, None)
    except Exception as e:  # noqa
        conn.send(("error", str(e)))
        return
    conn.send(("ready", None))
    buf = bytearray(1 << 18)
    mode, resp, t0 = None, 0, mono()
    acc = byt = rst = maxact = 0
    ps, live = [], {}

    def sec():
        i = (mono() - t0) // SEC
        while len(ps) <= i:
            ps.append([0, 0])
        return ps[i]

    def drop(c):
        live.pop(c.fileno(), None)
        try:
            sel.unregister(c)
        except (KeyError, ValueError):
            pass
        c.close()

    while True:
        for key, _ in sel.select(0.05):
            if key.data is None:
                for _ in range(256):
                    try:
                        c, _a = key.fileobj.accept()
                    except (BlockingIOError, OSError):
                        break
                    c.setblocking(False)
                    sel.register(c, selectors.EVENT_READ, [0])
                    live[c.fileno()] = c
                    if mode:
                        acc += 1
                        sec()[0] += 1
                        maxact = max(maxact, len(live))
                continue
            c, st = key.fileobj, key.data
            try:
                n = c.recv_into(buf)
            except BlockingIOError:
                continue
            except OSError:
                rst += 1
                drop(c)
                continue
            if n == 0:
                drop(c)
                continue
            if mode:
                byt += n
                sec()[1] += n
            if mode == "cps" and resp and not st[0]:
                st[0] = 1
                try:
                    c.send(b"y" * resp)
                except OSError:
                    pass
        if conn.poll():
            cmd = conn.recv()
            if cmd[0] == "arm":
                p = cmd[1] or {}
                mode, resp, t0 = p.get("mode", "stream"), int(p.get("resp", 0)), mono()
                acc = byt = rst = maxact = 0
                ps = []
                conn.send(("ok", None))
            elif cmd[0] == "snap":
                conn.send(("snap", {"n": acc, "bytes": byt, "active": len(live)}))
            elif cmd[0] == "collect":
                conn.send(("final", {"n": acc, "bytes": byt, "resets": rst, "max_active": maxact, "persec": ps}))
                mode = None
            elif cmd[0] == "quit":
                return


# ------------------------------------------------------------ CPS sender
def _cps_tx(conn, src, dst, ports, rate, dur, req, resp, hold_ms, rst, tmo):
    _die_with_parent()
    sel = selectors.DefaultSelector()
    clock = time.monotonic
    start = clock()
    end = start + dur
    c = collections.Counter()
    lats = array.array("d")
    live = {}
    port_i = 0
    nxt, scan = start + 1, start
    lin = struct.pack("ii", 1, 0)

    def close(ent):
        s = ent[0]
        live.pop(s.fileno(), None)
        try:
            sel.unregister(s)
        except (KeyError, ValueError):
            pass
        if rst:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, lin)
            except OSError:
                pass
        s.close()

    def fail(ent, why):
        c["fail"] += 1
        c[why] += 1
        close(ent)

    while True:
        now = clock()
        if now < end:
            due = int((now - start) * rate) + 1
            for _ in range(max(0, min(due - c["att"], 300))):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setblocking(False)
                try:
                    s.setsockopt(socket.IPPROTO_IP, 24, 1)       # IP_BIND_ADDRESS_NO_PORT
                except OSError:
                    pass
                c["att"] += 1
                try:
                    s.bind((src, 0))
                    e = s.connect_ex((dst, ports[port_i % len(ports)]))
                except OSError as ex:
                    e = ex.errno or errno.EADDRNOTAVAIL
                port_i += 1
                if e not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK):
                    c["fail"] += 1
                    c["error"] += 1
                    s.close()
                    continue
                ent = [s, now, "conn", 0, 0.0]
                live[s.fileno()] = ent
                sel.register(s, selectors.EVENT_WRITE, ent)
        elif not live:
            break
        for key, _ in sel.select(0.002):
            ent = key.data
            s = ent[0]
            if ent[2] == "conn":
                e = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if e:
                    fail(ent, {errno.ECONNREFUSED: "refused", errno.ETIMEDOUT: "timeout",
                               errno.ECONNRESET: "reset"}.get(e, "error"))
                    continue
                c["est"] += 1
                lats.append(clock() - ent[1])
                if req > 0:
                    try:
                        s.send(b"x" * req)
                    except OSError:
                        pass
                    ent[2] = "resp"
                    sel.modify(s, selectors.EVENT_READ, ent)
                elif hold_ms > 0:
                    ent[2], ent[4] = "hold", clock() + hold_ms / 1000.0
                    sel.unregister(s)
                else:
                    c["done"] += 1
                    close(ent)
            elif ent[2] == "resp":
                try:
                    d = s.recv(65536)
                except OSError:
                    d = b""
                ent[3] += len(d)
                if not d or ent[3] >= resp:
                    c["done"] += 1
                    close(ent)
        now = clock()
        if now - scan >= 0.1:
            scan = now
            for ent in list(live.values()):
                if ent[2] == "hold" and now >= ent[4]:
                    c["done"] += 1
                    close(ent)
                elif ent[2] in ("conn", "resp") and now - ent[1] > tmo:
                    if ent[2] == "conn":
                        fail(ent, "timeout")
                    else:
                        c["done"] += 1
                        close(ent)
        if now >= nxt:
            conn.send(("tick", c["att"], c["est"], c["fail"], len(live)))
            nxt += 1
            if conn.poll() and conn.recv() == "stop":
                break
    for ent in list(live.values()):
        close(ent)
    lat = lats.tolist()
    if len(lat) > 50000:
        lat = lat[::len(lat) // 50000 + 1]
    conn.send(("done", {"counts": dict(c), "lat": lat}))


# ------------------------------------------------------------ orchestration
def pct(vals, p):
    if not vals:
        return 0.0
    v = sorted(vals)
    return v[min(len(v) - 1, int(math.ceil(p / 100.0 * len(v))) - 1)]


class Stopped(Exception):
    pass


class Ctx:
    """Sender/receiver endpoints for one test run."""

    def __init__(self, p, stop_evt, progress):
        self.p, self.stop, self.progress = p, stop_evt, progress
        self.loopback = p["rx"].get("mode") == "loopback"
        self.src = "127.0.0.1" if self.loopback else p["tx_ip"]
        self.dst = "127.0.0.1" if self.loopback else p["rx"]["ip"]
        self.base = int(p.get("base_port", 5201))
        self.net = None
        self.udp, self.tcp = [], None

    def up(self):
        if not self.loopback:
            self.net = RxNet(self.p["rx"])
            self.net.up()

    @property
    def ns_pid(self):
        return self.net.pid if self.net else None

    def _spawn_rx(self, target, args):
        a, b = CTX.Pipe()
        pr = CTX.Process(target=target, args=(b,) + args, daemon=True)
        pr.start()
        if not a.poll(5):
            raise RuntimeError("receiver did not start")
        msg = a.recv()
        if msg[0] == "error":
            pr.terminate()
            raise RuntimeError("receiver: " + msg[1])
        return pr, a

    def udp_rx(self, n):
        while len(self.udp) < n:
            i = len(self.udp)
            self.udp.append(self._spawn_rx(_udp_rx, (self.ns_pid, self.dst if not self.loopback else "127.0.0.1", self.base + i)))
        return self.udp[:n]

    def tcp_rx(self):
        if not self.tcp:
            ports = [self.base + i for i in range(MAX_STREAMS)]
            self.tcp = self._spawn_rx(_tcp_rx, (self.ns_pid, self.dst, ports))
        return self.tcp

    @staticmethod
    def ask(conn, msg, tmo=5):
        conn.send(msg)
        if not conn.poll(tmo):
            raise RuntimeError("receiver not responding")
        return conn.recv()[1]

    def down(self):
        for pr, conn in self.udp + ([self.tcp] if self.tcp else []):
            try:
                conn.send(("quit",))
                pr.join(1)
                if pr.is_alive():
                    pr.terminate()
            except Exception:  # noqa
                pass
        if self.net:
            self.net.down()

    def check_stop(self):
        if self.stop.is_set():
            raise Stopped()


def merge_ps(lists, idx):
    return sum(l[idx] for l in lists if idx < len(l))


def udp_trial(ctx, payload, pps, dur, streams, series=None):
    """One UDP trial: returns a result dict."""
    payload = max(payload, HDR_LEN)
    streams = max(1, min(streams, MAX_STREAMS))
    rxs = ctx.udp_rx(streams)
    for _pr, conn in rxs:
        ctx.ask(conn, ("arm",))
    pipes, procs = [], []
    for i in range(streams):
        a, b = CTX.Pipe()
        pr = CTX.Process(target=_udp_tx, args=(b, ctx.src, ctx.dst, ctx.base + i, i, payload, pps / streams, dur), daemon=True)
        pr.start()
        pipes.append(a)
        procs.append(pr)
    sent_cum = [0] * streams
    hist = [[] for _ in range(streams)]
    done = [None] * streams
    err = None
    bits = (payload + 28) * 8

    def build(rs, live):
        out = []
        maxlen = max([len(r.get("persec") or []) for r in rs] or [0])
        kmax = min(len(h) for h in hist) if live else max(len(h) for h in hist)
        for k in range(kmax):
            if live and k >= maxlen - 1:
                break
            tx = sum((h[k] - (h[k - 1] if k else 0)) for h in hist if k < len(h))
            rx = sum(r["persec"][k][0] for r in rs if r.get("persec") and k < len(r["persec"]))
            out.append([k + 1, round(tx * bits / 1e6, 2), round(rx * bits / 1e6, 2),
                        round(max(0.0, (tx - rx) / tx * 100), 3) if tx else 0.0])
        return out

    try:
        while any(d is None for d in done):
            if ctx.stop.is_set():
                for a in pipes:
                    try:
                        a.send("stop")
                    except OSError:
                        pass
                raise Stopped()
            time.sleep(1.0)
            for i, a in enumerate(pipes):
                while a.poll():
                    m = a.recv()
                    if m[0] == "tick":
                        sent_cum[i] = m[1]
                        hist[i].append(m[1])
                    elif m[0] == "done":
                        done[i] = m[1]
                        sent_cum[i] = m[1]["sent"]
                        hist[i].append(m[1]["sent"])
                    elif m[0] == "error":
                        err = m[1]
                        done[i] = {"sent": 0, "errors": 0, "elapsed": 0}
            if err:
                raise RuntimeError("sender: " + err)
            snaps = [ctx.ask(c, ("snap",)) or {} for _p, c in rxs]
            if series is not None:
                series[:] = build(snaps, True)
        time.sleep(0.4)
        finals = [ctx.ask(c, ("collect",)) or {} for _p, c in rxs]
    finally:
        for pr in procs:
            if pr.is_alive():
                pr.terminate()
    if series is not None:
        series[:] = build(finals, False)
    sent = sum(d["sent"] for d in done)
    uniq = sum(f.get("uniq", 0) for f in finals)
    rxn = sum(f.get("n", 0) for f in finals) or 1
    el = max((d["elapsed"] for d in done), default=dur) or dur
    expect = pps * dur
    lat_min = min([f["lat_min_ms"] for f in finals if f.get("n")] or [0])
    return {
        "sent": sent, "received": uniq, "lost": max(0, sent - uniq),
        "loss_pct": round(max(0.0, (sent - uniq) / sent * 100), 4) if sent else 100.0,
        "dup": sum(f.get("dup", 0) for f in finals), "reorder": sum(f.get("reorder", 0) for f in finals),
        "pps_target": round(pps), "pps_sent": round(sent / el), "pps_recv": round(uniq / el),
        "tx_mbps": round(sent * bits / el / 1e6, 2), "rx_mbps": round(uniq * bits / el / 1e6, 2),
        "payload": payload, "streams": streams, "duration": round(el, 1),
        "jitter_ms": round(sum(f.get("jitter_ms", 0) * f.get("n", 0) for f in finals) / rxn, 4),
        "lat_min_ms": round(lat_min, 4),
        "lat_avg_ms": round(sum(f.get("lat_avg_ms", 0) * f.get("n", 0) for f in finals) / rxn, 4),
        "lat_max_ms": round(max([f.get("lat_max_ms", 0) for f in finals] or [0]), 4),
        "sender_errors": sum(d["errors"] for d in done),
        "limited": sent < 0.98 * expect,
    }


def tcp_trial(ctx, streams, dur, series=None):
    streams = max(1, min(streams, MAX_STREAMS * 4))
    _pr, rconn = ctx.tcp_rx()
    ctx.ask(rconn, ("arm", {"mode": "stream"}))
    lock = threading.Lock()
    ps, errs, opened = [], [], [0]
    end = [0.0]

    def worker(i):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((ctx.src, 0))
            s.settimeout(5)
            s.connect((ctx.dst, ctx.base + i % MAX_STREAMS))
            s.settimeout(2)
        except OSError as e:
            errs.append(str(e))
            return
        with lock:
            opened[0] += 1
        chunk = b"\x5a" * (128 * 1024)
        while time.monotonic() < end[0] and not ctx.stop.is_set():
            try:
                s.sendall(chunk)
            except OSError as e:
                errs.append(str(e))
                break
            i2 = int(time.monotonic() - t_start)
            with lock:
                while len(ps) <= i2:
                    ps.append(0)
                ps[i2] += len(chunk)
        s.close()

    t_start = time.monotonic()
    end[0] = t_start + dur
    ths = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(streams)]
    for t in ths:
        t.start()
    prev_tx = prev_rx = 0
    sec_i = 0
    while any(t.is_alive() for t in ths):
        time.sleep(1.0)
        sec_i += 1
        snap = ctx.ask(rconn, ("snap",))
        with lock:
            tx = sum(ps)
        if series is not None:
            series.append([sec_i, round((tx - prev_tx) * 8 / 1e6, 2), round((snap["bytes"] - prev_rx) * 8 / 1e6, 2), 0.0])
        prev_tx, prev_rx = tx, snap["bytes"]
    ctx.check_stop()
    time.sleep(0.3)
    fin = ctx.ask(rconn, ("collect",))
    el = time.monotonic() - t_start
    tx = sum(ps)
    secs = [x * 8 / 1e6 for x in ps[:-1]] or [tx * 8 / 1e6 / max(el, 1)]
    if not opened[0]:
        raise RuntimeError("no TCP connection could be opened: " + (errs[0] if errs else "unknown error"))
    return {"streams": streams, "opened": opened[0], "errors": len(errs), "error_msg": errs[0] if errs else "",
            "tx_bytes": tx, "rx_bytes": fin["bytes"], "duration": round(el, 1),
            "tx_mbps": round(tx * 8 / el / 1e6, 2), "rx_mbps": round(fin["bytes"] * 8 / el / 1e6, 2),
            "peak_mbps": round(max(secs), 2), "resets": fin["resets"]}


def cps_trial(ctx, rate, dur, req, resp, hold_ms, rst, series=None):
    _pr, rconn = ctx.tcp_rx()
    ctx.ask(rconn, ("arm", {"mode": "cps", "resp": resp}))
    ports = [ctx.base + i for i in range(MAX_STREAMS)]
    n = max(1, min(int(math.ceil(rate / 3000.0)), os.cpu_count() or 1, 8))
    pipes, procs = [], []
    for _ in range(n):
        a, b = CTX.Pipe()
        pr = CTX.Process(target=_cps_tx, args=(b, ctx.src, ctx.dst, ports, rate / float(n), dur, req, resp, hold_ms, rst, 3.0), daemon=True)
        pr.start()
        pipes.append(a)
        procs.append(pr)
    cum = [(0, 0, 0, 0)] * n
    done = [None] * n
    prev = (0, 0, 0)
    sec_i = 0
    try:
        while any(d is None for d in done):
            if ctx.stop.is_set():
                for a in pipes:
                    try:
                        a.send("stop")
                    except OSError:
                        pass
                raise Stopped()
            time.sleep(1.0)
            for i, a in enumerate(pipes):
                while a.poll():
                    m = a.recv()
                    if m[0] == "tick":
                        cum[i] = m[1:]
                    elif m[0] == "done":
                        done[i] = m[1]
            att, est, fl = (sum(c[k] for c in cum) for k in range(3))
            active = sum(c[3] for c in cum)
            sec_i += 1
            if series is not None:
                series.append([sec_i, att - prev[0], est - prev[1], active])
            prev = (att, est, fl)
        time.sleep(0.3)
        fin = ctx.ask(rconn, ("collect",))
    finally:
        for pr in procs:
            if pr.is_alive():
                pr.terminate()
    tot = collections.Counter()
    lat = []
    for d in done:
        tot.update(d["counts"])
        lat += d["lat"]
    att, est, fail = tot["att"], tot["est"], tot["fail"]
    secs = [x[0] for x in fin["persec"]] or [0]
    return {"target_cps": round(rate), "attempted": att, "established": est, "failed": fail,
            "fail_pct": round(fail / att * 100, 3) if att else 0.0,
            "refused": tot["refused"], "timeout": tot["timeout"], "reset": tot["reset"], "error": tot["error"],
            "avg_cps": round(est / dur, 1), "peak_cps": max(secs), "rx_accepted": fin["n"],
            "max_active": fin["max_active"], "lat_p50_ms": round(pct(lat, 50) * 1000, 3),
            "lat_p95_ms": round(pct(lat, 95) * 1000, 3), "lat_max_ms": round(max(lat or [0]) * 1000, 3),
            "workers": n, "req": req, "resp": resp, "hold_ms": hold_ms,
            "limited": att < 0.95 * rate * dur}


# ------------------------------------------------------------ RFC 2544
def line_pps(size, link_mbps):
    return link_mbps * 1e6 / (8.0 * (size + 20))


def streams_for(pps):
    return max(1, min(MAX_STREAMS, int(math.ceil(pps / 50000.0))))


def rfc2544(ctx, p, st):
    sizes = p["sizes"]
    link, trial_s = float(p["link_mbps"]), float(p["trial_s"])
    tol, res = float(p["loss_tol"]), float(p["resolution"])
    do_fl = bool(p.get("frame_loss"))
    rows_tp, rows_fl = st["rows"], st["rows2"]
    total = len(sizes) * 1
    st["steps"] = 0
    for size in sizes:
        ctx.check_stop()
        payload = max(HDR_LEN, size - RFC_OVERHEAD)
        lp = line_pps(size, link)
        st["phase"] = "throughput %d B" % size

        def trial(pc, series=True):
            ctx.check_stop()
            pps = lp * pc / 100.0
            st["series"] = []
            r = udp_trial(ctx, payload, pps, trial_s, streams_for(pps), st["series"])
            r["pct"] = round(pc, 2)
            r["ok"] = r["loss_pct"] <= tol and not r["limited"]
            st["steps"] += 1
            st["log"].append("%d B @ %.1f%%: loss %.3f%%%s" % (size, pc, r["loss_pct"], " (sender limited)" if r["limited"] else ""))
            return r

        lo, hi, best, limited_note = 0.0, 100.0, None, False
        r = trial(100.0)
        if r["ok"]:
            best, lo = r, 100.0
        else:
            if r["limited"]:
                limited_note = True
                hi = max(res, min(100.0, r["pps_sent"] / lp * 100.0 * 0.97))
            else:
                hi = 100.0
            while hi - lo > res:
                mid = (lo + hi) / 2.0
                r = trial(mid)
                if r["ok"]:
                    best, lo = r, mid
                elif r["limited"]:
                    limited_note = True
                    hi = mid
                else:
                    hi = mid
        row = {"size": size, "line_pps": round(lp), "limited": limited_note,
               "tp_pct": round(lo, 2) if best else 0.0, "tp_pps": best["pps_recv"] if best else 0,
               "tp_mbps": round(best["pps_recv"] * size * 8 / 1e6, 2) if best else 0.0,
               "loss_pct": best["loss_pct"] if best else None, "lat_min_ms": best["lat_min_ms"] if best else None,
               "lat_avg_ms": best["lat_avg_ms"] if best else None, "lat_max_ms": best["lat_max_ms"] if best else None,
               "jitter_ms": best["jitter_ms"] if best else None}
        rows_tp.append(row)
        if do_fl:
            st["phase"] = "frame loss %d B" % size
            clean = 0
            for pc in range(100, 0, -10):
                r = trial(float(pc))
                rows_fl.append({"size": size, "pct": pc, "offered_pps": r["pps_sent"], "loss_pct": r["loss_pct"],
                                "limited": r["limited"], "rx_mbps": round(r["pps_recv"] * size * 8 / 1e6, 2)})
                clean = clean + 1 if r["loss_pct"] <= tol else 0
                if clean >= 2:
                    break
    return {"throughput": rows_tp, "frame_loss": rows_fl}


# ------------------------------------------------------------ runner
class Runner:
    def __init__(self):
        self.lock = threading.Lock()
        self.thread = None
        self.stop_evt = threading.Event()
        self.st = self._blank()

    @staticmethod
    def _blank():
        return {"running": False, "kind": None, "phase": "", "step": 0, "steps": 0, "started": None, "finished": None,
                "params": None, "series": [], "result": None, "rows": [], "rows2": [], "log": [], "error": None,
                "stopped": False, "mode": None}

    @property
    def running(self):
        return bool(self.thread and self.thread.is_alive())

    def state(self):
        with self.lock:
            s = dict(self.st)
        s["running"] = self.running
        s["now"] = time.time()
        s["series"] = list(s["series"])
        s["rows"], s["rows2"], s["log"] = list(s["rows"]), list(s["rows2"]), list(s["log"])[-40:]
        return s

    def stop(self):
        self.stop_evt.set()

    def start(self, kind, p, logdir=None):
        with self.lock:
            if self.running:
                raise ValueError("A throughput test is already running.")
            self.stop_evt = threading.Event()
            self.st = self._blank()
            self.st.update({"running": True, "kind": kind, "params": p, "started": time.time(), "mode": p["rx"].get("mode")})
            self.thread = threading.Thread(target=self._run, args=(kind, p, logdir), daemon=True)
            self.thread.start()

    def _run(self, kind, p, logdir):
        st = self.st
        ctx = Ctx(p, self.stop_evt, st)
        try:
            st["phase"] = "preparing receiver"
            ctx.up()
            dur = float(p.get("duration", 10))
            if kind == "udp":
                st["phase"], st["steps"] = "UDP stream", 1
                pps = float(p["rate_mbps"]) * 1e6 / ((int(p["payload"]) + 28) * 8)
                st["result"] = udp_trial(ctx, int(p["payload"]), pps, dur, int(p.get("streams") or streams_for(pps)), st["series"])
            elif kind == "tcp":
                st["phase"], st["steps"] = "TCP throughput", 1
                st["result"] = tcp_trial(ctx, int(p["streams"]), dur, st["series"])
            elif kind == "cps":
                rates = ([float(p["rate"]) + i * float(p["step"]) for i in range(int(p["steps"]))]
                         if p.get("ramp") else [float(p["rate"])])
                st["steps"] = len(rates)
                for i, rate in enumerate(rates):
                    ctx.check_stop()
                    st["step"], st["phase"], st["series"] = i + 1, "connections/s: %d" % rate, []
                    r = cps_trial(ctx, rate, dur, int(p["req"]), int(p["resp"]), int(p["hold_ms"]), p.get("close", "rst") == "rst", st["series"])
                    r["ok"] = r["fail_pct"] <= float(p.get("max_fail_pct", 0.1)) and r["avg_cps"] >= 0.95 * rate
                    st["rows"].append(r)
                    st["log"].append("%d conn/s: established %d/%d, %.1f%% failed" % (rate, r["established"], r["attempted"], r["fail_pct"]))
                st["result"] = {"max_ok_cps": max([r["target_cps"] for r in st["rows"] if r["ok"]] or [0])}
            elif kind == "rfc2544":
                st["result"] = rfc2544(ctx, p, st)
        except Stopped:
            st["stopped"] = True
        except Exception as e:  # noqa
            st["error"] = str(e)
        finally:
            ctx.down()
            st["finished"], st["running"] = time.time(), False
            if logdir and (st["result"] or st["rows"]):
                try:
                    os.makedirs(logdir, exist_ok=True)
                    with open(os.path.join(logdir, "throughput.jsonl"), "a") as f:
                        f.write(json.dumps({k: st[k] for k in ("kind", "params", "started", "finished", "result", "rows", "rows2", "stopped")}) + "\n")
                except OSError:
                    pass


def check_env(rx):
    """Pre-flight for the isolated receiver; returns [{name, ok, detail}]."""
    out = []

    def add(name, ok, detail=""):
        out.append({"name": name, "ok": bool(ok), "detail": detail})
        return ok

    add("running as root", os.geteuid() == 0, "")
    for tool in ("ip", "unshare", "nsenter"):
        add("tool: " + tool, run(["which", tool], check=False).returncode == 0, "")
    if rx.get("mode") == "loopback":
        add("loopback self-test", True, "No namespace needed; this only tests the tool itself, not the FortiGate.")
        return out
    net = RxNet(rx)
    try:
        net.up()
        add("receiver namespace + %s on %s" % ("VLAN" if rx.get("vlan") else "macvlan", rx.get("parent")), True, "")
        gp = net.gateway_ping()
        if gp is not None:
            add("receiver can reach gateway %s" % rx.get("gateway"), gp, "" if gp else "No ping reply. Check the VLAN/bridge and the FortiGate interface or policy.")
    except Exception as e:  # noqa
        add("receiver namespace", False, str(e))
    finally:
        net.down()
    return out
