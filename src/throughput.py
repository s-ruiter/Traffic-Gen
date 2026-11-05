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
import ipaddress
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
try:
    CPUS = len(os.sched_getaffinity(0)) or 1          # respects the LXC's CPU limit (cpuset)
except AttributeError:
    CPUS = os.cpu_count() or 1
STREAM_CAP = max(1, min(MAX_STREAMS, CPUS // 2))     # one stream = one sender + one receiver process


def mono():
    return time.monotonic_ns()


def port_range():
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            lo, hi = f.read().split()
            return int(lo), int(hi)
    except (OSError, ValueError):
        return 32768, 60999


def tuple_capacity(src_ips, dst_ips, ports=MAX_STREAMS):
    """Rough number of concurrent TCP sessions possible: one source port per (src IP, dst IP, dst port)."""
    lo, hi = port_range()
    return int(src_ips) * int(dst_ips) * int(ports) * (hi - lo + 1)


# ------------------------------------------------------------ plumbing helpers
def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _die_with_parent():
    try:
        _libc().prctl(1, 9)           # PR_SET_PDEATHSIG, SIGKILL
    except Exception:  # noqa
        pass


def _worker_init():
    """Workers die with the web service, run at low priority (the GUI keeps priority) and may open many sockets."""
    _die_with_parent()
    try:
        os.nice(10)
    except OSError:
        pass
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard if hard != resource.RLIM_INFINITY else 1048576, hard))
    except (ImportError, ValueError, OSError):
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


def _netns_id(pid):
    try:
        return os.readlink("/proc/%d/ns/net" % pid)
    except OSError:
        return None


def kill_stale_holders():
    """Kill namespace holders (and anything inside their namespace) left behind by an earlier run."""
    mine = _netns_id(os.getpid())
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) == os.getpid():
            continue
        try:
            with open("/proc/%s/cmdline" % d, "rb") as f:
                cmd = f.read()
        except OSError:
            continue
        if (cmd.startswith(b"sleep\x0086400") or cmd.startswith(b"unshare\x00-n\x00sleep\x0086400")) and _netns_id(int(d)) not in (None, mine):
            try:
                os.kill(int(d), 9)
            except OSError:
                pass


def mac_for(ip):
    """A stable, locally administered MAC per receiver IP, so the FortiGate's ARP entry stays valid between tests."""
    b = ipaddress.IPv4Address(ip).packed
    return "02:54:47:%02x:%02x:%02x" % (b[1], b[2], b[3])


class RxNet:
    """Isolated receiver network: a holder process in its own netns plus a VLAN/macvlan interface."""

    def __init__(self, rx):
        self.rx, self.holder, self.pid = rx, None, None

    def up(self):
        rx = self.rx
        kill_stale_holders()
        run(["ip", "link", "del", RX_DEV], check=False)
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
            run(["ip", "link", "set", rx["parent"], "up"])          # the parent NIC has no IP, so it may still be down
            mac = mac_for(rx["ip"])
            if rx.get("vlan"):
                run(["ip", "link", "add", "link", rx["parent"], "name", RX_DEV, "address", mac, "type", "vlan", "id", str(int(rx["vlan"]))])
            else:
                run(["ip", "link", "add", "link", rx["parent"], "name", RX_DEV, "address", mac, "type", "macvlan", "mode", "bridge"])
            run(["ip", "link", "set", RX_DEV, "netns", str(self.pid)])
            ns = ["nsenter", "-t", str(self.pid), "-n"]
            run(ns + ["ip", "link", "set", "lo", "up"])
            first = ipaddress.IPv4Address(rx["ip"])
            ips = [str(first + i) for i in range(max(1, int(rx.get("count") or 1)))]
            for ip in ips:
                run(ns + ["ip", "addr", "add", "%s/%d" % (ip, int(rx["prefix"])), "dev", RX_DEV])
            run(ns + ["ip", "link", "set", RX_DEV, "up"])
            if rx.get("gateway"):
                run(ns + ["ip", "route", "add", "default", "via", rx["gateway"]])
            for ip in ips:
                run(ns + ["arping", "-U", "-c", "2", "-I", RX_DEV, ip], check=False)
            if rx.get("gateway"):                                  # makes the gateway (re)learn our MAC address
                run(ns + ["ping", "-c", "1", "-W", "1", "-I", rx["ip"], rx["gateway"]], check=False)
        except Exception:
            self.down()
            raise

    def gateway_probe(self):
        """(ping answered, ARP answered) for the receiver gateway, from inside the receiver namespace."""
        gw = self.rx.get("gateway")
        if not gw:
            return None, None
        ns = ["nsenter", "-t", str(self.pid), "-n"]
        ping = run(ns + ["ping", "-c", "2", "-W", "1", "-I", self.rx["ip"], gw], check=False).returncode == 0
        arp = run(ns + ["arping", "-c", "2", "-w", "3", "-I", RX_DEV, gw], check=False).returncode == 0
        return ping, arp

    def carrier(self):
        try:
            with open("/sys/class/net/%s/carrier" % self.rx["parent"]) as f:
                return f.read().strip() == "1"
        except OSError:
            return None

    def down(self):
        if self.holder:
            ns_id = _netns_id(self.pid)
            run(["nsenter", "-t", str(self.pid), "-n", "ip", "link", "del", RX_DEV], check=False)   # frees MAC and IPs at once
            if ns_id:                                                # kill whatever is still inside the namespace
                for d in os.listdir("/proc"):
                    if d.isdigit() and int(d) not in (os.getpid(), self.pid) and _netns_id(int(d)) == ns_id:
                        try:
                            os.kill(int(d), 9)
                        except OSError:
                            pass
            try:
                self.holder.kill()
                self.holder.wait(timeout=5)
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
        if seq < (1 << 25):
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
    _worker_init()
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
    _worker_init()
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
    _worker_init()
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
    mode, resp, t0 = None, 0, [None]
    acc = byt = rst = maxact = 0
    ps, live = [], {}

    def sec():
        now = mono()
        if t0[0] is None:
            t0[0] = now
        i = (now - t0[0]) // SEC
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
            if mode == "conc":
                try:
                    c.send(b"h")
                except OSError:
                    pass
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
                mode, resp, t0 = p.get("mode", "stream"), int(p.get("resp", 0)), [None]
                acc = byt = rst = maxact = 0
                ps = []
                conn.send(("ok", None))
            elif cmd[0] == "snap":
                conn.send(("snap", {"n": acc, "bytes": byt, "active": len(live), "persec": [list(x) for x in ps]}))
            elif cmd[0] == "collect":
                conn.send(("final", {"n": acc, "bytes": byt, "resets": rst, "max_active": maxact, "persec": ps}))
                mode = None
            elif cmd[0] == "quit":
                return


# ------------------------------------------------------------ CPS sender
def _cps_tx(conn, src, dst, ports, rate, dur, req, resp, hold_ms, rst, tmo):
    _worker_init()
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


# ------------------------------------------------------------ concurrent sessions sender
def _conc_tx(conn, srcs, dsts, ports, rate, target, hold_s, hb_s, fail_pct, tmo):
    """Open up to `target` TCP connections at `rate`/s, keep them open for `hold_s` with a heartbeat, count drops."""
    _worker_init()
    sel = selectors.DefaultSelector()
    clock = time.monotonic
    start = clock()
    c = collections.Counter()
    lats = array.array("d")
    live = {}
    pending = collections.deque()          # connections still in the handshake (oldest first)
    hbq = collections.deque()              # established connections, round-robin for the heartbeat
    lin = struct.pack("ii", 1, 0)
    ns, nd, npt = len(srcs), len(dsts), len(ports)
    idx, alive, peak = 0, 0, 0
    ramping, ramp_end, reason, first_fail_alive = True, None, "", None
    win = collections.deque()
    nxt_tick, last_hb = start + 1, start

    def close(ent, rst=True):
        s = ent[0]
        ent[2] = "closed"
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

    def lost(ent):
        nonlocal alive
        if ent[2] == "up":
            alive -= 1
            c["dropped"] += 1
        close(ent)

    def failed(ent, why):
        nonlocal first_fail_alive
        c["fail"] += 1
        c[why] += 1
        if first_fail_alive is None:
            first_fail_alive = alive
        close(ent)

    while True:
        now = clock()
        # ---- ramp up
        if ramping:
            if c["est"] >= target:
                ramping, ramp_end, reason = False, now, "target"
            else:
                due = int((now - start) * rate) + 1
                for _ in range(max(0, min(due - c["att"], 300, target - c["est"] - len(pending) + 0))):
                    i = idx
                    idx += 1
                    src, dst = srcs[i % ns], dsts[(i // ns) % nd]
                    port = ports[(i // (ns * nd)) % npt]
                    c["att"] += 1
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    except OSError:                                  # out of file descriptors
                        c["fail"] += 1
                        c["error"] += 1
                        if first_fail_alive is None:
                            first_fail_alive = alive
                        break
                    s.setblocking(False)
                    try:
                        s.setsockopt(socket.IPPROTO_IP, 24, 1)       # IP_BIND_ADDRESS_NO_PORT
                    except OSError:
                        pass
                    try:
                        s.bind((src, 0))
                        e = s.connect_ex((dst, port))
                    except OSError as ex:
                        e = ex.errno or errno.EADDRNOTAVAIL
                    if e not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK):
                        c["fail"] += 1
                        c["error"] += 1
                        if first_fail_alive is None:
                            first_fail_alive = alive
                        s.close()
                        continue
                    ent = [s, now, "conn", 0.0, now]
                    live[s.fileno()] = ent
                    pending.append(ent)
                    sel.register(s, selectors.EVENT_WRITE, ent)
        elif ramp_end is not None and now - ramp_end >= hold_s:
            break
        # ---- socket events
        for key, ev in sel.select(0.002):
            ent = key.data
            s = ent[0]
            if ent[2] == "conn":
                e = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if e:
                    failed(ent, {errno.ECONNREFUSED: "refused", errno.ETIMEDOUT: "timeout", errno.ECONNRESET: "reset"}.get(e, "error"))
                    continue
                c["est"] += 1
                alive += 1
                peak = max(peak, alive)
                lats.append(clock() - ent[1])
                ent[2] = "up"
                sel.modify(s, selectors.EVENT_READ, ent)
                hbq.append(ent)
            elif ent[2] == "up":
                try:
                    d = s.recv(64)
                except BlockingIOError:
                    continue
                except OSError:
                    d = b""
                if d:
                    ent[3] = 0.0                    # heartbeat answered
                else:
                    lost(ent)
        # ---- handshake time-outs (oldest first)
        while pending and (pending[0][2] != "conn" or now - pending[0][1] > tmo):
            ent = pending.popleft()
            if ent[2] == "conn":
                failed(ent, "timeout")
        # ---- heartbeat: every connection once per hb_s
        if hb_s > 0 and hbq and now - last_hb >= 0.05:
            k = min(len(hbq), int(len(hbq) * (now - last_hb) / hb_s) + 1)
            last_hb = now
            for _ in range(k):
                ent = hbq.popleft()
                if ent[2] != "up":
                    continue
                if ent[3] and now - ent[3] > 10:
                    lost(ent)
                    continue
                try:
                    ent[0].send(b"h")
                    if not ent[3]:
                        ent[3] = now
                except OSError:
                    lost(ent)
                    continue
                hbq.append(ent)
        elif hbq and len(hbq) > 2 * max(alive, 1):
            hbq = collections.deque(e for e in hbq if e[2] == "up")
        # ---- once a second: tick, failure window, stop message
        if now >= nxt_tick:
            nxt_tick += 1
            conn.send(("tick", c["att"], c["est"], c["fail"], alive, c["dropped"], 1 if ramping else 0))
            win.append((now, c["att"], c["fail"]))
            while win and now - win[0][0] > 3.5:
                win.popleft()
            if ramping and len(win) >= 2:
                da, df = win[-1][1] - win[0][1], win[-1][2] - win[0][2]
                if da >= 50 and df * 100.0 / da > fail_pct:
                    ramping, ramp_end, reason = False, now, "failures"
            if conn.poll() and conn.recv() == "stop":
                reason = reason or "stopped"
                break
    final_alive = alive
    for ent in list(live.values()):
        close(ent)
    lat = lats.tolist()
    if len(lat) > 50000:
        lat = lat[::len(lat) // 50000 + 1]
    conn.send(("done", {"counts": dict(c), "lat": lat, "peak": peak, "final": final_alive, "reason": reason or "target",
                        "first_fail_alive": first_fail_alive, "ramp_s": round((ramp_end or clock()) - start, 1)}))


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
        cnt = max(1, int(p["rx"].get("count") or 1))
        if self.loopback:
            self.dsts = ["127.0.0.%d" % (1 + i) for i in range(cnt)]
        else:
            self.dsts = [str(ipaddress.IPv4Address(p["rx"]["ip"]) + i) for i in range(cnt)]
        self.base = int(p.get("base_port", 5201))
        self.net = None
        self.udp, self.tcp = [], None

    def warn(self, msg):
        w = self.progress.setdefault("warnings", [])
        if msg not in w:
            w.append(msg)

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
            self.tcp = self._spawn_rx(_tcp_rx, (self.ns_pid, "0.0.0.0", ports))
        return self.tcp

    @staticmethod
    def ask(conn, msg, tmo=15):
        conn.send(msg)
        if not conn.poll(tmo):
            raise RuntimeError("receiver not responding")
        return conn.recv()[1]

    def down(self):
        for pr, conn in self.udp + ([self.tcp] if self.tcp else []):
            try:
                conn.send(("quit",))
                pr.join(2)
                if pr.is_alive():
                    pr.terminate()
                    pr.join(2)
                if pr.is_alive():
                    os.kill(pr.pid, 9)
                    pr.join(2)
            except Exception:  # noqa
                pass
        if self.net:
            self.net.down()

    def check_stop(self):
        if self.stop.is_set():
            raise Stopped()

    def path_check(self):
        """Before a TCP based test: make sure the sender can really reach the receiver through the firewall."""
        if self.loopback:
            return
        self.tcp_rx()
        last, t0, tries = None, time.time(), 0
        while time.time() - t0 < 30:
            self.check_stop()
            tries += 1
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                c.bind((self.src, 0))
                c.settimeout(2)
                c.connect((self.dsts[0], self.base))
                c.close()
                self.progress["log"].append("Path check OK after %d attempt(s) / %.0f s: %s reached %s:%d through the FortiGate." % (tries, time.time() - t0, self.src, self.dsts[0], self.base))
                if tries > 1:
                    self.warn("The path to the receiver was only reachable after %.0f s. The FortiGate may still be clearing sessions or its ARP entry from the previous test." % (time.time() - t0))
                return
            except OSError as e:
                last = e
                c.close()
                time.sleep(0.5)
        raise RuntimeError(
            "The sender (%s) cannot reach the receiver (%s port %d) through the FortiGate after %d attempts in %.0f s: %s. Nothing was sent.\n"
            "Check: (1) the FortiGate policy allows TCP and UDP %d-%d from %s to %s, (2) the receiver gateway %s is the FortiGate's IP on the receiver network, "
            "(3) the FortiGate is not low on memory after an earlier test: run 'diagnose hardware sysinfo conserve' (memory used + freeable must stay below the extreme threshold) and "
            "'diagnose sys session stat' (extreme_low_mem and memory_tension_drop mean new sessions are being dropped); wait until the memory recovers, or use a lower session target.\n"
            "Diagnostics: %s"
            % (self.src, self.dsts[0], self.base, tries, time.time() - t0, last, self.base, self.base + MAX_STREAMS - 1, self.src, self.dsts[0],
               (self.p["rx"].get("gateway") or "-"), self.diagnostics()))

    def diagnostics(self):
        out = []
        try:
            r = run(["ip", "route", "get", self.dsts[0], "from", self.src], check=False)
            out.append("sender route: " + (r.stdout.strip().splitlines() or [r.stderr.strip()])[0][:140])
            gw = self.p.get("tx_gw")
            if gw:
                ok = run(["ping", "-c", "1", "-W", "1", "-I", self.src, gw], check=False).returncode == 0
                out.append("sender->its gateway %s: ping %s" % (gw, "ok" if ok else "no reply"))
            if self.net and self.net.pid:
                ping, arp = self.net.gateway_probe()
                out.append("receiver->gateway %s: ping %s, ARP %s" % (self.p["rx"].get("gateway"), "ok" if ping else "no reply", "ok" if arp else "no reply"))
                nb = run(["nsenter", "-t", str(self.net.pid), "-n", "ip", "-br", "neigh"], check=False).stdout.strip().replace("\n", "; ")
                lk = run(["nsenter", "-t", str(self.net.pid), "-n", "ip", "-br", "link", "show", RX_DEV], check=False).stdout.strip()
                out.append("receiver link: %s; neighbours: %s" % (lk[:90], nb[:200] or "none"))
        except Exception as e:  # noqa
            out.append("(diagnostics failed: %s)" % e)
        return " | ".join(out)


def _drain(a):
    """Read all pending messages; second value is True when the other end is gone."""
    out = []
    try:
        while a.poll():
            out.append(a.recv())
    except (EOFError, OSError):
        return out, True
    return out, False


def merge_ps(lists, idx):
    return sum(l[idx] for l in lists if idx < len(l))


def udp_trial(ctx, payload, pps, dur, streams, series=None):
    """One UDP trial: returns a result dict."""
    payload = max(payload, HDR_LEN)
    want = max(1, min(streams, MAX_STREAMS))
    streams = min(want, STREAM_CAP)
    if streams < want:
        ctx.warn("Streams reduced from %d to %d: this LXC has %d CPU core(s) and each stream needs a sender and a receiver process. "
                 "Give the LXC more cores for higher rates." % (want, streams, CPUS))
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
        while not live and len(out) > 1 and out[-1][1] == 0:
            out.pop()
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
                msgs, eof = _drain(a)
                for m in msgs:
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
                if eof and done[i] is None:
                    err = "sender process stopped unexpectedly"
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


def _tcp_tx(conn, src, dst, ports, nconn, dur, first):
    """One process drives `nconn` TCP connections (threads; sendall releases the GIL)."""
    _worker_init()
    lock, stop = threading.Lock(), threading.Event()
    st = {"bytes": 0, "opened": 0, "errors": 0, "msg": ""}
    t0 = time.monotonic()
    end = t0 + dur

    def one(i):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind((src, 0))
            s.settimeout(5)
            s.connect((dst, ports[(first + i) % len(ports)]))
            s.settimeout(2)
        except OSError as e:
            with lock:
                st["errors"] += 1
                st["msg"] = str(e)
            return
        with lock:
            st["opened"] += 1
        chunk = b"\x5a" * (128 * 1024)
        while time.monotonic() < end and not stop.is_set():
            try:
                s.sendall(chunk)
            except OSError as e:
                with lock:
                    st["errors"] += 1
                    st["msg"] = str(e)
                break
            with lock:
                st["bytes"] += len(chunk)
        s.close()

    ths = [threading.Thread(target=one, args=(i,), daemon=True) for i in range(nconn)]
    for t in ths:
        t.start()
    nxt = t0 + 1
    while any(t.is_alive() for t in ths):
        time.sleep(0.05)
        now = time.monotonic()
        if now >= nxt:
            with lock:
                conn.send(("tick", st["bytes"]))
            nxt += 1
        if conn.poll() and conn.recv() == "stop":
            stop.set()
    for t in ths:
        t.join(2)
    with lock:
        st["elapsed"] = time.monotonic() - t0
        conn.send(("done", dict(st)))


def tcp_trial(ctx, streams, dur, series=None):
    streams = max(1, min(streams, MAX_STREAMS * 4))
    nproc = min(streams, CPUS)
    _pr, rconn = ctx.tcp_rx()
    ctx.ask(rconn, ("arm", {"mode": "stream"}))
    ports = [ctx.base + i for i in range(MAX_STREAMS)]
    counts = [streams // nproc + (1 if i < streams % nproc else 0) for i in range(nproc)]
    pipes, procs, first = [], [], 0
    for n in counts:
        a, b = CTX.Pipe()
        pr = CTX.Process(target=_tcp_tx, args=(b, ctx.src, ctx.dst, ports, n, dur, first), daemon=True)
        pr.start()
        pipes.append(a)
        procs.append(pr)
        first += n
    hist = [[] for _ in range(nproc)]
    done = [None] * nproc

    def build(snap, live):
        out = []
        ps = (snap or {}).get("persec") or []
        kmax = min(len(h) for h in hist) if live else max(len(h) for h in hist)
        for k in range(kmax):
            if live and k >= len(ps) - 1:
                break
            tx = sum((h[k] - (h[k - 1] if k else 0)) for h in hist if k < len(h))
            rx = ps[k][1] if k < len(ps) else 0
            out.append([k + 1, round(tx * 8 / 1e6, 2), round(rx * 8 / 1e6, 2), 0.0])
        while not live and len(out) > 1 and out[-1][1] == 0:
            out.pop()
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
                msgs, eof = _drain(a)
                for m in msgs:
                    if m[0] == "tick":
                        hist[i].append(m[1])
                    elif m[0] == "done":
                        done[i] = m[1]
                        hist[i].append(m[1]["bytes"])
                if eof and done[i] is None:
                    done[i] = {"bytes": 0, "opened": 0, "errors": 1, "msg": "sender process stopped unexpectedly", "elapsed": 0}
            if series is not None:
                series[:] = build(ctx.ask(rconn, ("snap",)), True)
        time.sleep(0.3)
        fin = ctx.ask(rconn, ("collect",))
    finally:
        for pr in procs:
            if pr.is_alive():
                pr.terminate()
    if series is not None:
        series[:] = build(fin, False)
    opened = sum(d["opened"] for d in done)
    errs = sum(d["errors"] for d in done)
    if not opened:
        raise RuntimeError("no TCP connection could be opened: " + (next((d["msg"] for d in done if d["msg"]), "") or "unknown error"))
    tx = sum(d["bytes"] for d in done)
    el = max(d["elapsed"] for d in done) or dur
    rxs = [x[2] for x in (series or [])]
    return {"streams": streams, "processes": nproc, "opened": opened, "errors": errs,
            "error_msg": next((d["msg"] for d in done if d["msg"]), ""), "tx_bytes": tx, "rx_bytes": fin["bytes"],
            "duration": round(el, 1), "tx_mbps": round(tx * 8 / el / 1e6, 2), "rx_mbps": round(fin["bytes"] * 8 / el / 1e6, 2),
            "peak_mbps": round(max(rxs or [0]), 2), "resets": fin["resets"]}


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
                msgs, eof = _drain(a)
                for m in msgs:
                    if m[0] == "tick":
                        cum[i] = m[1:]
                    elif m[0] == "done":
                        done[i] = m[1]
                if eof and done[i] is None:
                    done[i] = {"counts": {}, "lat": []}
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


def conc_trial(ctx, p, series=None):
    srcs = p.get("tx_ips") or [ctx.src]
    dsts = ctx.dsts
    target, rate = int(p["target"]), float(p["rate"])
    hold, hb, failp = float(p["hold_s"]), float(p["heartbeat_s"]), float(p["fail_pct"])
    nw = max(1, min(CPUS, int(math.ceil(rate / 3000.0)), 8, target))
    _pr, rconn = ctx.tcp_rx()
    ctx.ask(rconn, ("arm", {"mode": "conc"}))
    ports = [ctx.base + i for i in range(MAX_STREAMS)]
    shares = [target // nw + (1 if i < target % nw else 0) for i in range(nw)]
    pipes, procs = [], []
    for i in range(nw):
        a, b = CTX.Pipe()
        # every worker walks the full address/port space, offset so that workers do not collide on the same combinations
        pr = CTX.Process(target=_conc_tx, args=(b, srcs[i % len(srcs):] + srcs[:i % len(srcs)], dsts, ports, rate / nw, shares[i], hold, hb, failp, 3.0), daemon=True)
        pr.start()
        pipes.append(a)
        procs.append(pr)
    cum = [(0, 0, 0, 0, 0, 1)] * nw
    done = [None] * nw
    sec_i, rx_peak = 0, 0
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
                msgs, eof = _drain(a)
                for m in msgs:
                    if m[0] == "tick":
                        cum[i] = m[1:]
                    elif m[0] == "done":
                        done[i] = m[1]
                if eof and done[i] is None:
                    done[i] = {"counts": {}, "lat": [], "peak": 0, "final": 0, "reason": "error", "first_fail_alive": None, "ramp_s": 0}
            alive = sum(x[3] for x in cum)
            ramping = any(x[5] for x in cum)
            snap = ctx.ask(rconn, ("snap",)) or {}
            rx_open = snap.get("active", 0)
            rx_peak = max(rx_peak, rx_open)
            sec_i += 1
            ctx.progress["phase"] = ("ramping up: %s of %s sessions open" if ramping else "holding: %s of %s sessions open") % (n_fmt(alive), n_fmt(target))
            if series is not None and any(d is None for d in done):
                series.append([sec_i, alive, rx_open, sum(x[2] for x in cum)])
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
    peak = sum(d["peak"] for d in done)
    final = sum(d["final"] for d in done)
    reasons = {d["reason"] for d in done}
    ff = [d["first_fail_alive"] for d in done if d["first_fail_alive"] is not None]
    dropped = tot["dropped"]
    reason = "target reached" if reasons <= {"target"} else ("failures began" if "failures" in reasons else "stopped" if "stopped" in reasons else "error")
    return {"target": target, "peak_sessions": peak, "final_sessions": final, "rx_peak": max(rx_peak, fin.get("max_active", 0)),
            "attempted": tot["att"], "established": tot["est"], "failed": tot["fail"], "dropped": dropped,
            "fail_pct": round(tot["fail"] * 100.0 / tot["att"], 3) if tot["att"] else 0.0,
            "timeout": tot["timeout"], "refused": tot["refused"], "reset": tot["reset"], "error": tot["error"],
            "reason": reason, "limit_at": sum(ff) if ff else None, "ramp_s": max(d["ramp_s"] for d in done),
            "lat_p50_ms": round(pct(lat, 50) * 1000, 3), "lat_p95_ms": round(pct(lat, 95) * 1000, 3), "lat_max_ms": round(max(lat or [0]) * 1000, 3),
            "workers": nw, "src_ips": len(srcs), "dst_ips": len(dsts), "hold_s": hold, "heartbeat_s": hb,
            "ok": reason == "target reached" and dropped == 0 and peak >= 0.99 * target}


def n_fmt(v):
    return "{:,}".format(int(v))


# ------------------------------------------------------------ RFC 2544
def line_pps(size, link_mbps):
    return link_mbps * 1e6 / (8.0 * (size + 20))


def streams_for(pps):
    return max(1, min(STREAM_CAP, int(math.ceil(pps / 50000.0))))


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


# ------------------------------------------------------------ warnings / monitoring
def plan_warnings(kind, p):
    """Warnings shown before a test starts: things that will limit the result or load the LXC."""
    w = []
    cores = "%d CPU core%s" % (CPUS, "" if CPUS == 1 else "s")
    if kind == "udp":
        pps = float(p["rate_mbps"]) * 1e6 / ((int(p["payload"]) + 28) * 8)
        need = int(math.ceil(pps / 50000.0))
        if need > STREAM_CAP:
            w.append("%.0f Mbit/s with %d-byte packets is about %d packets/s and needs roughly %d stream(s); this LXC has %s and allows %d. "
                     "The sender will probably not reach the target rate (the result is then marked 'limited by sender'). Add CPU cores to the LXC or lower the rate."
                     % (p["rate_mbps"], p["payload"], pps, need, cores, STREAM_CAP))
        elif CPUS <= 2 and p["rate_mbps"] > 300:
            w.append("At %.0f Mbit/s the sender and receiver processes keep this LXC (%s) very busy; the GUI may react more slowly. 4 cores are recommended above 300 Mbit/s." % (p["rate_mbps"], cores))
    elif kind == "tcp":
        if CPUS <= 2:
            w.append("TCP throughput is CPU-bound: this LXC has %s, so expect roughly 1 Gbit/s at best and a busy CPU. 4 cores are recommended." % cores)
    elif kind == "cps":
        top = float(p["rate"]) + (float(p["step"]) * (int(p["steps"]) - 1) if p.get("ramp") else 0)
        workers = min(int(math.ceil(top / 3000.0)), CPUS, 8)
        if top > workers * 4000:
            w.append("%.0f connections/s needs more than the %d worker process(es) this LXC (%s) allows (about 4000 conn/s each). The result will be marked 'limited by sender'." % (top, workers, cores))
        conc = top * int(p["hold_ms"]) / 1000.0
        if conc > 20000:
            w.append("About %d connections will be open at the same time. This can fill the FortiGate session table and affects other users of that firewall." % conc)
        avail = mem_available_mb()
        est = conc * 6 / 1024.0          # rough: both ends of a connection, in this LXC
        if avail and est > 0.5 * avail:
            w.append("Holding about %d connections open needs roughly %d MB of memory (both ends run in this LXC) and only %d MB is available. "
                     "Give the LXC more memory or lower the rate or hold time." % (conc, est, avail))
    elif kind == "concurrent":
        target = int(p["target"])
        src_n = len(p.get("tx_ips") or [1])
        dst_n = int((p.get("rx") or {}).get("count") or 1)
        cap = tuple_capacity(src_n, dst_n)
        if target > 50000 and (src_n < 2 or dst_n < 2):
            w.append("More than 50,000 concurrent sessions with %d source IP%s and %d receiver IP%s: all sessions share very few address pairs. This can run out of source ports "
                     "(about %d per source IP, destination IP and port) and concentrates the load on a few flows, which is not how a real network looks. "
                     "Use 2 or more source IPs ('Source IPs to use') and 2 or more receiver IPs ('Number of receiver IPs' on the Path card)."
                     % (src_n, "" if src_n == 1 else "s", dst_n, "" if dst_n == 1 else "s", port_range()[1] - port_range()[0] + 1))
        elif target > 0.5 * cap:
            w.append("The target is more than half of the roughly %s sessions that the address and port space allows (%d source IP(s) x %d receiver IP(s) x %d ports). Add source or receiver IPs for headroom." % (n_fmt(cap), src_n, dst_n, MAX_STREAMS))
        if target > 20000:
            w.append("%s sessions held open can fill the FortiGate session table and memory (conserve mode, 'extreme low memory') and affect everyone behind that firewall. "
                     "A small FortiGate VM (for example 2 GB RAM) may already be short of memory at a few tens of thousands of sessions: start lower and watch "
                     "'diagnose hardware sysinfo conserve' and 'diagnose sys session stat'. Only run this on a firewall you may load like this." % n_fmt(target))
        avail = mem_available_mb()
        est = target * 6 / 1024.0
        if avail and est > 0.5 * avail:
            w.append("Holding %s sessions needs roughly %d MB of memory (both ends run in this LXC) and only %d MB is available. Give the LXC more memory or lower the target." % (n_fmt(target), est, avail))
        mins = target / float(max(p["rate"], 1)) / 60.0
        if mins > 10:
            w.append("Ramping up to %s sessions at %s per second takes about %d minutes. Increase the open rate for a shorter test." % (n_fmt(target), n_fmt(p["rate"]), mins))
        if CPUS <= 2 and p["rate"] > 3000:
            w.append("An open rate above 3,000 per second keeps this LXC (%d CPU cores) very busy." % CPUS)
    elif kind == "rfc2544":
        small = [x for x in p["sizes"] if x < 256]
        if small and float(p["link_mbps"]) >= 500:
            w.append("Frames below 256 bytes at %.0f Mbit/s need hundreds of thousands to over a million packets per second, which this Python tester cannot generate on %s. "
                     "Those rows will be marked 'limited by sender' and do not show the FortiGate's limit." % (p["link_mbps"], cores))
        trials = len(p["sizes"]) * (8 + (6 if p.get("frame_loss") else 0))
        mins = trials * float(p["trial_s"]) / 60.0
        if mins > 20:
            w.append("This RFC 2544 run can take about %d minutes (%d sizes x ~%d trials x %gs). Use fewer sizes or a shorter trial length for a quick test." % (mins, len(p["sizes"]), trials // len(p["sizes"]), p["trial_s"]))
        if CPUS <= 2 and float(p["link_mbps"]) > 300:
            w.append("%s cores: the LXC will be very busy during this test and the GUI may react more slowly." % CPUS)
    return w


def mem_available_mb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) / 1024.0
    except (OSError, ValueError):
        pass
    return None


def _cpu_stat():
    try:
        with open("/proc/stat") as f:
            v = [int(x) for x in f.readline().split()[1:]]
        return sum(v), v[3] + (v[4] if len(v) > 4 else 0)
    except (OSError, ValueError, IndexError):
        return None


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
                "stopped": False, "mode": None, "warnings": [], "cpu": None, "cpu_peak": None, "cores": CPUS}

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
        s["warnings"] = list(s["warnings"])
        return s

    def stop(self):
        self.stop_evt.set()

    def start(self, kind, p, logdir=None):
        with self.lock:
            if self.running:
                raise ValueError("A throughput test is already running.")
            self.stop_evt = threading.Event()
            self.st = self._blank()
            self.st.update({"running": True, "kind": kind, "params": p, "started": time.time(), "mode": p["rx"].get("mode"),
                            "warnings": plan_warnings(kind, p)})
            self.thread = threading.Thread(target=self._run, args=(kind, p, logdir), daemon=True)
            self.thread.start()

    def _monitor(self, st, done):
        """Sample LXC CPU use once a second; warn when it stays saturated."""
        prev, hot = _cpu_stat(), 0
        while prev and not done.wait(1.0):
            cur = _cpu_stat()
            if not cur or cur[0] <= prev[0]:
                continue
            pc = 100.0 * (1 - (cur[1] - prev[1]) / float(cur[0] - prev[0]))
            prev = cur
            st["cpu"] = round(pc)
            st["cpu_peak"] = max(st["cpu_peak"] or 0, round(pc))
            hot = hot + 1 if pc >= 92 else 0
            if hot == 3 and "CPU saturated" not in " ".join(st["warnings"]):
                st["warnings"].append("CPU saturated (%d%%): the result may be limited by this LXC instead of the network. "
                                      "Lower the rate or streams, or give the LXC more CPU cores." % pc)

    def _run(self, kind, p, logdir):
        st = self.st
        ctx = Ctx(p, self.stop_evt, st)
        mon_done = threading.Event()
        threading.Thread(target=self._monitor, args=(st, mon_done), daemon=True).start()
        try:
            st["phase"] = "preparing receiver"
            ctx.up()
            if kind in ("tcp", "cps", "concurrent"):
                st["phase"] = "checking the path"
                ctx.path_check()
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
            elif kind == "concurrent":
                st["phase"], st["steps"] = "concurrent sessions", 1
                st["result"] = conc_trial(ctx, p, st["series"])
            elif kind == "rfc2544":
                st["result"] = rfc2544(ctx, p, st)
        except Stopped:
            st["stopped"] = True
        except Exception as e:  # noqa
            st["error"] = str(e)
        finally:
            mon_done.set()
            ctx.down()
            st["finished"], st["running"] = time.time(), False
            if logdir and (st["result"] or st["rows"]):
                try:
                    os.makedirs(logdir, exist_ok=True)
                    with open(os.path.join(logdir, "throughput.jsonl"), "a") as f:
                        f.write(json.dumps({k: st[k] for k in ("kind", "params", "started", "finished", "result", "rows", "rows2", "stopped", "warnings", "cpu_peak", "cores")}) + "\n")
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
        car = net.carrier()
        if car is not None:
            add("link on %s" % rx.get("parent"), car, "" if car else
                "No carrier. Check in Proxmox that the NIC is connected to the right bridge (and VLAN tag) and that the FortiGate port is up.")
        ping, arp = net.gateway_probe()
        gw = rx.get("gateway")
        if ping:
            add("receiver can reach gateway %s" % gw, True, "")
        elif arp:
            add("receiver can reach gateway %s" % gw, True,
                "The gateway answers ARP, so the link works, but it does not answer ping. Enable PING under Administrative Access on that FortiGate interface if you want ping to work; the tests themselves do not need it.")
        elif ping is not None:
            add("receiver can reach gateway %s" % gw, False,
                "No ping and no ARP reply, so frames do not reach the gateway. Check: (1) the FortiGate has IP %s on the interface or VLAN interface connected to this NIC, (2) the bridge and VLAN tag of this NIC in Proxmox, "
                "(3) the Proxmox firewall is off on this NIC (firewall=0), (4) the receiver IP %s/%s is in the same network as the gateway." % (gw, rx.get("ip"), rx.get("prefix")))
    except Exception as e:  # noqa
        add("receiver namespace", False, str(e))
    finally:
        net.down()
    return out
