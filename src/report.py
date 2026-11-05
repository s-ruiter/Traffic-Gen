#!/usr/bin/env python3
"""PDF reports for Traffic-Gen results (stdlib only: a small PDF writer plus report layouts)."""
import time
import zlib

# Helvetica / Helvetica-Bold advance widths (1/1000 em) for ASCII 32..126
_REG = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
        556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
        1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
        667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
        333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
        556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
         556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
         975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
         333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
         611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584]
_SUBST = {"≤": "<=", "≥": ">=", "→": "->", "⚠": "!", "✔": "OK", "✘": "X", "−": "-", "×": "x", "…": "...", "→": "->"}

INK = (0.06, 0.06, 0.07)
MUTED = (0.42, 0.43, 0.46)
LINE = (0.89, 0.89, 0.9)
BRAND = (0.855, 0.16, 0.11)
GREEN = (0.09, 0.64, 0.29)
AMBER = (0.85, 0.47, 0.02)


def _clean(s):
    s = str(s)
    for a, b in _SUBST.items():
        s = s.replace(a, b)
    return s.encode("cp1252", "replace").decode("latin-1")


def _esc(s):
    return _clean(s).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


class Pdf:
    W, H, M = 595.28, 841.89, 42.0

    def __init__(self, title, footer):
        self.title, self.footer = title, footer
        self.pages, self.ops, self.y = [], None, 0
        self.new_page()

    # ---- primitives
    def new_page(self):
        self.ops = []
        self.pages.append(self.ops)
        self.y = self.H - self.M

    @staticmethod
    def _c(c):
        return "%.3f %.3f %.3f" % c

    def width(self, s, size=9, bold=False):
        tab = _BOLD if bold else _REG
        return sum(tab[ord(ch) - 32] if 32 <= ord(ch) < 127 else 556 for ch in _clean(s)) * size / 1000.0

    def text(self, x, y, s, size=9, bold=False, color=INK, align="l"):
        w = self.width(s, size, bold)
        if align == "r":
            x -= w
        elif align == "c":
            x -= w / 2
        self.ops.append("BT /%s %.1f Tf %s rg %.2f %.2f Td (%s) Tj ET" % ("F2" if bold else "F1", size, self._c(color), x, y, _esc(s)))

    def line(self, x1, y1, x2, y2, w=0.5, color=LINE):
        self.ops.append("%s RG %.2f w %.2f %.2f m %.2f %.2f l S" % (self._c(color), w, x1, y1, x2, y2))

    def rect(self, x, y, w, h, fill=None, stroke=None, sw=0.5):
        op = "%.2f %.2f %.2f %.2f re " % (x, y, w, h)
        if fill:
            self.ops.append("%s rg %s f" % (self._c(fill), op))
        if stroke:
            self.ops.append("%s RG %.2f w %sS" % (self._c(stroke), sw, op))

    def poly(self, pts, color, w=1.2):
        if len(pts) < 2:
            return
        d = "%.2f %.2f m " % pts[0] + " ".join("%.2f %.2f l" % p for p in pts[1:])
        self.ops.append("%s RG %.2f w %s S" % (self._c(color), w, d))

    # ---- layout
    def need(self, h):
        if self.y - h < self.M + 24:
            self.new_page()

    def header(self, title, sub):
        self.rect(self.M, self.y - 4, 22, 22, fill=BRAND)
        self.poly([(self.M + 4, self.y + 7), (self.M + 8.5, self.y + 7), (self.M + 11, self.y + 14.5), (self.M + 14, self.y - 0.5), (self.M + 16.5, self.y + 7), (self.M + 18.5, self.y + 7)], (1, 1, 1), 1.6)
        self.text(self.M + 30, self.y + 8, "Traffic-Gen", 11, True)
        self.text(self.W - self.M, self.y + 8, sub, 8, False, MUTED, "r")
        self.y -= 34
        self.text(self.M, self.y, title, 19, True)
        self.y -= 10
        self.line(self.M, self.y, self.W - self.M, self.y, 1.2, BRAND)
        self.y -= 18

    def h2(self, s, keep=0):
        self.need(48 + keep)
        self.y -= 14
        self.text(self.M, self.y, s.upper(), 8, True, MUTED)
        self.y -= 6

    def para(self, s, size=9, color=INK, indent=0.0, bold=False):
        maxw = self.W - 2 * self.M - indent
        for raw in str(s).split("\n"):
            words, cur = raw.split(" "), ""
            lines = []
            for w in words:
                t = (cur + " " + w).strip()
                if self.width(t, size, bold) <= maxw or not cur:
                    cur = t
                else:
                    lines.append(cur)
                    cur = w
            lines.append(cur)
            for ln in lines:
                self.need(size * 1.5)
                self.y -= size * 1.35
                self.text(self.M + indent, self.y, ln, size, bold, color)
        self.y -= 3

    def kv(self, pairs, cols=3):
        cw = (self.W - 2 * self.M) / cols
        for i in range(0, len(pairs), cols):
            self.need(34)
            for j, (k, v, col) in enumerate((p + (INK,))[:3] if len(p) == 2 else p for p in pairs[i:i + cols]):
                x = self.M + j * cw
                self.text(x, self.y - 8, str(k).upper(), 6.5, True, MUTED)
                self.text(x, self.y - 22, str(v), 11, True, col)
            self.y -= 34
        self.y -= 4

    def table(self, headers, rows, widths, aligns=None, size=7.5, colors=None):
        tot = float(sum(widths))
        ws = [(self.W - 2 * self.M) * w / tot for w in widths]
        aligns = aligns or ["l"] * len(headers)

        def draw_head():
            self.need(30)
            self.y -= 12
            x = self.M
            for h, w, a in zip(headers, ws, aligns):
                self.text(x + (w - 4 if a == "r" else 0), self.y, h.upper(), 6.3, True, MUTED, "r" if a == "r" else "l")
                x += w
            self.y -= 5
            self.line(self.M, self.y, self.W - self.M, self.y, 0.7)

        draw_head()
        for ri, r in enumerate(rows):
            if self.y - 16 < self.M + 24:
                self.new_page()
                draw_head()
            self.y -= 12
            x = self.M
            for ci, (c, w, a) in enumerate(zip(r, ws, aligns)):
                s = str(c)
                while self.width(s, size) > w - 6 and len(s) > 2:
                    s = s[:-2] + "..."
                col = (colors[ri][ci] if colors and colors[ri] and colors[ri][ci] else INK)
                self.text(x + (w - 4 if a == "r" else 0), self.y, s, size, False, col, "r" if a == "r" else "l")
                x += w
            self.y -= 4
            self.line(self.M, self.y, self.W - self.M, self.y, 0.3)
        self.y -= 6

    def chart(self, series, l1, l2, unit, h=120, dual=False):
        """series: list of [t, a, b, ...]; a is red, b is black. dual = each series has its own scale
        (left axis for a, right axis for b), otherwise both share one axis in `unit`."""
        if len(series) < 2:
            return
        self.need(h + 40)
        x0, x1 = self.M + 44, self.W - self.M - (44 if dual else 0)
        top, bot = self.y - 6, self.y - 6 - h
        A, B = [s[1] for s in series], [s[2] for s in series]
        ma = max(max(A), 1e-9) * 1.1
        mb = max(max(B), 1e-9) * 1.1 if dual else ma
        if not dual:
            ma = mb = max(ma, max(max(B), 1e-9) * 1.1)
        fmt = lambda v: ("%.0f" if v >= 10 else "%.1f") % v  # noqa: E731
        for i in range(5):
            yy = top - (top - bot) * i / 4.0
            self.line(x0, yy, x1, yy, 0.3)
            self.text(x0 - 4, yy - 2.5, fmt(ma * (1 - i / 4.0)), 6.5, False, BRAND if dual else MUTED, "r")
            if dual:
                self.text(x1 + 4, yy - 2.5, fmt(mb * (1 - i / 4.0)), 6.5, False, INK)

        def pts(d, m):
            n = len(d) - 1
            return [(x0 + (x1 - x0) * i / n, bot + (top - bot) * v / m) for i, v in enumerate(d)]

        self.poly(pts(A, ma), BRAND, 1.4)
        self.poly(pts(B, mb), INK, 1.0)
        self.text(x0, bot - 11, "0 s", 6.5, False, MUTED)
        self.text(x1, bot - 11, "%d s" % len(series), 6.5, False, MUTED, "r")
        lab1 = "%s (%s)" % (l1, unit) if unit else l1
        self.rect(self.M, bot - 24, 8, 3, fill=BRAND)
        self.text(self.M + 12, bot - 25, lab1 + (" - left axis" if dual else ""), 7, False, MUTED)
        lx = self.M + 24 + self.width(lab1 + (" - left axis" if dual else ""), 7)
        self.rect(lx, bot - 24, 8, 3, fill=INK)
        self.text(lx + 12, bot - 25, l2 + (" - right axis" if dual else ""), 7, False, MUTED)
        self.y = bot - 34

    def render(self):
        n = len(self.pages)
        objs = []

        def add(b):
            objs.append(b if isinstance(b, bytes) else b.encode("latin-1"))
            return len(objs)

        add("<< /Type /Catalog /Pages 2 0 R >>")
        add(b"")                                               # pages (filled below)
        add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        kids = []
        for i, ops in enumerate(self.pages):
            page_ops = list(ops)
            self.ops = page_ops
            self.line(self.M, self.M - 6, self.W - self.M, self.M - 6, 0.4)
            self.text(self.M, self.M - 18, self.footer, 7, False, MUTED)
            self.text(self.W - self.M, self.M - 18, "Page %d of %d" % (i + 1, n), 7, False, MUTED, "r")
            data = zlib.compress("\n".join(page_ops).encode("latin-1"))
            c = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(data) + data + b"\nendstream")
            p = add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>" % (self.W, self.H, c))
            kids.append("%d 0 R" % p)
        objs[1] = ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join(kids), n)).encode("latin-1")
        info = add("<< /Title (%s) /Producer (Traffic-Gen) >>" % _esc(self.title))
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offs = []
        for i, o in enumerate(objs):
            offs.append(len(out))
            out += b"%d 0 obj\n" % (i + 1) + o + b"\nendobj\n"
        xr = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for o in offs:
            out += b"%010d 00000 n \n" % o
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, info, xr)
        return bytes(out)


# ---------------------------------------------------------------- helpers
def ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "-"


def dur(sec):
    sec = int(max(0, sec or 0))
    return "%d:%02d:%02d" % (sec // 3600, sec % 3600 // 60, sec % 60) if sec >= 3600 else "%d:%02d" % (sec // 60, sec % 60)


def f(v, d=2):
    return "-" if v is None else ("%." + str(d) + "f") % v


def n(v):
    return "-" if v is None else "{:,}".format(int(v)).replace(",", " ")


KIND = {"udp": "UDP stream", "tcp": "TCP throughput", "rfc2544": "RFC 2544", "cps": "Connections per second"}
PLABEL = {"payload": "Payload (bytes)", "rate_mbps": "Rate (Mbit/s)", "streams": "Streams", "duration": "Duration (s)", "sizes": "Frame sizes (bytes)",
          "link_mbps": "Link rate (Mbit/s)", "trial_s": "Trial length (s)", "loss_tol": "Loss tolerance (%)", "resolution": "Resolution (% of link)",
          "frame_loss": "Frame loss test", "rate": "Connections/s", "ramp": "Ramp up", "step": "Step (+conn/s)", "steps": "Steps", "req": "Request (bytes)",
          "resp": "Response (bytes)", "hold_ms": "Hold open (ms)", "close": "Close", "max_fail_pct": "Pass if failures <= (%)"}


# ---------------------------------------------------------------- Throughput report
def tp_report(st, version):
    kind = st.get("kind") or ""
    p = st.get("params") or {}
    rx = p.get("rx") or {}
    r = st.get("result") or {}
    pdf = Pdf("Throughput report - " + KIND.get(kind, kind), "Traffic-Gen %s - Throughput report" % version)
    pdf.header("Throughput report", ts(st.get("finished") or st.get("now")))
    state = "Stopped by user" if st.get("stopped") else ("Failed" if st.get("error") else "Finished")
    pdf.kv([("Test", KIND.get(kind, kind)), ("Status", state, RED_IF(st.get("error"))),
            ("Duration", dur((st.get("finished") or st.get("now") or 0) - (st.get("started") or 0))),
            ("Started", ts(st.get("started"))), ("Finished", ts(st.get("finished"))),
            ("Mode", "Self-test (loopback)" if rx.get("mode") == "loopback" else "Isolated (via FortiGate)")])
    if rx.get("mode") != "loopback":
        pdf.kv([("Sender IP", p.get("tx_ip") or "-"), ("Receiver IP", "%s/%s" % (rx.get("ip"), rx.get("prefix"))),
                ("Receiver gateway", rx.get("gateway") or "-"), ("Receiver interface", rx.get("parent") or "-"),
                ("Ports (UDP/TCP)", "%s-%s" % (p.get("base_port"), (p.get("base_port") or 0) + 7)),
                ("LXC CPU", "%s cores, peak %s%%" % (st.get("cores"), st.get("cpu_peak")) if st.get("cpu_peak") is not None else "%s cores" % st.get("cores"))])
    if st.get("error"):
        pdf.h2("Error")
        pdf.para(st["error"], 9, BRAND)
    if rx.get("mode") == "loopback":
        pdf.para("Self-test: this traffic stayed inside the LXC (127.0.0.1) and did not cross the FortiGate. The numbers show what the LXC can generate, not the performance of the network or firewall.", 8.5, AMBER)
    if st.get("warnings"):
        pdf.h2("Warnings")
        for w in st["warnings"]:
            pdf.para("! " + w, 8.5, AMBER)
    pars = [(PLABEL[k], ", ".join(str(x) for x in v) if isinstance(v, list) else ("yes" if v is True else "no" if v is False else v))
            for k, v in p.items() if k in PLABEL]
    if pars:
        pdf.h2("Test parameters")
        pdf.kv([(a, b) for a, b in pars], 4)
    if kind == "udp" and r:
        pdf.h2("Result")
        pdf.kv([("Packet loss", f(r.get("loss_pct"), 3) + " %", GREEN if (r.get("loss_pct") or 0) <= 0.1 else BRAND), ("Sent", n(r.get("sent")) + " pkts"),
                ("Received", n(r.get("received")) + " pkts"), ("Lost", n(r.get("lost")) + " pkts"), ("Sent rate", f(r.get("tx_mbps")) + " Mbit/s"),
                ("Received rate", f(r.get("rx_mbps")) + " Mbit/s"), ("Jitter", f(r.get("jitter_ms"), 3) + " ms"),
                ("Latency min / avg / max", "%s / %s / %s ms" % (f(r.get("lat_min_ms")), f(r.get("lat_avg_ms")), f(r.get("lat_max_ms")))),
                ("Reordered / duplicates", "%s / %s" % (r.get("reorder"), r.get("dup"))), ("Streams", r.get("streams")),
                ("Packets/s sent", n(r.get("pps_sent"))), ("Sender limit reached", "yes" if r.get("limited") else "no", AMBER if r.get("limited") else INK)], 3)
    elif kind == "tcp" and r:
        pdf.h2("Result")
        pdf.kv([("Throughput", f(r.get("rx_mbps")) + " Mbit/s"), ("Peak (1 s)", f(r.get("peak_mbps")) + " Mbit/s"), ("Data received", "%.1f MB" % ((r.get("rx_bytes") or 0) / 1e6)),
                ("Streams opened", "%s / %s" % (r.get("opened"), r.get("streams"))), ("Errors", r.get("errors")), ("Resets", r.get("resets"))], 3)
    elif kind == "rfc2544":
        pdf.h2("Throughput and latency (RFC 2544)")
        rows, cols = [], []
        for x in st.get("rows") or []:
            note = "limited by sender" if x.get("limited") else ("no loss-free rate" if not x.get("tp_pct") else "")
            rows.append([x["size"], n(x["line_pps"]), n(x["tp_pps"]), f(x["tp_pct"], 1), f(x["tp_mbps"], 1), f(x["loss_pct"], 3),
                         "%s / %s / %s" % (f(x["lat_min_ms"]), f(x["lat_avg_ms"]), f(x["lat_max_ms"])), f(x["jitter_ms"], 3), note])
            cols.append([None] * 8 + [AMBER if x.get("limited") else None])
        pdf.table(["Frame B", "Line pps", "Tput pps", "% link", "Mbit/s", "Loss %", "Latency min/avg/max ms", "Jitter ms", "Note"], rows,
                  [7, 9, 9, 6, 7, 6, 17, 8, 12], ["r"] * 8 + ["l"], 7, cols)
        if st.get("rows2"):
            pdf.h2("Frame loss rate (RFC 2544)")
            pdf.table(["Frame (B)", "Offered % of link", "Offered pps", "Received Mbit/s", "Loss %", "Note"],
                      [[x["size"], x["pct"], n(x["offered_pps"]), f(x["rx_mbps"], 1), f(x["loss_pct"], 3), "sender limited" if x.get("limited") else ""] for x in st["rows2"]],
                      [8, 12, 12, 12, 10, 14], ["r"] * 5 + ["l"], 7.5)
    elif kind == "cps":
        pdf.h2("Connections per second")
        pdf.kv([("Highest sustained", n(r.get("max_ok_cps")) + " conn/s", GREEN if r.get("max_ok_cps") else BRAND)], 3)
        rows, cols = [], []
        for x in st.get("rows") or []:
            ok = "OK" if x.get("ok") else ("sender limited" if x.get("limited") else "failing")
            rows.append([n(x["target_cps"]), "%s / %s" % (n(x["established"]), n(x["attempted"])), f(x["fail_pct"], 2), f(x["avg_cps"], 0), x["peak_cps"],
                         "%s / %s / %s" % (f(x["lat_p50_ms"]), f(x["lat_p95_ms"]), f(x["lat_max_ms"])), n(x["rx_accepted"]), x["max_active"], ok])
            cols.append([None] * 8 + [GREEN if x.get("ok") else (AMBER if x.get("limited") else BRAND)])
        pdf.table(["Target/s", "Est. / attempted", "Failed %", "Avg/s", "Peak/s", "Connect p50/p95/max ms", "Rx accepted", "Max open", "Result"], rows,
                  [7, 14, 7, 6, 6, 17, 9, 7, 9], ["r"] * 8 + ["l"], 7, cols)
    series = st.get("series") or []
    if series:
        pdf.h2("Connections per second (last step)" if kind == "cps" else "Throughput over time" + (" (last trial)" if kind == "rfc2544" else ""), keep=170)
        pdf.chart(series, "attempted" if kind == "cps" else "sent", "established" if kind == "cps" else "received", "conn/s" if kind == "cps" else "Mbit/s")
    if st.get("log"):
        pdf.h2("Progress log")
        for ln in st["log"][-30:]:
            pdf.para(ln, 7.5, MUTED)
    return pdf.render()


def RED_IF(err):
    return BRAND if err else GREEN


# ---------------------------------------------------------------- Traffic test report
def traffic_report(st, version):
    t = st.get("totals") or {}
    tr, ok = t.get("requests", 0), t.get("ok", 0)
    pdf = Pdf("Traffic test report", "Traffic-Gen %s - Traffic test report" % version)
    pdf.header("Traffic test report", ts(st.get("finished") or st.get("now")))
    end = st.get("finished") or st.get("now") or 0
    pdf.kv([("Status", "Running" if st.get("running") else "Finished"), ("Duration", dur(end - (st.get("started") or 0))), ("Intensity", st.get("intensity")),
            ("Started", ts(st.get("started"))), ("Finished", ts(st.get("finished"))), ("Source IPs x sessions", "%s x %s" % (st.get("sources"), st.get("threads_per_ip")))])
    pdf.h2("Result")
    kp = [("Requests", n(tr)), ("Succeeded", ("%d %%" % round(ok / tr * 100)) if tr else "-", GREEN), ("Blocked", n(t.get("blocked", 0)), AMBER if t.get("blocked") else INK),
          ("Errors", n(t.get("error", 0)), BRAND if t.get("error") else INK), ("Data", "%.1f MB" % ((t.get("bytes") or 0) / 1e6))]
    exb, exm = t.get("ex_blocked", 0), t.get("ex_missed", 0)
    if exb + exm:
        kp += [("Malware detection rate", "%d %%" % round(exb / float(exb + exm) * 100), BRAND if exm else GREEN), ("Missed (let through)", n(exm), BRAND if exm else INK)]
    pdf.kv(kp, 3)
    series = st.get("series") or []
    if len(series) > 2:
        pts = []
        for i in range(1, len(series)):
            dt = (series[i][0] - series[i - 1][0]) or 2
            pts.append([i, (series[i][2] - series[i - 1][2]) * 8 / dt / 1e6, (series[i][1] - series[i - 1][1]) / dt])
        pdf.h2("Throughput and requests over time", keep=170)
        pdf.chart(pts, "Mbit/s", "requests/s", "", dual=True)
    apps = sorted((st.get("apps") or {}).items(), key=lambda kv: -kv[1].get("requests", 0))
    if apps:
        pdf.h2("Per application")
        pdf.table(["Application", "Requests", "OK", "Blocked", "Missed", "Errors", "Data MB"],
                  [[a, n(c.get("requests", 0)), n(c.get("ok", 0)), n(c.get("blocked", 0)), n(c.get("missed", 0)), n(c.get("error", 0)), "%.1f" % ((c.get("bytes") or 0) / 1e6)] for a, c in apps],
                  [18, 9, 9, 9, 9, 9, 9], ["l"] + ["r"] * 6, 7.5)
    srcs = sorted((st.get("src") or {}).items(), key=lambda kv: -kv[1].get("requests", 0))
    if srcs:
        pdf.h2("Per source IP" + (" (top 40 of %d)" % len(srcs) if len(srcs) > 40 else ""))
        pdf.table(["Source IP", "Requests", "OK", "Blocked", "Errors", "Data MB"],
                  [[a, n(c.get("requests", 0)), n(c.get("ok", 0)), n(c.get("blocked", 0)), n(c.get("error", 0)), "%.1f" % ((c.get("bytes") or 0) / 1e6)] for a, c in srcs[:40]],
                  [18, 10, 10, 10, 10, 10], ["l"] + ["r"] * 5, 7.5)
    pdf.para("Compare these numbers with the FortiGate logs (/var/log/trafficgen/requests.log holds one JSON line per request). A FortiGate block page or connection reset counts as blocked; a malware test file that is delivered counts as missed.", 8, MUTED)
    return pdf.render()
