"""Source-network management for the traffic LXC.

A *network* = optional VLAN sub-interface on a parent NIC + N consecutive IPv4
addresses + gateway. Each network gets its own routing table (source-based
policy routing) so test traffic leaves via its own gateway while the
management interface keeps the default route.
"""
import ipaddress
import json
import os
import re
import subprocess

STATE = os.environ.get("TRAFFICGEN_STATE", "/var/lib/trafficgen/net-state.json")
DEV_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", "%s: not found" % cmd[0])


def dev_of(n):
    return "%s.%d" % (n["parent"], n["vlan"]) if n.get("vlan") else n["parent"]


def ips_of(n):
    first = ipaddress.IPv4Address(n["first"])
    return [str(first + i) for i in range(int(n["count"]))]


def sources(cfg):
    out = []
    for n in cfg.get("networks", []):
        for ip in ips_of(n):
            out.append({"ip": ip, "dns": n.get("dns") or n["gateway"], "dev": dev_of(n), "net": n.get("name", "")})
    return out


# ------------------------------------------------------------ inspection
def interfaces():
    r = sh(["ip", "-j", "addr"])
    out = []
    try:
        data = json.loads(r.stdout)
    except ValueError:
        return out
    for i in data:
        if i["ifname"] == "lo":
            continue
        out.append({"name": i["ifname"].split("@")[0], "up": i.get("operstate") in ("UP", "UNKNOWN"),
                    "mac": i.get("address", ""),
                    "addrs": ["%s/%d" % (a["local"], a["prefixlen"]) for a in i.get("addr_info", []) if a["family"] == "inet"]})
    return out


def live_addrs():
    return {i["name"]: {a.split("/")[0] for a in i["addrs"]} for i in interfaces()}


def mgmt_network(mgmt):
    for i in interfaces():
        if i["name"] == mgmt and i["addrs"]:
            return ipaddress.ip_interface(i["addrs"][0]).network
    return None


# ------------------------------------------------------------ validation
def validate(networks, mgmt):
    """Return (normalised list, errors)."""
    errs, out, nets = [], [], []
    existing = {i["name"] for i in interfaces()}
    mnet = mgmt_network(mgmt)
    if len(networks) > 16:
        return [], ["Maximaal 16 netwerken."]
    for idx, n in enumerate(networks, 1):
        tag = "Netwerk %d" % idx
        try:
            parent = str(n.get("parent", "")).strip()
            if not DEV_RE.match(parent) or parent == mgmt or "." in parent:
                errs.append("%s: ongeldige of niet toegestane interface '%s'." % (tag, parent))
                continue
            if parent not in existing:
                errs.append("%s: interface '%s' bestaat niet in deze LXC." % (tag, parent))
                continue
            vlan = n.get("vlan")
            vlan = int(vlan) if str(vlan or "").strip() else None
            if vlan is not None and not 1 <= vlan <= 4094:
                errs.append("%s: VLAN moet tussen 1 en 4094 liggen." % tag)
                continue
            prefix = int(n.get("prefix", 24))
            if not 8 <= prefix <= 30:
                errs.append("%s: prefix moet tussen 8 en 30 liggen." % tag)
                continue
            first = ipaddress.IPv4Address(str(n.get("first", "")).strip())
            gw = ipaddress.IPv4Address(str(n.get("gateway", "")).strip())
            count = int(n.get("count", 1))
            if not 1 <= count <= 250:
                errs.append("%s: aantal IP's moet tussen 1 en 250 liggen." % tag)
                continue
            net = ipaddress.ip_network("%s/%d" % (first, prefix), strict=False)
            last = first + (count - 1)
            if last not in net or gw not in net:
                errs.append("%s: IP-bereik en gateway moeten in %s liggen." % (tag, net))
                continue
            if first <= gw <= last:
                errs.append("%s: de gateway %s valt binnen het bronbereik." % (tag, gw))
                continue
            dns = str(n.get("dns", "")).strip()
            if dns:
                ipaddress.IPv4Address(dns)
            if mnet and net.overlaps(mnet):
                errs.append("%s: %s overlapt met het management-netwerk %s." % (tag, net, mnet))
                continue
            for other, o in nets:
                if net.overlaps(other):
                    errs.append("%s: %s overlapt met %s." % (tag, net, o))
                    break
            else:
                nets.append((net, tag))
                out.append({"name": str(n.get("name", "")).strip()[:40] or "net%d" % idx, "parent": parent, "vlan": vlan,
                            "first": str(first), "prefix": prefix, "gateway": str(gw), "count": count, "dns": dns})
        except (ValueError, TypeError) as e:
            errs.append("%s: ongeldige invoer (%s)." % (tag, e))
    return out, errs


# ------------------------------------------------------------ apply
def _load_state():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {}


def teardown():
    st = _load_state()
    for r in st.get("rules", []):
        sh(["ip", "rule", "del", "from", r["net"], "lookup", str(r["table"]), "priority", str(r["prio"])])
        sh(["ip", "route", "flush", "table", str(r["table"])])
    for a in reversed(st.get("addrs", [])):
        sh(["ip", "addr", "del", a["cidr"], "dev", a["dev"]])
    for v in st.get("vlans", []):
        sh(["ip", "link", "del", v])
    if os.path.exists(STATE):
        os.remove(STATE)


def apply(networks, mgmt):
    """Replace the previous configuration with `networks`. Returns log lines."""
    nets, errs = validate(networks, mgmt)
    if errs:
        raise ValueError("\n".join(errs))
    teardown()
    st = {"rules": [], "addrs": [], "vlans": []}
    log = []
    live = {i["name"] for i in interfaces()}
    for idx, n in enumerate(nets):
        dev, table, prio = dev_of(n), 100 + idx, 1000 + idx
        sh(["ip", "link", "set", n["parent"], "up"])
        if n["vlan"] and dev not in live:
            r = sh(["ip", "link", "add", "link", n["parent"], "name", dev, "type", "vlan", "id", str(n["vlan"])])
            if r.returncode:
                log.append("%s: VLAN aanmaken mislukt: %s" % (n["name"], r.stderr.strip()))
                continue
            st["vlans"].append(dev)
            live.add(dev)
        sh(["ip", "link", "set", dev, "up"])
        sh(["sysctl", "-qw", "net.ipv4.conf.%s.rp_filter=0" % dev.replace(".", "/"),
            "net.ipv4.conf.%s.arp_announce=2" % dev.replace(".", "/")])
        net = ipaddress.ip_network("%s/%d" % (n["first"], n["prefix"]), strict=False)
        added = 0
        for ip in ips_of(n):
            cidr = "%s/%d" % (ip, n["prefix"])
            r = sh(["ip", "addr", "add", cidr, "dev", dev])
            if r.returncode == 0 or "exists" in r.stderr.lower():
                if r.returncode == 0:
                    st["addrs"].append({"dev": dev, "cidr": cidr})
                added += 1
                subprocess.Popen(["arping", "-q", "-c", "1", "-w", "1", "-U", "-I", dev, ip],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                log.append("%s: %s toevoegen mislukt: %s" % (n["name"], ip, r.stderr.strip()))
        sh(["ip", "route", "replace", str(net), "dev", dev, "src", n["first"], "table", str(table)])
        r = sh(["ip", "route", "replace", "default", "via", n["gateway"], "dev", dev, "onlink", "table", str(table)])
        if r.returncode:
            log.append("%s: route mislukt: %s" % (n["name"], r.stderr.strip()))
        sh(["ip", "rule", "add", "from", str(net), "lookup", str(table), "priority", str(prio)])
        st["rules"].append({"net": str(net), "table": table, "prio": prio})
        log.append("%s: %s, %d/%d adressen actief via %s" % (n["name"], net, added, n["count"], dev))
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    json.dump(st, open(STATE, "w"))
    return log, nets


def status(cfg):
    live = live_addrs()
    ifs = {i["name"]: i for i in interfaces()}
    out = []
    for n in cfg.get("networks", []):
        dev = dev_of(n)
        want = ips_of(n)
        have = sum(1 for ip in want if ip in live.get(dev, set()))
        out.append({"name": n.get("name"), "dev": dev, "want": len(want), "have": have, "up": bool(ifs.get(dev, {}).get("up"))})
    return out


def test(cfg):
    """Ping gateway + DNS lookup from the first IP of each network."""
    import trafficgen
    res = []
    for n in cfg.get("networks", []):
        src, gw = n["first"], n["gateway"]
        gw_ok = trafficgen.ping_probe(gw, src, count=2)
        dns_ok, detail = False, ""
        try:
            trafficgen.dns_resolve("www.microsoft.com", n.get("dns") or gw, src, timeout=2)
            dns_ok = True
        except OSError as e:
            detail = str(e)
        res.append({"name": n.get("name"), "gateway_ping": gw_ok, "dns": dns_ok, "detail": detail})
    return res
