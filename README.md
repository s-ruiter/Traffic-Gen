# Traffic-Gen

A Proxmox LXC with a web GUI that generates realistic user traffic (Netflix, YouTube, Facebook, Teams, Office 365, Zoom, Salesforce, updates, SD-WAN probes, ...) from **multiple source IPs and VLANs**, to monitor a FortiGate (SD-WAN, Application Control, Web Filter) and to test its security efficacy.

## Install (on the Proxmox host, as root)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/s-ruiter/Traffic-Gen/main/install.sh)"
```

or from a clone:

```bash
git clone https://github.com/s-ruiter/Traffic-Gen.git
cd Traffic-Gen && bash install.sh
```

The wizard creates a Debian 12 LXC with **two NICs**:

| NIC  | Purpose | Setting |
|------|---------|---------|
| eth0 | Management (web GUI) | bridge, VLAN, IP/gateway/DNS from the wizard |
| eth1 | Test traffic | bridge (optional tag); **no IP**, the rest is configured in the GUI |

At the end you get the GUI URL (`https://<mgmt-ip>:8443`, self-signed certificate) and the admin password (chosen by you or generated).

## Update

Run on the Proxmox host as root. Configuration, password, certificate and logs are preserved; a running test is stopped by the restart.

```bash
curl -fsSL https://raw.githubusercontent.com/s-ruiter/Traffic-Gen/main/update.sh | bash
# several Traffic-Gen LXCs? pass the container ID:
curl -fsSL https://raw.githubusercontent.com/s-ruiter/Traffic-Gen/main/update.sh | bash -s 105
```

## In the GUI

- **Dashboard**: duration (5 min to 2 hours, until stopped, or custom), intensity, sessions per IP, start/stop, live throughput, requests, blocked/errors, per application and per source IP, latest requests.
- **Traffic mix**: weight per group (Microsoft 365, Collaboration, Streaming, Social, SaaS, Web, Updates, Downloads, SD-WAN probes, Web filter test, Malware, IOC) and per-app on/off.
- **Network**: per source network the interface (eth1), optional VLAN, first IP, prefix, number of IPs, gateway and DNS. *Apply* creates the VLAN sub-interface, adds the IPs and sets up source-based routing, so test traffic goes through its own gateway (the FortiGate) and management stays separate. *Test connection* pings the gateway and tests DNS from the source network.
- **Settings**: change password, verify TLS certificates of target sites (off by default, for SSL deep inspection) and the IOC switches.

## Proxmox notes

- If you use VLANs in the GUI, leave the eth1 tag empty in the wizard and make sure the bridge is VLAN-aware and passes the VLANs you need. For a single flat network you can set a tag on eth1.
- Network changes are applied on *Apply* and when the service starts. Applying is blocked while a test is running.

## Logs and CLI

- `/var/log/trafficgen/requests.log`: JSON per request, to compare with FortiGate logs.
- `trafficgen run -d 5` runs a foreground test with the configured networks; `trafficgen apps` lists the profiles; `trafficgen passwd` resets the GUI password.
- Custom app list: copy `/opt/trafficgen/profiles.yaml` to `/etc/trafficgen/profiles.yaml`.
- Service: `systemctl status trafficgen-web`, logs with `journalctl -u trafficgen-web`.

## Notes

- Make sure the FortiGate policy allows the source networks to the internet.
- The Web filter, Malware and IOC groups have weight 0 by default.

## Testing security efficacy

Two groups in **Traffic mix**, meant to test FortiGate AV, IPS, botnet/DNS filter and web filter:

- **Malware test**: only standard, harmless test files (EICAR over HTTP and HTTPS, EICAR zip, WICAR test pages, `testmynids.org`). Nothing is stored. A FortiGate block page or connection reset counts as *blocked*, a file that gets through counts as *missed*. The dashboard shows the **detection rate**. HTTPS files are only detectable with SSL deep inspection; without inspection expect *missed*.
- **IOC / botnet behaviour**: DGA-like DNS lookups, DNS tunnelling (long hex subdomains, TXT), dynamic DNS and mining pool lookups. Under **Settings** you can enable more: bare TCP connects (Tor directory authorities, mining ports) and a daily fetched botnet C2 IP list (abuse.ch Feodo Tracker). No data is ever sent to, or downloaded from, IOCs; only DNS queries and a TCP connect that closes immediately.

For IOC traffic the FortiGate log is leading: compare `/var/log/trafficgen/requests.log` (source IP, time, target) with the botnet, DNS filter and IPS logs. The GUI counts a DNS answer with the FortiGuard block portal IP (configurable) as *blocked*.

Only use this on networks where you are allowed to do so.
