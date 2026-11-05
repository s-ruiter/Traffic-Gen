# Traffic-Gen

A Proxmox LXC with a web GUI that generates realistic user traffic (Netflix, YouTube, Facebook, Teams, Office 365, Zoom, Salesforce, updates, SD-WAN probes, ...) from **multiple source IPs and networks**, to monitor a FortiGate (SD-WAN, Application Control, Web Filter) and to test its security efficacy.

## Install (on the Proxmox host, as root)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/s-ruiter/Traffic-Gen/main/install.sh)"
```

or from a clone:

```bash
git clone https://github.com/s-ruiter/Traffic-Gen.git
cd Traffic-Gen && bash install.sh
```

The wizard creates a Debian 12 LXC (default 4 CPU cores, 2 GB RAM, 4 GB disk; 2 cores and 1 GB are enough for the traffic generator alone, the Throughput tester needs the extra cores for 1 Gbit/s) with **two NICs** and optionally a third for the Throughput receiver:

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

- **Dashboard**: a welcome page with a short explanation of the tool and pictures of the three test flows (traffic test, security efficacy, throughput), plus quick getting-started steps.
- **Traffic mix**: start and stop the traffic test (duration from 5 min to 2 hours, until stopped, or custom; intensity; sessions per IP) and follow it live: throughput, requests, blocked/errors, per application and per source IP, latest requests. Below that, preset buttons (*Security test only*, *No security test*, *Default mix*) and the weight per group (Microsoft 365, Collaboration, Streaming, Social, SaaS, Web, Updates, Downloads, SD-WAN probes, Web filter test, Malware, IOC) and per-app on/off.
- **Network**: per source network the interface (eth1), first IP, prefix, number of IPs, gateway and DNS. *Apply* creates the VLAN sub-interface, adds the IPs and sets up source-based routing, so test traffic goes through its own gateway (the FortiGate) and management stays separate. *Test connection* pings the gateway and tests DNS from the source network.
- **Throughput**: bandwidth, packet loss (UDP, TCP, RFC 2544) and connections-per-second tests between two networks.
- **Settings**: change password, verify TLS certificates of target sites (off by default, for SSL deep inspection) and the IOC switches.

## Throughput, packet loss and connections per second

The **Throughput** page turns the LXC into a small bandwidth tester (up to about 1 Gbit/s, meant for relatively small tests). A sender on one of your source networks sends traffic *through the FortiGate* to a receiver on a second network, and the receiver checks everything that arrives:

- **UDP stream**: fixed rate, packet size and duration. Reports packet loss, reordering, duplicates, throughput, jitter and one-way latency, with a pass/fail on the loss you allow.
- **TCP throughput**: parallel streams, goodput measured at the receiver.
- **RFC 2544**: throughput (binary search for the highest rate within your loss tolerance), optional frame loss rate and latency at the throughput rate, for the standard frame sizes 64 to 1518 bytes.
- **Connections per second**: TCP connections at a set rate, optionally ramped up in steps, with optional request/response payload and hold time. Reports established/failed connections, achieved rate and connect latency, and the highest sustained rate.

- **Concurrent sessions**: opens TCP connections at a set rate until the target is reached or failures begin (up to 500,000), holds them open for a set time and uses a heartbeat to detect sessions the FortiGate drops. Reports the peak number of concurrent sessions (also as seen by the receiver), failures and where they began, sessions lost during the hold, and the connect latency. Above 50,000 sessions the app warns unless several source IPs ('Source IPs to use') and several receiver IPs ('Number of receiver IPs' on the Path card) are used, and it asks for confirmation, because a full session table can trigger conserve mode and affects everyone behind that firewall. One source IP, one receiver IP and 8 ports allow about 225,000 sessions; more IPs raise that limit.

Only the sender network is set up on the Network page. The receiver is configured entirely on the Throughput page (it is not a network under Network). Setup (**Throughput > Path**): pick the sender network (the first IP of a network from the Network page, which must be applied) and describe the receiver: interface, receiver IP, prefix and gateway. The test needs a **third interface**: eth0 is management, eth1 is the sender, and eth2 is the receiver. The receiver must be in a *different* network than the sender, so the traffic crosses the FortiGate. The receiver needs one IP address, a prefix and a gateway (optionally several consecutive receiver IPs, only useful for the Concurrent sessions test). The receiver gateway is the FortiGate's own address in the receiver network (the FortiGate interface connected to eth2); it is required so the receiver can answer the sender, which is in another network. The sender's gateway is the one from its source network on the Network page. That IP is not configured on eth2 itself: the app puts it on a virtual interface in the receiver namespace only while a test runs, so eth2 stays without an IP in the LXC. Keep the Proxmox firewall off on that NIC (`firewall=0`), because the virtual interface has its own MAC address. VLAN tags are set by Proxmox on the LXC network device, not in the app. The installer can add eth2 for you; for an existing LXC run `pct set <CTID> -net2 name=eth2,bridge=<bridge>,tag=<vlan>,firewall=0` on the Proxmox host and restart the LXC. The GUI warns when no suitable interface is available. The receiver lives in its own network namespace on a macvlan interface of eth2 and is created only while a test runs. Allow UDP and TCP on ports 5201-5208 (configurable base port) from the sender network to the receiver IP in the FortiGate policy. *Check environment* verifies the setup and the gateway.

The *Self-test* mode runs sender and receiver both inside the LXC on 127.0.0.1. The traffic never leaves the LXC and does not touch the FortiGate; use it to see what the LXC itself can generate and to check that the tool works.

Receiver reliability: the receiver's virtual interface gets a fixed MAC address per receiver IP, so the FortiGate's ARP entry stays valid between tests, and every test is cleaned up completely (stale namespaces and processes are removed). Before a TCP based test (TCP, connections per second, concurrent sessions) the tool checks that the sender can really reach the receiver through the FortiGate and stops with a clear message if not, instead of running a test that sends nothing.

FortiGate memory: every concurrent session costs the FortiGate memory. On a small FortiGate VM (for example 2 GB RAM) a few tens of thousands of sessions can already push it into conserve mode or 'extreme low memory', after which it drops new sessions (visible as `extreme_low_mem` and `memory_tension_drop` in `diagnose sys session stat`) until memory recovers. Start with a lower target, raise it step by step and watch `diagnose hardware sysinfo conserve` during the test. The path check before a TCP test then fails with a clear message instead of a test that sends nothing.

Load protection: the test processes run at low priority so the GUI stays responsive, the number of streams and workers is limited to what the LXC's CPU cores allow, and a CPU monitor shows the LXC load during a test. The GUI warns before a test starts when the chosen rate, frame sizes, connection count or run time will not fit this LXC (for example too few cores, very small frames, or many simultaneous connections that could fill the FortiGate session table), and during a test when the CPU stays saturated, because the result is then limited by the LXC instead of the network. For 1 Gbit/s give the LXC 4 CPU cores.

Reports: after a test you can download the results as a **PDF report** (test setup, parameters, results, warnings, chart and tables) from the Throughput page and from the Traffic mix page; the Throughput page also offers the raw results as JSON. The PDF is generated on the LXC, no extra packages needed.

Notes: the tester is written in Python, so a single LXC reaches roughly 0.1 to 1 Gbit/s depending on packet size and CPU cores. Small frames (64 bytes) are limited by packets per second, and such results are marked "limited by sender" instead of being reported as network loss. Throughput and CPU of the Proxmox host and bridge are part of the path being measured. Only one test (traffic or throughput) runs at a time. Results are also appended to `/var/log/trafficgen/throughput.jsonl`.

## Proxmox notes

- VLAN tags are set by Proxmox on each LXC network device (the tag fields in the wizard, or `pct set`). The GUI no longer shows a VLAN field; a network that was saved earlier with a VLAN keeps working and still shows it.
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
