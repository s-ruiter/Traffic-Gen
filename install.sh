#!/usr/bin/env bash
# Traffic-Gen LXC installer for Proxmox VE (wizard driven).
# Run as root on the Proxmox host:
#   git clone http://10.10.100.3:8010/sander/Traffic-Gen.git && cd Traffic-Gen && bash install.sh
set -euo pipefail

REPO_URL="${REPO_URL:-http://10.10.100.3:8010/sander/Traffic-Gen.git}"
TITLE="Traffic-Gen LXC installer"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "Run as root on the Proxmox host."
command -v pct >/dev/null || die "pct not found - this must run on a Proxmox VE host."
command -v whiptail >/dev/null || apt-get install -y whiptail >/dev/null

# --- locate sources (next to this script, or clone) -------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
if [[ ! -f "$HERE/src/trafficgen.py" ]]; then
  command -v git >/dev/null || apt-get install -y git >/dev/null
  HERE="$(mktemp -d)"; git clone --depth 1 "$REPO_URL" "$HERE"
fi

# --- wizard helpers ----------------------------------------------------------
ask()   { # ask "text" "default" -> stdout
  local v; v=$(whiptail --title "$TITLE" --inputbox "$1" 10 70 "$2" 3>&1 1>&2 2>&3) || exit 1; echo "$v"; }
menu()  { # menu "text" tag item tag item ...
  local t="$1"; shift
  whiptail --title "$TITLE" --menu "$t" 18 70 8 "$@" 3>&1 1>&2 2>&3 || exit 1; }
valid_cidr() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; }
valid_ip()   { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

whiptail --title "$TITLE" --msgbox "This wizard creates a Debian 12 LXC that generates realistic\nuser traffic (Netflix, Teams, O365, Facebook, ...) from multiple\nsource IPs, to monitor a FortiGate (SD-WAN, App Control, Web Filter).\n\nYou can change everything later with 'trafficgen wizard' inside the LXC." 14 70

# --- container settings ------------------------------------------------------
CTID=$(ask "Container ID" "$(pvesh get /cluster/nextid)")
pct status "$CTID" &>/dev/null && die "CTID $CTID already exists."
HOSTNAME=$(ask "Hostname" "trafficgen")

mapfile -t BRIDGES < <(ip -o link show type bridge | awk -F': ' '{print $2}')
[[ ${#BRIDGES[@]} -gt 0 ]] || BRIDGES=(vmbr0)
args=(); for b in "${BRIDGES[@]}"; do args+=("$b" "bridge"); done
BRIDGE=$(menu "Network bridge" "${args[@]}")
VLAN=$(ask "VLAN tag (empty = none)" "")

while :; do
  MODE=$(menu "IP configuration of the LXC (primary source IP)" static "Static IP" dhcp "DHCP")
  if [[ $MODE == static ]]; then
    IPCIDR=$(ask "IP address with prefix (e.g. 192.168.10.50/24)" "")
    valid_cidr "$IPCIDR" || { whiptail --msgbox "Invalid format. Use a.b.c.d/nn" 8 50; continue; }
    GW=$(ask "Gateway (the FortiGate interface IP)" "${IPCIDR%.*/*}.1")
    valid_ip "$GW" || { whiptail --msgbox "Invalid gateway" 8 50; continue; }
    NETCFG="name=eth0,bridge=$BRIDGE,ip=$IPCIDR,gw=$GW"
  else
    IPCIDR=""; NETCFG="name=eth0,bridge=$BRIDGE,ip=dhcp"
  fi
  break
done
[[ -n $VLAN ]] && NETCFG+=",tag=$VLAN"
DNS=$(ask "DNS server (empty = Proxmox host default)" "${GW:-}")

EXTRA_FIRST=""; EXTRA_COUNT=0
if [[ $MODE == static ]]; then
  EXTRA_COUNT=$(ask "Number of EXTRA source IPs (same subnet, 0 = only the primary IP)" "9")
  if [[ $EXTRA_COUNT -gt 0 ]]; then
    base="${IPCIDR%/*}"; last="${base##*.}"
    EXTRA_FIRST=$(ask "First extra source IP (they run consecutively from here)" "${base%.*}.$((last+1))")
    valid_ip "$EXTRA_FIRST" || die "Invalid IP: $EXTRA_FIRST"
  fi
else
  whiptail --msgbox "DHCP selected: only the DHCP address is used as source.\nExtra source IPs need static config; set them later in\n/etc/trafficgen/config.yaml (trafficgen wizard)." 10 60
fi

DURATION=$(ask "Default test duration in minutes (0 = until stopped)" "10")
INTENSITY=$(menu "Traffic intensity (think time between actions)" medium "Medium" low "Low (calm office)" high "High (busy)")
THREADS=$(ask "Parallel sessions per source IP" "2")

mapfile -t STORES < <(pvesm status -content rootdir | awk 'NR>1{print $1}')
[[ ${#STORES[@]} -gt 0 ]] || die "No storage with content type rootdir found."
args=(); for s in "${STORES[@]}"; do args+=("$s" "storage"); done
STORAGE=$(menu "Storage for the container disk" "${args[@]}")
DISK=$(ask "Disk size (GB)" "4")
CORES=$(ask "CPU cores" "2")
MEM=$(ask "Memory (MB)" "1024")

PW=$(whiptail --title "$TITLE" --passwordbox "Root password for the LXC (empty = random, console access via 'pct enter')" 10 70 3>&1 1>&2 2>&3) || exit 1
[[ -n $PW ]] || PW=$(openssl rand -base64 12)

whiptail --title "$TITLE" --yesno "Create LXC with:\n
 CTID/hostname : $CTID / $HOSTNAME
 Network       : $NETCFG
 DNS           : ${DNS:-host default}
 Extra IPs     : ${EXTRA_COUNT} from ${EXTRA_FIRST:-n/a}
 Duration      : $DURATION min, intensity $INTENSITY, $THREADS sessions/IP
 Resources     : $CORES cores, ${MEM}MB, ${DISK}GB on $STORAGE

Continue?" 20 70 || exit 1

# --- template ----------------------------------------------------------------
TSTORE=$(pvesm status -content vztmpl | awk 'NR>1{print $1; exit}')
[[ -n $TSTORE ]] || die "No storage with content type vztmpl found."
pveam update >/dev/null
TEMPLATE=$(pveam list "$TSTORE" | awk '/debian-12-standard/{print $1}' | sort | tail -1)
if [[ -z $TEMPLATE ]]; then
  NAME=$(pveam available --section system | awk '/debian-12-standard/{print $2}' | sort | tail -1)
  [[ -n $NAME ]] || die "No debian-12 template available."
  echo ">> Downloading $NAME"; pveam download "$TSTORE" "$NAME"
  TEMPLATE="$TSTORE:vztmpl/$NAME"
fi

# --- create LXC --------------------------------------------------------------
echo ">> Creating LXC $CTID"
create=(pct create "$CTID" "$TEMPLATE" --hostname "$HOSTNAME" --unprivileged 1
  --cores "$CORES" --memory "$MEM" --swap 256 --rootfs "$STORAGE:$DISK"
  --net0 "$NETCFG" --features nesting=1 --onboot 1 --password "$PW"
  --description "Traffic-Gen: FortiGate traffic generator")
[[ -n $DNS ]] && create+=(--nameserver "$DNS")
"${create[@]}"
pct start "$CTID"

echo ">> Waiting for network"
for _ in $(seq 1 30); do
  pct exec "$CTID" -- ping -c1 -W1 deb.debian.org &>/dev/null && break || sleep 2
done
pct exec "$CTID" -- ping -c1 -W2 deb.debian.org &>/dev/null || die "LXC has no internet/DNS - check gateway/firewall. Container $CTID left running for debugging."

# --- provision ---------------------------------------------------------------
echo ">> Installing packages"
pct exec "$CTID" -- bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq python3 python3-yaml iproute2 iputils-ping iputils-arping logrotate ca-certificates >/dev/null'

pct exec "$CTID" -- mkdir -p /opt/trafficgen /etc/trafficgen /var/log/trafficgen
pct push "$CTID" "$HERE/src/trafficgen.py" /opt/trafficgen/trafficgen.py --perms 755
pct push "$CTID" "$HERE/src/profiles.yaml" /opt/trafficgen/profiles.yaml
pct exec "$CTID" -- ln -sf /opt/trafficgen/trafficgen.py /usr/local/bin/trafficgen

TMPCFG=$(mktemp)
cat > "$TMPCFG" <<EOF
source:
  interface: eth0
  include_primary: true
  first: "${EXTRA_FIRST}"
  count: ${EXTRA_COUNT}
  keep_ips: false
duration_minutes: ${DURATION}
threads_per_ip: ${THREADS}
intensity: ${INTENSITY}
tls_verify: false
dns_server: "${DNS}"
groups:
  office365: 25
  collab: 20
  streaming: 20
  social: 10
  saas: 10
  web: 10
  updates: 3
  download: 2
  sdwan: 5
  webfilter: 0   # set >0 to include web filter test sites (expect blocks)
  security: 0    # set >0 to include EICAR download tests
EOF
pct push "$CTID" "$TMPCFG" /etc/trafficgen/config.yaml; rm -f "$TMPCFG"

TMPLR=$(mktemp)
printf '/var/log/trafficgen/*.log {\n  weekly\n  rotate 4\n  compress\n  missingok\n  notifempty\n  copytruncate\n}\n' > "$TMPLR"
pct push "$CTID" "$TMPLR" /etc/logrotate.d/trafficgen; rm -f "$TMPLR"

# keep ARP/neighbour behaviour sane with many source IPs on one interface
pct exec "$CTID" -- bash -c 'echo "net.ipv4.conf.all.arp_announce=2" > /etc/sysctl.d/99-trafficgen.conf; sysctl -q -p /etc/sysctl.d/99-trafficgen.conf || true'

IPSHOW=${IPCIDR%/*}; [[ -n $IPSHOW ]] || IPSHOW=$(pct exec "$CTID" -- hostname -I | awk '{print $1}')
cat <<EOF

=====================================================================
 Traffic-Gen LXC $CTID ($HOSTNAME) ready - primary IP: $IPSHOW
 Root password: $PW

 pct enter $CTID
   trafficgen start            # run in background (default ${DURATION} min)
   trafficgen start -d 30      # 30 minutes
   trafficgen start -g streaming,collab -i high
   trafficgen status | stop | apps | wizard
 Logs: /var/log/trafficgen/requests.log, last-run.json
=====================================================================
EOF
