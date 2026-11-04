#!/usr/bin/env bash
# Traffic-Gen LXC installer for Proxmox VE (wizard driven).
# Run as root on the Proxmox host:
#   git clone http://10.10.100.3:8010/sander/Traffic-Gen.git && cd Traffic-Gen && bash install.sh
#
# The LXC gets two NICs:
#   eth0 = management (web GUI, set up here)
#   eth1 = test traffic (no IP; source networks/VLANs/IP count are set in the GUI)
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

whiptail --title "$TITLE" --msgbox "This wizard creates a Debian 12 LXC with two NICs:\n  eth0 = management (web GUI)\n  eth1 = test traffic (no IP; source networks, VLANs and the\n         number of source IPs are set in the web GUI)\n\nThe LXC generates realistic user traffic (Netflix, Teams, O365,\nFacebook, ...) to monitor a FortiGate (SD-WAN, App Control, Web Filter)." 16 72

# --- container settings ------------------------------------------------------
CTID=$(ask "Container ID" "$(pvesh get /cluster/nextid)")
pct status "$CTID" &>/dev/null && die "CTID $CTID already exists."
HOSTNAME=$(ask "Hostname" "trafficgen")

mapfile -t BRIDGES < <(ip -o link show type bridge | awk -F': ' '{print $2}')
[[ ${#BRIDGES[@]} -gt 0 ]] || BRIDGES=(vmbr0)
args=(); for b in "${BRIDGES[@]}"; do args+=("$b" "bridge"); done

# management NIC (eth0)
MBRIDGE=$(menu "Bridge for the MANAGEMENT interface (eth0, web GUI)" "${args[@]}")
MVLAN=$(ask "Management VLAN tag (empty = none)" "")
while :; do
  MODE=$(menu "Management IP configuration" static "Static IP" dhcp "DHCP")
  if [[ $MODE == static ]]; then
    IPCIDR=$(ask "Management IP with prefix (e.g. 192.168.1.50/24)" "")
    valid_cidr "$IPCIDR" || { whiptail --msgbox "Invalid format. Use a.b.c.d/nn" 8 50; continue; }
    GW=$(ask "Management gateway" "${IPCIDR%.*/*}.1")
    valid_ip "$GW" || { whiptail --msgbox "Invalid gateway" 8 50; continue; }
    NET0="name=eth0,bridge=$MBRIDGE,ip=$IPCIDR,gw=$GW,firewall=0"
  else
    IPCIDR=""; GW=""; NET0="name=eth0,bridge=$MBRIDGE,ip=dhcp,firewall=0"
  fi
  break
done
[[ -n $MVLAN ]] && NET0+=",tag=$MVLAN"
DNS=$(ask "DNS server for management (empty = Proxmox host default)" "$GW")

# traffic NIC (eth1)
TBRIDGE=$(menu "Bridge for the TRAFFIC interface (eth1, towards the FortiGate)" "${args[@]}")
TVLAN=$(ask "Tag for eth1 (empty = trunk/untagged; use VLANs in the GUI)" "")
NET1="name=eth1,bridge=$TBRIDGE,firewall=0"
[[ -n $TVLAN ]] && NET1+=",tag=$TVLAN"

PORT=$(ask "Web GUI port (HTTPS)" "8443")

mapfile -t STORES < <(pvesm status -content rootdir | awk 'NR>1{print $1}')
[[ ${#STORES[@]} -gt 0 ]] || die "No storage with content type rootdir found."
args=(); for s in "${STORES[@]}"; do args+=("$s" "storage"); done
STORAGE=$(menu "Storage for the container disk" "${args[@]}")
DISK=$(ask "Disk size (GB)" "4")
CORES=$(ask "CPU cores" "2")
MEM=$(ask "Memory (MB)" "1024")

while :; do
  APW=$(whiptail --title "$TITLE" --passwordbox "Admin password for the WEB GUI (min. 8 characters; empty = generate)" 10 70 3>&1 1>&2 2>&3) || exit 1
  if [[ -z $APW ]]; then APW=$(openssl rand -base64 12 | tr -d '/+='); break; fi
  [[ ${#APW} -ge 8 ]] && break
  whiptail --msgbox "Password too short." 8 40
done
ROOTPW=$(openssl rand -base64 12)

whiptail --title "$TITLE" --yesno "Create LXC with:\n
 CTID/hostname : $CTID / $HOSTNAME
 eth0 (mgmt)   : $NET0
 eth1 (traffic): $NET1
 GUI           : https://<mgmt-ip>:$PORT
 Resources     : $CORES cores, ${MEM}MB, ${DISK}GB on $STORAGE

Continue?" 17 78 || exit 1

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
  --net0 "$NET0" --net1 "$NET1" --features nesting=1 --onboot 1 --password "$ROOTPW"
  --description "Traffic-Gen: FortiGate traffic generator (web GUI on mgmt IP :$PORT)")
[[ -n $DNS ]] && create+=(--nameserver "$DNS")
"${create[@]}"
pct start "$CTID"

echo ">> Waiting for network"
for _ in $(seq 1 30); do
  pct exec "$CTID" -- ping -c1 -W1 deb.debian.org &>/dev/null && break || sleep 2
done
pct exec "$CTID" -- ping -c1 -W2 deb.debian.org &>/dev/null || die "LXC has no internet/DNS on the management network - check gateway/DNS/firewall. Container $CTID left running for debugging."

# --- provision ---------------------------------------------------------------
echo ">> Installing packages"
pct exec "$CTID" -- bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq python3 python3-yaml iproute2 iputils-ping iputils-arping openssl logrotate ca-certificates >/dev/null'

pct exec "$CTID" -- mkdir -p /opt/trafficgen/web /etc/trafficgen/tls /var/log/trafficgen /var/lib/trafficgen
for f in trafficgen.py netconf.py webui.py profiles.yaml; do
  pct push "$CTID" "$HERE/src/$f" "/opt/trafficgen/$f" --perms 644
done
pct push "$CTID" "$HERE/src/web/index.html" /opt/trafficgen/web/index.html --perms 644
pct exec "$CTID" -- chmod 755 /opt/trafficgen/trafficgen.py
pct exec "$CTID" -- ln -sf /opt/trafficgen/trafficgen.py /usr/local/bin/trafficgen

MGMT_IP=${IPCIDR%/*}
[[ -n $MGMT_IP ]] || MGMT_IP=$(pct exec "$CTID" -- hostname -I | awk '{print $1}')

echo ">> TLS certificate + admin password"
pct exec "$CTID" -- openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$HOSTNAME" \
  -addext "subjectAltName=DNS:$HOSTNAME,IP:$MGMT_IP" \
  -keyout /etc/trafficgen/tls/server.key -out /etc/trafficgen/tls/server.crt 2>/dev/null
pct exec "$CTID" -- chmod 600 /etc/trafficgen/tls/server.key

TMPPW=$(mktemp); chmod 600 "$TMPPW"; printf '%s' "$APW" > "$TMPPW"
pct push "$CTID" "$TMPPW" /root/.tg-pw --perms 600; rm -f "$TMPPW"
pct exec "$CTID" -- bash -c 'trafficgen passwd --file /root/.tg-pw && rm -f /root/.tg-pw'

pct exec "$CTID" -- bash -c "printf 'mgmt_interface: eth0\n' > /etc/trafficgen/config.yaml"

TMPU=$(mktemp)
cat > "$TMPU" <<UNIT
[Unit]
Description=Traffic-Gen web GUI and engine
After=network-online.target
Wants=network-online.target

[Service]
Environment=TRAFFICGEN_PORT=$PORT
ExecStart=/usr/bin/python3 /opt/trafficgen/webui.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
pct push "$CTID" "$TMPU" /etc/systemd/system/trafficgen-web.service; rm -f "$TMPU"

TMPLR=$(mktemp)
printf '/var/log/trafficgen/*.log {\n  weekly\n  rotate 4\n  compress\n  missingok\n  notifempty\n  copytruncate\n}\n' > "$TMPLR"
pct push "$CTID" "$TMPLR" /etc/logrotate.d/trafficgen; rm -f "$TMPLR"

pct exec "$CTID" -- systemctl daemon-reload
pct exec "$CTID" -- systemctl enable --now trafficgen-web.service
sleep 2
pct exec "$CTID" -- systemctl is-active --quiet trafficgen-web.service \
  || echo "WARNING: service not active - check: pct exec $CTID -- journalctl -u trafficgen-web"

cat <<DONE

=====================================================================
 Traffic-Gen LXC $CTID ($HOSTNAME) is ready.

 Web GUI : https://$MGMT_IP:$PORT   (self-signed certificate)
 Login   : admin password: $APW
 LXC root password (console only): $ROOTPW

 Next: open the GUI > Netwerk, add a source network on eth1
 (VLAN, first IP, gateway, number of IPs) and click Toepassen.
 Then start a test from the Dashboard.
=====================================================================
DONE
