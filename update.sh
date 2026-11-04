#!/usr/bin/env bash
# Update an existing Traffic-Gen LXC to the latest version from the repo.
# Run as root on the Proxmox host:
#   curl -fsSL http://10.10.100.3:8010/sander/Traffic-Gen/raw/branch/main/update.sh | bash
#   curl -fsSL .../update.sh | bash -s 105        # explicit container ID
# Config, admin password, certificate and logs inside the LXC are left untouched.
set -euo pipefail

main() {
  REPO_URL="${REPO_URL:-http://10.10.100.3:8010/sander/Traffic-Gen.git}"
  die() { echo "ERROR: $*" >&2; exit 1; }
  [[ $EUID -eq 0 ]] || die "Run as root on the Proxmox host."
  command -v pct >/dev/null || die "pct not found - run this on the Proxmox VE host."

  CTID="${1:-}"
  if [[ -z $CTID ]]; then
    mapfile -t FOUND < <(for id in $(pct list | awk 'NR>1{print $1}'); do
      pct config "$id" | grep -q '^description:.*Traffic-Gen' && echo "$id"; done)
    [[ ${#FOUND[@]} -ge 1 ]] || die "No Traffic-Gen LXC found. Pass the container ID as argument."
    [[ ${#FOUND[@]} -eq 1 ]] || die "Several Traffic-Gen LXCs found (${FOUND[*]}). Pass the container ID as argument."
    CTID="${FOUND[0]}"
  fi
  [[ $(pct status "$CTID") == *running* ]] || die "LXC $CTID is not running."
  pct exec "$CTID" -- test -d /opt/trafficgen || die "LXC $CTID has no /opt/trafficgen - not a Traffic-Gen LXC."

  echo ">> Downloading latest sources"
  TMP="$(mktemp -d)"; trap 'rm -rf -- "${TMP:?}"' EXIT
  curl -fsSL "${ARCHIVE_URL:-${REPO_URL%.git}/archive/main.tar.gz}" | tar -xz -C "$TMP" --strip-components=1 \
    || die "Could not download sources."
  [[ -f $TMP/src/trafficgen.py ]] || die "Downloaded archive looks wrong."

  echo ">> Updating LXC $CTID"
  for f in trafficgen.py netconf.py webui.py profiles.yaml; do
    pct push "$CTID" "$TMP/src/$f" "/opt/trafficgen/$f" --perms 644
  done
  pct exec "$CTID" -- mkdir -p /opt/trafficgen/web
  pct push "$CTID" "$TMP/src/web/index.html" /opt/trafficgen/web/index.html --perms 644
  pct exec "$CTID" -- chmod 755 /opt/trafficgen/trafficgen.py

  echo ">> Restarting service (a running test will be stopped)"
  pct exec "$CTID" -- systemctl restart trafficgen-web.service
  sleep 2
  pct exec "$CTID" -- systemctl is-active --quiet trafficgen-web.service \
    && echo ">> Done. Reload the web GUI (Ctrl+F5)." \
    || echo "WARNING: service not active - check: pct exec $CTID -- journalctl -u trafficgen-web -n 30"
}

main "$@"; exit $?
