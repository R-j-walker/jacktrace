#!/usr/bin/env bash
set -euo pipefail

# JackTrace (Raspberry Pi 4 Network Tester) — Phase 1 + Phase 2 Setup
# Usage on Raspberry Pi OS Lite (Bookworm / Trixie):
#   sudo bash scripts/setup_pi.sh [eth0]

IFACE="${1:-eth0}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/setup_pi.sh"
  exit 1
fi

echo "==> [1/6] Installing Linux networking packages (lldpd, ethtool, arp-scan, ieee-data, iw, iperf3, traceroute, bluez, nmap)..."
apt-get update -qq
apt-get install -y lldpd ethtool iproute2 iputils-ping tcpdump arp-scan ieee-data iw iperf3 traceroute bluez nmap python3-venv python3-pip

echo "==> [2/6] Configuring lldpd to enable LLDP, LLDP-MED, Cisco CDP, EDP, FDP & SONMP..."
cat >/etc/default/lldpd <<'EOF'
# Enable Cisco CDP (-c), Extreme EDP (-e), Foundry FDP (-f), Nortel SONMP (-s)
DAEMON_ARGS="-c -e -f -s"
EOF

mkdir -p /etc/lldpd.d
cat >/etc/lldpd.d/nettester.conf <<EOF
configure system interface pattern ${IFACE},eth*,enx*,!wlan*
configure med fast-start enable
configure dot3 power pd supported enabled powerpairs signal class class-4 type 2 source pse priority low requested 13000 allocated 25500
EOF

systemctl enable lldpd
systemctl restart lldpd

echo "==> [3/6] Ensuring IP forwarding is off & unplugged eth0 never stalls boot..."
sysctl -w net.ipv4.ip_forward=0 >/dev/null || true
systemctl disable NetworkManager-wait-online.service 2>/dev/null || true
systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true

echo "==> [4/6] Ensuring optional tailcat binary for ephemeral WireGuard/DERP tunnels..."
if ! command -v tailcat >/dev/null 2>&1; then
  ARCH="$(uname -m)"
  case "${ARCH}" in
    aarch64|arm64) TC_ARCH="arm64" ;;
    armv7l|armv6l) TC_ARCH="arm" ;;
    x86_64) TC_ARCH="amd64" ;;
    *) TC_ARCH="" ;;
  esac
  if [[ -n "${TC_ARCH}" ]]; then
    TC_URL="$(curl -fsSL --max-time 8 https://api.github.com/repos/tailscale/tailcat/releases/latest 2>/dev/null \
      | grep -Eo "https://[^\"]+linux[_-]${TC_ARCH}[^\"]*\\.tar\\.gz" | head -n1 || true)"
    if [[ -n "${TC_URL}" ]]; then
      TMP_TC="$(mktemp -d)"
      if curl -fsSL --max-time 25 "${TC_URL}" -o "${TMP_TC}/tailcat.tgz" && tar -xzf "${TMP_TC}/tailcat.tgz" -C "${TMP_TC}"; then
        TC_BIN="$(find "${TMP_TC}" -type f -name tailcat | head -n1 || true)"
        if [[ -n "${TC_BIN}" ]]; then
          install -m 0755 "${TC_BIN}" /usr/local/bin/tailcat
          echo "    Installed tailcat to /usr/local/bin/tailcat"
        fi
      else
        echo "    [warn] tailcat download failed (offline?) — skipping optional tailcat install"
      fi
      rm -rf "${TMP_TC}"
    else
      echo "    [warn] Could not resolve tailcat release for ${TC_ARCH} (offline?) — skipping"
    fi
  fi
fi

echo "==> [5/6] Updating Python virtual environment in ${APP_DIR}/.venv..."
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --upgrade pip -q
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt" -q

echo "==> [6/6] Updating and restarting pi-nettester systemd service on port 8080..."
sed "s|__APP_DIR__|${APP_DIR}|g; s|__IFACE__|${IFACE}|g" \
  "${APP_DIR}/systemd/pi-nettester.service" >/etc/systemd/system/pi-nettester.service

systemctl daemon-reload
systemctl enable pi-nettester.service
systemctl restart pi-nettester.service

WLAN_IP="$(ip -4 -br addr show wlan0 2>/dev/null | awk '{print $3}' | cut -d/ -f1 || true)"
ALL_IPS="$(hostname -I | xargs)"

echo ""
echo "============================================================"
echo " JackTrace (Phase 2) is LIVE!"
echo " Monitored Test Port : ${IFACE}"
if [[ -n "${WLAN_IP}" ]]; then
  echo " Bench Web UI (Wi-Fi): http://${WLAN_IP}:8080"
  echo " PDF Audit Report    : http://${WLAN_IP}:8080/api/audit/report.pdf"
  echo " 800x480 Kiosk URL   : http://${WLAN_IP}:8080/?kiosk=1"
else
  echo " Bench Web UI        : http://${ALL_IPS%% *}:8080"
fi
echo " Service Logs        : sudo journalctl -u pi-nettester -f"
echo "============================================================"
