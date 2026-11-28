#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"

# JackTrace — x86_64 Linux & GPD Pocket 3 Provisioning Script
# Tested on Debian 13 (Trixie), Debian 12 (Bookworm), and Ubuntu 24.04 LTS.
#
# Usage:
#   sudo bash scripts/setup_x86.sh [--iface enp2s0] [--mode desktop|kiosk] [--profile generic|gpd-pocket3]
#
# Examples:
#   sudo bash scripts/setup_x86.sh --profile gpd-pocket3 --mode desktop
#   sudo bash scripts/setup_x86.sh --profile gpd-pocket3 --mode kiosk

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KIOSK_USER="${SUDO_USER:-$(ls /home 2>/dev/null | head -n 1 || true)}"
IFACE=""
MODE="desktop"
PROFILE="generic"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)
      IFACE="${2:-}"
      shift 2
      ;;
    --mode)
      MODE="${2:-desktop}"
      shift 2
      ;;
    --profile)
      PROFILE="${2:-generic}"
      shift 2
      ;;
    -h|--help)
      sed -n '3,14p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/setup_x86.sh [--profile gpd-pocket3] [--mode desktop|kiosk]"
  exit 1
fi

if [[ "${MODE}" != "desktop" && "${MODE}" != "kiosk" ]]; then
  echo "Invalid --mode '${MODE}'; expected 'desktop' or 'kiosk'"
  exit 1
fi

if [[ "${PROFILE}" != "generic" && "${PROFILE}" != "gpd-pocket3" ]]; then
  echo "Invalid --profile '${PROFILE}'; expected 'generic' or 'gpd-pocket3'"
  exit 1
fi

detect_wired_iface() {
  local p name real
  for p in /sys/class/net/*; do
    name="$(basename "${p}")"
    [[ "${name}" == "lo" ]] && continue
    [[ -e "${p}/wireless" || -e "${p}/phy80211" ]] && continue
    real="$(readlink -f "${p}" 2>/dev/null || echo "")"
    [[ "${real}" == *"/virtual/"* ]] && continue
    echo "${name}"
    return 0
  done
  echo "eth0"
}

detect_wifi_iface() {
  local p name real
  for p in /sys/class/net/*; do
    name="$(basename "${p}")"
    [[ "${name}" == "lo" ]] && continue
    if [[ -e "${p}/wireless" || -e "${p}/phy80211" ]]; then
      real="$(readlink -f "${p}" 2>/dev/null || echo "")"
      [[ "${real}" == *"/virtual/"* ]] && continue
      echo "${name}"
      return 0
    fi
  done
  echo "wlan0"
}

if [[ -z "${IFACE}" ]]; then
  IFACE="$(detect_wired_iface)"
fi
WIFI_IFACE="$(detect_wifi_iface)"

echo "==> [1/6] Installing Linux networking packages (iface=${IFACE}, wifi=${WIFI_IFACE}, profile=${PROFILE}, mode=${MODE})..."
apt-get update -qq
apt-get install -y \
  lldpd ethtool iproute2 iputils-ping tcpdump arp-scan ieee-data iw \
  iperf3 traceroute bluez nmap network-manager python3-venv python3-pip curl

if apt-cache show firmware-iwlwifi >/dev/null 2>&1; then
  apt-get install -y firmware-iwlwifi || true
fi

echo "==> [2/6] Configuring lldpd for LLDP, LLDP-MED, CDP, EDP, FDP & SONMP..."
cat >/etc/default/lldpd <<'EOF'
# Enable Cisco CDP (-c), Extreme EDP (-e), Foundry FDP (-f), Nortel SONMP (-s)
DAEMON_ARGS="-c -e -f -s"
EOF

mkdir -p /etc/lldpd.d
cat >/etc/lldpd.d/nettester.conf <<EOF
configure system interface pattern ${IFACE},eth*,en*,!wl*
configure med fast-start enable
EOF

systemctl enable lldpd
systemctl restart lldpd

echo "==> [3/6] Enforcing ip_forward=0 & disabling wait-online boot stalls..."
sysctl -w net.ipv4.ip_forward=0 >/dev/null || true
systemctl disable NetworkManager-wait-online.service 2>/dev/null || true
systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true

echo "==> [4/6] Ensuring optional tailcat binary for ephemeral WireGuard/DERP tunnels..."
if ! command -v tailcat >/dev/null 2>&1; then
  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64|amd64) TC_ARCH="amd64" ;;
    aarch64|arm64) TC_ARCH="arm64" ;;
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
      echo "    [warn] Could not resolve tailcat release for ${TC_ARCH} — skipping"
    fi
  fi
fi

echo "==> [5/6] Setting up Python virtual environment & pi-nettester.service..."
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --upgrade pip -q
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt" -q

sed "s|__APP_DIR__|${APP_DIR}|g; s|__IFACE__|${IFACE}|g" \
  "${APP_DIR}/systemd/pi-nettester.service" >/etc/systemd/system/pi-nettester.service

mkdir -p /etc/systemd/system/pi-nettester.service.d
cat >/etc/systemd/system/pi-nettester.service.d/x86-env.conf <<EOF
[Service]
Environment="NETTESTER_WIFI_IFACE=${WIFI_IFACE}"
EOF

systemctl daemon-reload
systemctl enable pi-nettester.service
systemctl restart pi-nettester.service

if [[ "${PROFILE}" == "gpd-pocket3" ]]; then
  echo "==> Applying GPD Pocket 3 display & touch calibration quirks..."
  mkdir -p /etc/default/grub.d
  cat >/etc/default/grub.d/90-jacktrace-gpd-pocket3.cfg <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT fbcon=rotate:1 video=DSI-1:panel_orientation=right_side_up"
EOF
  if command -v update-grub >/dev/null 2>&1; then
    update-grub || true
  fi

  mkdir -p /etc/udev/rules.d
  cat >/etc/udev/rules.d/99-gpd-pocket3-touch.rules <<'EOF'
ACTION=="add|change", SUBSYSTEM=="input", KERNEL=="event*", ATTRS{name}=="GXTP7380:00 27C6:0113*", ENV{LIBINPUT_CALIBRATION_MATRIX}="0 1 0 -1 0 1"
EOF
  udevadm control --reload-rules 2>/dev/null || true
  udevadm trigger --subsystem-match=input 2>/dev/null || true
fi

echo "==> [6/6] Configuring JackTrace UI mode '${MODE}'..."
if [[ "${MODE}" == "desktop" ]]; then
  cat >/usr/local/bin/jacktrace-app <<'EOF'
#!/usr/bin/env bash
set -e
for _ in $(seq 1 20); do
  if curl -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:8080/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.4
done

URL="http://127.0.0.1:8080/?mode=app"
for bin in chromium chromium-browser google-chrome microsoft-edge; do
  if command -v "${bin}" >/dev/null 2>&1; then
    exec "${bin}" --app="${URL}" --no-first-run --noerrdialogs
  fi
done
exec xdg-open "${URL}"
EOF
  chmod +x /usr/local/bin/jacktrace-app

  mkdir -p /usr/share/applications
  cat >/usr/share/applications/jacktrace.desktop <<'EOF'
[Desktop Entry]
Type=Application
Name=JackTrace Network Analyzer
Comment=Field Network Analyzer & Cable/Wi-Fi Workbench
Exec=/usr/local/bin/jacktrace-app
Icon=network-wired
Terminal=false
Categories=Network;System;Utility;
StartupNotify=true
EOF
else
  if [[ -z "${KIOSK_USER}" ]]; then
    echo "Cannot determine non-root kiosk user; create a user first and re-run with sudo."
    exit 1
  fi
  CHROME_PKG="chromium"
  if ! apt-cache show chromium >/dev/null 2>&1; then
    CHROME_PKG="chromium-browser"
  fi
  apt-get install -y cage wlr-randr seatd libgl1-mesa-dri fonts-dejavu-core fonts-noto-color-emoji "${CHROME_PKG}"
  CHROME_BIN="$(command -v chromium || command -v chromium-browser)"
  usermod -aG video,render,input,tty "${KIOSK_USER}" || true
  systemctl enable seatd || true
  systemctl start seatd || true

  ROTATE_CMD=""
  if [[ "${PROFILE}" == "gpd-pocket3" ]]; then
    ROTATE_CMD='(sleep 2 && wlr-randr --output DSI-1 --transform 270 --scale 1.5 2>/dev/null || true) &'
  fi

  cat >/usr/local/bin/jacktrace-kiosk-launch <<EOF
#!/usr/bin/env bash
set -e
for _ in {1..24}; do
  if curl -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:8080/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

${ROTATE_CMD}
rm -rf /tmp/jacktrace-chromium
exec "${CHROME_BIN}" \\
  --kiosk \\
  --ozone-platform=wayland \\
  --touch-events=enabled \\
  --overscroll-history-navigation=0 \\
  --noerrdialogs \\
  --disable-infobars \\
  --disable-session-crashed-bubble \\
  --no-first-run \\
  --check-for-update-interval=31536000 \\
  --user-data-dir=/tmp/jacktrace-chromium \\
  "http://127.0.0.1:8080/?mode=app"
EOF
  chmod +x /usr/local/bin/jacktrace-kiosk-launch

  cat >/etc/systemd/system/jacktrace-kiosk.service <<EOF
[Unit]
Description=JackTrace Fullscreen Wayland Kiosk (Cage + Chromium)
After=systemd-user-sessions.service pi-nettester.service seatd.service
Wants=pi-nettester.service seatd.service
Conflicts=getty@tty1.service

[Service]
User=${KIOSK_USER}
PAMName=login
TTYPath=/dev/tty1
StandardInput=tty-fail
Environment="XDG_SESSION_TYPE=wayland"
Environment="WLR_LIBINPUT_NO_DEVICES=1"
ExecStart=/usr/bin/cage -s -- /usr/local/bin/jacktrace-kiosk-launch
Restart=always
RestartSec=2

[Install]
WantedBy=graphical.target multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable jacktrace-kiosk.service
fi

echo ""
echo "============================================================"
echo " JackTrace x86_64 Setup Complete!"
echo " Wired Test Port : ${IFACE}"
echo " Wi-Fi Interface : ${WIFI_IFACE}"
echo " Profile / Mode  : ${PROFILE} / ${MODE}"
echo " App UI URL      : http://127.0.0.1:8080/?mode=app"
echo " Service Logs    : sudo journalctl -u pi-nettester -f"
echo "============================================================"
