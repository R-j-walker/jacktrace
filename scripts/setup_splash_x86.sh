#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"

# JackTrace — x86_64 & GPD Pocket 3 Seamless Plymouth Boot Splash Installer
# Usage:
#   sudo bash scripts/setup_splash_x86.sh [--profile generic|gpd-pocket3]

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      sed -n '4,7p' "${BASH_SOURCE[0]}"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/setup_splash_x86.sh"
  exit 1
fi

if [[ -z "${PROFILE}" ]]; then
  if grep -q "G1621-02" /sys/class/dmi/id/product_name 2>/dev/null; then
    PROFILE="gpd-pocket3"
  else
    PROFILE="generic"
  fi
fi

KIOSK_USER="${SUDO_USER:-$(ls /home 2>/dev/null | head -n 1 || true)}"

echo "==> [1/6] Installing Plymouth boot splash packages..."
apt-get update -qq
apt-get install -y plymouth plymouth-themes

echo "==> [2/6] Generating 1920x1200 JackTrace Plymouth theme..."
THEME_DIR="/usr/share/plymouth/themes/jacktrace-x86"
mkdir -p "${THEME_DIR}"

LOGO_JPG="${APP_DIR}/branding/logos/concept_1_pinout_pulse.jpg"
SPLASH_PNG="${APP_DIR}/branding/logos/splash_800x480.png"
SRC_IMG="${SPLASH_PNG}"
FIT_RATIO="1.0"
if [[ ! -f "${SRC_IMG}" ]]; then
  SRC_IMG="${LOGO_JPG}"
  FIT_RATIO="0.62"
fi

if [[ -x "${APP_DIR}/.venv/bin/python" ]] && "${APP_DIR}/.venv/bin/python" -c "import PIL" 2>/dev/null; then
  "${APP_DIR}/.venv/bin/python" - <<PY
from PIL import Image
src = Image.open("${SRC_IMG}").convert("RGB")
w, h = src.size
corners = [src.getpixel((4, 4)), src.getpixel((w - 5, 4)), src.getpixel((4, h - 5)), src.getpixel((w - 5, h - 5))]
bg = tuple(round(sum(c[i] for c in corners) / 4) for i in range(3))
tw, th = 1920, 1200
fit = float("${FIT_RATIO}")
canvas = Image.new("RGB", (tw, th), bg)
scale = min((tw * fit) / w, (th * fit) / h)
nw, nh = max(1, round(w * scale)), max(1, round(h * scale))
resized = src.resize((nw, nh), Image.Resampling.LANCZOS)
canvas.paste(resized, ((tw - nw) // 2, (th - nh) // 2))
canvas.save("${THEME_DIR}/splash.png", "PNG", optimize=True)
PY
elif [[ -f "${SPLASH_PNG}" ]]; then
  cp "${SPLASH_PNG}" "${THEME_DIR}/splash.png"
else
  echo "ERROR: No splash logo found under ${APP_DIR}/branding/logos/" >&2
  exit 1
fi

cat >"${THEME_DIR}/jacktrace-x86.plymouth" <<'EOF'
[Plymouth Theme]
Name=JackTrace x86
Description=JackTrace Network Analyzer Boot Splash
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/jacktrace-x86
ScriptFile=/usr/share/plymouth/themes/jacktrace-x86/jacktrace-x86.script
EOF

cat >"${THEME_DIR}/jacktrace-x86.script" <<'EOF'
Window.SetBackgroundTopColor(0.067, 0.071, 0.078);
Window.SetBackgroundBottomColor(0.067, 0.071, 0.078);

splash_img = Image("splash.png");
ww = Window.GetWidth();
wh = Window.GetHeight();
iw = splash_img.GetWidth();
ih = splash_img.GetHeight();

scale = Math.Min(ww / iw, wh / ih);
nw = Math.Int(iw * scale);
nh = Math.Int(ih * scale);
scaled_img = splash_img.Scale(nw, nh);
splash_sprite = Sprite(scaled_img);
splash_sprite.SetPosition(Math.Int((ww - nw) / 2), Math.Int((wh - nh) / 2), 100);
EOF

mkdir -p /etc/plymouth
cat >/etc/plymouth/plymouthd.conf <<'EOF'
[Daemon]
Theme=jacktrace-x86
ShowDelay=0
DeviceTimeout=5
EOF

echo "==> [3/6] Building initramfs with 'jacktrace-x86' theme..."
plymouth-set-default-theme -R jacktrace-x86

echo "==> [4/6] Configuring quiet GRUB boot parameters..."
mkdir -p /etc/default/grub.d
if [[ "${PROFILE}" == "gpd-pocket3" ]]; then
  cat >/etc/default/grub.d/90-jacktrace-gpd-pocket3.cfg <<'EOF'
GRUB_TIMEOUT=1
GRUB_TIMEOUT_STYLE=hidden
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT fbcon=rotate:1 video=DSI-1:panel_orientation=right_side_up"
EOF
fi

cat >/etc/default/grub.d/91-jacktrace-splash.cfg <<'EOF'
GRUB_TIMEOUT=1
GRUB_TIMEOUT_STYLE=hidden
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT quiet splash loglevel=3 logo.nologo vt.global_cursor_default=0 plymouth.ignore-serial-consoles"
EOF

if command -v update-grub >/dev/null 2>&1; then
  update-grub
fi

echo "==> [5/6] Installing Plymouth-to-Cage DRM handoff (/usr/local/bin/jacktrace-kiosk-pre)..."
cat >/usr/local/bin/jacktrace-kiosk-pre <<'EOF'
#!/usr/bin/env bash
for _ in $(seq 1 24); do
  if curl -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:8080/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if command -v plymouth >/dev/null 2>&1 && plymouth --ping >/dev/null 2>&1; then
  plymouth quit --retain-splash >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if ! plymouth --ping >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
fi
exit 0
EOF
chmod +x /usr/local/bin/jacktrace-kiosk-pre

echo "==> [6/6] Enabling jacktrace-splash-handoff.service..."
cp "${APP_DIR}/systemd/jacktrace-splash-handoff.service" /etc/systemd/system/jacktrace-splash-handoff.service

KIOSK_UNIT="/etc/systemd/system/jacktrace-kiosk.service"
if [[ -f "${KIOSK_UNIT}" ]] && ! grep -q "jacktrace-splash-handoff.service" "${KIOSK_UNIT}"; then
  python3 - "${KIOSK_UNIT}" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
txt = p.read_text(encoding="utf-8")
txt = txt.replace(
    "After=systemd-user-sessions.service pi-nettester.service seatd.service",
    "After=systemd-user-sessions.service pi-nettester.service seatd.service jacktrace-splash-handoff.service",
)
txt = txt.replace(
    "Wants=pi-nettester.service seatd.service",
    "Wants=pi-nettester.service seatd.service jacktrace-splash-handoff.service",
)
txt = txt.replace(
    "Conflicts=getty@tty1.service",
    "Conflicts=getty@tty1.service plymouth-quit.service",
)
p.write_text(txt, encoding="utf-8")
PY
fi

systemctl daemon-reload
systemctl enable jacktrace-splash-handoff.service
if [[ -f "${KIOSK_UNIT}" ]]; then
  systemctl enable jacktrace-kiosk.service
fi

echo ""
echo "============================================================"
echo " JackTrace x86 Boot Splash is installed!"
echo " Theme   : $(plymouth-set-default-theme)"
echo " Profile : ${PROFILE}"
echo " User    : ${KIOSK_USER:-n/a}"
echo "============================================================"
