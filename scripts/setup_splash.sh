#!/usr/bin/env bash
set -euo pipefail

# JackTrace — Raspberry Pi 4 Plymouth Boot & Shutdown Splash Installer (800x480 DSI)
# Usage:
#   sudo bash scripts/setup_splash.sh

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/setup_splash.sh"
  exit 1
fi

BOOT_DIR="/boot/firmware"
if [[ ! -d "${BOOT_DIR}" && -d "/boot" ]]; then
  BOOT_DIR="/boot"
fi

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" && -d "/home/${SUDO_USER}" ]]; then
  KIOSK_USER="${SUDO_USER}"
else
  KIOSK_USER="$(ls /home | head -n 1)"
fi

echo "==> [1/6] Installing Plymouth boot splash packages..."
apt-get update -qq
apt-get install -y plymouth plymouth-themes

echo "==> [2/6] Installing JackTrace 800x480 Plymouth theme..."
THEME_DIR="/usr/share/plymouth/themes/jacktrace"
mkdir -p "${THEME_DIR}"

SPLASH_SRC="${APP_DIR}/branding/logos/splash_800x480.png"
LOGO_JPG="${APP_DIR}/branding/logos/concept_1_pinout_pulse.jpg"

if [[ -f "${SPLASH_SRC}" ]]; then
  cp "${SPLASH_SRC}" "${THEME_DIR}/splash.png"
elif [[ -f "${LOGO_JPG}" && -x "${APP_DIR}/.venv/bin/python" ]]; then
  "${APP_DIR}/.venv/bin/python" - <<PY
from PIL import Image
src = Image.open("${LOGO_JPG}").convert("RGB")
w, h = src.size
corners = [src.getpixel((8, 8)), src.getpixel((w - 9, 8)), src.getpixel((8, h - 9)), src.getpixel((w - 9, h - 9))]
bg = tuple(round(sum(c[i] for c in corners) / 4) for i in range(3))
canvas = Image.new("RGB", (800, 480), bg)
scale = min(800 / w, 480 / h)
nw, nh = round(w * scale), round(h * scale)
resized = src.resize((nw, nh), Image.Resampling.LANCZOS)
canvas.paste(resized, ((800 - nw) // 2, (480 - nh) // 2))
canvas.save("${THEME_DIR}/splash.png", "PNG", optimize=True)
PY
else
  echo "ERROR: Neither ${SPLASH_SRC} nor ${LOGO_JPG} found." >&2
  exit 1
fi

cat >"${THEME_DIR}/jacktrace.plymouth" <<'EOF'
[Plymouth Theme]
Name=JackTrace
Description=JackTrace Handheld Network Tester Boot Splash
ModuleName=script

[script]
ImageDir=/usr/share/plymouth/themes/jacktrace
ScriptFile=/usr/share/plymouth/themes/jacktrace/jacktrace.script
EOF

cat >"${THEME_DIR}/jacktrace.script" <<'EOF'
Window.SetBackgroundTopColor(0.067, 0.071, 0.078);
Window.SetBackgroundBottomColor(0.067, 0.071, 0.078);

splash_img = Image("splash.png");
scaled_img = splash_img.Scale(Window.GetWidth(), Window.GetHeight());
splash_sprite = Sprite(scaled_img);
splash_sprite.SetPosition(0, 0, 100);
EOF

mkdir -p /etc/plymouth
cat >/etc/plymouth/plymouthd.conf <<'EOF'
[Daemon]
Theme=jacktrace
ShowDelay=0
DeviceTimeout=5
EOF

echo "==> [3/6] Building initramfs with 'jacktrace' theme..."
plymouth-set-default-theme -R jacktrace

echo "==> [4/6] Configuring quiet firmware & kernel boot flags in ${BOOT_DIR}..."
CFG_FILE="${BOOT_DIR}/config.txt"
if [[ -f "${CFG_FILE}" ]]; then
  if [[ ! -f "${CFG_FILE}.bak" ]]; then
    cp -a "${CFG_FILE}" "${CFG_FILE}.bak"
  fi
  if grep -qE '^disable_splash=' "${CFG_FILE}"; then
    sed -i 's/^disable_splash=.*/disable_splash=1/' "${CFG_FILE}"
  else
    printf '\n# Hide Raspberry Pi firmware rainbow splash\ndisable_splash=1\n' >> "${CFG_FILE}"
  fi
fi

CMD_FILE="${BOOT_DIR}/cmdline.txt"
if [[ -f "${CMD_FILE}" ]]; then
  if [[ ! -f "${CMD_FILE}.bak" ]]; then
    cp -a "${CMD_FILE}" "${CMD_FILE}.bak"
  fi
  python3 - "${CMD_FILE}" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
tokens = p.read_text(encoding="utf-8").strip().split()
updated = []
for tok in tokens:
    if tok == "console=tty1":
        if "console=tty3" not in updated and "console=tty3" not in tokens:
            updated.append("console=tty3")
        continue
    updated.append(tok)

for flag in (
    "quiet",
    "splash",
    "loglevel=3",
    "logo.nologo",
    "vt.global_cursor_default=0",
    "plymouth.ignore-serial-consoles",
):
    if flag not in updated:
        updated.append(flag)

p.write_text(" ".join(updated) + "\n", encoding="utf-8")
PY
fi

echo "==> [5/6] Installing seamless Plymouth-to-Cage handoff (/usr/local/bin/jacktrace-kiosk-pre)..."
cat >/usr/local/bin/jacktrace-kiosk-pre <<'EOF'
#!/usr/bin/env bash
# Hold Plymouth splash until FastAPI serves /, then release DRM cleanly while retaining splash.
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

echo "==> [6/6] Installing jacktrace-splash-handoff.service & updating jacktrace-kiosk.service for user '${KIOSK_USER}'..."
cp "${APP_DIR}/systemd/jacktrace-splash-handoff.service" /etc/systemd/system/jacktrace-splash-handoff.service
sed "s|__KIOSK_USER__|${KIOSK_USER}|g" \
  "${APP_DIR}/systemd/jacktrace-kiosk.service" >/etc/systemd/system/jacktrace-kiosk.service
systemctl daemon-reload
systemctl enable jacktrace-splash-handoff.service
systemctl enable jacktrace-kiosk.service

echo ""
echo "============================================================"
echo " JackTrace Boot Splash is installed!"
echo " Theme         : $(plymouth-set-default-theme)"
echo " Config        : ${CFG_FILE} (disable_splash=1)"
echo " Cmdline       : $(cat "${CMD_FILE}")"
echo "============================================================"
