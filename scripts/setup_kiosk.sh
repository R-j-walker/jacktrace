#!/usr/bin/env bash
set -euo pipefail

# JackTrace — Waveshare 4.3"/5" DSI Touchscreen Kiosk Installer (Raspberry Pi 4)
# Usage:
#   sudo bash scripts/setup_kiosk.sh           # Standard landscape orientation
#   sudo bash scripts/setup_kiosk.sh --flip    # Flip display + touch 180 degrees

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KIOSK_USER="${SUDO_USER:-$(ls /home | head -n 1)}"
FLIP_180=0

if [[ "${1:-}" == "--flip" ]]; then
  FLIP_180=1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo bash scripts/setup_kiosk.sh"
  exit 1
fi

# 1. Configure /boot/firmware/config.txt (or /boot/config.txt) for Waveshare 4.3"/5" DSI
BOOT_CFG="/boot/firmware/config.txt"
if [[ ! -f "${BOOT_CFG}" && -f "/boot/config.txt" ]]; then
  BOOT_CFG="/boot/config.txt"
fi

echo "==> [1/4] Configuring Waveshare 4.3\"/5\" DSI overlay in ${BOOT_CFG}..."
sed -i '/vc4-kms-dsi-7inch/d' "${BOOT_CFG}"
if [[ "${FLIP_180}" -eq 1 ]]; then
  echo "dtoverlay=vc4-kms-dsi-7inch,invx,invy" >> "${BOOT_CFG}"
else
  echo "dtoverlay=vc4-kms-dsi-7inch" >> "${BOOT_CFG}"
fi

# 2. Install lightweight Wayland kiosk stack + emoji/UI fonts
echo "==> [2/4] Installing Cage Wayland kiosk compositor, Chromium & UI fonts..."
apt-get update -qq
CHROME_PKG="chromium"
if ! apt-cache show chromium >/dev/null 2>&1; then
  CHROME_PKG="chromium-browser"
fi
apt-get install -y cage wlr-randr seatd libgl1-mesa-dri fonts-dejavu-core fonts-noto-color-emoji "${CHROME_PKG}"

CHROME_BIN="$(command -v chromium || command -v chromium-browser)"
usermod -aG video,render,input,tty "${KIOSK_USER}" || true
systemctl enable seatd || true
systemctl start seatd || true

# 3. Create kiosk launcher helper scripts
echo "==> [3/4] Writing /usr/local/bin/jacktrace-kiosk-pre & jacktrace-kiosk-launch..."
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

cat >/usr/local/bin/jacktrace-kiosk-launch <<EOF
#!/usr/bin/env bash
set -e
export XCURSOR_PATH=/usr/share/jacktrace-cursors
export XCURSOR_THEME=default
export XCURSOR_SIZE=24
export WLR_NO_HARDWARE_CURSORS=1

# Wait up to 12s for local JackTrace FastAPI backend on 127.0.0.1:8080
for _ in {1..24}; do
  if curl -fsS --connect-timeout 1 --max-time 2 http://127.0.0.1:8080/ >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if [[ "${FLIP_180}" -eq 1 ]]; then
  (sleep 2 && wlr-randr --output DSI-1 --transform 180 2>/dev/null || true) &
fi

rm -rf /tmp/jacktrace-chromium
exec "${CHROME_BIN}" \\
  --kiosk \\
  --ozone-platform=wayland \\
  --touch-events=enabled \\
  --disable-pinch \\
  --overscroll-history-navigation=0 \\
  --noerrdialogs \\
  --disable-infobars \\
  --disable-session-crashed-bubble \\
  --no-first-run \\
  --check-for-update-interval=31536000 \\
  --user-data-dir=/tmp/jacktrace-chromium \\
  "http://127.0.0.1:8080/?kiosk=1"
EOF
chmod +x /usr/local/bin/jacktrace-kiosk-launch

echo "    Installing isolated transparent Xcursor path (/usr/share/jacktrace-cursors) for Cage 0.1.x + Chromium..."
rm -rf /usr/share/jacktrace-cursors
mkdir -p /usr/share/jacktrace-cursors/default/cursors
cat >/usr/share/jacktrace-cursors/default/index.theme <<'EOF'
[Icon Theme]
Name=default
Comment=Transparent cursor theme for JackTrace touchscreen kiosk
EOF
python3 - <<'PY'
import struct
sizes = [16, 24, 32, 48]
pos = 16 + 12 * len(sizes)
toc, chunks = [], []
for sz in sizes:
    toc.append(struct.pack("<III", 0xFFFD0002, sz, pos))
    px = b"\x00" * (sz * sz * 4)
    chunks.append(struct.pack("<IIIIIIIII", 36, 0xFFFD0002, sz, 1, sz, sz, 0, 0, 0) + px)
    pos += 36 + len(px)
data = struct.pack("<4sIII", b"Xcur", 16, 0x00010000, len(sizes)) + b"".join(toc) + b"".join(chunks)
with open("/usr/share/jacktrace-cursors/default/cursors/left_ptr", "wb") as f:
    f.write(data)
PY
for src_dir in /usr/share/icons/PiXflat/cursors /usr/share/icons/Adwaita/cursors; do
  if [[ -d "${src_dir}" ]]; then
    for cur_file in "${src_dir}"/*; do
      [[ -e "${cur_file}" || -L "${cur_file}" ]] || continue
      cur_name="$(basename "${cur_file}")"
      [[ "${cur_name}" == "left_ptr" ]] && continue
      ln -sf left_ptr "/usr/share/jacktrace-cursors/default/cursors/${cur_name}"
    done
  fi
done
for name in default arrow pointer hand hand1 hand2 pointing_hand openhand closedhand text xterm ibeam watch wait left_ptr_watch progress half-busy crosshair cross grab grabbing not-allowed crossed_circle question_arrow help fleur size_all top_left_arrow ew-resize ns-resize nesw-resize nwse-resize; do
  ln -sf left_ptr "/usr/share/jacktrace-cursors/default/cursors/${name}"
done
for alias_theme in jacktrace-blank PiXflat Adwaita hicolor; do
  ln -sfn default "/usr/share/jacktrace-cursors/${alias_theme}"
done

KIOSK_HOME="$(getent passwd "${KIOSK_USER}" | cut -d: -f6)"
if [[ -n "${KIOSK_HOME}" && -d "${KIOSK_HOME}" ]]; then
  rm -rf "${KIOSK_HOME}/.icons/default" "${KIOSK_HOME}/.local/share/icons/default"
  mkdir -p "${KIOSK_HOME}/.icons" "${KIOSK_HOME}/.local/share/icons" "${KIOSK_HOME}/.config/gtk-3.0"
  ln -sfn /usr/share/jacktrace-cursors/default "${KIOSK_HOME}/.icons/default"
  ln -sfn /usr/share/jacktrace-cursors/default "${KIOSK_HOME}/.local/share/icons/default"
  cat >"${KIOSK_HOME}/.config/gtk-3.0/settings.ini" <<'EOF'
[Settings]
gtk-cursor-theme-name=default
gtk-cursor-theme-size=24
EOF
  chown -Rh "${KIOSK_USER}:${KIOSK_USER}" "${KIOSK_HOME}/.icons" "${KIOSK_HOME}/.local" "${KIOSK_HOME}/.config"
fi

# 4. Install systemd service on tty1
echo "==> [4/4] Installing jacktrace-splash-handoff.service & jacktrace-kiosk.service for user '${KIOSK_USER}'..."
cp "${APP_DIR}/systemd/jacktrace-splash-handoff.service" /etc/systemd/system/jacktrace-splash-handoff.service
sed "s|__KIOSK_USER__|${KIOSK_USER}|g" \
  "${APP_DIR}/systemd/jacktrace-kiosk.service" >/etc/systemd/system/jacktrace-kiosk.service

systemctl disable getty@tty1.service || true
systemctl daemon-reload
systemctl enable jacktrace-splash-handoff.service
systemctl enable jacktrace-kiosk.service

echo ""
echo "============================================================"
echo " Waveshare 4.3\"/5\" DSI Kiosk is configured for '${KIOSK_USER}'!"
echo " Orientation : $( [[ "${FLIP_180}" -eq 1 ]] && echo '180° Flipped' || echo 'Standard 0°' )"
echo " Next Step   : Power off ('sudo shutdown -h now'), connect"
echo "               the 15-pin DSI ribbon cable, and power on!"
echo "============================================================"
