import glob
import os
import socket
import subprocess
from pathlib import Path
from typing import Optional, Tuple, Union

from .models import SystemHealthState

DEFAULT_CMDLINE_PATH = Path("/boot/firmware/cmdline.txt")
DSI_ROTATE_TOKEN = "video=DSI-1:800x480M@60,rotate=180"


def _find_backlight_dir() -> Optional[str]:
    dirs = sorted(glob.glob("/sys/class/backlight/*"))
    return dirs[0] if dirs else None


def read_dsi_flipped(cmdline_path: Union[str, Path] = DEFAULT_CMDLINE_PATH) -> bool:
    """Check whether 180-degree DSI KMS rotation token is present in kernel cmdline.txt."""
    try:
        text = Path(cmdline_path).read_text(encoding="utf-8", errors="ignore")
        return "video=DSI-1:" in text and "rotate=180" in text
    except OSError:
        return False


def set_dsi_flipped(
    flipped: bool,
    cmdline_path: Union[str, Path] = DEFAULT_CMDLINE_PATH,
) -> Tuple[bool, str]:
    """Safely add or remove 180-degree DSI rotation token in kernel cmdline.txt (applies after reboot)."""
    p = Path(cmdline_path)
    try:
        if not p.is_file():
            return False, f"Cmdline file not found: {p}"
        raw = p.read_text(encoding="utf-8", errors="ignore").strip()
        tokens = [t for t in raw.split() if not t.startswith("video=DSI-1:")]
        if flipped:
            tokens.append(DSI_ROTATE_TOKEN)
        p.write_text(" ".join(tokens) + "\n", encoding="utf-8")
        lbl = "180° Flipped" if flipped else "0° Normal"
        return True, f"DSI orientation set to {lbl} (reboot Pi to apply)"
    except OSError as exc:
        return False, str(exc)


def read_overlayfs_state() -> Tuple[bool, bool]:
    """Return (overlayfs_active_now, overlayfs_enabled_for_next_boot)."""
    if os.name == "nt":
        return False, False
    active_now = False
    try:
        mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="ignore")
        for line in mounts.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "/" and parts[2] == "overlay":
                active_now = True
                break
    except OSError:
        pass

    next_boot = active_now
    try:
        proc = subprocess.run(
            ["sudo", "-n", "raspi-config", "nonint", "get_overlay_conf"],
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        if proc.returncode == 0:
            next_boot = proc.stdout.strip() == "0"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return active_now, next_boot


def set_overlayfs_enabled(enable: bool) -> Tuple[bool, str]:
    """Enable or disable Raspberry Pi OS OverlayFS read-only root (applies after reboot)."""
    if os.name == "nt":
        return False, "OverlayFS toggle requires Raspberry Pi OS (Linux)"
    subcmd = "enable_overlayfs" if enable else "disable_overlayfs"
    try:
        proc = subprocess.run(
            ["sudo", "-n", "raspi-config", "nonint", subcmd],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )
        if proc.returncode == 0:
            lbl = "Read-Only OverlayFS enabled" if enable else "Read-Only OverlayFS disabled"
            return True, f"{lbl} (reboot Pi to apply)"
        detail = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        return False, f"raspi-config {subcmd} failed: {detail[:90]}"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)[:90]


def read_system_health(
    screen_flipped: Optional[bool] = None,
    reboot_required: bool = False,
) -> SystemHealthState:
    hostname = socket.gethostname()
    cpu_temp: Optional[float] = None
    uptime_str = "—"
    backlight_pct: Optional[int] = None
    flipped = read_dsi_flipped() if (os.name != "nt" and screen_flipped is None) else bool(screen_flipped)
    overlay_active, overlay_pending = read_overlayfs_state()

    if os.name != "nt":
        # Raspberry Pi thermal zone
        try:
            with open("/sys/class/thermal/thermal_zone0/temp", "r", encoding="utf-8") as fh:
                milli = int(fh.read().strip())
                cpu_temp = round(milli / 1000.0, 1)
        except OSError:
            pass

        # Uptime
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as fh:
                secs = int(float(fh.read().split()[0]))
                hrs, rem = divmod(secs, 3600)
                mins, _ = divmod(rem, 60)
                uptime_str = f"{hrs}h {mins}m" if hrs else f"{mins}m"
        except OSError:
            pass

        # DSI / panel backlight percentage
        bl_dir = _find_backlight_dir()
        if bl_dir:
            try:
                with open(os.path.join(bl_dir, "brightness"), "r", encoding="utf-8") as fb:
                    cur = int(fb.read().strip())
                with open(os.path.join(bl_dir, "max_brightness"), "r", encoding="utf-8") as fm:
                    mx = max(1, int(fm.read().strip()))
                backlight_pct = int(round((cur / mx) * 100))
            except OSError:
                pass
    else:
        cpu_temp = 46.5
        uptime_str = "1h 14m"
        backlight_pct = 100

    return SystemHealthState(
        hostname=hostname,
        cpu_temp_c=cpu_temp,
        uptime_str=uptime_str,
        backlight_pct=backlight_pct,
        screen_flipped=flipped,
        reboot_required=reboot_required,
        overlayfs_active=overlay_active,
        overlayfs_pending_enable=overlay_pending,
    )


def set_dsi_backlight(pct: int) -> bool:
    pct = max(15, min(100, pct))
    bl_dir = _find_backlight_dir()
    if not bl_dir:
        return False
    try:
        with open(os.path.join(bl_dir, "max_brightness"), "r", encoding="utf-8") as fm:
            mx = max(1, int(fm.read().strip()))
        val = max(1, int(round((pct / 100.0) * mx)))
        with open(os.path.join(bl_dir, "brightness"), "w", encoding="utf-8") as fb:
            fb.write(str(val))
        return True
    except OSError:
        return False


def trigger_power_action(action: str) -> bool:
    """Safely shut down or reboot the Raspberry Pi before unplugging the USB-C power bank."""
    if os.name == "nt":
        return False
    if action == "shutdown":
        subprocess.Popen(["sudo", "-n", "shutdown", "-h", "now"])
        return True
    if action == "reboot":
        subprocess.Popen(["sudo", "-n", "reboot"])
        return True
    return False
