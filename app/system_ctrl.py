import glob
import os
import platform
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Optional, Tuple, Union

from .models import PlatformCapabilities, SystemHealthState

DEFAULT_CMDLINE_PATH = Path("/boot/firmware/cmdline.txt")
DSI_ROTATE_TOKEN = "video=DSI-1:800x480M@60,rotate=180"
_NON_TDR_DRIVERS = frozenset({"r8169", "r8125", "r8152", "ax88179_178a", "cdc_ncm"})


def detect_is_raspberry_pi(
    model_paths: Tuple[str, ...] = (
        "/proc/device-tree/model",
        "/sys/firmware/devicetree/base/model",
    ),
) -> bool:
    """Return True when running on Raspberry Pi hardware."""
    if os.name == "nt" or platform.system() != "Linux":
        return False
    for path in model_paths:
        try:
            txt = Path(path).read_text(encoding="utf-8", errors="ignore")
            if "raspberry pi" in txt.lower():
                return True
        except OSError:
            continue
    return False


def read_cpu_temp_c(thermal_root: str = "/sys/class/thermal") -> Optional[float]:
    """Read CPU temperature in Celsius, preferring x86_pkg_temp or cpu-thermal zones."""
    if not os.path.isdir(thermal_root):
        return None

    zones: list[Tuple[str, str]] = []
    try:
        entries = sorted(os.listdir(thermal_root))
    except OSError:
        return None

    for name in entries:
        if not name.startswith("thermal_zone"):
            continue
        zdir = os.path.join(thermal_root, name)
        temp_path = os.path.join(zdir, "temp")
        if not os.path.isfile(temp_path):
            continue
        ztype = ""
        try:
            ztype = Path(os.path.join(zdir, "type")).read_text(encoding="utf-8", errors="ignore").strip().lower()
        except OSError:
            pass
        zones.append((ztype, temp_path))

    preferred_order = ("x86_pkg_temp", "cpu-thermal", "cpu_thermal", "soc-thermal", "coretemp", "k10temp", "acpitz")
    ordered_paths: list[str] = []
    for pref in preferred_order:
        for ztype, tpath in zones:
            if ztype == pref and tpath not in ordered_paths:
                ordered_paths.append(tpath)
    for _, tpath in zones:
        if tpath not in ordered_paths:
            ordered_paths.append(tpath)

    for tpath in ordered_paths:
        try:
            raw = Path(tpath).read_text(encoding="utf-8", errors="ignore").strip()
            milli = int(raw)
            val = round(milli / 1000.0, 1) if abs(milli) >= 1000 else round(float(milli), 1)
            if -20.0 <= val <= 130.0:
                return val
        except (OSError, ValueError):
            continue
    return None


def read_battery_status(power_supply_root: str = "/sys/class/power_supply") -> Tuple[Optional[int], str]:
    """Read primary laptop/UPS battery capacity (%) and charging status from sysfs."""
    if not os.path.isdir(power_supply_root):
        return None, ""
    try:
        names = sorted(os.listdir(power_supply_root))
    except OSError:
        return None, ""

    candidates: list[str] = []
    for name in names:
        pdir = os.path.join(power_supply_root, name)
        if name.upper().startswith("BAT"):
            candidates.insert(0, pdir)
            continue
        try:
            ptype = Path(os.path.join(pdir, "type")).read_text(encoding="utf-8", errors="ignore").strip().lower()
            if ptype == "battery":
                candidates.append(pdir)
        except OSError:
            continue

    for pdir in candidates:
        cap_file = os.path.join(pdir, "capacity")
        if not os.path.isfile(cap_file):
            continue
        try:
            cap_val = int(Path(cap_file).read_text(encoding="utf-8", errors="ignore").strip())
            cap_val = max(0, min(100, cap_val))
        except (OSError, ValueError):
            continue
        status = ""
        try:
            status = Path(os.path.join(pdir, "status")).read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            pass
        return cap_val, status

    return None, ""


def _read_nic_driver_name(iface: str) -> str:
    if not iface:
        return ""
    drv_path = os.path.join("/sys/class/net", iface, "device", "driver")
    if not os.path.exists(drv_path):
        return ""
    try:
        return os.path.basename(os.path.realpath(drv_path)).lower()
    except OSError:
        return ""


def _find_wayland_session() -> Optional[Tuple[str, str, str]]:
    """Locate an active Wayland socket under /run/user/<uid>/wayland-0 and return (username, runtime_dir, display)."""
    run_user = Path("/run/user")
    if not run_user.is_dir():
        return None
    try:
        for entry in sorted(run_user.iterdir()):
            sock = entry / "wayland-0"
            if not sock.exists():
                continue
            try:
                uid = int(entry.name)
            except ValueError:
                continue
            username = ""
            try:
                import pwd
                username = pwd.getpwuid(uid).pw_name
            except Exception:
                pass
            return username, str(entry), "wayland-0"
    except OSError:
        pass
    return None


def set_wayland_flip(
    flipped: bool,
    output: str = "DSI-1",
    scale: str = "1.5",
) -> Tuple[bool, str]:
    """Rotate active Wayland kiosk output live via wlr-randr (270 normal landscape, 90 flipped tablet mode)."""
    if os.name == "nt":
        return False, "Live Wayland rotation requires Linux"
    wlr = shutil.which("wlr-randr")
    if not wlr:
        return False, "wlr-randr not installed"
    sess = _find_wayland_session()
    if not sess:
        return False, "No active Wayland session found"
    username, runtime_dir, display = sess
    transform = "90" if flipped else "270"
    base_cmd = [
        "env",
        f"XDG_RUNTIME_DIR={runtime_dir}",
        f"WAYLAND_DISPLAY={display}",
        wlr,
        "--output",
        output,
        "--transform",
        transform,
        "--scale",
        scale,
    ]
    cmds = [base_cmd]
    if username and hasattr(os, "geteuid") and os.geteuid() == 0:
        cmds = [["sudo", "-n", "-u", username, *base_cmd]]
    elif username:
        cmds.append(["sudo", "-n", "-u", username, *base_cmd])

    last_err = "wlr-randr failed"
    for cmd in cmds:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4.0, check=False)
            if proc.returncode == 0:
                lbl = "180° Flipped" if flipped else "0° Normal"
                return True, f"Display rotated live to {lbl} (transform {transform})"
            last_err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            last_err = str(exc)
    return False, last_err[:120]


def detect_platform_capabilities(
    active_iface: str = "eth0",
    demo_mode: bool = False,
    battery_pct: Optional[int] = None,
) -> PlatformCapabilities:
    """Detect runtime hardware capabilities for Raspberry Pi, x86 Linux, or Demo hosts."""
    arch = platform.machine() or ""
    if demo_mode or os.name == "nt" or platform.system() != "Linux":
        return PlatformCapabilities(
            platform_kind="demo",
            arch=arch,
            is_raspberry_pi=False,
            has_battery=(battery_pct is not None),
            supports_backlight=True,
            supports_dsi_flip=True,
            supports_live_flip=False,
            supports_overlayfs=True,
            supports_tdr=True,
        )

    is_pi = detect_is_raspberry_pi()
    is_x86 = arch.lower() in ("x86_64", "amd64", "i686", "i386")
    kind = "raspberry_pi" if is_pi else ("x86_linux" if is_x86 else "generic_linux")

    bl_ok = _find_backlight_dir() is not None
    dsi_flip_ok = is_pi and DEFAULT_CMDLINE_PATH.is_file()
    live_flip_ok = (not is_pi) and (shutil.which("wlr-randr") is not None) and (_find_wayland_session() is not None)
    overlay_ok = is_pi and (shutil.which("raspi-config") is not None)

    drv = _read_nic_driver_name(active_iface)
    supports_tdr = drv not in _NON_TDR_DRIVERS

    return PlatformCapabilities(
        platform_kind=kind,
        arch=arch,
        is_raspberry_pi=is_pi,
        has_battery=(battery_pct is not None),
        supports_backlight=bl_ok,
        supports_dsi_flip=dsi_flip_ok,
        supports_live_flip=live_flip_ok,
        supports_overlayfs=overlay_ok,
        supports_tdr=supports_tdr,
    )


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
    if cmdline_path == DEFAULT_CMDLINE_PATH and not detect_is_raspberry_pi():
        return False, "DSI rotation toggle requires Raspberry Pi OS"
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
    if os.name == "nt" or not detect_is_raspberry_pi():
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
    wifi_iface: str = "wlan0",
    active_iface: str = "eth0",
    demo_mode: bool = False,
) -> SystemHealthState:
    hostname = socket.gethostname()
    cpu_temp: Optional[float] = None
    uptime_str = "—"
    backlight_pct: Optional[int] = None
    battery_pct: Optional[int] = None
    battery_status = ""
    is_pi = detect_is_raspberry_pi()
    flipped = read_dsi_flipped() if (is_pi and screen_flipped is None) else bool(screen_flipped)
    overlay_active, overlay_pending = read_overlayfs_state() if is_pi else (False, False)

    if os.name != "nt":
        cpu_temp = read_cpu_temp_c()
        battery_pct, battery_status = read_battery_status()

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

    caps = detect_platform_capabilities(
        active_iface=active_iface,
        demo_mode=demo_mode,
        battery_pct=battery_pct,
    )

    return SystemHealthState(
        hostname=hostname,
        cpu_temp_c=cpu_temp,
        uptime_str=uptime_str,
        backlight_pct=backlight_pct,
        battery_pct=battery_pct,
        battery_status=battery_status,
        wifi_iface=wifi_iface or "wlan0",
        screen_flipped=flipped,
        reboot_required=reboot_required,
        overlayfs_active=overlay_active,
        overlayfs_pending_enable=overlay_pending,
        capabilities=caps,
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
