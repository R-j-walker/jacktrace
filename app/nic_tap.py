import asyncio
import os
import re
import shutil
import subprocess
from typing import Callable, List, Optional, Tuple

from .config import settings
from .models import InlineTapState, NetworkHardwareState, NicInterfaceInfo

IFACE_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{2,15}$")


def _resolve_bin(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for prefix in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        cand = f"{prefix}/{name}"
        if os.path.exists(cand):
            return cand
    return name


def _run_sys(cmd: List[str], timeout: float = 3.0) -> Tuple[int, str, str]:
    resolved = [_resolve_bin(cmd[0]), *cmd[1:]]
    try:
        proc = subprocess.run(resolved, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return -1, "", str(exc)


def _read_sysfs_file(path: str, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return default


def parse_ethtool_max_speed(ethtool_text: str) -> int:
    """Detect maximum supported Ethernet speed (Mbps) from `ethtool <iface>` output."""
    sup_block = ethtool_text or ""
    m_sup = re.search(
        r"Supported link modes:(.*?)(?:\n\t[A-Z]|\Z)",
        sup_block,
        re.DOTALL,
    )
    if m_sup:
        sup_block = m_sup.group(1)

    for speed, token in ((10000, "10000base"), (5000, "5000base"), (2500, "2500base"), (1000, "1000base")):
        if token in sup_block:
            return speed
    return 100


def validate_eth_iface(iface: str) -> str:
    clean = (iface or "").strip()
    if not IFACE_NAME_RE.match(clean):
        raise ValueError("Invalid Ethernet interface name")
    low = clean.lower()
    if low == "lo" or low.startswith(("br", "wlan", "wlp", "docker", "veth", "virbr")):
        raise ValueError(f"Interface '{clean}' cannot be used as a wired test port")
    return clean


def _is_wired_nic_dir(net_dir: str, name: str) -> bool:
    low = name.lower()
    if low == "lo" or "." in name:
        return False
    if low.startswith(("br", "docker", "veth", "virbr", "wlan", "wlp")):
        return False
    base = os.path.join(net_dir, name)
    if not os.path.exists(os.path.join(base, "device")):
        return False
    if os.path.exists(os.path.join(base, "wireless")) or os.path.exists(os.path.join(base, "phy80211")):
        return False
    return True


def enumerate_ethernet_nics(active_iface: str, demo_mode: bool) -> List[NicInterfaceInfo]:
    if demo_mode:
        return [
            NicInterfaceInfo(
                iface="eth0",
                mac="DC:A6:32:8F:14:2B",
                carrier_up=True,
                operstate="up",
                speed_mbps=1000,
                max_speed_mbps=1000,
                driver="bcmgenet",
                is_usb=False,
                supports_2500=False,
                active=(active_iface == "eth0"),
            ),
            NicInterfaceInfo(
                iface="eth1",
                mac="00:E0:4C:68:25:01",
                carrier_up=True,
                operstate="up",
                speed_mbps=2500,
                max_speed_mbps=2500,
                driver="r8152",
                is_usb=True,
                supports_2500=True,
                active=(active_iface == "eth1"),
            ),
        ]

    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return [NicInterfaceInfo(iface=active_iface, active=True)]

    nics: List[NicInterfaceInfo] = []
    for name in sorted(os.listdir(net_dir)):
        if not _is_wired_nic_dir(net_dir, name):
            continue
        base = os.path.join(net_dir, name)
        mac = _read_sysfs_file(os.path.join(base, "address"), "—").upper()
        carrier_up = _read_sysfs_file(os.path.join(base, "carrier"), "0") == "1"
        operstate = _read_sysfs_file(os.path.join(base, "operstate"), "down")
        spd_raw = _read_sysfs_file(os.path.join(base, "speed"), "")
        speed_mbps = int(spd_raw) if (carrier_up and spd_raw.isdigit() and int(spd_raw) > 0) else None

        drv_link = os.path.realpath(os.path.join(base, "device", "driver"))
        driver = os.path.basename(drv_link) if os.path.exists(drv_link) else "unknown"
        dev_path = os.path.realpath(os.path.join(base, "device"))
        is_usb = "/usb" in dev_path.lower() or name.startswith("enx")

        rc, eth_out, _ = _run_sys(["ethtool", name], timeout=2.0)
        max_spd = parse_ethtool_max_speed(eth_out) if rc == 0 and eth_out else (speed_mbps or 1000)

        nics.append(
            NicInterfaceInfo(
                iface=name,
                mac=mac,
                carrier_up=carrier_up,
                operstate=operstate,
                speed_mbps=speed_mbps,
                max_speed_mbps=max_spd,
                driver=driver,
                is_usb=is_usb,
                supports_2500=(max_spd >= 2500),
                active=(name == active_iface),
            )
        )

    if not nics:
        nics.append(NicInterfaceInfo(iface=active_iface, active=True))
    return nics


class NicTapManager:
    """Manages Dual-NIC Linux bridge `br0` transparent inline tap with LLDP/802.1X passthrough."""

    def __init__(self, on_change: Optional[Callable[[], None]] = None) -> None:
        self.on_change = on_change
        self.tap = InlineTapState()

    def _notify(self) -> None:
        if self.on_change:
            self.on_change()

    @staticmethod
    def _enable_live_bridge_sync(nic_a: str, nic_b: str) -> Tuple[bool, str]:
        if os.name == "nt":
            return False, "Inline Tap requires Linux bridge kernel module"
        if not os.path.isdir(f"/sys/class/net/{nic_a}") or not os.path.isdir(f"/sys/class/net/{nic_b}"):
            return (
                False,
                "Plug a USB Ethernet adapter (e.g. USB 2.5GbE) into the Pi to enable Dual-NIC Inline Tap.",
            )

        # CRITICAL SAFETY: ensure IPv4 routing/forwarding is disabled across bridge
        _run_sys(["sysctl", "-w", "net.ipv4.ip_forward=0"], timeout=2.0)
        _run_sys(["modprobe", "bridge"], timeout=3.0)
        _run_sys(["ip", "link", "del", "br0"], timeout=2.0)

        rc, _o, err = _run_sys(["ip", "link", "add", "name", "br0", "type", "bridge", "stp_state", "0"], timeout=3.0)
        if rc != 0:
            return False, f"Failed to create br0: {err or 'ip link add failed'}"

        # Forward link-local group multicast (LLDP 01:80:c2:00:00:0e + 802.1X EAPOL 01:80:c2:00:00:03)
        fwd_path = "/sys/class/net/br0/bridge/group_fwd_mask"
        mask_ok = False
        for mask in ("0xfff8\n", "0x4008\n"):
            try:
                with open(fwd_path, "w", encoding="utf-8") as fh:
                    fh.write(mask)
                mask_ok = True
                break
            except OSError:
                continue

        for nic in (nic_a, nic_b):
            rc, _o, err = _run_sys(["ip", "link", "set", nic, "master", "br0", "promisc", "on", "up"], timeout=3.0)
            if rc != 0:
                NicTapManager._disable_live_bridge_sync(nic_a, nic_b)
                return False, f"Failed to attach {nic} to br0: {err or 'ip link failed'}"

        rc, _o, err = _run_sys(["ip", "link", "set", "br0", "promisc", "on", "up"], timeout=3.0)
        if rc != 0:
            NicTapManager._disable_live_bridge_sync(nic_a, nic_b)
            return False, f"Failed to bring br0 up: {err}"

        note = "LLDP + 802.1X passthrough active" if mask_ok else "br0 active (standard bridge mask)"
        return True, f"Inline Tap Active ({nic_a} ⇄ br0 ⇄ {nic_b}) • {note}"

    @staticmethod
    def _disable_live_bridge_sync(nic_a: str = "eth0", nic_b: str = "") -> None:
        if os.name == "nt":
            return
        _run_sys(["sysctl", "-w", "net.ipv4.ip_forward=0"], timeout=2.0)
        for nic in {n for n in (nic_a, nic_b) if n}:
            if os.path.isdir(f"/sys/class/net/{nic}"):
                _run_sys(["ip", "link", "set", nic, "nomaster", "promisc", "off"], timeout=2.0)
        if os.path.isdir("/sys/class/net/br0"):
            _run_sys(["ip", "link", "set", "br0", "down"], timeout=2.0)
            _run_sys(["ip", "link", "del", "br0"], timeout=2.0)

    async def enable_tap(self, nic_a: str, nic_b: str, demo_mode: bool) -> Tuple[bool, str]:
        clean_a = validate_eth_iface(nic_a)
        clean_b = validate_eth_iface(nic_b)
        if clean_a == clean_b:
            raise ValueError("Inline Tap requires two different Ethernet interfaces (e.g. eth0 + eth1)")

        if demo_mode:
            self.tap = InlineTapState(
                active=True,
                bridge_iface="br0",
                nic_a=clean_a,
                nic_b=clean_b,
                eapol_lldp_passthrough=True,
                rx_packets=1482,
                tx_packets=1396,
                status=f"Demo Tap Active ({clean_a} ⇄ br0 ⇄ {clean_b})",
                error="",
            )
            self._notify()
            return True, self.tap.status

        ok, msg = await asyncio.to_thread(self._enable_live_bridge_sync, clean_a, clean_b)
        if ok:
            self.tap = InlineTapState(
                active=True,
                bridge_iface="br0",
                nic_a=clean_a,
                nic_b=clean_b,
                eapol_lldp_passthrough=True,
                status=msg,
                error="",
            )
        else:
            self.tap = InlineTapState(
                active=False,
                bridge_iface="br0",
                nic_a=clean_a,
                nic_b=clean_b,
                status="Inactive",
                error=msg,
            )
        self._notify()
        return ok, msg

    async def disable_tap(self, demo_mode: bool) -> Tuple[bool, str]:
        prev_a = self.tap.nic_a or settings.iface
        prev_b = self.tap.nic_b
        if not demo_mode:
            await asyncio.to_thread(self._disable_live_bridge_sync, prev_a, prev_b)
        self.tap = InlineTapState(
            active=False,
            bridge_iface="br0",
            nic_a=prev_a,
            nic_b=prev_b,
            status="Inactive",
            error="",
        )
        self._notify()
        return True, "Inline Tap disabled"

    def shutdown(self) -> None:
        if os.name != "nt":
            self._disable_live_bridge_sync(self.tap.nic_a or settings.iface, self.tap.nic_b)
        self.tap.active = False
        self.tap.status = "Inactive"

    def build_state(self, active_iface: str, demo_mode: bool) -> NetworkHardwareState:
        nics = enumerate_ethernet_nics(active_iface, demo_mode=demo_mode)
        tap_copy = self.tap.model_copy()
        if tap_copy.active and not demo_mode and os.name != "nt":
            rx = _read_sysfs_file("/sys/class/net/br0/statistics/rx_packets", "0")
            tx = _read_sysfs_file("/sys/class/net/br0/statistics/tx_packets", "0")
            tap_copy.rx_packets = int(rx) if rx.isdigit() else 0
            tap_copy.tx_packets = int(tx) if tx.isdigit() else 0
        return NetworkHardwareState(
            active_iface=active_iface,
            nics=nics,
            tap=tap_copy,
        )
