import asyncio
import json
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .audit import DATA_DIR
from .models import BluetoothPrinterDevice, PrinterState, SavedWallPort, TesterSnapshot

DEFAULT_PRINTER_SETTINGS_PATH = DATA_DIR / "printer_settings.json"
PRINTER_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
PRINTER_NAME_HINTS = (
    "MTP",
    "PT-",
    "RPP",
    "POS",
    "PRINTER",
    "THERMAL",
    "PERIPAGE",
    "NIIMBOT",
    "BIXOLON",
    "EPSON",
    "STAR",
    "ZEBRA",
    "BT-58",
    "58MM",
    "MPT",
)

ESC_INIT = b"\x1b@"
ESC_ALIGN_LEFT = b"\x1ba\x00"
ESC_ALIGN_CENTER = b"\x1ba\x01"
ESC_BOLD_ON = b"\x1bE\x01"
ESC_BOLD_OFF = b"\x1bE\x00"
GS_SIZE_DOUBLE = b"\x1d!\x11"
GS_SIZE_NORMAL = b"\x1d!\x00"
GS_PARTIAL_CUT = b"\x1dV\x42\x00"


def _resolve_bin(name: str) -> str:
    found = shutil.which(name)
    if found:
        return found
    for prefix in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        cand = f"{prefix}/{name}"
        if os.path.exists(cand):
            return cand
    return name


def _ascii_safe(text: str, max_len: int = 32) -> str:
    clean = (
        (text or "-")
        .replace("•", "|")
        .replace("—", "-")
        .replace("–", "-")
        .replace("→", "->")
        .replace("Ω", "Ohm")
    )
    encoded = clean.encode("ascii", errors="replace").decode("ascii")
    return encoded[:max_len]


def _escpos_qr(data: str) -> bytes:
    """Build standard Epson GS ( k Model 2 QR code ESC/POS command."""
    payload = _ascii_safe(data, max_len=140).encode("ascii", errors="replace")
    if not payload:
        return b""
    store_len = len(payload) + 3
    pl = store_len & 0xFF
    ph = (store_len >> 8) & 0xFF
    return b"".join(
        [
            b"\x1d(k\x04\x00\x31\x41\x32\x00",  # Model 2
            b"\x1d(k\x03\x00\x31\x43\x04",      # Module size 4
            b"\x1d(k\x03\x00\x31\x45\x31",      # Error correction M
            b"\x1d(k" + bytes([pl, ph]) + b"\x31\x50\x30" + payload,
            b"\x1d(k\x03\x00\x31\x51\x30",      # Print QR symbol
        ]
    )


def build_wall_drop_label(port: SavedWallPort) -> Tuple[bytes, str]:
    """Generate 58mm ESC/POS bytes and a 32-column plain-text preview for a saved wall drop."""
    lines = [
        f"JACKTRACE | {_ascii_safe(port.job_name, 20)}",
        "--------------------------------",
        f"DROP:   {_ascii_safe(port.drop_label, 24)} [{_ascii_safe(port.verdict, 6)}]",
        f"SWITCH: {_ascii_safe(port.switch_name, 24)}",
        f"PORT:   {_ascii_safe(port.port_id, 24)}",
        f"LINK:   {_ascii_safe(port.speed_summary, 24)}",
        f"VLAN:   {_ascii_safe(port.vlan_summary, 24)}",
        f"PoE:    {_ascii_safe(port.poe_summary, 24)}",
        f"TDR:    {_ascii_safe(port.tdr_summary, 24)}",
        f"IP:     {_ascii_safe(port.ip_cidr, 24)}",
    ]
    if port.notes:
        lines.append(f"NOTE:   {_ascii_safe(port.notes, 24)}")
    lines.append("--------------------------------")
    lines.append(f"SEC: {_ascii_safe(port.security_grade, 10)} | {_ascii_safe(port.saved_at[:16], 16)}")

    qr_data = f"{port.drop_label}|{port.switch_name}|{port.port_id}|{port.vlan_summary}"
    preview = "\n".join([f"      [ {port.drop_label} ]", *lines, f"[QR] {qr_data[:27]}"])

    raw = bytearray()
    raw.extend(ESC_INIT)
    raw.extend(ESC_ALIGN_CENTER)
    raw.extend(ESC_BOLD_ON)
    raw.extend(GS_SIZE_DOUBLE)
    raw.extend((_ascii_safe(port.drop_label, 14) + "\n").encode("ascii"))
    raw.extend(GS_SIZE_NORMAL)
    raw.extend(ESC_BOLD_OFF)
    raw.extend(ESC_ALIGN_LEFT)
    for ln in lines:
        raw.extend((ln + "\n").encode("ascii"))
    raw.extend(ESC_ALIGN_CENTER)
    raw.extend(_escpos_qr(qr_data))
    raw.extend(b"\n\n\n")
    raw.extend(GS_PARTIAL_CUT)
    return bytes(raw), preview


def build_live_receipt(snap: TesterSnapshot) -> Tuple[bytes, str]:
    """Generate 58mm ESC/POS bytes and preview for the currently tested live/demo port."""
    sw_name = snap.switch.switch_name if snap.switch.detected else "UNPATCHED / UNKNOWN"
    sw_model = snap.switch.model if snap.switch.detected else "-"
    port_id = snap.switch.port_id if snap.switch.detected else "-"
    spd = f"{snap.link.speed_mbps or '?'}M {snap.link.duplex}" if snap.link.carrier_up else "NO LINK"
    poe = (
        f"{snap.poe.standard} ({snap.poe.allocated_watts or '?'}W)"
        if snap.poe.supported
        else "None"
    )
    vlan = f"V{snap.vlan.native_vlan}" if snap.vlan.native_vlan is not None else "Untagged"
    if snap.vlan.voice_vlan is not None:
        vlan += f" VoIP:{snap.vlan.voice_vlan}"
    tdr = (
        snap.tdr.overall_verdict
        if snap.tdr.overall_verdict != "NOT_RUN"
        else ("4 Pairs OK" if (snap.link.speed_mbps or 0) >= 1000 else "-")
    )

    lines = [
        "JACKTRACE PORT DIAGNOSTIC",
        "--------------------------------",
        f"VERDICT: {_ascii_safe(snap.autotest_verdict, 23)}",
        f"SWITCH:  {_ascii_safe(sw_name, 23)}",
        f"MODEL:   {_ascii_safe(sw_model, 23)}",
        f"PORT:    {_ascii_safe(port_id, 23)}",
        f"PANEL:   {_ascii_safe(snap.switch.panel.summary, 23)}",
        f"LINK:    {_ascii_safe(spd, 23)}",
        f"PoE:     {_ascii_safe(poe, 23)}",
        f"VLAN:    {_ascii_safe(vlan, 23)}",
        f"IP/GW:   {_ascii_safe(snap.l3.ipv4_address + ' / ' + snap.l3.gateway_ip, 23)}",
        f"TDR:     {_ascii_safe(tdr, 23)}",
        f"SEC:     {_ascii_safe(f'{snap.security.grade} ({snap.security.score}/100)', 23)}",
        "--------------------------------",
        f"NIC: {_ascii_safe(snap.link.iface, 8)}  TIME: {_ascii_safe(snap.timestamp, 10)}",
    ]
    qr_data = f"{sw_name}|{port_id}|{vlan}|{snap.l3.ipv4_address}"
    preview = "\n".join([*lines, f"[QR] {qr_data[:27]}"])

    raw = bytearray()
    raw.extend(ESC_INIT)
    raw.extend(ESC_ALIGN_CENTER)
    raw.extend(ESC_BOLD_ON)
    raw.extend(b"JACKTRACE PORT REPORT\n")
    raw.extend(ESC_BOLD_OFF)
    raw.extend(ESC_ALIGN_LEFT)
    for ln in lines[1:]:
        raw.extend((ln + "\n").encode("ascii"))
    raw.extend(ESC_ALIGN_CENTER)
    raw.extend(_escpos_qr(qr_data))
    raw.extend(b"\n\n\n")
    raw.extend(GS_PARTIAL_CUT)
    return bytes(raw), preview


def parse_bluetoothctl_devices(all_out: str, paired_out: str) -> List[BluetoothPrinterDevice]:
    """Parse `bluetoothctl devices` + `bluetoothctl devices Paired`, sorting thermal printers first."""
    paired_macs = set()
    dev_re = re.compile(r"Device\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.+)")
    for line in (paired_out or "").splitlines():
        m = dev_re.search(line)
        if m:
            paired_macs.add(m.group(1).upper())

    seen = {}
    for line in (all_out or "").splitlines():
        m = dev_re.search(line)
        if not m:
            continue
        mac = m.group(1).upper()
        name = m.group(2).strip()
        seen[mac] = BluetoothPrinterDevice(
            mac=mac,
            name=name,
            paired=(mac in paired_macs),
            connected=False,
        )

    def _sort_key(d: BluetoothPrinterDevice) -> Tuple[int, int, str]:
        up = d.name.upper()
        is_printer_hint = any(h in up for h in PRINTER_NAME_HINTS)
        return (0 if is_printer_hint else 1, 0 if d.paired else 1, up)

    return sorted(seen.values(), key=_sort_key)


class BluetoothPrinterManager:
    """BlueZ discovery + RFCOMM ESC/POS printing manager."""

    def __init__(
        self,
        settings_path: Path = DEFAULT_PRINTER_SETTINGS_PATH,
        on_change: Optional[Callable[[], None]] = None,
    ) -> None:
        self.settings_path = Path(settings_path)
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)
        self.on_change = on_change
        self.state = PrinterState()
        self._load_settings()

    def _notify(self) -> None:
        if self.on_change:
            self.on_change()

    def _load_settings(self) -> None:
        if not self.settings_path.is_file():
            return
        try:
            raw = json.loads(self.settings_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.state.selected_mac = str(raw.get("selected_mac") or "")
                self.state.selected_name = str(raw.get("selected_name") or "Not Paired")
                ch = int(raw.get("rfcomm_channel") or 1)
                self.state.rfcomm_channel = max(1, min(ch, 30))
                if self.state.selected_mac:
                    self.state.last_status = f"Printer selected: {self.state.selected_name}"
        except Exception:
            pass

    def _save_settings(self) -> None:
        payload = {
            "selected_mac": self.state.selected_mac,
            "selected_name": self.state.selected_name,
            "rfcomm_channel": self.state.rfcomm_channel,
        }
        self.settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def _run_cmd(cmd: List[str], timeout: float = 8.0) -> Tuple[int, str, str]:
        resolved = [_resolve_bin(cmd[0]), *cmd[1:]]
        try:
            proc = subprocess.run(resolved, capture_output=True, text=True, timeout=timeout, check=False)
            return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            return -1, "", str(exc)

    def _ensure_bt_powered_sync(self) -> Tuple[bool, str]:
        if os.name == "nt":
            return False, "Bluetooth requires Linux BlueZ host"
        self._run_cmd(["rfkill", "unblock", "bluetooth"], timeout=3.0)
        rc, out, err = self._run_cmd(["bluetoothctl", "power", "on"], timeout=4.0)
        if rc != 0 and "No default controller" in (out + err):
            return False, "No Bluetooth controller detected"
        return True, ""

    def _scan_sync(self) -> Tuple[List[BluetoothPrinterDevice], str]:
        ok, err = self._ensure_bt_powered_sync()
        if not ok:
            return [], err
        # Short active inquiry scan followed by reading discovered/paired device cache
        self._run_cmd(["bluetoothctl", "--timeout", "6", "scan", "on"], timeout=8.5)
        rc_all, all_out, err_all = self._run_cmd(["bluetoothctl", "devices"], timeout=4.0)
        _rc_p, paired_out, _ = self._run_cmd(["bluetoothctl", "devices", "Paired"], timeout=4.0)
        if rc_all != 0 and err_all:
            return [], err_all
        devs = parse_bluetoothctl_devices(all_out, paired_out)
        if not devs:
            return [], "No Bluetooth devices found nearby — ensure printer is powered ON & discoverable"
        return devs, f"Found {len(devs)} Bluetooth device(s)"

    async def scan(self, demo_mode: bool) -> PrinterState:
        if self.state.scanning:
            return self.snapshot()
        self.state.scanning = True
        self.state.last_status = "Scanning Bluetooth printers (6s)..."
        self._notify()

        try:
            if demo_mode:
                await asyncio.sleep(0.35)
                devs = [
                    BluetoothPrinterDevice(mac="00:11:22:33:44:55", name="MTP-2 58mm Thermal", paired=True, connected=True, rssi=-52),
                    BluetoothPrinterDevice(mac="66:77:88:99:AA:BB", name="PeriPage-A6-4F12", paired=False, connected=False, rssi=-68),
                ]
                self.state.bt_available = True
                self.state.devices = devs
                if not self.state.selected_mac:
                    self.state.selected_mac = devs[0].mac
                    self.state.selected_name = devs[0].name
                    self._save_settings()
                self.state.last_status = f"Demo: {len(devs)} thermal printer(s) ready"
            else:
                devs, msg = await asyncio.to_thread(self._scan_sync)
                self.state.devices = devs
                self.state.last_status = msg
        finally:
            self.state.scanning = False
            self._notify()
        return self.snapshot()

    async def select_printer(self, mac: str, name: str, channel: int, demo_mode: bool) -> PrinterState:
        clean_mac = (mac or "").strip().upper()
        if not PRINTER_MAC_RE.match(clean_mac):
            raise ValueError("Invalid Bluetooth MAC address (expected AA:BB:CC:DD:EE:FF)")
        if not (1 <= int(channel) <= 30):
            raise ValueError("RFCOMM channel must be between 1 and 30")

        self.state.selected_mac = clean_mac
        self.state.selected_name = (name or "BT Thermal Printer").strip()[:40]
        self.state.rfcomm_channel = int(channel)
        self._save_settings()

        if not demo_mode and os.name != "nt":
            def _pair_sync() -> str:
                ok, err = self._ensure_bt_powered_sync()
                if not ok:
                    return err
                self._run_cmd(["bluetoothctl", "trust", clean_mac], timeout=4.0)
                rc, out, perr = self._run_cmd(["bluetoothctl", "pair", clean_mac], timeout=8.0)
                if rc == 0 or "AlreadyExists" in (out + perr):
                    return f"Paired & selected {self.state.selected_name}"
                return f"Selected {self.state.selected_name} (pair note: {(perr or out)[:45]})"

            self.state.last_status = await asyncio.to_thread(_pair_sync)
        else:
            self.state.last_status = f"Selected {self.state.selected_name} (ch {self.state.rfcomm_channel})"

        self._notify()
        return self.snapshot()

    def _rfcomm_send_sync(self, raw: bytes) -> Tuple[bool, str]:
        if not self.state.selected_mac:
            return False, "No Bluetooth printer selected"
        if not hasattr(socket, "AF_BLUETOOTH") or not hasattr(socket, "BTPROTO_RFCOMM"):
            return False, "Python AF_BLUETOOTH RFCOMM socket unsupported on this OS"
        ok, err = self._ensure_bt_powered_sync()
        if not ok:
            return False, err

        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        sock.settimeout(8.0)
        try:
            sock.connect((self.state.selected_mac, self.state.rfcomm_channel))
            sock.sendall(raw)
            return True, f"Printed {len(raw)}B to {self.state.selected_name}"
        except OSError as exc:
            return False, f"BT print failed ({self.state.selected_mac}): {str(exc)[:60]}"
        finally:
            try:
                sock.close()
            except OSError:
                pass

    async def print_payload(self, raw: bytes, preview: str, demo_mode: bool) -> PrinterState:
        self.state.last_preview = preview
        self.state.printing = True
        self._notify()
        try:
            if demo_mode:
                await asyncio.sleep(0.25)
                if not self.state.selected_mac:
                    self.state.selected_mac = "00:11:22:33:44:55"
                    self.state.selected_name = "MTP-2 58mm Thermal"
                    self._save_settings()
                self.state.last_print_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                self.state.last_status = f"Demo printed ({len(raw)}B) to {self.state.selected_name}"
            else:
                ok, msg = await asyncio.to_thread(self._rfcomm_send_sync, raw)
                if ok:
                    self.state.last_print_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                self.state.last_status = msg
        finally:
            self.state.printing = False
            self._notify()
        return self.snapshot()

    def snapshot(self) -> PrinterState:
        return self.state.model_copy(deep=True)
