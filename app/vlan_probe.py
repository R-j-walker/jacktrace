import asyncio
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from .models import VlanProbeEntry, VlanProbeState
from .security import probe_dhcp_servers_sync

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_VLAN_SETTINGS_PATH = BASE_DIR / "data" / "vlan_settings.json"
DEFAULT_PRESET_VLANS = [10, 40, 50, 100, 140, 210]
_IFACE_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _resolve_bin(name: str, fallback: str) -> str:
    return shutil.which(name) or (fallback if os.path.isfile(fallback) else name)


def validate_vlan_list(vlans: Sequence[int]) -> List[int]:
    cleaned: List[int] = []
    for raw in vlans:
        vid = int(raw)
        if vid < 1 or vid > 4094:
            raise ValueError(f"VLAN ID out of range (1–4094): {vid}")
        if vid not in cleaned:
            cleaned.append(vid)
    return cleaned[:12]


def _run_priv_cmd(cmd: List[str], timeout: float = 4.0) -> Tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0 and hasattr(os, "geteuid") and os.geteuid() != 0:
            proc2 = subprocess.run(
                ["sudo", "-n", *cmd], capture_output=True, text=True, timeout=timeout, check=False
            )
            return proc2.returncode, (proc2.stderr or proc2.stdout).strip()
        return proc.returncode, (proc.stderr or proc.stdout).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return -1, str(exc)


class VlanTrunkProber:
    def __init__(
        self,
        on_change: Optional[Callable[[], None]] = None,
        settings_path: Path = DEFAULT_VLAN_SETTINGS_PATH,
    ) -> None:
        self._on_change = on_change or (lambda: None)
        self._settings_path = Path(settings_path)
        self._presets = self._load_presets()
        self.state = VlanProbeState(preset_vlans=list(self._presets))

    def _load_presets(self) -> List[int]:
        try:
            if self._settings_path.is_file():
                data = json.loads(self._settings_path.read_text(encoding="utf-8"))
                vals = validate_vlan_list(data.get("preset_vlans", []))
                if vals:
                    return vals
        except Exception:
            pass
        return list(DEFAULT_PRESET_VLANS)

    def set_presets(self, vlans: Sequence[int]) -> List[int]:
        cleaned = validate_vlan_list(vlans)
        if not cleaned:
            raise ValueError("Provide at least one VLAN ID between 1 and 4094.")
        self._presets = cleaned
        self.state.preset_vlans = list(cleaned)
        try:
            self._settings_path.parent.mkdir(parents=True, exist_ok=True)
            self._settings_path.write_text(
                json.dumps({"preset_vlans": cleaned}, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass
        self._on_change()
        return cleaned

    def snapshot(self) -> VlanProbeState:
        return self.state.model_copy(deep=True)

    async def run_probe(
        self,
        iface: str,
        local_mac: str,
        observed_vlans: Sequence[int],
        demo_mode: bool,
        override_presets: Optional[Sequence[int]] = None,
    ) -> VlanProbeState:
        if self.state.running:
            return self.snapshot()

        if override_presets is not None:
            self.set_presets(override_presets)

        presets = list(self._presets)
        observed_set = {int(v) for v in observed_vlans if 2 <= int(v) <= 4094}
        candidates: List[Tuple[int, str]] = []
        seen: set[int] = set()

        for v in sorted(observed_set):
            if v not in seen:
                candidates.append((v, "observed"))
                seen.add(v)
        for v in presets:
            if v > 1 and v not in seen:
                candidates.append((v, "preset"))
                seen.add(v)

        self.state = VlanProbeState(
            running=True,
            preset_vlans=presets,
            results=[],
            error="",
        )
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.25)
            demo_map = {
                40: VlanProbeEntry(
                    vlan_id=40,
                    source="observed",
                    status="LIVE_DHCP",
                    dhcp_server_ip="172.24.10.1",
                    offered_ip="172.24.10.162",
                    router_ip="172.24.10.1",
                    dns_ip="172.24.10.5",
                    subnet_mask="255.255.255.0",
                ),
                140: VlanProbeEntry(
                    vlan_id=140,
                    source="observed",
                    status="LIVE_DHCP",
                    dhcp_server_ip="172.24.140.1",
                    offered_ip="172.24.140.28",
                    router_ip="172.24.140.1",
                    dns_ip="172.24.10.5",
                    subnet_mask="255.255.255.0",
                ),
                210: VlanProbeEntry(
                    vlan_id=210,
                    source="observed",
                    status="LIVE_DHCP",
                    dhcp_server_ip="172.24.210.1",
                    offered_ip="172.24.210.54",
                    router_ip="172.24.210.1",
                    dns_ip="1.1.1.1",
                    subnet_mask="255.255.255.0",
                ),
            }
            entries = [
                demo_map.get(vid, VlanProbeEntry(vlan_id=vid, source=src, status="NO_REPLY"))
                for (vid, src) in candidates
            ]
            entries.sort(key=lambda e: (0 if e.status == "LIVE_DHCP" else 1, e.vlan_id))
            self.state = VlanProbeState(
                running=False,
                last_run_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                preset_vlans=presets,
                results=entries,
                error="",
            )
            self._on_change()
            return self.snapshot()

        if os.name == "nt" or not _IFACE_RE.match(iface or ""):
            self.state = VlanProbeState(
                running=False,
                last_run_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                preset_vlans=presets,
                results=[],
                error="Active 802.1Q VLAN probing requires Linux eth0 hardware.",
            )
            self._on_change()
            return self.snapshot()

        def _exec_live_probe() -> VlanProbeState:
            ip_bin = _resolve_bin("ip", "/usr/sbin/ip")
            modprobe_bin = _resolve_bin("modprobe", "/usr/sbin/modprobe")
            _run_priv_cmd([modprobe_bin, "8021q"], timeout=3.0)

            entries: List[VlanProbeEntry] = []
            err_msg = ""

            for vid, src in candidates:
                subif = f"{iface}.{vid}"
                # Pre-clean if stale sub-interface existed
                _run_priv_cmd([ip_bin, "link", "delete", "dev", subif], timeout=2.0)

                rc_add, add_out = _run_priv_cmd(
                    [ip_bin, "link", "add", "link", iface, "name", subif, "type", "vlan", "id", str(vid)],
                    timeout=3.0,
                )
                if rc_add != 0:
                    err_msg = add_out or f"Failed to create VLAN interface {subif}"
                    entries.append(VlanProbeEntry(vlan_id=vid, source=src, status="ERROR"))
                    continue

                try:
                    _run_priv_cmd([ip_bin, "link", "set", "dev", subif, "up"], timeout=2.0)
                    time.sleep(0.08)
                    offers = probe_dhcp_servers_sync(subif, local_mac, listen_sec=1.1)
                    if offers:
                        o = offers[0]
                        entries.append(
                            VlanProbeEntry(
                                vlan_id=vid,
                                source=src,
                                status="LIVE_DHCP",
                                dhcp_server_ip=o.server_ip,
                                offered_ip=o.offered_ip,
                                router_ip=o.router_ip,
                                dns_ip=o.dns_ip,
                                subnet_mask=o.subnet_mask,
                            )
                        )
                    elif vid in observed_set:
                        entries.append(VlanProbeEntry(vlan_id=vid, source=src, status="TRAFFIC_ONLY"))
                    else:
                        entries.append(VlanProbeEntry(vlan_id=vid, source=src, status="NO_REPLY"))
                finally:
                    _run_priv_cmd([ip_bin, "link", "delete", "dev", subif], timeout=2.5)

            entries.sort(
                key=lambda e: (
                    0 if e.status == "LIVE_DHCP" else (1 if e.status == "TRAFFIC_ONLY" else 2),
                    e.vlan_id,
                )
            )
            return VlanProbeState(
                running=False,
                last_run_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                preset_vlans=presets,
                results=entries,
                error=err_msg if not entries else "",
            )

        self.state = await asyncio.to_thread(_exec_live_probe)
        self._on_change()
        return self.snapshot()
