import asyncio
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from .models import WifiClientNetwork, WifiClientState, WifiSavedProfile

HOTSPOT_PROFILE_NAME = "JackTrace-Hotspot"


def resolve_nmcli_bin() -> Optional[str]:
    """Resolve `nmcli` binary path even when sbin/bin dirs differ in service PATH."""
    found = shutil.which("nmcli")
    if found:
        return found
    for cand in ("/usr/bin/nmcli", "/bin/nmcli", "/usr/sbin/nmcli"):
        if os.path.isfile(cand):
            return cand
    return None


def _run_nmcli(nmcli_bin: str, args: List[str], timeout: float = 15.0) -> Tuple[int, str, str]:
    """Execute nmcli safely without shell=True, falling back to sudo -n if non-root."""
    try:
        proc = subprocess.run(
            [nmcli_bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0 and hasattr(os, "geteuid") and os.geteuid() != 0:
            proc2 = subprocess.run(
                ["sudo", "-n", nmcli_bin, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return proc2.returncode, proc2.stdout, proc2.stderr
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return -1, "", str(exc)


def split_nmcli_terse(line: str) -> List[str]:
    """Split a single `nmcli -t` line on unescaped colons, unescaping `\\:` and `\\\\`."""
    fields: List[str] = []
    buf: List[str] = []
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "\\" and i + 1 < n:
            nxt = line[i + 1]
            if nxt in (":", "\\"):
                buf.append(nxt)
                i += 2
                continue
        if ch == ":":
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    fields.append("".join(buf))
    return fields


def parse_nmcli_band(freq_str: str) -> str:
    """Convert `nmcli` frequency string (e.g. '5260 MHz') to band label."""
    m = re.search(r"(\d+)", freq_str or "")
    if not m:
        return "2.4 GHz"
    freq_mhz = int(m.group(1))
    if freq_mhz >= 5925:
        return "6 GHz"
    if freq_mhz > 4900:
        return "5 GHz"
    return "2.4 GHz"


def normalize_nmcli_security(sec_str: str) -> str:
    """Normalize `nmcli` security flags into concise UI labels."""
    raw = (sec_str or "").strip().upper()
    if not raw or raw == "--":
        return "Open"
    if "802.1X" in raw:
        return "WPA2-Ent"
    if "SAE" in raw and "WPA2" in raw:
        return "WPA2/WPA3"
    if "SAE" in raw or "WPA3" in raw:
        return "WPA3"
    if "WPA2" in raw:
        return "WPA2"
    if "WPA1" in raw or "WPA" in raw:
        return "WPA"
    if "WEP" in raw:
        return "WEP"
    return sec_str.strip()


def validate_ssid(ssid: str) -> str:
    """Validate and clean a Wi-Fi SSID (rejects empty or control characters)."""
    cleaned = (ssid or "").strip()
    if not cleaned:
        raise ValueError("SSID cannot be empty")
    if any(c in cleaned for c in ("\r", "\n", "\x00")):
        raise ValueError("SSID contains invalid control characters")
    if len(cleaned) > 64:
        raise ValueError("SSID is too long (max 64 characters)")
    return cleaned


def validate_password(pw: Optional[str]) -> Optional[str]:
    """Validate an optional Wi-Fi passphrase without logging or echoing it."""
    if pw is None or pw == "":
        return None
    if any(c in pw for c in ("\r", "\n", "\x00")):
        raise ValueError("Password contains invalid control characters")
    if len(pw) > 128:
        raise ValueError("Password is too long (max 128 characters)")
    return pw


def _sanitize_error(err: str, password: Optional[str] = None) -> str:
    msg = (err or "").strip()
    if password:
        msg = msg.replace(password, "****")
    return msg[:200] if len(msg) > 200 else msg


def parse_nmcli_wifi_list(text: str, saved_by_ssid: Dict[str, str]) -> List[WifiClientNetwork]:
    """Parse `nmcli -t -f IN-USE,SSID,BSSID,SIGNAL,FREQ,SECURITY device wifi list`."""
    by_ssid: Dict[str, WifiClientNetwork] = {}
    for raw_line in (text or "").splitlines():
        if not raw_line.strip():
            continue
        parts = split_nmcli_terse(raw_line)
        if len(parts) < 6:
            continue
        in_use_raw, ssid_raw, bssid_raw, sig_raw, freq_raw, sec_raw = parts[:6]
        ssid = ssid_raw.strip()
        if not ssid or ssid == "--":
            continue

        in_use = in_use_raw.strip() == "*"
        bssid = bssid_raw.strip().upper() or "—"
        try:
            sig_pct = max(0, min(100, int(sig_raw.strip())))
        except ValueError:
            sig_pct = 0
        band = parse_nmcli_band(freq_raw)
        security = normalize_nmcli_security(sec_raw)
        prof_name = saved_by_ssid.get(ssid, "")

        cand = WifiClientNetwork(
            ssid=ssid,
            bssid=bssid,
            signal_pct=sig_pct,
            band=band,
            security=security,
            in_use=in_use,
            saved=bool(prof_name),
            profile_name=prof_name,
        )
        prev = by_ssid.get(ssid)
        if prev is None:
            by_ssid[ssid] = cand
        elif cand.in_use and not prev.in_use:
            by_ssid[ssid] = cand
        elif cand.in_use == prev.in_use and cand.signal_pct > prev.signal_pct:
            by_ssid[ssid] = cand

    nets = list(by_ssid.values())
    nets.sort(key=lambda n: (not n.in_use, not n.saved, -n.signal_pct, n.ssid.lower()))
    return nets


def parse_nmcli_connections(text: str, iface: str) -> Tuple[List[Dict[str, object]], bool]:
    """Parse `nmcli -t -f NAME,TYPE,UUID,DEVICE,AUTOCONNECT connection show`."""
    profiles: List[Dict[str, object]] = []
    ap_mode_active = False

    for raw_line in (text or "").splitlines():
        if not raw_line.strip():
            continue
        parts = split_nmcli_terse(raw_line)
        if len(parts) < 5:
            continue
        name, ctype, uuid, dev, auto = parts[:5]
        if ctype.strip() != "802-11-wireless":
            continue
        clean_name = name.strip()
        dev_clean = dev.strip()
        if clean_name == HOTSPOT_PROFILE_NAME:
            if dev_clean == iface:
                ap_mode_active = True
            continue
        profiles.append(
            {
                "name": clean_name,
                "uuid": uuid.strip(),
                "active": dev_clean == iface,
                "autoconnect": auto.strip().lower() in ("yes", "true", "1"),
            }
        )
    return profiles, ap_mode_active


def parse_nmcli_device_show(text: str) -> Tuple[str, str]:
    """Parse `nmcli -t -f GENERAL.CONNECTION,IP4.ADDRESS device show <iface>`."""
    active_profile = ""
    ipv4 = "—"
    for raw_line in (text or "").splitlines():
        s = raw_line.strip()
        if not s:
            continue
        parts = split_nmcli_terse(s)
        if len(parts) < 2:
            continue
        key = parts[0].strip()
        val = ":".join(parts[1:]).strip()
        if key == "GENERAL.CONNECTION":
            active_profile = "" if val in ("", "--") else val
        elif key.startswith("IP4.ADDRESS") and ipv4 == "—" and val and val != "--":
            ipv4 = val.split("/", 1)[0].strip() or "—"
    return active_profile, ipv4


class WifiClientManager:
    """Manages NetworkManager client Wi-Fi connections and saved profiles on wlan0."""

    def __init__(self, iface: str = "wlan0", on_change: Optional[Callable[[], None]] = None) -> None:
        self.iface = iface
        self._on_change = on_change or (lambda: None)
        self.nmcli_bin = resolve_nmcli_bin()
        self.state = WifiClientState(
            available=bool(self.nmcli_bin) or os.name == "nt",
            iface=iface,
        )
        self._last_demo_mode: Optional[bool] = None
        self._init_demo_store()

    def _init_demo_store(self) -> None:
        self._demo_connected = True
        self._demo_ap_active = False
        self._demo_active_ssid = "Corp-5G-Office"
        self._demo_ipv4 = "192.168.10.42"
        self._demo_profiles: List[Dict[str, object]] = [
            {"name": "Corp-5G-Office", "ssid": "Corp-5G-Office", "uuid": "demo-uuid-corp", "autoconnect": True},
            {"name": "Phone-Hotspot", "ssid": "Phone-Hotspot", "uuid": "demo-uuid-phone", "autoconnect": True},
            {"name": "Home-WiFi", "ssid": "Home-WiFi", "uuid": "demo-uuid-home", "autoconnect": True},
        ]
        self._demo_raw_networks: List[Dict[str, object]] = [
            {"ssid": "Corp-5G-Office", "bssid": "F0:9F:C2:00:00:02", "signal_pct": 84, "band": "5 GHz", "security": "WPA2/WPA3"},
            {"ssid": "Phone-Hotspot", "bssid": "5A:3E:19:88:21:04", "signal_pct": 76, "band": "5 GHz", "security": "WPA2"},
            {"ssid": "Boardroom-Guest", "bssid": "38:21:C7:91:0B:48", "signal_pct": 68, "band": "2.4 GHz", "security": "Open"},
            {"ssid": "Warehouse-Mesh", "bssid": "90:6C:AC:11:02:A8", "signal_pct": 52, "band": "5 GHz", "security": "WPA3"},
            {"ssid": "Client-Corp-5G", "bssid": "F0:9F:C2:00:00:04", "signal_pct": 63, "band": "5 GHz", "security": "WPA2"},
        ]

    def _build_demo_state(self, status: Optional[str] = None, error: str = "") -> WifiClientState:
        saved_by_ssid = {str(p["ssid"]): str(p["name"]) for p in self._demo_profiles}
        profiles = [
            WifiSavedProfile(
                name=str(p["name"]),
                ssid=str(p["ssid"]),
                uuid=str(p["uuid"]),
                active=self._demo_connected and str(p["ssid"]) == self._demo_active_ssid,
                autoconnect=bool(p.get("autoconnect", True)),
            )
            for p in self._demo_profiles
        ]
        profiles.sort(key=lambda p: (not p.active, p.ssid.lower()))

        nets: List[WifiClientNetwork] = []
        active_sig: Optional[int] = None
        for raw in self._demo_raw_networks:
            ssid = str(raw["ssid"])
            in_use = self._demo_connected and ssid == self._demo_active_ssid
            sig = int(raw["signal_pct"])
            if in_use:
                active_sig = sig
            prof = saved_by_ssid.get(ssid, "")
            nets.append(
                WifiClientNetwork(
                    ssid=ssid,
                    bssid=str(raw["bssid"]),
                    signal_pct=sig,
                    band=str(raw["band"]),
                    security=str(raw["security"]),
                    in_use=in_use,
                    saved=bool(prof),
                    profile_name=prof,
                )
            )
        nets.sort(key=lambda n: (not n.in_use, not n.saved, -n.signal_pct, n.ssid.lower()))

        active_prof = saved_by_ssid.get(self._demo_active_ssid, self._demo_active_ssid) if self._demo_connected else ""
        default_status = (
            f"Connected to {self._demo_active_ssid} ({self._demo_ipv4})"
            if self._demo_connected
            else "Disconnected"
        )
        return WifiClientState(
            available=True,
            iface=self.iface,
            connected=self._demo_connected,
            ap_mode_active=self._demo_ap_active,
            active_ssid=self._demo_active_ssid if self._demo_connected else "—",
            active_profile=active_prof,
            ipv4=self._demo_ipv4 if self._demo_connected else "—",
            signal_pct=active_sig,
            busy=False,
            status=status if status is not None else default_status,
            error=error,
            last_scan_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            saved_profiles=profiles,
            available_networks=nets,
        )

    def snapshot(self, demo_mode: bool = False) -> WifiClientState:
        if demo_mode:
            if self._last_demo_mode is False or not self.state.saved_profiles:
                self.state = self._build_demo_state()
        else:
            if self._last_demo_mode is True:
                self.state = WifiClientState(
                    available=bool(self.nmcli_bin),
                    iface=self.iface,
                )
        self._last_demo_mode = demo_mode
        return self.state.model_copy(deep=True)

    def _query_live_state_sync(self, rescan: bool = False) -> WifiClientState:
        nm = self.nmcli_bin or resolve_nmcli_bin()
        self.nmcli_bin = nm
        if not nm:
            return WifiClientState(
                available=False,
                iface=self.iface,
                busy=False,
                status="NetworkManager (nmcli) unavailable",
                error="nmcli binary not found on host",
            )

        rc_conn, out_conn, err_conn = _run_nmcli(
            nm, ["-t", "-f", "NAME,TYPE,UUID,DEVICE,AUTOCONNECT", "connection", "show"], timeout=6.0
        )
        raw_profs, ap_active = parse_nmcli_connections(out_conn if rc_conn == 0 else "", self.iface)

        saved_profiles: List[WifiSavedProfile] = []
        saved_by_ssid: Dict[str, str] = {}
        for p in raw_profs:
            uuid = str(p["uuid"])
            name = str(p["name"])
            ssid = name
            rc_s, out_s, _ = _run_nmcli(
                nm, ["-g", "802-11-wireless.ssid", "connection", "show", "uuid", uuid], timeout=4.0
            )
            if rc_s == 0 and out_s.strip():
                ssid = out_s.strip().splitlines()[0].strip()
            saved_profiles.append(
                WifiSavedProfile(
                    name=name,
                    ssid=ssid,
                    uuid=uuid,
                    active=bool(p["active"]),
                    autoconnect=bool(p["autoconnect"]),
                )
            )
            if ssid not in saved_by_ssid or p["active"]:
                saved_by_ssid[ssid] = name

        saved_profiles.sort(key=lambda p: (not p.active, p.ssid.lower(), p.name.lower()))

        rc_dev, out_dev, _ = _run_nmcli(
            nm, ["-t", "-f", "GENERAL.CONNECTION,IP4.ADDRESS", "device", "show", self.iface], timeout=5.0
        )
        active_profile, ipv4 = parse_nmcli_device_show(out_dev if rc_dev == 0 else "")

        scan_flag = "yes" if (rescan and not ap_active) else "no"
        scan_timeout = 15.0 if scan_flag == "yes" else 6.0
        rc_w, out_w, err_w = _run_nmcli(
            nm,
            ["-t", "-f", "IN-USE,SSID,BSSID,SIGNAL,FREQ,SECURITY", "device", "wifi", "list", "ifname", self.iface, "--rescan", scan_flag],
            timeout=scan_timeout,
        )
        nets = parse_nmcli_wifi_list(out_w if rc_w == 0 else "", saved_by_ssid)

        connected = bool(active_profile) and not ap_active
        active_ssid = "—"
        active_sig: Optional[int] = None
        if connected:
            in_use_net = next((n for n in nets if n.in_use), None)
            matched_prof = next((p for p in saved_profiles if p.name == active_profile), None)
            if in_use_net:
                active_ssid = in_use_net.ssid
                active_sig = in_use_net.signal_pct
            elif matched_prof:
                active_ssid = matched_prof.ssid
            else:
                active_ssid = active_profile

        err_msg = ""
        if rc_conn != 0 and err_conn.strip():
            err_msg = _sanitize_error(err_conn)
        elif rescan and rc_w != 0 and err_w.strip() and not ap_active:
            err_msg = _sanitize_error(err_w)

        if ap_active:
            status_txt = f"Field AP (JackTrace-AP) active on {self.iface}"
        elif connected:
            ip_part = f" ({ipv4})" if ipv4 != "—" else ""
            status_txt = f"Connected to {active_ssid}{ip_part}"
        else:
            status_txt = f"Disconnected ({self.iface} idle)"

        last_ts = self.state.last_scan_at
        if rescan or nets or not last_ts:
            last_ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

        return WifiClientState(
            available=True,
            iface=self.iface,
            connected=connected,
            ap_mode_active=ap_active,
            active_ssid=active_ssid,
            active_profile=active_profile,
            ipv4=ipv4 if connected else "—",
            signal_pct=active_sig,
            busy=False,
            status=status_txt,
            error=err_msg,
            last_scan_at=last_ts,
            saved_profiles=saved_profiles,
            available_networks=nets,
        )

    async def refresh_status(self, demo_mode: bool = False, rescan: bool = False) -> WifiClientState:
        if demo_mode:
            if rescan:
                self.state.busy = True
                self.state.status = "Scanning Wi-Fi networks..."
                self._on_change()
                await asyncio.sleep(0.15)
            self.state = self._build_demo_state()
            self._last_demo_mode = True
            self._on_change()
            return self.state.model_copy(deep=True)

        if rescan:
            self.state.busy = True
            self.state.error = ""
            self.state.status = "Scanning nearby Wi-Fi..."
            self._on_change()

        fresh = await asyncio.to_thread(self._query_live_state_sync, rescan)
        self.state = fresh
        self._last_demo_mode = False
        self._on_change()
        return self.state.model_copy(deep=True)

    async def connect(
        self,
        ssid: str = "",
        password: Optional[str] = None,
        hidden: bool = False,
        profile_name: Optional[str] = None,
        demo_mode: bool = False,
    ) -> WifiClientState:
        clean_prof = (profile_name or "").strip()
        clean_pw = validate_password(password)
        if clean_prof:
            if any(c in clean_prof for c in ("\r", "\n", "\x00")) or len(clean_prof) > 96:
                raise ValueError("Invalid Wi-Fi profile name")
            clean_ssid = ssid.strip() if ssid else clean_prof
        else:
            clean_ssid = validate_ssid(ssid)

        self.state.busy = True
        self.state.error = ""
        self.state.status = f"Connecting to {clean_ssid}..."
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.2)
            self._demo_ap_active = False
            if clean_prof:
                prof = next((p for p in self._demo_profiles if p["name"] == clean_prof), None)
                if not prof:
                    self.state = self._build_demo_state(status="Connect failed", error=f"Saved profile not found: {clean_prof}")
                    self._on_change()
                    return self.state.model_copy(deep=True)
                clean_ssid = str(prof["ssid"])
            else:
                existing_net = next((n for n in self._demo_raw_networks if n["ssid"] == clean_ssid), None)
                if existing_net and existing_net["security"] != "Open" and not clean_pw:
                    has_prof = any(p["ssid"] == clean_ssid for p in self._demo_profiles)
                    if not has_prof:
                        self.state = self._build_demo_state(status="Password required", error=f"Passphrase required for {clean_ssid}")
                        self._on_change()
                        return self.state.model_copy(deep=True)
                if not existing_net:
                    self._demo_raw_networks.insert(
                        0,
                        {
                            "ssid": clean_ssid,
                            "bssid": "DE:AD:BE:EF:12:34",
                            "signal_pct": 78,
                            "band": "5 GHz",
                            "security": "WPA2" if clean_pw else "Open",
                        },
                    )
                if not any(p["ssid"] == clean_ssid for p in self._demo_profiles):
                    self._demo_profiles.append(
                        {
                            "name": clean_ssid,
                            "ssid": clean_ssid,
                            "uuid": f"demo-uuid-{len(self._demo_profiles) + 1}",
                            "autoconnect": True,
                        }
                    )

            self._demo_connected = True
            self._demo_active_ssid = clean_ssid
            self._demo_ipv4 = "192.168.10.42"
            self.state = self._build_demo_state(status=f"Connected to {clean_ssid} ({self._demo_ipv4})")
            self._last_demo_mode = True
            self._on_change()
            return self.state.model_copy(deep=True)

        def _exec_live_connect() -> WifiClientState:
            nm = self.nmcli_bin or resolve_nmcli_bin()
            self.nmcli_bin = nm
            if not nm:
                return WifiClientState(
                    available=False,
                    iface=self.iface,
                    status="nmcli not found",
                    error="NetworkManager (nmcli) not available",
                )

            # Stop Field AP hotspot if active before joining client Wi-Fi
            rc_c, out_c, _ = _run_nmcli(nm, ["-t", "-f", "NAME,TYPE,UUID,DEVICE,AUTOCONNECT", "connection", "show"], timeout=6.0)
            raw_profs, ap_active = parse_nmcli_connections(out_c if rc_c == 0 else "", self.iface)
            if ap_active:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True, check=False)
                _run_nmcli(nm, ["connection", "down", HOTSPOT_PROFILE_NAME], timeout=6.0)
                _run_nmcli(nm, ["connection", "delete", HOTSPOT_PROFILE_NAME], timeout=6.0)

            matching_prof_name = clean_prof
            if not matching_prof_name:
                for p in raw_profs:
                    rc_s, out_s, _ = _run_nmcli(
                        nm, ["-g", "802-11-wireless.ssid", "connection", "show", "uuid", str(p["uuid"])], timeout=4.0
                    )
                    p_ssid = out_s.strip().splitlines()[0].strip() if (rc_s == 0 and out_s.strip()) else str(p["name"])
                    if p_ssid == clean_ssid:
                        matching_prof_name = str(p["name"])
                        break

            err_out = ""
            ok = False

            if matching_prof_name and not clean_pw:
                rc_up, _, err_up = _run_nmcli(
                    nm, ["connection", "up", "id", matching_prof_name, "ifname", self.iface], timeout=22.0
                )
                ok = rc_up == 0
                err_out = err_up
            else:
                cmd = ["device", "wifi", "connect", clean_ssid]
                if clean_pw:
                    cmd += ["password", clean_pw]
                if hidden:
                    cmd += ["hidden", "yes"]
                cmd += ["ifname", self.iface]
                rc_join, _, err_join = _run_nmcli(nm, cmd, timeout=25.0)
                ok = rc_join == 0
                err_out = err_join

                if not ok and not hidden:
                    _run_nmcli(nm, ["device", "wifi", "rescan", "ifname", self.iface], timeout=10.0)
                    rc_retry, _, err_retry = _run_nmcli(nm, cmd, timeout=25.0)
                    ok = rc_retry == 0
                    err_out = err_retry

                if not ok and matching_prof_name and clean_pw:
                    _run_nmcli(
                        nm,
                        ["connection", "modify", matching_prof_name, "wifi-sec.key-mgmt", "wpa-psk", "wifi-sec.psk", clean_pw],
                        timeout=6.0,
                    )
                    rc_up2, _, err_up2 = _run_nmcli(
                        nm, ["connection", "up", "id", matching_prof_name, "ifname", self.iface], timeout=22.0
                    )
                    ok = rc_up2 == 0
                    err_out = err_up2

            fresh = self._query_live_state_sync(rescan=False)
            if ok and fresh.connected:
                ip_part = f" ({fresh.ipv4})" if fresh.ipv4 != "—" else ""
                fresh.status = f"Connected to {fresh.active_ssid}{ip_part}"
                fresh.error = ""
            elif not ok:
                fresh.error = _sanitize_error(err_out or f"Failed to connect to {clean_ssid}", clean_pw)
                fresh.status = f"Connect failed: {clean_ssid}"
            return fresh

        self.state = await asyncio.to_thread(_exec_live_connect)
        self._last_demo_mode = False
        self._on_change()
        return self.state.model_copy(deep=True)

    async def disconnect(self, demo_mode: bool = False) -> WifiClientState:
        self.state.busy = True
        self.state.error = ""
        self.state.status = f"Disconnecting {self.iface}..."
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.1)
            self._demo_connected = False
            self._demo_active_ssid = "—"
            self._demo_ipv4 = "—"
            self.state = self._build_demo_state(status=f"Disconnected ({self.iface} idle)")
            self._last_demo_mode = True
            self._on_change()
            return self.state.model_copy(deep=True)

        def _exec_live_disconnect() -> WifiClientState:
            nm = self.nmcli_bin or resolve_nmcli_bin()
            self.nmcli_bin = nm
            if not nm:
                return self.state
            rc, _, err = _run_nmcli(nm, ["device", "disconnect", self.iface], timeout=8.0)
            fresh = self._query_live_state_sync(rescan=False)
            if rc != 0 and err.strip():
                fresh.error = _sanitize_error(err)
            else:
                fresh.status = f"Disconnected ({self.iface} idle)"
            return fresh

        self.state = await asyncio.to_thread(_exec_live_disconnect)
        self._last_demo_mode = False
        self._on_change()
        return self.state.model_copy(deep=True)

    async def forget_profile(
        self, uuid: str = "", name: str = "", demo_mode: bool = False
    ) -> WifiClientState:
        clean_uuid = (uuid or "").strip()
        clean_name = (name or "").strip()
        if not clean_uuid and not clean_name:
            raise ValueError("Provide uuid or name of Wi-Fi profile to forget")
        if clean_name == HOTSPOT_PROFILE_NAME:
            raise ValueError("Cannot forget managed hotspot profile")

        if demo_mode:
            target = next(
                (p for p in self._demo_profiles if (clean_uuid and p["uuid"] == clean_uuid) or (clean_name and p["name"] == clean_name)),
                None,
            )
            if not target:
                raise ValueError("Wi-Fi profile not found")
            self._demo_profiles = [p for p in self._demo_profiles if p is not target]
            if self._demo_connected and target["ssid"] == self._demo_active_ssid:
                self._demo_connected = False
                self._demo_active_ssid = "—"
                self._demo_ipv4 = "—"
            self.state = self._build_demo_state(status=f"Forgot profile {target['name']}")
            self._last_demo_mode = True
            self._on_change()
            return self.state.model_copy(deep=True)

        def _exec_live_forget() -> WifiClientState:
            nm = self.nmcli_bin or resolve_nmcli_bin()
            self.nmcli_bin = nm
            if not nm:
                raise ValueError("NetworkManager (nmcli) not available")

            rc_c, out_c, _ = _run_nmcli(nm, ["-t", "-f", "NAME,TYPE,UUID,DEVICE,AUTOCONNECT", "connection", "show"], timeout=6.0)
            raw_profs, _ = parse_nmcli_connections(out_c if rc_c == 0 else "", self.iface)
            match = next(
                (
                    p
                    for p in raw_profs
                    if (clean_uuid and p["uuid"] == clean_uuid) or (clean_name and p["name"] == clean_name)
                ),
                None,
            )
            if not match:
                raise ValueError("Matching saved Wi-Fi profile not found")

            rc_d, _, err_d = _run_nmcli(nm, ["connection", "delete", "uuid", str(match["uuid"])], timeout=8.0)
            fresh = self._query_live_state_sync(rescan=False)
            if rc_d != 0:
                fresh.error = _sanitize_error(err_d or f"Failed to forget {match['name']}")
            else:
                fresh.status = f"Forgot {match['name']}"
            return fresh

        self.state = await asyncio.to_thread(_exec_live_forget)
        self._last_demo_mode = False
        self._on_change()
        return self.state.model_copy(deep=True)
