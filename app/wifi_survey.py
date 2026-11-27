import asyncio
import os
import random
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from .models import WifiNetwork, WifiSurveyState, WifiWalkSample, WifiWalkState
from .oui_db import lookup_mac_vendor

_BSSID_CLEAN_RE = re.compile(r"^[0-9A-Fa-f]{12}$")


def resolve_iw_bin() -> str:
    """Resolve `iw` binary path even when `/usr/sbin` is omitted from service/non-root PATH."""
    found = shutil.which("iw")
    if found:
        return found
    for cand in ("/usr/sbin/iw", "/sbin/iw", "/usr/bin/iw"):
        if os.path.isfile(cand):
            return cand
    return "iw"


def normalize_bssid(bssid: str) -> str:
    """Validate and normalize a BSSID MAC address into uppercase AA:BB:CC:DD:EE:FF."""
    raw = re.sub(r"[:\-.]", "", (bssid or "").strip())
    if not _BSSID_CLEAN_RE.match(raw):
        raise ValueError(f"Invalid BSSID MAC address: {bssid!r}")
    up = raw.upper()
    return ":".join(up[i : i + 2] for i in range(0, 12, 2))


def freq_to_channel(freq_mhz: int) -> Tuple[int, str]:
    """Convert Wi-Fi center frequency (MHz) to (channel_number, band_label)."""
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5, "2.4 GHz"
    if freq_mhz == 2484:
        return 14, "2.4 GHz"
    if 5000 < freq_mhz < 5925:
        return (freq_mhz - 5000) // 5, "5 GHz"
    if 5950 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5, "6 GHz"
    return 0, "Unknown"


def dbm_to_quality_pct(dbm: int) -> int:
    """Map RSSI dBm (-100..-50) to linear 0..100% link quality score."""
    return max(0, min(100, 2 * (dbm + 100)))


def parse_iw_info(text: str) -> dict:
    """Parse `iw dev <iface> info` output."""
    info = {
        "type": "managed",
        "ssid": "",
        "channel": None,
        "freq_mhz": None,
        "width_mhz": 20,
    }
    if not text:
        return info

    m_type = re.search(r"^\s*type\s+(\S+)", text, re.MULTILINE)
    if m_type:
        info["type"] = m_type.group(1).strip()

    m_ssid = re.search(r"^\s*ssid\s+(.+)$", text, re.MULTILINE)
    if m_ssid:
        info["ssid"] = m_ssid.group(1).strip()

    m_chan = re.search(
        r"^\s*channel\s+(\d+)\s+\((\d+)\s*MHz\)(?:,\s*width:\s*(\d+)\s*MHz)?",
        text,
        re.MULTILINE,
    )
    if m_chan:
        info["channel"] = int(m_chan.group(1))
        info["freq_mhz"] = int(m_chan.group(2))
        if m_chan.group(3):
            info["width_mhz"] = int(m_chan.group(3))

    return info


def parse_iw_link(text: str) -> dict:
    """Parse `iw dev <iface> link` output for currently associated AP metrics."""
    res = {
        "connected": False,
        "bssid": "—",
        "ssid": "—",
        "freq_mhz": None,
        "channel": None,
        "band": "—",
        "signal_dbm": None,
        "rx_mbps": None,
        "tx_mbps": None,
    }
    if not text or "Not connected" in text:
        return res

    m_bssid = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", text)
    if not m_bssid:
        return res

    res["connected"] = True
    res["bssid"] = m_bssid.group(1).upper()

    m_ssid = re.search(r"^\s*SSID:\s*(.+)$", text, re.MULTILINE)
    if m_ssid:
        res["ssid"] = m_ssid.group(1).strip() or "<Hidden>"

    m_freq = re.search(r"^\s*freq:\s*(\d+(?:\.\d+)?)", text, re.MULTILINE)
    if m_freq:
        f_mhz = int(round(float(m_freq.group(1))))
        ch, band = freq_to_channel(f_mhz)
        res["freq_mhz"] = f_mhz
        res["channel"] = ch
        res["band"] = band

    m_sig = re.search(r"^\s*signal:\s*(-?\d+(?:\.\d+)?)\s*dBm", text, re.MULTILINE)
    if m_sig:
        res["signal_dbm"] = int(round(float(m_sig.group(1))))

    m_rx = re.search(r"^\s*rx bitrate:\s*(\d+(?:\.\d+)?)\s*MBit/s", text, re.MULTILINE)
    if m_rx:
        res["rx_mbps"] = round(float(m_rx.group(1)), 1)

    m_tx = re.search(r"^\s*tx bitrate:\s*(\d+(?:\.\d+)?)\s*MBit/s", text, re.MULTILINE)
    if m_tx:
        res["tx_mbps"] = round(float(m_tx.group(1)), 1)

    return res


def _parse_single_bss_block(lines: List[str]) -> Optional[WifiNetwork]:
    header = lines[0].strip()
    m_hdr = re.match(r"^BSS\s+([0-9a-fA-F:]{17})", header)
    if not m_hdr:
        return None

    bssid = m_hdr.group(1).upper()
    associated = "-- associated" in header

    ssid = "<Hidden>"
    freq_mhz = 2412
    signal_dbm = -90
    ds_chan: Optional[int] = None
    ht_prim_chan: Optional[int] = None
    sec_offset = "no secondary"
    vht_width_code: Optional[int] = None
    vht_center_seg1: Optional[int] = None
    privacy_cap = False

    has_ht = False
    has_vht = False
    has_he = False

    has_rsn = False
    has_wpa = False
    rsn_suites: set[str] = set()
    section = ""

    for raw in lines[1:]:
        line = raw.rstrip("\r\n")
        stripped = line.strip()
        if not stripped:
            continue

        # Detect top-level IE sections (single leading tab in `iw scan`)
        if re.match(r"^\t[A-Za-z0-9]", line):
            if stripped.startswith("RSN:"):
                section = "rsn"
                has_rsn = True
            elif stripped.startswith("WPA:"):
                section = "wpa"
                has_wpa = True
            elif stripped.startswith("HT operation:"):
                section = "ht_op"
                has_ht = True
            elif stripped.startswith("VHT operation:"):
                section = "vht_op"
                has_vht = True
            elif stripped.startswith("HT capabilities:"):
                section = "ht_cap"
                has_ht = True
            elif stripped.startswith("VHT capabilities:"):
                section = "vht_cap"
                has_vht = True
            elif stripped.startswith("HE capabilities:"):
                section = "he_cap"
                has_he = True
            else:
                section = "other"

        if stripped.startswith("freq:"):
            m_f = re.search(r"freq:\s*(\d+(?:\.\d+)?)", stripped)
            if m_f:
                freq_mhz = int(round(float(m_f.group(1))))
        elif stripped.startswith("signal:"):
            m_s = re.search(r"signal:\s*(-?\d+(?:\.\d+)?)", stripped)
            if m_s:
                signal_dbm = int(round(float(m_s.group(1))))
        elif stripped.startswith("capability:"):
            privacy_cap = "Privacy" in stripped
        elif line.lstrip("\t ").startswith("SSID:"):
            after = line.split("SSID:", 1)[1]
            val = after[1:] if after.startswith(" ") else after
            val_clean = val.strip()
            if val_clean and not re.fullmatch(r"(?:\\x00)+", val_clean):
                ssid = val_clean
            else:
                ssid = "<Hidden>"
        elif stripped.startswith("DS Parameter set:"):
            m_ds = re.search(r"channel\s+(\d+)", stripped)
            if m_ds:
                ds_chan = int(m_ds.group(1))
        elif section == "ht_op":
            if "primary channel:" in stripped:
                m_hp = re.search(r"primary channel:\s*(\d+)", stripped)
                if m_hp:
                    ht_prim_chan = int(m_hp.group(1))
            elif "secondary channel offset:" in stripped:
                sec_offset = stripped.split(":", 1)[1].strip().lower()
        elif section == "vht_op":
            if "channel width:" in stripped:
                m_vw = re.search(r"channel width:\s*(\d+)", stripped)
                if m_vw:
                    vht_width_code = int(m_vw.group(1))
            elif "center freq segment 1:" in stripped:
                m_vc = re.search(r"center freq segment 1:\s*(\d+)", stripped)
                if m_vc:
                    vht_center_seg1 = int(m_vc.group(1))
        elif section == "rsn" and "Authentication suites:" in stripped:
            suites_txt = stripped.split(":", 1)[1].upper()
            if "SAE" in suites_txt:
                rsn_suites.add("SAE")
            if "PSK" in suites_txt:
                rsn_suites.add("PSK")
            if "802.1X" in suites_txt:
                rsn_suites.add("802.1X")

    ch_from_freq, band = freq_to_channel(freq_mhz)
    channel = ds_chan or ht_prim_chan or ch_from_freq
    if ds_chan and band == "2.4 GHz" and freq_mhz > 2500:
        channel = ch_from_freq

    width_mhz = 20
    center_channel = channel

    if vht_width_code == 1:
        width_mhz = 80
        if vht_center_seg1 and vht_center_seg1 > 0:
            center_channel = vht_center_seg1
    elif vht_width_code in (2, 3):
        width_mhz = 160
        if vht_center_seg1 and vht_center_seg1 > 0:
            center_channel = vht_center_seg1
    elif "above" in sec_offset:
        width_mhz = 40
        center_channel = channel + 2
    elif "below" in sec_offset:
        width_mhz = 40
        center_channel = channel - 2

    if has_he:
        wifi_gen = "Wi-Fi 6"
    elif has_vht:
        wifi_gen = "Wi-Fi 5"
    elif has_ht:
        wifi_gen = "Wi-Fi 4"
    else:
        wifi_gen = "802.11a/g"

    if has_rsn:
        if "SAE" in rsn_suites and "PSK" in rsn_suites:
            security = "WPA2/WPA3"
        elif "SAE" in rsn_suites:
            security = "WPA3"
        elif "802.1X" in rsn_suites:
            security = "WPA2-Ent"
        else:
            security = "WPA2"
    elif has_wpa:
        security = "WPA"
    elif privacy_cap:
        security = "WEP"
    else:
        security = "Open"

    return WifiNetwork(
        bssid=bssid,
        ssid=ssid,
        vendor=lookup_mac_vendor(bssid),
        freq_mhz=freq_mhz,
        channel=channel,
        band=band,
        width_mhz=width_mhz,
        center_channel=center_channel,
        signal_dbm=signal_dbm,
        quality_pct=dbm_to_quality_pct(signal_dbm),
        security=security,
        wifi_gen=wifi_gen,
        associated=associated,
    )


def parse_iw_scan_output(text: str) -> List[WifiNetwork]:
    """Parse `iw dev <iface> scan` text into sorted WifiNetwork objects."""
    if not text:
        return []

    blocks: List[List[str]] = []
    cur: List[str] = []
    for raw_line in text.splitlines():
        if re.match(r"^BSS\s+[0-9a-fA-F:]{17}", raw_line):
            if cur:
                blocks.append(cur)
            cur = [raw_line]
        elif cur:
            cur.append(raw_line)
    if cur:
        blocks.append(cur)

    nets: List[WifiNetwork] = []
    for blk in blocks:
        item = _parse_single_bss_block(blk)
        if item is not None:
            nets.append(item)

    nets.sort(key=lambda n: n.signal_dbm, reverse=True)
    return nets


def recommend_best_24g_channel(networks: List[WifiNetwork]) -> int:
    """Recommend non-overlapping 2.4 GHz channel (1, 6, or 11) with lowest RF interference."""
    nets_24 = [n for n in networks if n.band == "2.4 GHz"]
    scores: Dict[int, float] = {}
    for ch in (1, 6, 11):
        energy = 0.0
        for ap in nets_24:
            dist = abs(ap.center_channel - ch)
            if dist <= 4:
                energy += max(1, ap.signal_dbm + 100) * (1.0 - dist * 0.18)
        scores[ch] = energy
    return min((1, 6, 11), key=lambda c: scores[c])


def build_demo_wifi_networks() -> List[WifiNetwork]:
    """Representative multi-band office RF survey dataset for Demo Mode."""
    specs = [
        ("F0:9F:C2:00:00:02", "Corp-5G-Office", 5300, 60, "5 GHz", 80, 58, -54, "WPA2/WPA3", "Wi-Fi 6", True),
        ("F0:9F:C2:00:00:01", "Corp-24G-Office", 2437, 6, "2.4 GHz", 20, 6, -57, "WPA2/WPA3", "Wi-Fi 6", False),
        ("F0:9F:C2:00:00:04", "UniFi-NorthWing", 5180, 36, "5 GHz", 80, 42, -61, "WPA2", "Wi-Fi 5", False),
        ("00:1E:F7:4A:9C:22", "HQ-Enterprise", 5220, 44, "5 GHz", 40, 42, -64, "WPA2-Ent", "Wi-Fi 5", False),
        ("38:21:C7:91:0B:48", "Boardroom-Guest", 2412, 1, "2.4 GHz", 20, 1, -67, "Open", "Wi-Fi 5", False),
        ("F0:9F:C2:00:00:05", "UniFi-IoT", 2437, 6, "2.4 GHz", 40, 8, -71, "WPA2", "Wi-Fi 4", False),
        ("D8:07:B6:44:9E:12", "DIRECT-DeskRouter", 2437, 6, "2.4 GHz", 20, 6, -73, "WPA2", "Wi-Fi 4", False),
        ("00:1E:F7:4A:9C:23", "HQ-Enterprise", 5500, 100, "5 GHz", 80, 106, -75, "WPA2-Ent", "Wi-Fi 6", False),
        ("90:6C:AC:11:02:A8", "Warehouse-Mesh", 5745, 149, "5 GHz", 40, 151, -81, "WPA3", "Wi-Fi 6", False),
        ("B0:BE:76:12:44:8A", "<Hidden>", 2412, 1, "2.4 GHz", 20, 1, -84, "WPA2", "Wi-Fi 4", False),
    ]
    nets = [
        WifiNetwork(
            bssid=bssid,
            ssid=ssid,
            vendor=lookup_mac_vendor(bssid),
            freq_mhz=freq,
            channel=ch,
            band=band,
            width_mhz=width,
            center_channel=center_ch,
            signal_dbm=dbm,
            quality_pct=dbm_to_quality_pct(dbm),
            security=sec,
            wifi_gen=gen,
            associated=assoc,
        )
        for (bssid, ssid, freq, ch, band, width, center_ch, dbm, sec, gen, assoc) in specs
    ]
    nets.sort(key=lambda n: n.signal_dbm, reverse=True)
    return nets


def _run_iw_cmd(iw_bin: str, args: List[str], timeout: float = 12.0) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            [iw_bin, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0 and hasattr(os, "geteuid") and os.geteuid() != 0:
            proc2 = subprocess.run(
                ["sudo", "-n", iw_bin, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return proc2.returncode, proc2.stdout, proc2.stderr
        return proc.returncode, proc.stdout, proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return -1, "", str(exc)


class WifiSurveyManager:
    def __init__(self, iface: str = "wlan0", on_change: Optional[Callable[[], None]] = None) -> None:
        self.iface = iface
        self._on_change = on_change or (lambda: None)
        self.iw_bin = resolve_iw_bin()
        self.state = WifiSurveyState(iface=iface)
        self._walk_task: Optional[asyncio.Task] = None
        self._last_demo_mode: Optional[bool] = None

    def _populate_demo_state(self) -> None:
        nets = build_demo_wifi_networks()
        assoc = next((n for n in nets if n.associated), nets[0])
        self.state = WifiSurveyState(
            scanning=False,
            ap_mode_blocked=False,
            iface=self.iface,
            connected_ssid=assoc.ssid,
            connected_bssid=assoc.bssid,
            connected_dbm=assoc.signal_dbm,
            connected_channel=assoc.channel,
            last_scan_at="Demo Survey",
            total_count=len(nets),
            count_24g=sum(1 for n in nets if n.band == "2.4 GHz"),
            count_5g=sum(1 for n in nets if n.band == "5 GHz"),
            best_24g_channel=recommend_best_24g_channel(nets),
            error="",
            networks=nets,
            walk=self.state.walk,
        )

    def snapshot(self, demo_mode: bool = False) -> WifiSurveyState:
        if demo_mode:
            if self._last_demo_mode is False or not self.state.networks:
                self._populate_demo_state()
        else:
            if self._last_demo_mode is True:
                self.stop_walk(notify=False)
                self.state = WifiSurveyState(iface=self.iface)
        self._last_demo_mode = demo_mode
        return self.state.model_copy(deep=True)

    async def scan(self, demo_mode: bool) -> WifiSurveyState:
        if self.state.scanning:
            return self.state.model_copy(deep=True)

        self.state.scanning = True
        self.state.error = ""
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.2)
            self._populate_demo_state()
            self.state.last_scan_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            self._last_demo_mode = True
            self._on_change()
            return self.state.model_copy(deep=True)

        def _exec_live_scan() -> WifiSurveyState:
            rc_info, out_info, _ = _run_iw_cmd(self.iw_bin, ["dev", self.iface, "info"], timeout=3.0)
            info = parse_iw_info(out_info) if rc_info == 0 else {}
            if str(info.get("type", "")).upper() == "AP":
                return WifiSurveyState(
                    scanning=False,
                    ap_mode_blocked=True,
                    iface=self.iface,
                    connected_ssid=info.get("ssid") or "JackTrace-AP",
                    error="Field AP (JackTrace-AP) active on wlan0 — stop Field AP in View 08 before scanning",
                    networks=[],
                    walk=self.state.walk,
                )

            rc_lnk, out_lnk, _ = _run_iw_cmd(self.iw_bin, ["dev", self.iface, "link"], timeout=3.0)
            link_info = parse_iw_link(out_lnk) if rc_lnk == 0 else {"connected": False}

            rc_scan, out_scan, err_scan = _run_iw_cmd(self.iw_bin, ["dev", self.iface, "scan"], timeout=12.0)
            if rc_scan != 0 or not out_scan.strip():
                rc_dump, out_dump, err_dump = _run_iw_cmd(
                    self.iw_bin, ["dev", self.iface, "scan", "dump"], timeout=5.0
                )
                if out_dump.strip():
                    out_scan = out_dump
                    err_scan = ""
                else:
                    err_scan = err_dump or err_scan or f"iw scan failed (exit {rc_scan})"

            nets = parse_iw_scan_output(out_scan)
            conn_bssid = link_info.get("bssid", "—")
            if conn_bssid != "—":
                for ap in nets:
                    if ap.bssid == conn_bssid:
                        ap.associated = True
                        if link_info.get("signal_dbm") is not None:
                            ap.signal_dbm = link_info["signal_dbm"]
                            ap.quality_pct = dbm_to_quality_pct(ap.signal_dbm)

            count_24 = sum(1 for n in nets if n.band == "2.4 GHz")
            count_5 = sum(1 for n in nets if n.band == "5 GHz")
            best_24 = recommend_best_24g_channel(nets) if count_24 > 0 else 1

            return WifiSurveyState(
                scanning=False,
                ap_mode_blocked=False,
                iface=self.iface,
                connected_ssid=link_info.get("ssid", "—"),
                connected_bssid=conn_bssid,
                connected_dbm=link_info.get("signal_dbm"),
                connected_channel=link_info.get("channel"),
                last_scan_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                total_count=len(nets),
                count_24g=count_24,
                count_5g=count_5,
                best_24g_channel=best_24,
                error=err_scan.strip() if (not nets and err_scan) else "",
                networks=nets,
                walk=self.state.walk,
            )

        self.state = await asyncio.to_thread(_exec_live_scan)
        self._last_demo_mode = False
        self._on_change()
        return self.state.model_copy(deep=True)

    def stop_walk(self, notify: bool = True) -> None:
        if self._walk_task is not None and not self._walk_task.done():
            self._walk_task.cancel()
        self._walk_task = None
        self.state.walk.running = False
        if notify:
            self._on_change()

    async def start_walk(self, bssid: str, demo_mode: bool) -> None:
        target_bssid = normalize_bssid(bssid)
        self.stop_walk(notify=False)

        if demo_mode and not self.state.networks:
            self._populate_demo_state()

        matched = next((n for n in self.state.networks if n.bssid == target_bssid), None)
        if not demo_mode and self.state.ap_mode_blocked:
            raise RuntimeError(self.state.error or "Field AP is active on wlan0")

        ssid = matched.ssid if matched else (
            self.state.connected_ssid if target_bssid == self.state.connected_bssid else target_bssid
        )
        band = matched.band if matched else "—"
        channel = matched.channel if matched else (self.state.connected_channel or 0)
        freq_mhz = matched.freq_mhz if matched else 0
        base_dbm = matched.signal_dbm if matched else (self.state.connected_dbm or -58)

        self.state.walk = WifiWalkState(
            running=True,
            bssid=target_bssid,
            ssid=ssid,
            band=band,
            channel=channel,
            freq_mhz=freq_mhz,
            samples=[],
        )
        self._on_change()

        async def _loop() -> None:
            seq = 0
            cur_dbm_walk = float(base_dbm)
            try:
                while seq < 300 and self.state.walk.running:
                    seq += 1
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    dbm_val: Optional[int] = None
                    rx_mbps: Optional[float] = None
                    tx_mbps: Optional[float] = None

                    if demo_mode:
                        await asyncio.sleep(0.05 if seq == 1 else 0.95)
                        cur_dbm_walk = max(-88.0, min(-34.0, cur_dbm_walk + random.uniform(-3.0, 3.0)))
                        dbm_val = int(round(cur_dbm_walk))
                        rx_mbps = 433.3
                        tx_mbps = 351.0
                    else:
                        t0 = time.monotonic()
                        is_assoc = (target_bssid == self.state.connected_bssid)

                        def _poll_once() -> Tuple[Optional[int], Optional[float], Optional[float]]:
                            if is_assoc:
                                rc, out, _ = _run_iw_cmd(self.iw_bin, ["dev", self.iface, "link"], timeout=3.0)
                                if rc == 0:
                                    lnk = parse_iw_link(out)
                                    if lnk.get("connected") and lnk.get("bssid") == target_bssid:
                                        return lnk.get("signal_dbm"), lnk.get("rx_mbps"), lnk.get("tx_mbps")

                            args = ["dev", self.iface, "scan"]
                            if freq_mhz > 0:
                                args += ["freq", str(freq_mhz), "flush"]
                            rc_s, out_s, _ = _run_iw_cmd(self.iw_bin, args, timeout=6.0)
                            if rc_s != 0 or not out_s.strip():
                                _, out_s, _ = _run_iw_cmd(self.iw_bin, ["dev", self.iface, "scan", "dump"], timeout=4.0)
                            parsed = parse_iw_scan_output(out_s)
                            ap = next((n for n in parsed if n.bssid == target_bssid), None)
                            if ap:
                                return ap.signal_dbm, None, None
                            return None, None, None

                        dbm_val, rx_mbps, tx_mbps = await asyncio.to_thread(_poll_once)
                        interval = 1.0 if is_assoc else 2.0
                        elapsed = time.monotonic() - t0
                        if elapsed < interval:
                            await asyncio.sleep(interval - elapsed)

                    if not self.state.walk.running:
                        break

                    samples = list(self.state.walk.samples)
                    samples.append(
                        WifiWalkSample(seq=seq, ts=ts, signal_dbm=dbm_val, rx_mbps=rx_mbps, tx_mbps=tx_mbps)
                    )
                    if len(samples) > 60:
                        samples = samples[-60:]

                    vals = [s.signal_dbm for s in samples if s.signal_dbm is not None]
                    mn = min(vals) if vals else None
                    mx = max(vals) if vals else None
                    av = round(sum(vals) / len(vals), 1) if vals else None

                    self.state.walk = WifiWalkState(
                        running=True,
                        bssid=target_bssid,
                        ssid=ssid,
                        band=band,
                        channel=channel,
                        freq_mhz=freq_mhz,
                        current_dbm=dbm_val if dbm_val is not None else self.state.walk.current_dbm,
                        min_dbm=mn,
                        max_dbm=mx,
                        avg_dbm=av,
                        rx_mbps=rx_mbps if rx_mbps is not None else self.state.walk.rx_mbps,
                        tx_mbps=tx_mbps if tx_mbps is not None else self.state.walk.tx_mbps,
                        samples=samples,
                    )
                    self._on_change()
            except asyncio.CancelledError:
                pass
            finally:
                self.state.walk.running = False
                self._on_change()

        self._walk_task = asyncio.create_task(_loop())

    def shutdown(self) -> None:
        self.stop_walk(notify=False)
