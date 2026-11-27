import json
import os
import re
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .audit import DATA_DIR
from .models import LinkTelemetry, PhyWiringState, TdrPairResult, TdrReportState

# Linux ioctl constants for MDIO / MII register access
SIOCGMIIPHY = 0x8947
SIOCGMIIREG = 0x8948
SIOCSMIIREG = 0x8949

# Standard IEEE 802.3 MII registers
MII_BMCR = 0x00
MII_PHYSID1 = 0x02
MII_PHYSID2 = 0x03
MII_ADVERTISE = 0x04
MII_CTRL1000 = 0x09
MII_STAT1000 = 0x0A

STAT1000_MS_RES = 0x4000
STAT1000_LOK = 0x2000
STAT1000_ROK = 0x1000
STAT1000_IDLE_ERR_MASK = 0x00FF

# Broadcom BCM54xx non-disruptive PHY wiring / integrity status & read-to-clear error counters
# IMPORTANT: Do not read 0x1A (ISR) during polling so kernel PHY interrupts are never stolen.
MII_BCM54XX_ESR = 0x11
BCM54XX_ESR_MDIX = 0x2000
BCM54XX_ESR_LOCK = 0x0200
MII_BCM54XX_RERR_CNT = 0x12
MII_BCM54XX_FCS_CNT = 0x13
MII_BCM54XX_RX_NOT_OK_CNT = 0x14

BMCR_SPEED1000 = 0x0040
BMCR_FULLDPLX = 0x0100
BMCR_ANRESTART = 0x0200
BMCR_ANENABLE = 0x1000
BMCR_RESET = 0x8000
BMCR_1G_AN = BMCR_ANENABLE | BMCR_FULLDPLX | BMCR_SPEED1000          # 0x1140
BMCR_1G_AN_RESTART = BMCR_1G_AN | BMCR_ANRESTART                     # 0x1340
ADVERTISE_CSMA = 0x0001
ADVERTISE_ALL_10_100 = 0x01E1
CTRL1000_ALL_1G = 0x0300

DEFAULT_TICKS_PER_METER = float(os.getenv("NETTESTER_TDR_TICKS_PER_M", "97.4"))
DEFAULT_NVP_PCT = 69.0
TDR_SETTINGS_PATH = DATA_DIR / "tdr_settings.json"
TDR_CABLE_PRESETS = {
    "cat5e": ("Cat5e (69%)", 69.0),
    "cat6": ("Cat6 (72%)", 72.0),
    "cat6a": ("Cat6A (76%)", 76.0),
}


def ticks_per_meter_for_nvp(nvp_pct: float) -> float:
    """Scale Broadcom ECD raw ticks/m linearly for the configured cable NVP% (55–85%)."""
    nvp = float(nvp_pct)
    if nvp < 55.0 or nvp > 85.0:
        raise ValueError("NVP percentage must be between 55% and 85%")
    return round(DEFAULT_TICKS_PER_METER * (DEFAULT_NVP_PCT / nvp), 2)


def load_tdr_calibration(path: Path = TDR_SETTINGS_PATH) -> Tuple[str, float]:
    try:
        if path.is_file():
            raw = json.loads(path.read_text(encoding="utf-8"))
            nvp = float(raw.get("nvp_pct", DEFAULT_NVP_PCT))
            if 55.0 <= nvp <= 85.0:
                label = str(raw.get("cable_type") or f"Custom ({nvp:.0f}%)")
                return label, round(nvp, 1)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return "Cat5e (69%)", DEFAULT_NVP_PCT


def save_tdr_calibration(
    cable_type: str,
    nvp_pct: float,
    path: Path = TDR_SETTINGS_PATH,
) -> Tuple[str, float]:
    nvp = round(float(nvp_pct), 1)
    if nvp < 55.0 or nvp > 85.0:
        raise ValueError("NVP percentage must be between 55% and 85%")
    label = (cable_type or "").strip() or f"Custom ({nvp:g}%)"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"cable_type": label, "nvp_pct": nvp}, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass
    return label, nvp

# Broadcom BCM54xx Expansion & RDB registers (from Linux include/linux/brcmphy.h)
MII_BCM54XX_EXP_DATA = 0x15
MII_BCM54XX_EXP_SEL = 0x17
MII_BCM54XX_RDB_ADDR = 0x1E
MII_BCM54XX_RDB_DATA = 0x1F

BCM54XX_RDB_REG0087 = 0x0087
BCM54XX_ACCESS_MODE_LEGACY_EN = 0x8000

MII_BCM54XX_EXP_SEL_ER = 0x0F00
BCM54XX_EXP_ECD_CTRL = MII_BCM54XX_EXP_SEL_ER + 0xC0          # 0x0FC0
BCM54XX_EXP_ECD_FAULT_TYPE = MII_BCM54XX_EXP_SEL_ER + 0xC1    # 0x0FC1
BCM54XX_EXP_ECD_PAIR_A_LEN = MII_BCM54XX_EXP_SEL_ER + 0xC2    # 0x0FC2
BCM54XX_ECD_LENGTH_INVALID = 0xFFFF

# ECD Control register bits
BCM54XX_ECD_CTRL_INVALID = 1 << 3
BCM54XX_ECD_CTRL_UNIT_MASK = 1 << 10       # 0 = cm, 1 = m
BCM54XX_ECD_CTRL_IN_PROGRESS = 1 << 11
BCM54XX_ECD_CTRL_BREAK_LINK = 1 << 12
BCM54XX_ECD_CTRL_CROSS_SHORT_DIS = 1 << 13
BCM54XX_ECD_CTRL_RUN = 1 << 15

# ECD Fault Type nibbles (Pair A: 15..12, Pair B: 11..8, Pair C: 7..4, Pair D: 3..0)
ECD_FAULT_INVALID = 0x0
ECD_FAULT_OK = 0x1
ECD_FAULT_OPEN = 0x2
ECD_FAULT_SAME_SHORT = 0x3
ECD_FAULT_CROSS_SHORT = 0x4
ECD_FAULT_BUSY = 0x9

PAIR_SPECS = [
    ("Pair A", "Pins 1–2", "White/Orange • Orange"),
    ("Pair B", "Pins 3–6", "White/Green • Green"),
    ("Pair C", "Pins 4–5", "Blue • White/Blue"),
    ("Pair D", "Pins 7–8", "White/Brown • Brown"),
]


class MdioBusAccessor:
    """Low-level Linux `SIOCGMIIREG`/`SIOCSMIIREG` ioctl wrapper for an Ethernet interface."""

    def __init__(self, iface: str):
        import fcntl  # Linux-only

        self._fcntl = fcntl
        self.iface = iface
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.phy_id = self._discover_phy_id()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _pack_ifreq(self, phy_id: int, reg_num: int, val_in: int = 0) -> bytes:
        ifname = self.iface.encode("utf-8")[:15]
        ifname_padded = ifname.ljust(16, b"\x00")
        return ifname_padded + struct.pack("=HHHH", phy_id, reg_num, val_in, 0) + (b"\x00" * 16)

    def _discover_phy_id(self) -> int:
        buf = self._pack_ifreq(0, 0, 0)
        out = self._fcntl.ioctl(self.sock.fileno(), SIOCGMIIPHY, buf)
        phy_id, _, _, _ = struct.unpack("=HHHH", out[16:24])
        return phy_id

    def read_reg(self, reg_num: int) -> int:
        buf = self._pack_ifreq(self.phy_id, reg_num & 0x1F, 0)
        out = self._fcntl.ioctl(self.sock.fileno(), SIOCGMIIREG, buf)
        _, _, _, val_out = struct.unpack("=HHHH", out[16:24])
        return val_out

    def write_reg(self, reg_num: int, val: int) -> None:
        buf = self._pack_ifreq(self.phy_id, reg_num & 0x1F, val & 0xFFFF)
        self._fcntl.ioctl(self.sock.fileno(), SIOCSMIIREG, buf)

    def read_exp(self, exp_reg: int) -> int:
        self.write_reg(MII_BCM54XX_EXP_SEL, exp_reg)
        return self.read_reg(MII_BCM54XX_EXP_DATA)

    def write_exp(self, exp_reg: int, val: int) -> None:
        self.write_reg(MII_BCM54XX_EXP_SEL, exp_reg)
        self.write_reg(MII_BCM54XX_EXP_DATA, val)


def is_broadcom_phy_uid(uid: int) -> bool:
    return (uid >> 16) in (0x600D, 0x0362)


def format_phy_uid(uid: int) -> str:
    if (uid & 0xFFFFFFF0) == 0x600D84A0:
        rev = uid & 0xF
        return f"Broadcom BCM54213PE (0x{uid:08x} rev {rev})"
    if is_broadcom_phy_uid(uid):
        return f"Broadcom Gigabit PHY (0x{uid:08x})"
    return f"IEEE PHY (0x{uid:08x})"


def decode_phy_wiring_regs(
    phy_uid: Optional[int],
    stat1000: Optional[int] = None,
    esr: Optional[int] = None,
    rerr: int = 0,
    fcs: int = 0,
    rx_not_ok: int = 0,
    carrier_up: bool = True,
    speed_mbps: Optional[int] = None,
    ethtool_mdix: str = "Unknown",
    ethtool_ms: str = "Unknown",
) -> PhyWiringState:
    """Decode non-disruptive IEEE 802.3 (`0x0A`) + Broadcom BCM54xx (`0x11..0x14`) PHY registers."""
    phy_name = format_phy_uid(phy_uid) if phy_uid is not None else "—"
    mdix_state = "Unknown"
    master_slave = "Unknown"
    local_rx_ok: Optional[bool] = None
    remote_rx_ok: Optional[bool] = None
    descrambler_locked: Optional[bool] = None
    idle_errors = 0
    rx_symbol_errors = 0
    false_carrier_errors = 0
    local_rx_not_ok_count = 0
    remote_rx_not_ok_count = 0

    if carrier_up:
        if stat1000 is not None and (speed_mbps is None or speed_mbps == 1000):
            master_slave = "Master" if (stat1000 & STAT1000_MS_RES) else "Slave"
            local_rx_ok = bool(stat1000 & STAT1000_LOK)
            remote_rx_ok = bool(stat1000 & STAT1000_ROK)
            idle_errors = stat1000 & STAT1000_IDLE_ERR_MASK
        elif ethtool_ms in ("Master", "Slave"):
            master_slave = ethtool_ms

        if phy_uid is not None and is_broadcom_phy_uid(phy_uid) and esr is not None:
            mdix_state = "MDI-X" if (esr & BCM54XX_ESR_MDIX) else "MDI"
            descrambler_locked = bool(esr & BCM54XX_ESR_LOCK)
            rx_symbol_errors = rerr & 0xFFFF
            false_carrier_errors = fcs & 0xFF
            local_rx_not_ok_count = (rx_not_ok >> 8) & 0xFF
            remote_rx_not_ok_count = rx_not_ok & 0xFF
        elif ethtool_mdix in ("MDI", "MDI-X"):
            mdix_state = ethtool_mdix
    else:
        if ethtool_mdix in ("MDI", "MDI-X"):
            mdix_state = ethtool_mdix

    supported = bool(
        phy_uid is not None
        or ethtool_mdix in ("MDI", "MDI-X")
        or ethtool_ms in ("Master", "Slave")
    )
    return PhyWiringState(
        supported=supported,
        phy_name=phy_name,
        mdix_state=mdix_state,
        master_slave=master_slave,
        local_rx_ok=local_rx_ok,
        remote_rx_ok=remote_rx_ok,
        descrambler_locked=descrambler_locked,
        idle_errors=idle_errors,
        rx_symbol_errors=rx_symbol_errors,
        false_carrier_errors=false_carrier_errors,
        local_rx_not_ok_count=local_rx_not_ok_count,
        remote_rx_not_ok_count=remote_rx_not_ok_count,
    )


def read_phy_wiring_sync(
    iface: str,
    carrier_up: bool,
    speed_mbps: Optional[int] = None,
    ethtool_mdix: str = "Unknown",
    ethtool_ms: str = "Unknown",
    mdio_factory: Optional[Callable[[str], MdioBusAccessor]] = None,
) -> PhyWiringState:
    """
    Non-disruptive read-only MDIO poll for MDI/MDI-X crossover, Master/Slave, receiver lock,
    and physical-layer error counters. Never issues MDIO writes or reads `0x1A` (ISR).
    """
    if os.name == "nt" and mdio_factory is None:
        return decode_phy_wiring_regs(
            None,
            carrier_up=carrier_up,
            speed_mbps=speed_mbps,
            ethtool_mdix=ethtool_mdix,
            ethtool_ms=ethtool_ms,
        )

    factory = mdio_factory or MdioBusAccessor
    try:
        mdio = factory(iface)
    except OSError:
        return decode_phy_wiring_regs(
            None,
            carrier_up=carrier_up,
            speed_mbps=speed_mbps,
            ethtool_mdix=ethtool_mdix,
            ethtool_ms=ethtool_ms,
        )

    try:
        id1 = mdio.read_reg(MII_PHYSID1)
        id2 = mdio.read_reg(MII_PHYSID2)
        phy_uid = ((id1 & 0xFFFF) << 16) | (id2 & 0xFFFF)
        stat1000: Optional[int] = None
        esr: Optional[int] = None
        rerr = 0
        fcs = 0
        rx_not_ok = 0
        if carrier_up:
            stat1000 = mdio.read_reg(MII_STAT1000)
            if is_broadcom_phy_uid(phy_uid):
                esr = mdio.read_reg(MII_BCM54XX_ESR)
                rerr = mdio.read_reg(MII_BCM54XX_RERR_CNT)
                fcs = mdio.read_reg(MII_BCM54XX_FCS_CNT)
                rx_not_ok = mdio.read_reg(MII_BCM54XX_RX_NOT_OK_CNT)
        return decode_phy_wiring_regs(
            phy_uid,
            stat1000=stat1000,
            esr=esr,
            rerr=rerr,
            fcs=fcs,
            rx_not_ok=rx_not_ok,
            carrier_up=carrier_up,
            speed_mbps=speed_mbps,
            ethtool_mdix=ethtool_mdix,
            ethtool_ms=ethtool_ms,
        )
    except OSError:
        return decode_phy_wiring_regs(
            None,
            carrier_up=carrier_up,
            speed_mbps=speed_mbps,
            ethtool_mdix=ethtool_mdix,
            ethtool_ms=ethtool_ms,
        )
    finally:
        mdio.close()


def synthesize_wiremap_verdict(
    link: LinkTelemetry,
    tdr: TdrReportState,
    session_crc_errors: Optional[int] = None,
) -> Tuple[str, str]:
    """Combine hardware TDR, link downshift, and live PHY DSP/error monitors into a wiring verdict."""
    if tdr.overall_verdict == "FAIL":
        return "FAIL", tdr.summary

    if link.pair_downshift_suspected:
        return (
            "FAIL",
            "2-Pair Miswire / Broken Pair C (4–5) or D (7–8) — 1G switch downshifted to 100M",
        )

    if not link.carrier_up:
        if tdr.overall_verdict == "UNPATCHED":
            return "UNPATCHED", tdr.summary
        return (
            "IDLE",
            "No carrier — plug into switch or tap PULSE TDR to inspect unpatched cable",
        )

    pw = link.phy_wiring
    if pw.local_rx_ok is False or pw.remote_rx_ok is False or pw.descrambler_locked is False:
        return (
            "FAIL",
            "PHY Receiver NOT OK / Descrambler Unlocked — severe pair fault or split pair!",
        )

    crc_count = link.rx_crc_errors if session_crc_errors is None else max(0, session_crc_errors)
    total_phy_errs = (
        pw.idle_errors
        + pw.rx_symbol_errors
        + pw.false_carrier_errors
        + pw.local_rx_not_ok_count
        + pw.remote_rx_not_ok_count
    )
    if total_phy_errs > 0 or crc_count > 0:
        parts = []
        if pw.idle_errors > 0:
            parts.append(f"Idle: {pw.idle_errors}")
        if pw.rx_symbol_errors > 0:
            parts.append(f"Symbol: {pw.rx_symbol_errors}")
        if pw.false_carrier_errors > 0:
            parts.append(f"False Carrier: {pw.false_carrier_errors}")
        if pw.local_rx_not_ok_count > 0 or pw.remote_rx_not_ok_count > 0:
            parts.append(f"RX NOK: {pw.local_rx_not_ok_count}/{pw.remote_rx_not_ok_count}")
        if crc_count > 0:
            parts.append(f"CRC: {crc_count}")
        details = ", ".join(parts)
        return (
            "WARN",
            f"PHY signal noise ({details}) — suspect split pair, poor crimp, or EMI",
        )

    if link.speed_mbps and link.speed_mbps >= 1000:
        if pw.mdix_state == "MDI-X":
            mdix_lbl = "PHY: MDI-X (Auto)"
        elif pw.mdix_state == "MDI":
            mdix_lbl = "PHY: MDI (Auto)"
        else:
            mdix_lbl = "Auto-MDIX"
        spd_lbl = f"{link.speed_mbps / 1000:.1f}GbE" if link.speed_mbps >= 2500 else "1GbE"
        return (
            "PASS",
            f"All 4 TIA-568B pairs healthy ({spd_lbl} · {mdix_lbl} · 0 PHY errors)",
        )

    return (
        "PASS",
        f"2-Pair {link.speed_mbps or 100}M link healthy ({pw.mdix_state}) — tap PULSE TDR to verify unused Pairs C & D",
    )


def decode_bcm_ecd_registers(
    fault_reg: int,
    lengths_cm: Tuple[int, int, int, int],
    phy_label: str = "Broadcom BCM54213PE",
    raw_debug: str = "",
    ticks_per_meter: float = DEFAULT_TICKS_PER_METER,
    ctrl_reg: int = 0,
    prev_link_up: bool = False,
    prev_speed_mbps: Optional[int] = None,
) -> TdrReportState:
    """
    Convert raw Broadcom ECD fault register (`0x0fc1`) + 4 length registers (`0x0fc2..0x0fc5`)
    into a structured 4-pair `TdrReportState`.
    """
    nibbles = [
        (fault_reg >> 12) & 0xF,
        (fault_reg >> 8) & 0xF,
        (fault_reg >> 4) & 0xF,
        fault_reg & 0xF,
    ]

    pairs: List[TdrPairResult] = []
    for idx, (pname, pins, colors) in enumerate(PAIR_SPECS):
        code = nibbles[idx]
        raw_cm = lengths_cm[idx]
        dist_m: Optional[float] = None
        if code in (ECD_FAULT_OPEN, ECD_FAULT_SAME_SHORT, ECD_FAULT_CROSS_SHORT):
            if raw_cm not in (0, BCM54XX_ECD_LENGTH_INVALID) and raw_cm < 35000:
                dist_m = round(raw_cm / ticks_per_meter, 1)
            elif raw_cm == 0:
                dist_m = 0.0

        if code == ECD_FAULT_OK:
            status = "OK"
            detail = "100Ω Switch Terminated"
        elif code == ECD_FAULT_OPEN:
            status = "OPEN"
            if dist_m is not None:
                if dist_m < 0.8:
                    detail = f"Open @ {dist_m}m (Unplugged RJ45 jack)"
                else:
                    detail = f"Open Reflection @ {dist_m}m"
            else:
                detail = "Open Circuit (Unterminated)"
        elif code == ECD_FAULT_SAME_SHORT:
            status = "SHORT"
            detail = f"Intra-Pair Short @ {dist_m}m!" if dist_m is not None else "Intra-Pair Short!"
        elif code == ECD_FAULT_CROSS_SHORT:
            status = "CROSS_SHORT"
            detail = f"Cross-Pair Short @ {dist_m}m!" if dist_m is not None else "Inter-Pair Cross Short!"
        else:
            status = "UNKNOWN"
            detail = f"Code 0x{code:x}"

        pairs.append(
            TdrPairResult(
                pair_name=pname,
                pins=pins,
                wire_colors=colors,
                status=status,
                distance_m=dist_m,
                detail=detail,
            )
        )

    flp_invalid = bool(ctrl_reg & BCM54XX_ECD_CTRL_INVALID) or any(
        n in (ECD_FAULT_INVALID, ECD_FAULT_BUSY) for n in nibbles
    )

    if flp_invalid and prev_link_up:
        if (
            prev_speed_mbps
            and prev_speed_mbps >= 1000
            and not any(p.status in ("OPEN", "SHORT", "CROSS_SHORT") for p in pairs)
        ):
            pairs = [
                p.model_copy(
                    update={
                        "status": "OK",
                        "distance_m": None,
                        "detail": "100Ω Active 1GbE (Switch FLP noise)",
                    }
                )
                for p in pairs
            ]
            return TdrReportState(
                running=False,
                supported=True,
                method="BCM54213PE Hardware TDR",
                phy_id=phy_label,
                tested_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                overall_verdict="PASS",
                summary=(
                    "All 4 pairs verified via active 1000BASE-T link "
                    "(switch link pulses interfered with TDR — unplug far end to measure cable length)"
                ),
                raw_debug=raw_debug,
                pairs=pairs,
            )
        elif prev_speed_mbps == 100:
            for idx in (0, 1):
                if pairs[idx].status == "UNKNOWN":
                    pairs[idx] = pairs[idx].model_copy(
                        update={
                            "status": "OK",
                            "distance_m": None,
                            "detail": "Active 100BASE-TX (Switch FLP active)",
                        }
                    )

    ok_cnt = sum(1 for p in pairs if p.status == "OK")
    open_cnt = sum(1 for p in pairs if p.status == "OPEN")
    short_cnt = sum(1 for p in pairs if p.status in ("SHORT", "CROSS_SHORT"))
    open_dists = [p.distance_m for p in pairs if p.status == "OPEN" and p.distance_m is not None]

    # Synthesize clear engineer-level verdict across all 4 pairs
    if short_cnt > 0:
        verdict = "FAIL"
        summary = f"CABLE SHORT DETECTED ({short_cnt} pair(s) shorted — inspect punchdown / RJ45 crimp!)"
    elif ok_cnt == 4:
        verdict = "PASS"
        summary = "All 4 TIA-568B pairs intact & 100Ω terminated at switch"
    elif open_cnt == 4:
        if open_dists and max(open_dists) < 0.8:
            verdict = "UNPATCHED"
            summary = "No patch cable attached (<0.8m open at local RJ45 port)"
        elif open_dists and (max(open_dists) - min(open_dists)) <= 2.5:
            avg_len = round(sum(open_dists) / len(open_dists), 1)
            verdict = "UNPATCHED"
            summary = f"Unpatched Wall Drop: All 4 pairs intact to ~{avg_len}m (open at patch panel)"
        else:
            verdict = "FAIL"
            summary = f"Uneven Open Pairs ({', '.join(f'{d}m' for d in open_dists)}) — severed cable!"
    elif ok_cnt > 0 and open_cnt > 0:
        verdict = "FAIL"
        bad_names = [p.pair_name for p in pairs if p.status != "OK"]
        summary = f"BROKEN PAIR FAULT: {', '.join(bad_names)} OPEN while {ok_cnt} pair(s) terminated!"
    else:
        verdict = "WARN"
        summary = "Partial / inconclusive TDR reflection"

    return TdrReportState(
        running=False,
        supported=True,
        method="BCM54213PE Hardware TDR",
        phy_id=phy_label,
        tested_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        overall_verdict=verdict,
        summary=summary,
        raw_debug=raw_debug,
        pairs=pairs,
    )


def _try_ethtool_netlink_tdr(iface: str) -> Optional[TdrReportState]:
    """Try standard `ethtool --cable-test <iface>` first (for non-Broadcom USB NICs with mainline hooks)."""
    for prefix in ([], ["sudo", "-n"]):
        try:
            proc = subprocess.run(
                prefix + ["ethtool", "--cable-test", iface],
                capture_output=True,
                text=True,
                timeout=6.0,
                check=False,
            )
            if proc.returncode == 0 and "Pair" in proc.stdout:
                out = proc.stdout
                pairs: List[TdrPairResult] = []
                for pname, pins, colors in PAIR_SPECS:
                    letter = pname.split()[-1]
                    m_st = re.search(rf"Pair\s+{letter}\s*,\s*code\s+([A-Za-z_ -]+)", out)
                    m_ln = re.search(rf"Pair\s+{letter}\s*,\s*fault length:\s*([\d.]+)m", out)
                    raw_code = (m_st.group(1).strip().upper() if m_st else "UNKNOWN")
                    dist = round(float(m_ln.group(1)), 1) if m_ln else None
                    st = "OK" if "OK" in raw_code else ("OPEN" if "OPEN" in raw_code else ("SHORT" if "SHORT" in raw_code else raw_code))
                    det = f"{st} @ {dist}m" if dist is not None else st
                    pairs.append(
                        TdrPairResult(pair_name=pname, pins=pins, wire_colors=colors, status=st, distance_m=dist, detail=det)
                    )
                all_ok = all(p.status == "OK" for p in pairs)
                return TdrReportState(
                    running=False,
                    supported=True,
                    method="ethtool Netlink TDR",
                    phy_id="Kernel PHY Driver",
                    tested_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                    overall_verdict="PASS" if all_ok else "WARN",
                    summary="All 4 pairs OK" if all_ok else "Inspect pair fault results below",
                    pairs=pairs,
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return None


def run_hardware_tdr_sync(
    iface: str,
    mdio_factory: Optional[Callable[[str], MdioBusAccessor]] = None,
    prev_link_up: bool = False,
    prev_speed_mbps: Optional[int] = None,
    nvp_pct: Optional[float] = None,
    cable_type: Optional[str] = None,
) -> TdrReportState:
    """
    Execute a live Time Domain Reflectometry (TDR) pulse on `iface`.
    1. Tries standard `ethtool --cable-test` if supported by kernel driver.
    2. Otherwise drives Broadcom BCM54213PE / BCM54xx ECD hardware directly over MDIO ioctl.
    Always restores Gigabit auto-negotiation cleanly when finished.
    """
    saved_type, saved_nvp = load_tdr_calibration()
    eff_nvp = round(float(nvp_pct), 1) if nvp_pct is not None else saved_nvp
    eff_type = (cable_type or "").strip() or saved_type
    eff_ticks = ticks_per_meter_for_nvp(eff_nvp)

    if os.name == "nt" and mdio_factory is None:
        return TdrReportState(
            running=False,
            supported=False,
            cable_type=eff_type,
            nvp_pct=eff_nvp,
            summary="Hardware MDIO TDR requires Linux (Raspberry Pi 4).",
        )

    if mdio_factory is None:
        netlink_res = _try_ethtool_netlink_tdr(iface)
        if netlink_res is not None:
            return netlink_res.model_copy(update={"cable_type": eff_type, "nvp_pct": eff_nvp})

        # Ensure interface is administratively UP so PHY clock is awake
        subprocess.run(["ip", "link", "set", "dev", iface, "up"], capture_output=True, check=False)

    factory = mdio_factory or MdioBusAccessor
    try:
        mdio = factory(iface)
    except OSError as exc:
        return TdrReportState(
            running=False,
            supported=False,
            method="MDIO Access Denied",
            cable_type=eff_type,
            nvp_pct=eff_nvp,
            overall_verdict="WARN",
            summary=f"Run JackTrace service as root for raw MDIO TDR ({exc})",
        )

    orig_adv = ADVERTISE_ALL_10_100
    orig_c1000 = CTRL1000_ALL_1G
    try:
        id1 = mdio.read_reg(MII_PHYSID1)
        id2 = mdio.read_reg(MII_PHYSID2)
        phy_uid = ((id1 & 0xFFFF) << 16) | (id2 & 0xFFFF)
        phy_label = format_phy_uid(phy_uid)

        read_adv = mdio.read_reg(MII_ADVERTISE)
        orig_adv = read_adv if (read_adv & 0x01E0) else ADVERTISE_ALL_10_100
        read_c1000 = mdio.read_reg(MII_CTRL1000)
        orig_c1000 = read_c1000 if (read_c1000 & 0x0300) else CTRL1000_ALL_1G

        max_attempts = 4 if mdio_factory is None else 2
        attempts_used = 0
        ctrl_after = 0
        fault_reg = 0
        lengths_raw = (0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF)

        for attempt in range(max_attempts):
            attempts_used = attempt + 1
            # Wake PHY from APD sleep if unplugged/asleep or retrying after collision
            if (not prev_link_up) or (attempt >= 1):
                mdio.write_reg(MII_BMCR, BMCR_RESET)
                time.sleep(0.20 + attempt * 0.04)

            # Configure 1G AN without advertising capabilities, then expose legacy expansion registers
            mdio.write_reg(MII_BMCR, BMCR_1G_AN)
            mdio.write_reg(MII_ADVERTISE, ADVERTISE_CSMA)
            mdio.write_reg(MII_CTRL1000, 0x0000)
            mdio.write_reg(MII_BCM54XX_RDB_ADDR, BCM54XX_RDB_REG0087)
            mdio.write_reg(MII_BCM54XX_RDB_DATA, BCM54XX_ACCESS_MODE_LEGACY_EN)

            # Trigger clean ECD/TDR pulse (RUN | BREAK_LINK = 0x9000 directly)
            mdio.write_exp(BCM54XX_EXP_ECD_CTRL, BCM54XX_ECD_CTRL_RUN | BCM54XX_ECD_CTRL_BREAK_LINK)

            # Settle and poll until ECD_CTRL_IN_PROGRESS clears
            time.sleep(0.25)
            deadline = time.monotonic() + 2.5
            while time.monotonic() < deadline:
                st = mdio.read_exp(BCM54XX_EXP_ECD_CTRL)
                if not (st & BCM54XX_ECD_CTRL_IN_PROGRESS):
                    break
                time.sleep(0.05)

            ctrl_after = mdio.read_exp(BCM54XX_EXP_ECD_CTRL)
            fault_reg = mdio.read_exp(BCM54XX_EXP_ECD_FAULT_TYPE)
            lengths_raw = (
                mdio.read_exp(BCM54XX_EXP_ECD_PAIR_A_LEN + 0),
                mdio.read_exp(BCM54XX_EXP_ECD_PAIR_A_LEN + 1),
                mdio.read_exp(BCM54XX_EXP_ECD_PAIR_A_LEN + 2),
                mdio.read_exp(BCM54XX_EXP_ECD_PAIR_A_LEN + 3),
            )
            mdio.write_reg(MII_BCM54XX_EXP_SEL, 0x0000)

            is_clean = (
                not (ctrl_after & BCM54XX_ECD_CTRL_INVALID)
                and all(((fault_reg >> s) & 0xF) in (1, 2, 3, 4) for s in (12, 8, 4, 0))
            )
            if is_clean:
                break
            if mdio_factory is not None and not (ctrl_after & BCM54XX_ECD_CTRL_INVALID):
                break

        raw_debug = (
            f"phy={getattr(mdio, 'phy_id', '?')} tries={attempts_used} ctrl=0x{ctrl_after:04x} "
            f"fault=0x{fault_reg:04x} raw={[f'0x{v:04x}' for v in lengths_raw]}"
        )
        res = decode_bcm_ecd_registers(
            fault_reg,
            lengths_raw,
            phy_label=phy_label,
            raw_debug=raw_debug,
            ticks_per_meter=eff_ticks,
            ctrl_reg=ctrl_after,
            prev_link_up=prev_link_up,
            prev_speed_mbps=prev_speed_mbps,
        )
        return res.model_copy(update={"cable_type": eff_type, "nvp_pct": eff_nvp})
    except OSError as exc:
        return TdrReportState(
            running=False,
            supported=False,
            cable_type=eff_type,
            nvp_pct=eff_nvp,
            overall_verdict="WARN",
            summary=f"MDIO TDR read failed: {exc}",
        )
    finally:
        try:
            mdio.write_reg(MII_ADVERTISE, orig_adv)
            mdio.write_reg(MII_CTRL1000, orig_c1000)
            mdio.write_reg(MII_BMCR, BMCR_1G_AN_RESTART)
        except OSError:
            pass
        mdio.close()
        if mdio_factory is None:
            subprocess.run(["ethtool", "-s", iface, "autoneg", "on"], capture_output=True, check=False)
