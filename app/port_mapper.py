import re
from typing import Optional
from .models import PhysicalPanelLocation


def extract_trailing_port_number(port_id: str, port_descr: str = "") -> Optional[int]:
    """
    Extract the physical switch port index from common vendor strings:
      - Cisco: 'Gi1/0/24', 'GigabitEthernet0/12', 'Fa0/8', 'Te1/1/48'
      - HP/Aruba/Juniper: '1/1/24', 'ge-0/0/14', '24'
      - Ubiquiti/Netgear/MikroTik: 'Port 18', '0/22', 'ether5', 'swp7'
    """
    for candidate in (port_id or "", port_descr or ""):
        text = candidate.strip()
        if not text or text == "—":
            continue
        # Ignore pure MAC addresses
        if re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", text):
            continue
        # Match slash-separated interface indices like Gi1/0/24 or ge-0/0/14 -> last number
        m_slash = re.search(r"/(\d{1,2})(?:\.\d+)?$", text)
        if m_slash:
            num = int(m_slash.group(1))
            if 1 <= num <= 64:
                return num
        # Match 'Port 24', 'eth4', 'ether5', 'lan3', '24'
        m_plain = re.search(r"(?:port\s*|#|^|ether|eth|swp|lan)(\d{1,2})$", text, re.IGNORECASE)
        if m_plain:
            num = int(m_plain.group(1))
            if 1 <= num <= 64:
                return num
    return None


def infer_switch_port_count(model: str, raw_descr: str, port_num: Optional[int]) -> int:
    """Infer whether the switch faceplate is 8, 16, 24, or 48 ports."""
    combined = f"{model} {raw_descr}"
    # Common model patterns: C2960X-48, USW-48, 2930F-48G, C9300-48P, CRS326-24G, etc.
    if re.search(r"(?:^|[-_\s])48[A-Za-z0-9]*", combined) or (port_num and port_num > 24):
        return 48
    if re.search(r"(?:^|[-_\s])24[A-Za-z0-9]*", combined) or (port_num and port_num > 16):
        return 24
    if re.search(r"(?:^|[-_\s])16[A-Za-z0-9]*", combined) or (port_num and port_num > 8):
        return 16
    if re.search(r"(?:^|[-_\s])0?8[A-Za-z0-9]*", combined):
        return 8
    return 24


def map_port_to_panel(port_id: str, port_descr: str = "", model: str = "", raw_descr: str = "") -> PhysicalPanelLocation:
    """
    Compute human-friendly physical rack switch faceplate coordinates.
    Enterprise 16/24/48-port switches almost universally arrange ports in two stacked rows:
      - Odd ports (1, 3, 5...) on the Top Row
      - Even ports (2, 4, 6...) on the Bottom Row
    8-port compact switches typically use a single horizontal row (1..8).
    """
    pnum = extract_trailing_port_number(port_id, port_descr)
    total = infer_switch_port_count(model, raw_descr, pnum)

    if pnum is None:
        return PhysicalPanelLocation(
            port_number=None,
            total_ports=total,
            row_label="Unmapped",
            pair_column=None,
            summary="Check port ID label on switch",
        )

    if pnum > total:
        return PhysicalPanelLocation(
            port_number=pnum,
            total_ports=total,
            row_label="SFP+ / Uplink",
            pair_column=pnum - total,
            summary=f"SFP+ / Uplink Slot {pnum - total} (Port {pnum})",
        )

    if total == 8 and pnum <= 8:
        pos = "Far Left" if pnum == 1 else ("Far Right" if pnum == 8 else f"Slot {pnum} of 8")
        return PhysicalPanelLocation(
            port_number=pnum,
            total_ports=8,
            row_label="Single Row",
            pair_column=pnum,
            summary=f"Single Row • {pos}",
        )

    cols = total // 2
    pair_col = (pnum + 1) // 2
    is_odd = (pnum % 2) == 1
    row_lbl = "Top Row" if is_odd else "Bottom Row"

    if pair_col == 1:
        horiz = "Far Left (Pair 1)"
    elif pair_col == cols:
        horiz = f"Far Right (Pair {pair_col})"
    elif pair_col <= cols // 3:
        horiz = f"Left Section (Pair {pair_col} of {cols})"
    elif pair_col >= (cols * 2) // 3:
        horiz = f"Right Section (Pair {pair_col} of {cols})"
    else:
        horiz = f"Center Section (Pair {pair_col} of {cols})"

    return PhysicalPanelLocation(
        port_number=pnum,
        total_ports=total,
        row_label=row_lbl,
        pair_column=pair_col,
        summary=f"{row_lbl} • {horiz}",
    )
