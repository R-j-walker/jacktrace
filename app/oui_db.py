import os
from functools import lru_cache
from typing import Dict

# Built-in offline OUI prefixes for common IT, enterprise network, and rogue consumer hardware
BUILTIN_OUIS: Dict[str, str] = {
    "001EF7": "Cisco Systems",
    "00000C": "Cisco Systems",
    "001B0D": "Cisco Systems",
    "002584": "Cisco Systems",
    "58AC78": "Cisco Systems",
    "F04A02": "Cisco Meraki",
    "E0553D": "Cisco Meraki",
    "906CAC": "Fortinet Inc.",
    "00090F": "Fortinet Inc.",
    "704CA5": "Fortinet Inc.",
    "F09FC2": "Ubiquiti Inc.",
    "7483C2": "Ubiquiti Inc.",
    "245A4C": "Ubiquiti Inc.",
    "788A20": "Ubiquiti Inc.",
    "602232": "Ubiquiti Inc.",
    "D021F9": "Ubiquiti Inc.",
    "3821C7": "HPE / Aruba",
    "001A4B": "HPE / Aruba",
    "94F128": "HPE / Aruba",
    "204C03": "HPE / Aruba",
    "D89EF3": "Dell Inc.",
    "F8BC12": "Dell Inc.",
    "001422": "Dell Inc.",
    "B8CA3A": "Dell Inc.",
    "001132": "Synology Inc.",
    "9009D0": "Synology Inc.",
    "245EBE": "QNAP Systems",
    "3CD92B": "HP Inc.",
    "001E0B": "HP Inc.",
    "A0B3CC": "HP Inc.",
    "008077": "Brother Ind.",
    "DCA632": "Raspberry Pi",
    "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    "D83ADD": "Raspberry Pi",
    "D807B6": "TP-Link Tech",
    "50C7BF": "TP-Link Tech",
    "B0BE76": "TP-Link Tech",
    "14CC20": "TP-Link Tech",
    "A040A0": "Netgear",
    "28C68E": "Netgear",
    "C40415": "Netgear",
    "488F5A": "MikroTik",
    "DC2C6E": "MikroTik",
    "64D154": "MikroTik",
    "2C6BF5": "Juniper Networks",
    "54E032": "Juniper Networks",
    "005056": "VMware",
    "000C29": "VMware",
    "BC2411": "Proxmox Server",
    "00155D": "Microsoft Hyper-V",
    "3C22FB": "Apple Inc.",
    "F01898": "Apple Inc.",
    "ACDE48": "Apple Inc.",
    "C0A53E": "Hikvision",
    "4419B6": "Hikvision",
    "ACCC8E": "Axis Comm.",
    "00408C": "Axis Comm.",
    "C074AD": "Grandstream Networks",
    "000B82": "Grandstream Networks",
}


@lru_cache(maxsize=1)
def _load_system_oui_map() -> Dict[str, str]:
    """Load IEEE OUI table from Linux packages (ieee-data / arp-scan) if present."""
    table = dict(BUILTIN_OUIS)
    candidates = (
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/arp-scan/ieee-oui.txt",
        "/var/lib/ieee-data/oui.txt",
    )
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "(base 16)" in line:
                        parts = line.split("(base 16)", 1)
                        prefix = parts[0].strip().replace("-", "").upper()
                        vendor = parts[1].strip()
                        if len(prefix) == 6 and vendor:
                            table.setdefault(prefix, vendor[:22])
                    elif "\t" in line and len(line) > 7:
                        parts = line.split("\t", 1)
                        prefix = parts[0].strip().replace(":", "").replace("-", "").upper()
                        vendor = parts[1].strip()
                        if len(prefix) == 6 and vendor:
                            table.setdefault(prefix, vendor[:22])
            break
        except OSError:
            continue
    return table


def lookup_mac_vendor(mac: str) -> str:
    if not mac or mac == "—":
        return "Unknown"
    clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(clean) < 6:
        return "Unknown"
    # Check locally administered unicast MAC bit (random mobile MACs / VMs)
    prefix = clean[:6]
    table = _load_system_oui_map()
    if prefix in table:
        return table[prefix]
    try:
        first_byte = int(clean[:2], 16)
        if first_byte & 0x02:
            return "Randomized / Virtual MAC"
    except ValueError:
        pass
    return "Generic NIC"
