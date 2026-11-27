import json
import os
import re
import socket
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    L3Connectivity,
    LinkTelemetry,
    PoeTelemetry,
    StressTestResult,
    SwitchNeighbor,
    VlanAndNacTelemetry,
)
from .port_mapper import map_port_to_panel
from .tdr import read_phy_wiring_sync


def _run_cmd(cmd: List[str], timeout: float = 3.0) -> Tuple[int, str]:
    """Run a system CLI command safely and return (returncode, stdout)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1, ""


def _read_sysfs(iface: str, leaf: str, default: str = "") -> str:
    path = f"/sys/class/net/{iface}/{leaf}"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return default


def parse_ethtool_output(text: str) -> dict:
    """Parse standard `ethtool <iface>` output including link partner capabilities."""
    speed_mbps: Optional[int] = None
    duplex = "Unknown"
    autoneg = True
    link_detected: Optional[bool] = None

    m_spd = re.search(r"Speed:\s*(\d+)\s*Mb/s", text)
    if m_spd:
        speed_mbps = int(m_spd.group(1))

    m_dup = re.search(r"Duplex:\s*(\w+)", text)
    if m_dup:
        duplex = m_dup.group(1)

    m_an = re.search(r"^\s*Auto-negotiation:\s*(\w+)", text, re.IGNORECASE | re.MULTILINE)
    if m_an:
        autoneg = m_an.group(1).lower() == "on"

    m_lnk = re.search(r"Link detected:\s*(yes|no)", text, re.IGNORECASE)
    if m_lnk:
        link_detected = m_lnk.group(1).lower() == "yes"

    m_ms = re.search(r"master-slave status:\s*(\w+)", text, re.IGNORECASE)
    master_slave = "Unknown"
    if m_ms:
        ms_raw = m_ms.group(1).lower()
        if ms_raw == "master":
            master_slave = "Master"
        elif ms_raw == "slave":
            master_slave = "Slave"

    m_mdix = re.search(r"MDI-X:\s*(\S+)", text, re.IGNORECASE)
    mdix_state = "Unknown"
    if m_mdix:
        mx_raw = m_mdix.group(1).lower()
        if mx_raw.startswith("on"):
            mdix_state = "MDI-X"
        elif mx_raw.startswith("off"):
            mdix_state = "MDI"

    # Extract multi-line capability sections
    partner_block = ""
    m_part = re.search(
        r"Link partner advertised link modes:(.*?)(?:\n\t[A-Z]|\Z)",
        text,
        re.DOTALL,
    )
    if m_part:
        partner_block = m_part.group(1)

    local_block = ""
    m_loc = re.search(
        r"Advertised link modes:(.*?)(?:\n\t[A-Z]|\Z)",
        text,
        re.DOTALL,
    )
    if m_loc:
        local_block = m_loc.group(1)

    multi_modes = ("1000baseT", "2500baseT", "5000baseT", "10000baseT")
    partner_1g = any(m in partner_block for m in multi_modes)
    local_1g = any(m in local_block for m in multi_modes) if local_block else True

    return {
        "speed_mbps": speed_mbps,
        "duplex": duplex,
        "autoneg": autoneg,
        "link_detected": link_detected,
        "partner_supports_1g": partner_1g,
        "local_supports_1g": local_1g,
        "mdix_state": mdix_state,
        "master_slave": master_slave,
    }


def read_link_telemetry(iface: str) -> LinkTelemetry:
    operstate = _read_sysfs(iface, "operstate", "down")
    carrier_str = _read_sysfs(iface, "carrier", "0")
    mac = _read_sysfs(iface, "address", "00:00:00:00:00:00").upper()
    rx_crc = int(_read_sysfs(iface, "statistics/rx_crc_errors", "0") or 0)
    rx_pkts = int(_read_sysfs(iface, "statistics/rx_packets", "0") or 0)
    tx_pkts = int(_read_sysfs(iface, "statistics/tx_packets", "0") or 0)

    rc, eth_out = _run_cmd(["ethtool", iface], timeout=2.0)
    if rc != 0:
        rc, eth_out = _run_cmd(["sudo", "-n", "ethtool", iface], timeout=2.0)

    parsed = parse_ethtool_output(eth_out) if eth_out else {}
    carrier_up = (carrier_str == "1") or bool(parsed.get("link_detected"))

    speed = parsed.get("speed_mbps")
    if speed is None and carrier_up:
        spd_sys = _read_sysfs(iface, "speed", "")
        if spd_sys.isdigit():
            speed = int(spd_sys)

    duplex = parsed.get("duplex", "Unknown")
    if duplex == "Unknown" and carrier_up:
        dup_sys = _read_sysfs(iface, "duplex", "")
        if dup_sys:
            duplex = dup_sys.capitalize()

    partner_1g = parsed.get("partner_supports_1g", False)
    local_1g = parsed.get("local_supports_1g", True)

    downshift = False
    if not carrier_up:
        note = "No link carrier — plug into wall socket or tap PULSE HARDWARE TDR"
    elif speed and speed >= 2500:
        note = f"All 4 TIA-568B pairs active ({speed / 1000:.1f}GBASE-T multi-gig verified)"
    elif speed and speed >= 1000:
        note = "All 4 TIA-568B pairs active (1000BASE-T verified)"
    elif speed == 100 and partner_1g and local_1g:
        downshift = True
        note = "FAULT SUSPECTED: Switch advertises 1GbE but link downshifted to 100M (Pair C 4-5 or Pair D 7-8 open!)"
    elif speed == 100:
        note = "2-Pair 100BASE-TX link (Switch port only advertises 100M)"
    elif speed == 10:
        downshift = partner_1g
        note = "10BASE-T link — check cable quality or switch speed setting"
    else:
        note = "Carrier active"

    phy_wiring = read_phy_wiring_sync(
        iface,
        carrier_up=carrier_up,
        speed_mbps=speed if carrier_up else None,
        ethtool_mdix=parsed.get("mdix_state", "Unknown"),
        ethtool_ms=parsed.get("master_slave", "Unknown"),
    )

    return LinkTelemetry(
        iface=iface,
        carrier_up=carrier_up,
        operstate=operstate,
        mac_address=mac,
        speed_mbps=speed if carrier_up else None,
        duplex=duplex if carrier_up else "Down",
        autoneg=parsed.get("autoneg", True),
        partner_supports_1g=partner_1g,
        local_supports_1g=local_1g,
        pair_downshift_suspected=downshift,
        pair_diagnostic_note=note,
        rx_crc_errors=rx_crc,
        rx_packets=rx_pkts,
        tx_packets=tx_pkts,
        phy_wiring=phy_wiring,
    )


def _as_list(val: Any) -> List[Any]:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def clean_switch_model_and_vendor(descr: str, fallback_model: str = "") -> Tuple[str, str]:
    """Extract a concise human-readable switch make/model from verbose LLDP/CDP descriptions."""
    raw = f"{fallback_model} {descr}".strip()
    if not raw:
        return "Managed Network Switch", "Unknown"

    low = raw.lower()
    if "cisco" in low:
        vendor = "Cisco Systems"
        # Look for Catalyst / Nexus / CBS / Meraki model numbers
        m = re.search(r"(WS-C[0-9A-Z-]+|C9[2345]00[0-9A-Z-]*|C2960[A-Z0-9-]*|C3[678]50[A-Z0-9-]*|SG[0-9A-Z-]+|CBS[0-9A-Z-]+|MS[1234][0-9]{2}[A-Z0-9-]*)", raw, re.I)
        if m:
            mdl = m.group(1).upper().replace("WS-C", "Catalyst ")
            if not mdl.startswith(("Cisco", "Catalyst", "Meraki")):
                mdl = f"Cisco {mdl}"
            elif mdl.startswith("Catalyst"):
                mdl = f"Cisco {mdl}"
            return mdl, vendor
        return "Cisco Switch", vendor

    if "ubiquiti" in low or "unifi" in low or "usw-" in low or "edgeswitch" in low:
        vendor = "Ubiquiti Inc."
        m = re.search(r"(USW-[A-Za-z0-9-]+|US-[0-9A-Za-z-]+|ES-[0-9A-Za-z-]+)", raw)
        return (f"Ubiquiti {m.group(1)}" if m else "Ubiquiti UniFi Switch"), vendor

    if "aruba" in low or "procurve" in low or "hewlett" in low or "jl" in low:
        vendor = "HPE / Aruba"
        m = re.search(r"(Aruba\s+[0-9A-Za-z-]+|JL[0-9]{3}[A-Z]?|J9[0-9]{3}[A-Z]?)", raw, re.I)
        return (m.group(1) if m else "HPE Aruba Switch"), vendor

    if "juniper" in low or "junos" in low or "ex2" in low or "ex3" in low or "ex4" in low:
        vendor = "Juniper Networks"
        m = re.search(r"(EX[0-9]{4}[A-Za-z0-9-]*|QFX[0-9]{4}[A-Za-z0-9-]*)", raw, re.I)
        return (f"Juniper {m.group(1).upper()}" if m else "Juniper JUNOS Switch"), vendor

    if "mikrotik" in low or "routeros" in low or "swos" in low:
        vendor = "MikroTik"
        m = re.search(r"(CRS[0-9A-Za-z-]+|CSS[0-9A-Za-z-]+|RB[0-9A-Za-z-]+)", raw)
        return (f"MikroTik {m.group(1)}" if m else "MikroTik Switch"), vendor

    if "netgear" in low:
        vendor = "Netgear"
        m = re.search(r"(GS[0-9]{3}[A-Za-z0-9-]*|MS[0-9]{3}[A-Za-z0-9-]*|M4[0-9]{3}[A-Za-z0-9-]*)", raw, re.I)
        return (f"Netgear {m.group(1).upper()}" if m else "Netgear Managed Switch"), vendor

    if "fortinet" in low or "fortiswitch" in low:
        return "Fortinet FortiSwitch", "Fortinet"

    if "grandstream" in low or "gwn7" in low:
        vendor = "Grandstream Networks"
        m = re.search(r"(GWN[0-9A-Z-]+)", raw, re.I)
        return (f"Grandstream {m.group(1).upper()}" if m else "Grandstream Switch"), vendor

    # Generic first line trimmed
    first_line = descr.splitlines()[0].strip() if descr else fallback_model
    return (first_line[:44] if first_line else "Managed Switch"), "Generic"


def parse_lldpcli_json(
    raw_json: str, iface: str
) -> Tuple[SwitchNeighbor, PoeTelemetry, Optional[int], str, Optional[int]]:
    """
    Parse `lldpcli -f json show neighbors details` output for `iface`.
    Normalizes single-neighbor dicts and multi-neighbor lists (e.g. LLDP + CDPv2).
    Returns: (SwitchNeighbor, PoeTelemetry, native_vlan, native_vlan_name, voice_vlan)
    """
    data = json.loads(raw_json) if raw_json else {}
    lldp_root = data.get("lldp", {})
    raw_ifaces = _as_list(lldp_root.get("interface"))

    entries: List[dict] = []
    for item in raw_ifaces:
        if isinstance(item, dict):
            if iface in item:
                entries.extend(_as_list(item[iface]))
            elif item.get("name") == iface:
                entries.append(item)
            elif not entries and len(item) == 1:
                # Fallback if only one interface exists
                only_key = next(iter(item.keys()))
                if only_key == iface:
                    entries.extend(_as_list(item[only_key]))

    if not entries:
        return SwitchNeighbor(), PoeTelemetry(), None, "Untagged / Unknown", None

    protocols: List[str] = []
    sw_name = ""
    raw_descr = ""
    mgmt_ip = ""
    chassis_mac = ""
    port_id = ""
    port_descr = ""
    native_vlan: Optional[int] = None
    native_vlan_name = "Untagged / Unknown"
    voice_vlan: Optional[int] = None
    poe = PoeTelemetry()

    for ent in entries:
        via = str(ent.get("via", "LLDP")).upper()
        proto_clean = "CDP" if "CDP" in via else via
        if proto_clean not in protocols:
            protocols.append(proto_clean)

        # Chassis block: either {"SW-01": {...}} or direct {"descr": ..., "id": ...}
        chassis = ent.get("chassis", {})
        if isinstance(chassis, dict):
            if "id" in chassis or "descr" in chassis:
                c_name = str(chassis.get("name", ""))
                c_body = chassis
            elif len(chassis) >= 1:
                c_name = next(iter(chassis.keys()))
                c_body = chassis[c_name] if isinstance(chassis[c_name], dict) else {}
            else:
                c_name, c_body = "", {}

            if c_name and not sw_name:
                sw_name = c_name
            descr_val = str(c_body.get("descr", ""))
            if len(descr_val) > len(raw_descr):
                raw_descr = descr_val

            cid = c_body.get("id", {})
            if isinstance(cid, dict) and cid.get("type") == "mac" and not chassis_mac:
                chassis_mac = str(cid.get("value", "")).upper()

            mips = _as_list(c_body.get("mgmt-ip"))
            for ip_item in mips:
                ip_s = str(ip_item.get("value") if isinstance(ip_item, dict) else ip_item)
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_s) and not mgmt_ip:
                    mgmt_ip = ip_s

        # Port block
        port = ent.get("port", {})
        if isinstance(port, dict):
            pid = port.get("id", {})
            pid_val = str(pid.get("value", "")) if isinstance(pid, dict) else str(pid)
            pdesc_val = str(port.get("descr", ""))
            # Prefer short interface IDs like Gi1/0/24 over MAC addresses
            if pid_val and (not port_id or ":" in port_id):
                port_id = pid_val
            if pdesc_val and not port_descr:
                port_descr = pdesc_val

            # 802.3 Power via MDI TLV inside port.power
            pwr = port.get("power", {})
            if isinstance(pwr, dict) and pwr:
                supp = str(pwr.get("supported", "")).lower() in ("yes", "true", "1")
                enab = str(pwr.get("enabled", "")).lower() in ("yes", "true", "1")
                p_cls = str(pwr.get("class", "—"))
                p_typ = str(pwr.get("type", pwr.get("device-type", "")))
                p_pairs = str(pwr.get("powerpairs", pwr.get("pairs", "signal")))
                alloc_raw = pwr.get("allocated", pwr.get("power-allocated"))
                req_raw = pwr.get("requested", pwr.get("power-requested"))

                def _to_watts(v: Any) -> Optional[float]:
                    if v is None:
                        return None
                    m_num = re.search(r"(\d+(?:\.\d+)?)", str(v))
                    if not m_num:
                        return None
                    val_f = float(m_num.group(1))
                    # lldpd reports milliwatts if > 100 (e.g. 25500 -> 25.5W)
                    return round(val_f / 1000.0, 1) if val_f > 100 else round(val_f, 1)

                alloc_w = _to_watts(alloc_raw)
                req_w = _to_watts(req_raw)
                is_at = "2" in p_typ or "class-4" in p_cls.lower() or "class 4" in p_cls.lower() or (alloc_w and alloc_w > 15.5)
                std_lbl = "802.3at PoE+" if is_at else ("802.3af PoE" if (supp or enab) else "None")
                if supp or enab or alloc_w:
                    poe = PoeTelemetry(
                        supported=supp or enab,
                        enabled=enab or bool(alloc_w),
                        standard=std_lbl,
                        power_class=p_cls,
                        allocated_watts=alloc_w,
                        requested_watts=req_w,
                        power_pairs=p_pairs,
                        source_protocol=f"{proto_clean} MDI-Power TLV",
                    )

        # VLANs block
        for vl in _as_list(ent.get("vlan")):
            if isinstance(vl, dict):
                vid_s = str(vl.get("vlan-id", ""))
                vname = str(vl.get("value", ""))
                is_pvid = str(vl.get("pvid", "")).lower() in ("yes", "true", "1")
                if vid_s.isdigit():
                    vid_i = int(vid_s)
                    if is_pvid or native_vlan is None:
                        native_vlan = vid_i
                        if vname:
                            native_vlan_name = f"VLAN {vid_i} ({vname})"
                        else:
                            native_vlan_name = f"VLAN {vid_i}"
                    elif "voice" in vname.lower() or "voip" in vname.lower():
                        voice_vlan = vid_i

        # LLDP-MED Voice Policy block
        med = ent.get("lldp-med", {})
        if isinstance(med, dict):
            for pol in _as_list(med.get("policy")):
                if isinstance(pol, dict):
                    app_t = str(pol.get("apptype", pol.get("application_type", ""))).lower()
                    vid_m = str(pol.get("vid", pol.get("vlan-id", "")))
                    if "voice" in app_t and vid_m.isdigit():
                        voice_vlan = int(vid_m)

    model, vendor = clean_switch_model_and_vendor(raw_descr)
    panel = map_port_to_panel(port_id, port_descr, model, raw_descr)
    conf = "HIGH" if len(protocols) >= 2 else "CONFIRMED"

    neighbor = SwitchNeighbor(
        detected=True,
        protocols=protocols,
        confidence=conf,
        switch_name=sw_name or "Unnamed Switch",
        model=model,
        vendor=vendor,
        raw_descr=raw_descr,
        mgmt_ip=mgmt_ip or "—",
        chassis_mac=chassis_mac or "—",
        port_id=port_id or port_descr or "—",
        port_descr=port_descr or "—",
        panel=panel,
    )
    return neighbor, poe, native_vlan, native_vlan_name, voice_vlan


def extract_lldp_tagged_vlans(raw_json: str, iface: str) -> List[int]:
    """Extract non-PVID 802.1Q VLAN IDs advertised by LLDP neighbor TLVs."""
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError:
        return []
    entries = _as_list(data.get("lldp", {}).get("interface"))
    tagged: List[int] = []
    for item in entries:
        if not isinstance(item, dict) or iface not in item:
            continue
        ent = item[iface]
        for vl in _as_list(ent.get("vlan")):
            if not isinstance(vl, dict):
                continue
            vid_s = str(vl.get("vlan-id", ""))
            is_pvid = str(vl.get("pvid", "")).lower() in ("yes", "true", "1")
            if vid_s.isdigit() and not is_pvid:
                vid_i = int(vid_s)
                if 1 <= vid_i <= 4094 and vid_i not in tagged:
                    tagged.append(vid_i)
    return sorted(tagged)


def query_switch_and_vlans(
    iface: str, sniffer_data: dict
) -> Tuple[SwitchNeighbor, PoeTelemetry, VlanAndNacTelemetry]:
    rc, out = _run_cmd(["lldpcli", "-f", "json", "show", "neighbors", "details"], timeout=2.5)
    if rc != 0:
        rc, out = _run_cmd(["sudo", "-n", "lldpcli", "-f", "json", "show", "neighbors", "details"], timeout=2.5)

    neighbor, poe, native_vlan, native_vlan_name, voice_vlan = (
        parse_lldpcli_json(out, iface) if (rc == 0 and out) else (SwitchNeighbor(), PoeTelemetry(), None, "Untagged / Unknown", None)
    )
    lldp_tagged = extract_lldp_tagged_vlans(out, iface) if (rc == 0 and out) else []

    # Supplement or fallback using direct AF_PACKET sniffer cache
    raw_nb = sniffer_data.get("raw_neighbor", {})
    if not neighbor.detected and raw_nb:
        proto = raw_nb.get("protocol", "LLDP")
        raw_descr = raw_nb.get("raw_descr", "")
        raw_mdl = raw_nb.get("model", "")
        mdl, vnd = clean_switch_model_and_vendor(raw_descr, raw_mdl)
        pid = raw_nb.get("port_id", "—")
        pdesc = raw_nb.get("port_descr", "—")
        neighbor = SwitchNeighbor(
            detected=True,
            protocols=[proto],
            confidence="CONFIRMED",
            switch_name=raw_nb.get("switch_name", "Switch"),
            model=mdl,
            vendor=vnd,
            raw_descr=raw_descr,
            mgmt_ip=raw_nb.get("mgmt_ip", "—"),
            chassis_mac=raw_nb.get("chassis_mac", "—"),
            port_id=pid,
            port_descr=pdesc,
            panel=map_port_to_panel(pid, pdesc, mdl, raw_descr),
        )

    if native_vlan is None and raw_nb.get("native_vlan", "").isdigit():
        native_vlan = int(raw_nb["native_vlan"])
        native_vlan_name = f"VLAN {native_vlan}"
    if voice_vlan is None and raw_nb.get("voice_vlan", "").isdigit():
        voice_vlan = int(raw_nb["voice_vlan"])

    tagged = sorted(set(sniffer_data.get("tagged_vlans", [])) | set(lldp_tagged))
    if native_vlan and native_vlan not in tagged and voice_vlan:
        tagged = sorted(set(tagged + [native_vlan, voice_vlan]))

    eapol_seen = bool(sniffer_data.get("eapol_seen", False))
    nac_status = "802.1X Required (EAPOL Challenge Seen!)" if eapol_seen else "Open (No EAPOL Challenge)"

    vlan_info = VlanAndNacTelemetry(
        native_vlan=native_vlan,
        native_vlan_name=native_vlan_name,
        voice_vlan=voice_vlan,
        tagged_vlans=tagged,
        eapol_8021x_seen=eapol_seen,
        nac_status=nac_status,
    )
    return neighbor, poe, vlan_info


def _ping_single_ms(target_ip: str, iface: str = "") -> Optional[float]:
    if not target_ip or target_ip == "—":
        return None
    cmd = ["ping", "-c", "1", "-W", "1"]
    if iface and os.name != "nt":
        cmd.extend(["-I", iface])
    cmd.append(target_ip)
    rc, out = _run_cmd(cmd, timeout=2.0)
    if rc != 0:
        return None
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    return round(float(m.group(1)), 2) if m else None


def probe_l3_connectivity(iface: str, carrier_up: bool) -> L3Connectivity:
    if not carrier_up:
        return L3Connectivity(dhcp_status="Link Down")

    ipv4 = "—"
    cidr = "—"
    dhcp_status = "Waiting for DHCP..."

    rc, addr_out = _run_cmd(["ip", "-j", "-4", "addr", "show", "dev", iface], timeout=2.0)
    if rc == 0 and addr_out:
        try:
            arr = json.loads(addr_out)
            for item in arr:
                for ai in item.get("addr_info", []):
                    local_ip = ai.get("local", "")
                    plen = ai.get("prefixlen", "")
                    if local_ip:
                        ipv4 = local_ip
                        cidr = f"{local_ip}/{plen}"
                        if local_ip.startswith("169.254."):
                            dhcp_status = "APIPA Self-Assigned (No DHCP Offer!)"
                        else:
                            dhcp_status = "Bound (Dynamic)" if ai.get("dynamic") else "Static / Bound"
                        break
        except json.JSONDecodeError:
            pass

    # Default gateway on iface (fallback to global default route)
    gw_ip = "—"
    for rcmd in (
        ["ip", "-j", "-4", "route", "show", "default", "dev", iface],
        ["ip", "-j", "-4", "route", "show", "default"],
    ):
        rc, rout = _run_cmd(rcmd, timeout=2.0)
        if rc == 0 and rout:
            try:
                routes = json.loads(rout)
                for r in routes:
                    if r.get("gateway"):
                        gw_ip = r["gateway"]
                        break
                if gw_ip != "—":
                    break
            except json.JSONDecodeError:
                pass

    # DNS server from /etc/resolv.conf
    dns_srv = "—"
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            dns_srv = parts[1]
                            break
        except OSError:
            pass

    gw_ms = _ping_single_ms(gw_ip, iface) if gw_ip != "—" else None

    dns_ms: Optional[float] = None
    internet_ok = False
    http_ms: Optional[float] = None
    captive = False

    if ipv4 != "—" and not ipv4.startswith("169.254."):
        t0 = time.perf_counter()
        try:
            socket.getaddrinfo("one.one.one.one", 80, socket.AF_INET)
            dns_ms = round((time.perf_counter() - t0) * 1000.0, 1)
        except OSError:
            dns_ms = None

        # Quick HTTP 204 captive-portal / internet reachability probe
        t1 = time.perf_counter()
        try:
            req = urllib.request.Request(
                "http://connectivitycheck.gstatic.com/generate_204",
                headers={"User-Agent": "PiNetTester/0.1"},
            )
            with urllib.request.urlopen(req, timeout=1.8) as resp:
                http_ms = round((time.perf_counter() - t1) * 1000.0, 1)
                if resp.status == 204:
                    internet_ok = True
                else:
                    captive = True
        except Exception:
            internet_ok = False

    return L3Connectivity(
        ipv4_address=ipv4,
        subnet_cidr=cidr,
        dhcp_status=dhcp_status,
        gateway_ip=gw_ip,
        gateway_ping_ms=gw_ms,
        dns_server=dns_srv,
        dns_resolve_ms=dns_ms,
        internet_ok=internet_ok,
        http_probe_ms=http_ms,
        captive_portal=captive,
    )


def run_line_stress_test(iface: str, target_ip: str, count: int = 20) -> StressTestResult:
    """Send a rapid burst of ICMP echo requests while monitoring PHY CRC error counters."""
    crc_before = int(_read_sysfs(iface, "statistics/rx_crc_errors", "0") or 0)
    cmd = ["ping", "-c", str(count), "-i", "0.2", "-W", "1"]
    if iface and os.name != "nt":
        cmd.extend(["-I", iface])
    cmd.append(target_ip)

    rc, out = _run_cmd(cmd, timeout=max(8.0, count * 0.4 + 2.0))
    crc_after = int(_read_sysfs(iface, "statistics/rx_crc_errors", "0") or 0)
    crc_delta = max(0, crc_after - crc_before)

    tx, rx, loss = count, 0, 100.0
    m_stat = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+received.*?([\d.]+)%\s+packet loss", out)
    if m_stat:
        tx = int(m_stat.group(1))
        rx = int(m_stat.group(2))
        loss = float(m_stat.group(3))

    min_ms = avg_ms = max_ms = None
    m_rtt = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/", out)
    if m_rtt:
        min_ms = round(float(m_rtt.group(1)), 2)
        avg_ms = round(float(m_rtt.group(2)), 2)
        max_ms = round(float(m_rtt.group(3)), 2)

    if rx > 0 and loss == 0.0 and crc_delta == 0:
        verdict = "PASS (0% Loss, 0 CRC Errors)"
    elif rx > 0:
        verdict = f"WARN ({loss}% Loss, {crc_delta} CRC Errors)"
    else:
        verdict = "FAIL (Target Unreachable)"

    return StressTestResult(
        running=False,
        completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        target_ip=target_ip,
        packets_sent=tx,
        packets_received=rx,
        loss_percent=loss,
        min_ms=min_ms,
        avg_ms=avg_ms,
        max_ms=max_ms,
        crc_delta=crc_delta,
        verdict=verdict,
    )
