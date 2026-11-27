import platform
import random
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .models import (
    CleartextAlert,
    DhcpOfferInfo,
    ExposureTalker,
    Ipv6RaSender,
    L2ForensicsState,
    L3Connectivity,
    PassiveExposureState,
    SecurityFinding,
    SecurityMetricBar,
    SecurityReportState,
    StpBpduInfo,
    SubnetScanState,
    VlanAndNacTelemetry,
)
from .oui_db import lookup_mac_vendor

DHCP_MAGIC = b"\x63\x82\x53\x63"


def _ipv4_checksum(header: bytes) -> int:
    if len(header) % 2 == 1:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac_str_to_bytes(mac: str) -> bytes:
    parts = mac.replace("-", ":").split(":")
    if len(parts) == 6:
        try:
            return bytes(int(p, 16) for p in parts)
        except ValueError:
            pass
    return b"\x02\x42\xac\x11\x00\x99"


def build_dhcp_discover_frame(src_mac_str: str, xid: int) -> bytes:
    """Build a safe broadcast DHCPDISCOVER Ethernet frame (does not request or claim an IP lease)."""
    mac_b = _mac_str_to_bytes(src_mac_str)

    # BOOTP fixed header (236 bytes) + magic cookie + options
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,  # BOOTREQUEST
        1,  # Ethernet
        6,  # MAC len
        0,  # Hops
        xid,
        0,  # Secs
        0x8000,  # Broadcast flag
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00",
        mac_b + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    opts = (
        DHCP_MAGIC
        + b"\x35\x01\x01"  # Option 53: DHCPDISCOVER
        + b"\x3d\x07\x01" + mac_b  # Option 61: Client ID
        + b"\x37\x0c\x01\x03\x06\x0f\x2a\x2b\x33\x42\x43\x77\x96\xfc"  # Opts 1,3,6,15,42,43,51,66,67,119,150,252
        + b"\xff"
    )
    dhcp_payload = bootp + opts
    if len(dhcp_payload) < 300:
        dhcp_payload += b"\x00" * (300 - len(dhcp_payload))

    udp_len = 8 + len(dhcp_payload)
    udp_hdr = struct.pack("!HHHH", 68, 67, udp_len, 0)

    ip_tot_len = 20 + udp_len
    ip_id = random.randint(1, 65534)
    ip_hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_tot_len,
        ip_id,
        0,
        64,
        17,
        0,
        b"\x00\x00\x00\x00",
        b"\xff\xff\xff\xff",
    )
    csum = _ipv4_checksum(ip_hdr_no_csum)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_tot_len,
        ip_id,
        0,
        64,
        17,
        csum,
        b"\x00\x00\x00\x00",
        b"\xff\xff\xff\xff",
    )

    eth_hdr = b"\xff\xff\xff\xff\xff\xff" + mac_b + struct.pack("!H", 0x0800)
    return eth_hdr + ip_hdr + udp_hdr + dhcp_payload


def parse_dhcp_offer_frame(frame: bytes, expected_xid: int) -> Optional[dict]:
    """Inspect a raw Ethernet frame and extract DHCPOFFER details if it matches `expected_xid`."""
    if len(frame) < 14 + 20 + 8 + 240:
        return None

    src_mac = ":".join(f"{b:02X}" for b in frame[6:12])
    eth_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14

    if eth_type == 0x8100 and len(frame) >= 18 + 20 + 8 + 240:
        eth_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18

    if eth_type != 0x0800:
        return None

    ihl = (frame[offset] & 0x0F) * 4
    proto = frame[offset + 9]
    if proto != 17 or len(frame) < offset + ihl + 8 + 240:
        return None

    ip_src = socket.inet_ntoa(frame[offset + 12 : offset + 16])
    udp_off = offset + ihl
    sport, dport = struct.unpack("!HH", frame[udp_off : udp_off + 4])
    if sport != 67 or dport != 68:
        return None

    bootp_off = udp_off + 8
    bootp = frame[bootp_off:]
    if len(bootp) < 240:
        return None

    op = bootp[0]
    xid = struct.unpack("!I", bootp[4:8])[0]
    if op != 2 or xid != expected_xid:
        return None

    yiaddr = socket.inet_ntoa(bootp[16:20])
    siaddr = socket.inet_ntoa(bootp[20:24])
    if bootp[236:240] != DHCP_MAGIC:
        return None

    msg_type = 0
    server_id = ""
    router_ip = ""
    dns_ip = ""
    subnet_mask = ""
    lease_time_s: Optional[int] = None
    domain_name = ""
    ntp_server = ""
    tftp_server = ""
    boot_file = ""
    vendor_opt43 = ""
    wpad_url = ""

    idx = 240
    while idx < len(bootp):
        opt = bootp[idx]
        idx += 1
        if opt == 0:
            continue
        if opt == 255 or idx >= len(bootp):
            break
        olen = bootp[idx]
        idx += 1
        oval = bootp[idx : idx + olen]
        idx += olen

        if opt == 53 and len(oval) >= 1:
            msg_type = oval[0]
        elif opt == 54 and len(oval) >= 4:
            server_id = socket.inet_ntoa(oval[:4])
        elif opt == 1 and len(oval) >= 4:
            subnet_mask = socket.inet_ntoa(oval[:4])
        elif opt == 3 and len(oval) >= 4:
            router_ip = socket.inet_ntoa(oval[:4])
        elif opt == 6 and len(oval) >= 4:
            dns_ip = socket.inet_ntoa(oval[:4])
        elif opt == 15 and oval:
            domain_name = oval.decode("utf-8", errors="ignore").strip("\x00 ")
        elif opt == 42 and len(oval) >= 4:
            ntp_server = socket.inet_ntoa(oval[:4])
        elif opt == 43 and oval:
            printable = sum(1 for b in oval if 32 <= b <= 126)
            if printable / len(oval) >= 0.7:
                vendor_opt43 = oval.decode("ascii", errors="ignore").strip("\x00 ")
            else:
                vendor_opt43 = ":".join(f"{b:02X}" for b in oval[:16])
        elif opt == 51 and len(oval) >= 4:
            lease_time_s = struct.unpack("!I", oval[:4])[0]
        elif opt == 66 and oval:
            tftp_server = oval.decode("utf-8", errors="ignore").strip("\x00 ")
        elif opt == 67 and oval:
            boot_file = oval.decode("utf-8", errors="ignore").strip("\x00 ")
        elif opt == 150 and len(oval) >= 4:
            tftp_server = socket.inet_ntoa(oval[:4])
        elif opt == 252 and oval:
            wpad_url = oval.decode("utf-8", errors="ignore").strip("\x00 ")

    if not boot_file and len(bootp) >= 236:
        raw_bfile = bootp[108:236].split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()
        if raw_bfile:
            boot_file = raw_bfile

    if msg_type != 2:  # Must be DHCPOFFER
        return None

    srv = server_id or (siaddr if siaddr != "0.0.0.0" else ip_src)
    return {
        "server_ip": srv,
        "offered_ip": yiaddr,
        "server_mac": src_mac,
        "router_ip": router_ip or "—",
        "dns_ip": dns_ip or "—",
        "subnet_mask": subnet_mask or "—",
        "lease_time_s": lease_time_s,
        "domain_name": domain_name or "—",
        "ntp_server": ntp_server or "—",
        "tftp_server": tftp_server or "—",
        "boot_file": boot_file or "—",
        "vendor_opt43": vendor_opt43 or "—",
        "wpad_url": wpad_url or "—",
    }


def probe_dhcp_servers_sync(
    iface: str, local_mac: str, expected_gateway: str = "—", listen_sec: float = 2.4
) -> List[DhcpOfferInfo]:
    """Broadcast a safe non-lease DHCPDISCOVER on `iface` and collect all responding DHCP servers."""
    if platform.system() != "Linux" or not hasattr(socket, "AF_PACKET"):
        return []

    xid = random.randint(0x10000000, 0x7FFFFFFF)
    pkt = build_dhcp_discover_frame(local_mac, xid)
    offers_by_key: Dict[Tuple[str, str], dict] = {}

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((iface, 0))
        sock.settimeout(0.3)
    except OSError:
        return []

    with sock:
        try:
            sock.send(pkt)
        except OSError:
            return []

        deadline = time.monotonic() + listen_sec
        sent_retry = False
        while time.monotonic() < deadline:
            if not sent_retry and (deadline - time.monotonic()) < (listen_sec * 0.5) and not offers_by_key:
                try:
                    sock.send(pkt)
                except OSError:
                    pass
                sent_retry = True

            try:
                frame, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break

            parsed = parse_dhcp_offer_frame(frame, xid)
            if parsed:
                key = (parsed["server_ip"], parsed["server_mac"])
                offers_by_key[key] = parsed

    raw_list = list(offers_by_key.values())
    if not raw_list:
        return []

    results: List[DhcpOfferInfo] = []
    for item in raw_list:
        vendor = lookup_mac_vendor(item["server_mac"])
        if len(raw_list) == 1:
            auth = True
        elif expected_gateway != "—" and (
            item["router_ip"] == expected_gateway or item["server_ip"] == expected_gateway
        ):
            auth = True
        else:
            auth = False

        results.append(
            DhcpOfferInfo(
                server_ip=item["server_ip"],
                offered_ip=item["offered_ip"],
                server_mac=item["server_mac"],
                vendor=vendor,
                router_ip=item["router_ip"],
                dns_ip=item["dns_ip"],
                authorized=auth,
                subnet_mask=item.get("subnet_mask", "—"),
                lease_time_s=item.get("lease_time_s"),
                domain_name=item.get("domain_name", "—"),
                ntp_server=item.get("ntp_server", "—"),
                tftp_server=item.get("tftp_server", "—"),
                boot_file=item.get("boot_file", "—"),
                vendor_opt43=item.get("vendor_opt43", "—"),
                wpad_url=item.get("wpad_url", "—"),
            )
        )
    return results


def score_to_letter_grade(score: int) -> str:
    if score >= 93:
        return "A"
    if score >= 88:
        return "A-"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C+"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def evaluate_security_posture(
    dhcp_offers: List[DhcpOfferInfo],
    sniffer_data: dict,
    vlan: VlanAndNacTelemetry,
    l3: L3Connectivity,
    scan: SubnetScanState,
    checked_at: Optional[str] = None,
) -> SecurityReportState:
    findings: List[SecurityFinding] = []
    metrics: List[SecurityMetricBar] = []

    # 1. Rogue DHCP Integrity (25 pts)
    unique_servers = {o.server_ip for o in dhcp_offers}
    rogue_dhcp = len(unique_servers) > 1 or any(not o.authorized for o in dhcp_offers)

    if rogue_dhcp:
        dhcp_pts = 0
        dhcp_stat = "FAIL"
        lines = [
            f"{'Authorized' if o.authorized else 'ROGUE'}: {o.server_ip} (GW {o.router_ip} • {o.vendor} • {o.server_mac})"
            for o in dhcp_offers
        ]
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title=f"Rogue DHCP Detected ({len(dhcp_offers)} Servers Responded)",
                detail=" | ".join(lines) + " — Enable DHCP Snooping on switch VLAN.",
            )
        )
    elif len(dhcp_offers) == 1:
        dhcp_pts = 25
        dhcp_stat = "PASS"
        o = dhcp_offers[0]
        findings.append(
            SecurityFinding(
                severity="PASS",
                title="Single Authorized DHCP Server Verified",
                detail=f"Server {o.server_ip} ({o.vendor} • {o.server_mac}) offering {o.offered_ip}",
            )
        )
    elif l3.ipv4_address not in ("—", "") and not l3.ipv4_address.startswith("169.254."):
        dhcp_pts = 22
        dhcp_stat = "PASS"
        findings.append(
            SecurityFinding(
                severity="INFO",
                title="DHCP Active (Run Probe to Verify Rogue Servers)",
                detail=f"Bound IP {l3.ipv4_address} via gateway {l3.gateway_ip}",
            )
        )
    else:
        dhcp_pts = 15
        dhcp_stat = "INFO"

    metrics.append(
        SecurityMetricBar(name="Rogue DHCP Guard", score=dhcp_pts, max_score=25, status=dhcp_stat)
    )

    # 2. Passive ARP Spoofing / MITM Guard (25 pts)
    arp_count = int(sniffer_data.get("arp_frames_checked", 0))
    arp_conflicts: List[str] = list(sniffer_data.get("arp_conflicts", []))
    if arp_conflicts:
        arp_pts = 0
        arp_stat = "FAIL"
        arp_label = "CONFLICT!"
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title="ARP Conflict / Potential MITM Spoofing!",
                detail="; ".join(arp_conflicts[:2]),
            )
        )
    else:
        arp_pts = 25
        arp_stat = "PASS"
        arp_label = "PROTECTED"
        findings.append(
            SecurityFinding(
                severity="PASS",
                title="Passive ARP & Gateway MAC Monitor Clean",
                detail=f"{arp_count} ARP frames inspected • 0 duplicate IP claims or gateway MAC flaps",
            )
        )

    metrics.append(
        SecurityMetricBar(name="ARP Spoof / MITM", score=arp_pts, max_score=25, status=arp_stat)
    )

    # 3. VLAN Segmentation (20 pts)
    if vlan.native_vlan is not None and vlan.native_vlan > 1:
        vlan_pts = 20
        vlan_stat = "PASS"
    elif vlan.native_vlan == 1:
        vlan_pts = 12
        vlan_stat = "WARN"
        findings.append(
            SecurityFinding(
                severity="WARN",
                title="Port Assigned to Default VLAN 1",
                detail="Move wall sockets off default VLAN 1 onto a dedicated access VLAN.",
            )
        )
    else:
        vlan_pts = 18
        vlan_stat = "PASS"

    metrics.append(
        SecurityMetricBar(name="VLAN Isolation", score=vlan_pts, max_score=20, status=vlan_stat)
    )

    # 4. Exposed Legacy Services on Subnet (20 pts)
    telnet_hosts = [h.ip for h in scan.hosts if 23 in h.open_ports]
    raw_print_hosts = [h.ip for h in scan.hosts if 9100 in h.open_ports]
    smb_hosts = [h.ip for h in scan.hosts if 445 in h.open_ports or 139 in h.open_ports]

    svc_pts = 20
    svc_notes: List[str] = []
    if telnet_hosts:
        svc_pts -= 8
        svc_notes.append(f"Cleartext Telnet (:23) open on {', '.join(telnet_hosts[:3])}")
    if raw_print_hosts:
        svc_pts -= 2
        svc_notes.append(f"Raw JetDirect (:9100) open on {', '.join(raw_print_hosts[:2])}")
    if len(smb_hosts) > 3:
        svc_pts -= 2
        svc_notes.append(f"{len(smb_hosts)} SMB (:445) endpoints reachable from this VLAN")

    svc_pts = max(0, svc_pts)
    svc_stat = "PASS" if svc_pts >= 18 else ("WARN" if svc_pts >= 12 else "FAIL")
    if svc_notes:
        findings.append(
            SecurityFinding(
                severity="WARN",
                title="Exposed Legacy / Lateral Services on Subnet",
                detail=" • ".join(svc_notes),
            )
        )

    metrics.append(
        SecurityMetricBar(name="Exposed Services", score=svc_pts, max_score=20, status=svc_stat)
    )

    # 5. Port NAC / 802.1X Posture (10 pts)
    nac_pts = 10 if vlan.eapol_8021x_seen else 9
    metrics.append(
        SecurityMetricBar(name="802.1X / NAC", score=nac_pts, max_score=10, status="PASS")
    )

    total_score = dhcp_pts + arp_pts + vlan_pts + svc_pts + nac_pts

    # 6. Milestone 3 Deep L2 Forensics (STP/RSTP, Broadcast PPS Storm, IPv6 RA Guard, WPAD Opt 252)
    stp_dict = sniffer_data.get("stp") or {}
    stp_info = StpBpduInfo(**stp_dict) if stp_dict else StpBpduInfo()
    bcast_pps = float(sniffer_data.get("bcast_pps", 0.0))
    mcast_pps = float(sniffer_data.get("mcast_pps", 0.0))
    storm_detected = bool(sniffer_data.get("storm_detected", False)) or (bcast_pps >= 100.0)
    ra_raw = sniffer_data.get("ipv6_ra_senders", [])
    ra_senders: List[Ipv6RaSender] = []
    for r in ra_raw:
        if isinstance(r, Ipv6RaSender):
            ra_senders.append(r)
        elif isinstance(r, dict):
            mac_s = str(r.get("src_mac", "—"))
            ra_senders.append(
                Ipv6RaSender(
                    src_mac=mac_s,
                    src_ipv6=str(r.get("src_ipv6", "—")),
                    vendor=str(r.get("vendor") or lookup_mac_vendor(mac_s)),
                    router_lifetime_s=int(r.get("router_lifetime_s", 0)),
                    count=int(r.get("count", 1)),
                )
            )

    rogue_ra = len(ra_senders) > 1
    if storm_detected:
        total_score -= 20
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title=f"Broadcast Storm Detected ({bcast_pps:.1f} pps)",
                detail="Excessive L2 broadcast traffic (>100 pps) — check for switching loops or faulty NICs.",
            )
        )
    if rogue_ra:
        total_score -= 20
        findings.append(
            SecurityFinding(
                severity="CRITICAL",
                title=f"Multiple IPv6 Router Advertisements ({len(ra_senders)} Senders)",
                detail=", ".join(f"{r.src_ipv6} ({r.src_mac})" for r in ra_senders[:3])
                + " — Enable RA Guard on access ports.",
            )
        )
    wpad_hits = [o.wpad_url for o in dhcp_offers if o.wpad_url not in ("—", "")]
    if wpad_hits:
        total_score -= 5
        findings.append(
            SecurityFinding(
                severity="WARN",
                title="DHCP Option 252 (WPAD) Advertised",
                detail=f"Auto-proxy URL offered: {wpad_hits[0]} — Verify legitimate proxy or disable WPAD.",
            )
        )

    # 7. Passive Name-Resolution Exposure & Cleartext Leak Monitor (Phase 2)
    exp_raw = sniffer_data.get("exposure")
    if isinstance(exp_raw, PassiveExposureState):
        exp = exp_raw
    elif isinstance(exp_raw, dict):
        exp = PassiveExposureState(
            llmnr_count=int(exp_raw.get("llmnr_count", 0)),
            nbns_count=int(exp_raw.get("nbns_count", 0)),
            mdns_count=int(exp_raw.get("mdns_count", 0)),
            wpad_count=int(exp_raw.get("wpad_count", 0)),
            cleartext_count=int(exp_raw.get("cleartext_count", 0)),
            talkers=[
                t if isinstance(t, ExposureTalker) else ExposureTalker(**t)
                for t in exp_raw.get("talkers", [])
            ],
            cleartext_alerts=[
                a if isinstance(a, CleartextAlert) else CleartextAlert(**a)
                for a in exp_raw.get("cleartext_alerts", [])
            ],
        )
    else:
        exp = PassiveExposureState()

    high_poison = exp.wpad_count + exp.llmnr_count + exp.nbns_count
    if high_poison > 0:
        total_score -= 8 if exp.wpad_count > 0 else 5
        high_samples = [
            f"{t.protocol}:{t.src_ip}->{t.query}"
            for t in exp.talkers
            if t.risk == "HIGH"
        ][:3]
        findings.append(
            SecurityFinding(
                severity="WARN",
                title=f"LLMNR / NBT-NS / WPAD Exposure ({high_poison} Talkers)",
                detail=(", ".join(high_samples) + " — " if high_samples else "")
                + "Disable LLMNR/NetBIOS/WPAD via GPO/DHCP to prevent Responder credential poisoning.",
            )
        )

    has_cleartext_crit = any(a.severity == "CRITICAL" for a in exp.cleartext_alerts)
    if exp.cleartext_alerts:
        total_score -= 10 if has_cleartext_crit else 5
        alert_samples = [
            f"[{a.protocol}] {a.src_ip}->{a.dst_ip}: {a.detail}"
            for a in exp.cleartext_alerts[:3]
        ]
        findings.append(
            SecurityFinding(
                severity="CRITICAL" if has_cleartext_crit else "WARN",
                title=f"Cleartext Credentials / Protocols Observed ({len(exp.cleartext_alerts)})",
                detail=" | ".join(alert_samples),
            )
        )

    total_score = max(0, min(100, total_score))
    forensics = L2ForensicsState(
        stp=stp_info,
        bcast_pps=bcast_pps,
        mcast_pps=mcast_pps,
        storm_detected=storm_detected,
        ipv6_ra_senders=ra_senders,
        rogue_ra_detected=rogue_ra,
        exposure=exp,
    )

    grade = score_to_letter_grade(total_score)
    summary = (
        "Critical Alert (Rogue DHCP / ARP)"
        if (rogue_dhcp or arp_conflicts)
        else (
            "Critical Alert (L2 Storm / Rogue RA)"
            if (storm_detected or rogue_ra)
            else (
                "Critical Alert (Cleartext Leak)"
                if has_cleartext_crit
                else ("Healthy Network Posture" if total_score >= 88 else "Review Warnings")
            )
        )
    )

    return SecurityReportState(
        probing=False,
        last_checked_at=checked_at or datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        score=total_score,
        grade=grade,
        summary=summary,
        dhcp_offers=dhcp_offers,
        rogue_dhcp_detected=rogue_dhcp,
        arp_frames_checked=arp_count,
        arp_conflicts=arp_conflicts,
        arp_status=arp_label,
        metrics=metrics,
        findings=findings,
        forensics=forensics,
    )
