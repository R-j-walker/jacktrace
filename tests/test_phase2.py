import socket
import struct
from pathlib import Path
from fastapi.testclient import TestClient

from app.audit import AuditStore
from app.main import app
from app.models import (
    DhcpOfferInfo,
    DiscoveredHost,
    L3Connectivity,
    SubnetScanState,
    VlanAndNacTelemetry,
)
from app.oui_db import lookup_mac_vendor
from app.scanner import infer_host_role
from app.security import (
    DHCP_MAGIC,
    build_dhcp_discover_frame,
    evaluate_security_posture,
    parse_dhcp_offer_frame,
)
from app.sniffer import PassiveL2Sniffer


def test_oui_and_role_inference():
    assert "Cisco" in lookup_mac_vendor("00:1E:F7:4A:9C:18")
    assert "Raspberry Pi" in lookup_mac_vendor("DC:A6:32:11:22:33")
    assert "TP-Link" in lookup_mac_vendor("D8:07:B6:44:9E:12")

    assert infer_host_role("10.20.1.1", "10.20.1.1", "10.20.1.2", "Fortinet", [443]) == "Gateway / Firewall"
    assert infer_host_role("10.20.1.10", "10.20.1.1", "10.20.1.2", "Dell Inc.", [53, 88, 389]) == "Domain Controller"
    assert infer_host_role("10.20.1.42", "10.20.1.1", "10.20.1.2", "HP Inc.", [80, 9100]) == "Network Printer"


def test_dhcp_discover_and_offer_parser():
    xid = 0x33445566
    disc = build_dhcp_discover_frame("DC:A6:32:8F:14:2B", xid)
    assert len(disc) >= 342
    assert disc[0:6] == b"\xff\xff\xff\xff\xff\xff"

    # Build synthetic DHCPOFFER reply frame
    srv_mac = b"\xd8\x07\xb6\x44\x9e\x12"
    cli_mac = b"\xdc\xa6\x32\x8f\x14\x2b"
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2,  # BOOTREPLY
        1,
        6,
        0,
        xid,
        0,
        0x8000,
        b"\x00\x00\x00\x00",
        socket.inet_aton("192.168.0.105"),
        socket.inet_aton("192.168.0.1"),
        b"\x00\x00\x00\x00",
        cli_mac + b"\x00" * 10,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    opts = (
        DHCP_MAGIC
        + b"\x35\x01\x02"  # Option 53 = DHCPOFFER (2)
        + b"\x36\x04" + socket.inet_aton("192.168.0.1")  # Option 54 = Server ID
        + b"\x03\x04" + socket.inet_aton("192.168.0.1")  # Option 3 = Router
        + b"\x06\x04" + socket.inet_aton("8.8.8.8")      # Option 6 = DNS
        + b"\xff"
    )
    payload = bootp + opts
    udp = struct.pack("!HHHH", 67, 68, 8 + len(payload), 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp) + len(payload),
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton("192.168.0.1"),
        socket.inet_aton("255.255.255.255"),
    )
    eth = b"\xff\xff\xff\xff\xff\xff" + srv_mac + struct.pack("!H", 0x0800)
    parsed = parse_dhcp_offer_frame(eth + ip + udp + payload, xid)
    assert parsed is not None
    assert parsed["server_ip"] == "192.168.0.1"
    assert parsed["offered_ip"] == "192.168.0.105"
    assert parsed["server_mac"] == "D8:07:B6:44:9E:12"


def test_arp_conflict_and_security_scoring():
    sniffer = PassiveL2Sniffer("eth0")
    # Two different MACs claiming 10.20.1.1 (ARP spoofing!)
    for mac_b in (b"\x90\x6c\xac\x11\x02\xa0", b"\xde\xad\xbe\xef\x00\x01"):
        eth = b"\xff\xff\xff\xff\xff\xff" + mac_b + struct.pack("!H", 0x0806)
        arp = struct.pack(
            "!HHBBH6s4s6s4s",
            1,
            0x0800,
            6,
            4,
            2,
            mac_b,
            socket.inet_aton("10.20.1.1"),
            b"\x00" * 6,
            socket.inet_aton("10.20.1.148"),
        )
        sniffer._inspect_frame(eth + arp)

    s_data = sniffer.snapshot()
    assert s_data["arp_frames_checked"] == 2
    assert len(s_data["arp_conflicts"]) == 1

    # Rogue DHCP + ARP conflict -> severe drop in security score
    offers = [
        DhcpOfferInfo(server_ip="10.20.1.1", offered_ip="10.20.1.50", server_mac="90:6C:AC:11:02:A0", vendor="Fortinet", router_ip="10.20.1.1", authorized=True),
        DhcpOfferInfo(server_ip="192.168.0.1", offered_ip="192.168.0.50", server_mac="D8:07:B6:44:9E:12", vendor="TP-Link", router_ip="192.168.0.1", authorized=False),
    ]
    sec = evaluate_security_posture(
        offers,
        s_data,
        VlanAndNacTelemetry(native_vlan=20),
        L3Connectivity(ipv4_address="10.20.1.148", gateway_ip="10.20.1.1"),
        SubnetScanState(hosts=[DiscoveredHost(ip="10.20.1.2", open_ports=[22, 23])]),
    )
    assert sec.rogue_dhcp_detected is True
    assert sec.score < 50
    assert sec.grade == "F"


def test_audit_sqlite_pdf_and_phase2_routes(tmp_path: Path):
    store = AuditStore(db_path=tmp_path / "test_audit.db")
    with TestClient(app) as client:
        # Inject temporary SQLite store for clean isolated testing
        from app.main import runtime
        runtime.audit_store = store

        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})

        # Save two wall ports and verify auto-increment W-01 -> W-02 -> W-03
        r1 = client.post("/api/audit/save", json={})
        assert r1.status_code == 200
        assert r1.json()["drop_label"] == "W-01"

        r2 = client.post("/api/audit/save", json={})
        assert r2.status_code == 200
        assert r2.json()["drop_label"] == "W-02"

        snap = client.get("/api/snapshot").json()
        assert snap["audit"]["total_saved"] == 2
        assert snap["audit"]["next_drop_label"] == "W-03"
        assert snap["audit"]["qr_svg_data_uri"].startswith("data:image/svg+xml;base64,")

        # Generate and verify real PDF output
        r_pdf = client.get("/api/audit/report.pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert r_pdf.content.startswith(b"%PDF-1.")

        # Trigger demo PCAP and download it
        r_pcap_start = client.post("/api/audit/pcap/start", json={"duration_sec": 5.0})
        assert r_pcap_start.status_code == 200
        r_pcap_dl = client.get("/api/audit/latest.pcap")
        assert r_pcap_dl.status_code == 200
        assert len(r_pcap_dl.content) > 40
