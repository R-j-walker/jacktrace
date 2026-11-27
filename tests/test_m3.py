import socket
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.audit import AuditStore
from app.demo_data import build_demo_snapshot
from app.host_inspect import build_wol_magic_packet
from app.main import app, runtime
from app.models import (
    AuditPortalState,
    BlinkState,
    DhcpOfferInfo,
    L3Connectivity,
    StressTestResult,
    SubnetScanState,
    SystemHealthState,
    VlanAndNacTelemetry,
)
from app.security import DHCP_MAGIC, evaluate_security_posture, parse_dhcp_offer_frame
from app.sniffer import PassiveL2Sniffer
from app.snmp_client import (
    _enc_int,
    _enc_tlv,
    decode_oid,
    decode_snmp_v2c_response,
    encode_oid,
    encode_snmp_v2c_request,
    format_timeticks,
)
from app.system_ctrl import read_dsi_flipped, set_dsi_flipped


def test_sniffer_stp_bpdu_ipv6_ra_and_storm_scoring():
    sniffer = PassiveL2Sniffer("eth0")

    # 1. RSTP BPDU frame (LLC 42 42 03 + 35-byte BPDU)
    dst_stp = b"\x01\x80\xc2\x00\x00\x00"
    src_sw = b"\x00\x1e\xf7\x4a\x9c\x18"
    llc_stp = b"\x42\x42\x03"
    bpdu = struct.pack(
        "!HBBBH6sIH6sHHHHH",
        0,       # protocol ID
        2,       # RSTP version
        0x02,    # RST BPDU type
        0x3C,    # flags
        32768,   # root priority + sys id ext
        src_sw,  # root MAC
        4,       # path cost
        32768,   # bridge priority
        src_sw,  # bridge MAC
        0x8018,  # port ID (#24)
        0, 20, 2, 15,  # message age, max age, hello, fwd delay (16-bit placeholders)
    )[:35]
    # Pack exact 35-byte config/RSTP BPDU cleanly:
    bpdu_exact = (
        struct.pack("!HBBB", 0, 2, 0x02, 0x3C)
        + struct.pack("!H", 32768) + src_sw
        + struct.pack("!I", 4)
        + struct.pack("!H", 32768) + src_sw
        + struct.pack("!HHHHH", 0x8018, 0, 5120, 512, 3840)
    )
    frame_stp = dst_stp + src_sw + struct.pack("!H", len(llc_stp) + len(bpdu_exact)) + llc_stp + bpdu_exact
    sniffer._inspect_frame(frame_stp)

    # 2. Two distinct IPv6 Router Advertisements (ICMPv6 Type 134) -> Rogue RA!
    for rtr_mac, ipv6_str in (
        (b"\x90\x6c\xac\x11\x02\xa0", "fe80::1"),
        (b"\xde\xad\xbe\xef\x00\x99", "fe80::99"),
    ):
        eth_v6 = b"\x33\x33\x00\x00\x00\x01" + rtr_mac + struct.pack("!H", 0x86DD)
        ip6 = struct.pack(
            "!IHBB16s16s",
            0x60000000,
            16,
            58,  # ICMPv6
            255,
            socket.inet_pton(socket.AF_INET6, ipv6_str),
            socket.inet_pton(socket.AF_INET6, "ff02::1"),
        )
        icmp6_ra = struct.pack("!BBHHHII", 134, 0, 0, 0x4000 | 1800, 0, 0, 0)
        sniffer._inspect_frame(eth_v6 + ip6 + icmp6_ra)

    # 3. Simulate broadcast bursts -> 1050 frames in last 10s = 105.0 pps
    for _ in range(1050):
        sniffer._inspect_frame(b"\xff\xff\xff\xff\xff\xff" + src_sw + struct.pack("!H", 0x0800) + b"\x00" * 30)

    s_data = sniffer.snapshot()
    assert s_data["stp"]["detected"] is True
    assert s_data["stp"]["protocol"] == "RSTP"
    assert s_data["stp"]["root_priority"] == 32768
    assert s_data["stp"]["root_mac"] == "00:1E:F7:4A:9C:18"
    assert s_data["stp"]["root_path_cost"] == 4
    assert len(s_data["ipv6_ra_senders"]) == 2
    assert s_data["bcast_pps"] >= 100.0
    assert s_data["storm_detected"] is True

    offers = [DhcpOfferInfo(server_ip="10.20.1.1", wpad_url="http://192.168.0.1/wpad.dat", authorized=True)]
    sec = evaluate_security_posture(
        offers, s_data, VlanAndNacTelemetry(native_vlan=20), L3Connectivity(ipv4_address="10.20.1.148", gateway_ip="10.20.1.1"), SubnetScanState()
    )
    assert sec.forensics.storm_detected is True
    assert sec.forensics.rogue_ra_detected is True
    assert any("Broadcast Storm" in f.title for f in sec.findings)
    assert any("IPv6 Router Advertisements" in f.title for f in sec.findings)
    assert any("WPAD" in f.title for f in sec.findings)


def test_dhcp_extended_options_parsing():
    xid = 0x55667788
    srv_mac = b"\x90\x6c\xac\x11\x02\xa0"
    cli_mac = b"\xdc\xa6\x32\x8f\x14\x2b"
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2, 1, 6, 0, xid, 0, 0x8000,
        b"\x00" * 4, socket.inet_aton("10.20.1.155"), socket.inet_aton("10.20.1.1"), b"\x00" * 4,
        cli_mac + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128,
    )
    opts = (
        DHCP_MAGIC
        + b"\x35\x01\x02"
        + b"\x36\x04" + socket.inet_aton("10.20.1.1")
        + b"\x01\x04" + socket.inet_aton("255.255.255.0")
        + b"\x03\x04" + socket.inet_aton("10.20.1.1")
        + b"\x06\x04" + socket.inet_aton("10.20.1.10")
        + b"\x0f\x0a" + b"corp.local"
        + b"\x2a\x04" + socket.inet_aton("10.20.1.12")
        + b"\x2b\x09" + b"UniFi-AP!"
        + b"\x33\x04" + struct.pack("!I", 86400)
        + b"\x43\x09" + b"pxelinux0"
        + b"\x96\x04" + socket.inet_aton("10.20.1.20")
        + b"\xfc\x18" + b"http://proxy/wpad.dat\x00\x00\x00"
        + b"\xff"
    )
    payload = bootp + opts
    udp = struct.pack("!HHHH", 67, 68, 8 + len(payload), 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp) + len(payload), 1, 0, 64, 17, 0,
        socket.inet_aton("10.20.1.1"), socket.inet_aton("255.255.255.255"),
    )
    eth = b"\xff\xff\xff\xff\xff\xff" + srv_mac + struct.pack("!H", 0x0800)
    parsed = parse_dhcp_offer_frame(eth + ip + udp + payload, xid)
    assert parsed is not None
    assert parsed["subnet_mask"] == "255.255.255.0"
    assert parsed["lease_time_s"] == 86400
    assert parsed["domain_name"] == "corp.local"
    assert parsed["ntp_server"] == "10.20.1.12"
    assert parsed["vendor_opt43"] == "UniFi-AP!"
    assert parsed["tftp_server"] == "10.20.1.20"
    assert parsed["boot_file"] == "pxelinux0"
    assert parsed["wpad_url"] == "http://proxy/wpad.dat"


def test_snmp_ber_codec_and_wol_and_orientation(tmp_path: Path):
    # OID roundtrip including multi-byte arc (105 and 1280)
    oid = "1.3.6.1.2.1.105.1.3.1280.4.1"
    enc = encode_oid(oid)
    assert decode_oid(enc) == oid

    req = encode_snmp_v2c_request("public", ["1.3.6.1.2.1.1.5.0"])
    assert req[0] == 0x30

    # Construct synthetic GetResponse (0xA2)
    vb1 = _enc_tlv(0x30, encode_oid("1.3.6.1.2.1.1.5.0") + _enc_tlv(0x04, b"Core-Switch"))
    vb2 = _enc_tlv(0x30, encode_oid("1.3.6.1.2.1.1.3.0") + _enc_tlv(0x43, struct.pack("!I", 36540000)))
    pdu = _enc_tlv(0xA2, _enc_int(77) + _enc_int(0) + _enc_int(0) + _enc_tlv(0x30, vb1 + vb2))
    resp = _enc_tlv(0x30, _enc_int(1) + _enc_tlv(0x04, b"public") + pdu)
    rid, err_s, _err_i, pairs = decode_snmp_v2c_response(resp)
    assert rid == 77
    assert err_s == 0
    assert pairs[0] == ("1.3.6.1.2.1.1.5.0", "Core-Switch")
    assert pairs[1][1] == 36540000
    assert "4d" in format_timeticks(pairs[1][1])

    # Wake-on-LAN packet
    pkt = build_wol_magic_packet("DC:A6:32:8F:14:2B")
    assert len(pkt) == 102
    assert pkt[:6] == b"\xff" * 6
    assert pkt[6:12] == bytes.fromhex("dca6328f142b")
    with pytest.raises(ValueError):
        build_wol_magic_packet("invalid-mac")

    # 180-deg orientation helper on mock cmdline.txt
    cmd_p = tmp_path / "cmdline.txt"
    cmd_p.write_text("console=serial0,115200 root=PARTUUID=abc rootwait\n", encoding="utf-8")
    assert read_dsi_flipped(cmd_p) is False
    ok, _ = set_dsi_flipped(True, cmd_p)
    assert ok is True
    assert read_dsi_flipped(cmd_p) is True
    assert "root=PARTUUID=abc" in cmd_p.read_text(encoding="utf-8")
    ok2, _ = set_dsi_flipped(False, cmd_p)
    assert ok2 is True
    assert read_dsi_flipped(cmd_p) is False


def test_audit_multi_job_prefixes_csv_json_and_m3_routes(tmp_path: Path):
    store = AuditStore(db_path=tmp_path / "m3_audit.db")
    orig_store = runtime.audit_store
    orig_vp_path = runtime.vlan_prober._settings_path
    orig_snmp_path = runtime.snmp_mgr._settings_path

    runtime.audit_store = store
    runtime.vlan_prober._settings_path = tmp_path / "vlan.json"
    runtime.snmp_mgr._settings_path = tmp_path / "snmp.json"
    try:
        # Unit-check prefix & multi-job separation
        snap = build_demo_snapshot("healthy_1g", BlinkState(), StressTestResult(), AuditPortalState(), SystemHealthState())
        store.switch_or_create_job("Floor 2 APs", prefix="AP")
        p1 = store.save_snapshot(snap, notes="Near ceiling")
        assert p1.drop_label == "AP-01"
        store.set_prefix("CAM")
        p2 = store.save_snapshot(snap)
        assert p2.drop_label == "CAM-02"
        store.update_port_notes(p2.id, "North lobby dome")
        assert store.get_port_by_id(p2.id).notes == "North lobby dome"

        csv_txt = store.generate_csv_text()
        assert "AP-01" in csv_txt and "North lobby dome" in csv_txt

        with TestClient(app) as client:
            client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})

            # Switch job via API + set prefix
            r_sw = client.post("/api/audit/job/switch", json={"job_name": "Comms Room", "prefix": "SW"})
            assert r_sw.status_code == 200
            assert r_sw.json()["audit"]["job_name"] == "Comms Room"
            assert r_sw.json()["audit"]["next_drop_label"] == "SW-01"

            r_pref = client.post("/api/audit/prefix", json={"prefix": "DESK"})
            assert r_pref.status_code == 200
            assert r_pref.json()["audit"]["next_drop_label"] == "DESK-01"

            saved_id = client.post("/api/audit/save", json={}).json()["id"]
            r_notes = client.post(f"/api/audit/port/{saved_id}/notes", json={"notes": "Patch A12"})
            assert r_notes.status_code == 200
            assert r_notes.json()["audit"]["recent_ports"][0]["notes"] == "Patch A12"

            assert "text/csv" in client.get("/api/audit/report.csv").headers["content-type"]
            assert client.get("/api/audit/report.json").json()["job_name"] == "Comms Room"

            # VLAN Prober presets & run
            r_vp = client.post("/api/vlan/presets", json={"vlans": [40, 140, 210]})
            assert r_vp.status_code == 200
            assert r_vp.json()["vlan_probe"]["preset_vlans"] == [40, 140, 210]

            r_vrun = client.post("/api/vlan/probe", json={})
            assert r_vrun.status_code == 200
            v_res = r_vrun.json()["vlan_probe"]["results"]
            assert any(e["vlan_id"] == 40 and e["status"] == "LIVE_DHCP" for e in v_res)

            # SNMP Query
            r_snmp = client.post("/api/snmp/query", json={"community": "public"})
            assert r_snmp.status_code == 200
            assert r_snmp.json()["snmp"]["sys_name"] == "IDF2-SW03"

            # Tap-a-Host inspect & WoL
            r_host = client.post("/api/host/inspect", json={"ip": "172.24.10.2"})
            assert r_host.status_code == 200
            assert 22 in r_host.json()["open_ports"]
            r_wol = client.post("/api/host/wol", json={"ip": "172.24.10.2", "mac": "94:F1:28:6C:19:40"})
            assert r_wol.status_code == 200
            assert r_wol.json()["ok"] is True
    finally:
        runtime.audit_store = orig_store
        runtime.vlan_prober._settings_path = orig_vp_path
        runtime.snmp_mgr._settings_path = orig_snmp_path
