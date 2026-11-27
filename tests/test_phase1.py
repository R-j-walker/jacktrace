import json
import struct
from fastapi.testclient import TestClient

from app.main import app
from app.port_mapper import map_port_to_panel
from app.probes import extract_lldp_tagged_vlans, parse_ethtool_output, parse_lldpcli_json
from app.sniffer import PassiveL2Sniffer, extract_auxdata_vlan, reinsert_vlan_tag


def test_port_mapper_cisco_and_aruba():
    p24 = map_port_to_panel("Gi1/0/24", "FL2-DESK-13", "Cisco Catalyst 2960X-24PS-L", "")
    assert p24.port_number == 24
    assert p24.total_ports == 24
    assert p24.row_label == "Bottom Row"
    assert p24.pair_column == 12
    assert "Far Right" in p24.summary

    p48 = map_port_to_panel("1/1/7", "", "Aruba 2930F-48G", "")
    assert p48.port_number == 7
    assert p48.total_ports == 48
    assert p48.row_label == "Top Row"
    assert p48.pair_column == 4

    p8 = map_port_to_panel("Port 8", "", "USW-Lite-8-PoE", "")
    assert p8.port_number == 8
    assert p8.total_ports == 8
    assert p8.row_label == "Single Row"

    p49 = map_port_to_panel("eth1/0/49", "Office", "GWN7806P", "GWN7806P")
    assert p49.port_number == 49
    assert p49.total_ports == 48
    assert p49.row_label == "SFP+ / Uplink"
    assert "Uplink" in p49.summary


def test_parse_lldpcli_multi_protocol_cisco():
    sample = {
        "lldp": {
            "interface": [
                {
                    "eth0": {
                        "via": "LLDP",
                        "chassis": {
                            "SW-CORE-FL2-01": {
                                "id": {"type": "mac", "value": "00:1e:f7:4a:9c:18"},
                                "descr": "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M)",
                                "mgmt-ip": ["10.20.1.2"],
                            }
                        },
                        "port": {
                            "id": {"type": "ifname", "value": "Gi1/0/24"},
                            "descr": "FL2-OPEN-DESK-13",
                            "power": {
                                "supported": True,
                                "enabled": True,
                                "powerpairs": "signal",
                                "class": "class-4",
                                "type": "2",
                                "allocated": "25500",
                            },
                        },
                        "vlan": {"vlan-id": "20", "pvid": True, "value": "CORP_DATA"},
                        "lldp-med": {
                            "policy": {"apptype": "Voice", "vid": "110"}
                        },
                    }
                },
                {
                    "eth0": {
                        "via": "CDPv2",
                        "chassis": {
                            "SW-CORE-FL2-01": {
                                "descr": "cisco WS-C2960X-24PS-L",
                            }
                        },
                        "port": {"id": {"type": "ifname", "value": "GigabitEthernet1/0/24"}},
                    }
                },
            ]
        }
    }
    nb, poe, pvid, pvid_name, voice = parse_lldpcli_json(json.dumps(sample), "eth0")
    assert nb.detected is True
    assert nb.protocols == ["LLDP", "CDP"]
    assert nb.confidence == "HIGH"
    assert nb.switch_name == "SW-CORE-FL2-01"
    assert "2960X" in nb.model
    assert nb.mgmt_ip == "10.20.1.2"
    assert nb.panel.port_number == 24
    assert poe.supported is True
    assert poe.standard == "802.3at PoE+"
    assert poe.allocated_watts == 25.5
    assert pvid == 20
    assert "CORP_DATA" in pvid_name
    assert voice == 110


def test_parse_ethtool_100m_downshift():
    ethtool_sample = """Settings for eth0:
\tSupported ports: [ TP\t MII ]
\tSupports auto-negotiation: Yes
\tAdvertised link modes:\t10baseT/Half 10baseT/Full
\t                      \t100baseT/Half 100baseT/Full
\t                      \t1000baseT/Full
\tLink partner advertised link modes:\t10baseT/Half 10baseT/Full
\t                                   \t100baseT/Half 100baseT/Full
\t                                   \t1000baseT/Full
\tSpeed: 100Mb/s
\tDuplex: Full
\tAuto-negotiation: on
\tLink detected: yes
"""
    parsed = parse_ethtool_output(ethtool_sample)
    assert parsed["speed_mbps"] == 100
    assert parsed["duplex"] == "Full"
    assert parsed["autoneg"] is True
    assert parsed["partner_supports_1g"] is True
    assert parsed["local_supports_1g"] is True
    assert parsed["link_detected"] is True


def test_sniffer_8021q_eapol_and_cdp_parsing():
    sniffer = PassiveL2Sniffer("eth0")

    # 1. 802.1Q VLAN 110 + inner 802.1X EAPOL (0x888E)
    dst = b"\x01\x80\xc2\x00\x00\x03"
    src = b"\x00\x1e\xf7\x4a\x9c\x18"
    dot1q_eapol = dst + src + struct.pack("!HHH", 0x8100, 110, 0x888E) + b"\x02\x00\x00\x05\x01"
    sniffer._inspect_frame(dot1q_eapol)

    snap = sniffer.snapshot()
    assert 110 in snap["tagged_vlans"]
    assert snap["eapol_seen"] is True

    # 2. Cisco CDP frame over 802.3 LLC/SNAP
    cdp_dst = b"\x01\x00\x0c\xcc\xcc\xcc"
    llc_snap = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    dev_val = b"SW-CAB-01"
    port_val = b"Gi0/12"
    tlv_dev = struct.pack("!HH", 0x0001, 4 + len(dev_val)) + dev_val
    tlv_port = struct.pack("!HH", 0x0003, 4 + len(port_val)) + port_val
    tlv_vlan = struct.pack("!HHH", 0x000A, 6, 20)
    cdp_payload = b"\x02\xb4\x00\x00" + tlv_dev + tlv_port + tlv_vlan
    frame_len = len(llc_snap) + len(cdp_payload)
    cdp_frame = cdp_dst + src + struct.pack("!H", frame_len) + llc_snap + cdp_payload
    sniffer._inspect_frame(cdp_frame)

    snap2 = sniffer.snapshot()
    assert snap2["raw_neighbor"]["protocol"] == "CDP"
    assert snap2["raw_neighbor"]["switch_name"] == "SW-CAB-01"
    assert snap2["raw_neighbor"]["port_id"] == "Gi0/12"
    assert snap2["raw_neighbor"]["native_vlan"] == "20"


def test_sniffer_auxdata_vlan_reinsertion_and_lldp_tagged():
    # Kernel PACKET_AUXDATA cmsg strips 802.1Q tag from Ethernet frame; verify reinsertion
    aux_bytes = struct.pack("=IIIIHH", (1 << 4) | (1 << 6), 60, 14, 14, 108, 0x8100)
    vlan_meta = extract_auxdata_vlan([(263, 8, aux_bytes)])
    assert vlan_meta == (0x8100, 108)

    untagged_bcast = b"\xff\xff\xff\xff\xff\xff" + b"\xec\x74\xd7\x74\xbe\x85" + struct.pack("!H", 0xAAAA) + b"\x00" * 32
    rebuilt = reinsert_vlan_tag(untagged_bcast, vlan_meta[0], vlan_meta[1])
    sniffer = PassiveL2Sniffer("eth0")
    sniffer._inspect_frame(rebuilt)
    assert sniffer.snapshot()["tagged_vlans"] == [108]

    lldp_multi_vlan = json.dumps({
        "lldp": {
            "interface": [
                {
                    "eth0": {
                        "via": "LLDP",
                        "vlan": [
                            {"vlan-id": "1", "pvid": True},
                            {"vlan-id": "103", "pvid": False},
                            {"vlan-id": "108", "pvid": False},
                        ],
                    }
                }
            ]
        }
    })
    assert extract_lldp_tagged_vlans(lldp_multi_vlan, "eth0") == [103, 108]


def test_fastapi_endpoints_and_websocket():
    with TestClient(app) as client:
        r_idx = client.get("/")
        assert r_idx.status_code == 200
        assert "JACKTRACE" in r_idx.text

        # Force demo mode scenario: pair_fault_100m
        r_mode = client.post(
            "/api/mode",
            json={"demo_mode": True, "demo_scenario": "pair_fault_100m", "iface": "eth0"},
        )
        assert r_mode.status_code == 200
        data = r_mode.json()
        assert data["link"]["speed_mbps"] == 100
        assert data["link"]["pair_downshift_suspected"] is True
        assert data["switch"]["panel"]["port_number"] == 19

        # Toggle LED blinker ON then OFF
        r_blink_on = client.post("/api/blink/toggle", json={"mode": "speed-cycle"})
        assert r_blink_on.status_code == 200
        assert r_blink_on.json()["blink"]["active"] is True

        r_blink_off = client.post("/api/blink/toggle", json={"mode": "speed-cycle"})
        assert r_blink_off.status_code == 200
        assert r_blink_off.json()["blink"]["active"] is False

        # WebSocket snapshot push
        with client.websocket_connect("/ws") as ws:
            msg = json.loads(ws.receive_text())
            assert msg["switch"]["switch_name"] == "IDF2-SW03"
