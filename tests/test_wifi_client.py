import json
import pytest
from fastapi.testclient import TestClient

from app.main import app, runtime
from app.wifi_client import (
    normalize_nmcli_security,
    parse_nmcli_band,
    parse_nmcli_connections,
    parse_nmcli_device_show,
    parse_nmcli_wifi_list,
    split_nmcli_terse,
    validate_password,
    validate_ssid,
)


def test_split_nmcli_terse_and_band_security():
    line = r"*:Lab\:Net\\5G:02\:00\:00\:00\:00\:02:78:5260 MHz:WPA2 WPA3"
    parts = split_nmcli_terse(line)
    assert parts == [
        "*",
        r"Lab:Net\5G",
        "02:00:00:00:00:02",
        "78",
        "5260 MHz",
        "WPA2 WPA3",
    ]
    assert parse_nmcli_band("2462 MHz") == "2.4 GHz"
    assert parse_nmcli_band("5260 MHz") == "5 GHz"
    assert parse_nmcli_band("5955 MHz") == "6 GHz"
    assert normalize_nmcli_security("") == "Open"
    assert normalize_nmcli_security("--") == "Open"
    assert normalize_nmcli_security("WPA2 SAE") == "WPA2/WPA3"
    assert normalize_nmcli_security("SAE") == "WPA3"
    assert normalize_nmcli_security("WPA2 802.1X") == "WPA2-Ent"


def test_parse_nmcli_wifi_list_dedup_and_saved_matching():
    raw = "\n".join([
        r" :Corp-Office-5G:02\:00\:00\:00\:00\:01:88:2462 MHz:WPA2",
        r"*:Corp-Office-5G:02\:00\:00\:00\:00\:02:67:5260 MHz:WPA2",
        r" :CafeGuest:11\:22\:33\:44\:55\:66:54:2412 MHz:--",
        r" ::AA\:BB\:CC\:DD\:EE\:FF:40:2437 MHz:WPA2",
        r" :OfficeNet:AA\:11\:22\:33\:44\:55:72:5180 MHz:WPA2 SAE",
    ])
    nets = parse_nmcli_wifi_list(raw, {"Corp-Office-5G": "netplan-wlan0-corp", "OfficeNet": "OfficeNet"})
    assert [n.ssid for n in nets] == ["Corp-Office-5G", "OfficeNet", "CafeGuest"]
    assert nets[0].in_use is True
    assert nets[0].bssid == "02:00:00:00:00:02"
    assert nets[0].band == "5 GHz"
    assert nets[0].saved is True
    assert nets[0].profile_name == "netplan-wlan0-corp"
    assert nets[1].security == "WPA2/WPA3"
    assert nets[2].security == "Open"
    assert nets[2].saved is False


def test_parse_nmcli_connections_and_device_show():
    conn_raw = "\n".join([
        "netplan-wlan0-corp:802-11-wireless:00000000-1111-2222-3333-444444444441:wlan0:yes",
        "JackTrace-Hotspot:802-11-wireless:11111111-2222-3333-4444-555555555555:wlan0:no",
        "lo:loopback:00000000-1111-2222-3333-444444444442:lo:no",
        "netplan-eth0:802-3-ethernet:00000000-1111-2222-3333-444444444443::yes",
        "Phone-Hotspot:802-11-wireless:99999999-aaaa-bbbb-cccc-dddddddddddd::yes",
    ])
    profs, ap_active = parse_nmcli_connections(conn_raw, "wlan0")
    assert ap_active is True
    assert len(profs) == 2
    assert profs[0]["name"] == "netplan-wlan0-corp"
    assert profs[0]["active"] is True
    assert profs[1]["name"] == "Phone-Hotspot"
    assert profs[1]["active"] is False

    dev_raw = "GENERAL.CONNECTION:netplan-wlan0-corp\nIP4.ADDRESS[1]:192.168.0.110/24\n"
    prof_name, ipv4 = parse_nmcli_device_show(dev_raw)
    assert prof_name == "netplan-wlan0-corp"
    assert ipv4 == "192.168.0.110"


def test_wifi_client_validation():
    assert validate_ssid("  Office-5G ") == "Office-5G"
    with pytest.raises(ValueError):
        validate_ssid("   ")
    with pytest.raises(ValueError):
        validate_ssid("bad\nssid")
    assert validate_password("") is None
    assert validate_password("Super$ecret!99") == "Super$ecret!99"
    with pytest.raises(ValueError):
        validate_password("bad\rpass")


def test_wifi_client_api_routes_and_password_masking():
    runtime.wifi_client._init_demo_store()
    with TestClient(app) as client:
        r_mode = client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})
        assert r_mode.status_code == 200
        snap0 = r_mode.json()
        assert snap0["wifi_client"]["connected"] is True
        assert snap0["wifi_client"]["active_ssid"] == "Corp-5G-Office"

        r_st = client.get("/api/wifi/client/status")
        assert r_st.status_code == 200
        assert r_st.json()["ipv4"] == "192.168.10.42"

        r_scan = client.post("/api/wifi/client/scan")
        assert r_scan.status_code == 200
        ssids = [n["ssid"] for n in r_scan.json()["wifi_client"]["available_networks"]]
        assert "Boardroom-Guest" in ssids

        # Join open network without password
        r_open = client.post("/api/wifi/client/connect", json={"ssid": "Boardroom-Guest"})
        assert r_open.status_code == 200
        assert r_open.json()["wifi_client"]["active_ssid"] == "Boardroom-Guest"

        # Join WPA2 network with password — verify password is never leaked
        secret_pw = "UltraSecretPass!2026#"
        r_wpa = client.post("/api/wifi/client/connect", json={"ssid": "HiddenLab", "password": secret_pw, "hidden": True})
        assert r_wpa.status_code == 200
        wc_wpa = r_wpa.json()["wifi_client"]
        assert wc_wpa["active_ssid"] == "HiddenLab"
        assert secret_pw not in json.dumps(r_wpa.json())

        # Invalid control characters rejected
        r_bad = client.post("/api/wifi/client/connect", json={"ssid": "Bad\nNet"})
        assert r_bad.status_code == 400

        # Switch back to saved profile
        r_saved = client.post("/api/wifi/client/connect", json={"profile_name": "Phone-Hotspot", "ssid": "Phone-Hotspot"})
        assert r_saved.status_code == 200
        assert r_saved.json()["wifi_client"]["active_ssid"] == "Phone-Hotspot"

        # Disconnect
        r_disc = client.post("/api/wifi/client/disconnect")
        assert r_disc.status_code == 200
        assert r_disc.json()["wifi_client"]["connected"] is False

        # Forget profile
        r_fgt = client.post("/api/wifi/client/forget", json={"name": "HiddenLab"})
        assert r_fgt.status_code == 200
        remaining_names = [p["name"] for p in r_fgt.json()["wifi_client"]["saved_profiles"]]
        assert "HiddenLab" not in remaining_names

        # Refuses hotspot forget
        r_fgt_hs = client.post("/api/wifi/client/forget", json={"name": "JackTrace-Hotspot"})
        assert r_fgt_hs.status_code == 400
