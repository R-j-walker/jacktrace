from pathlib import Path
from fastapi.testclient import TestClient

from app.audit import AuditStore
from app.dot1x import Dot1xTestManager, parse_wpa_supplicant_line
from app.main import app
from app.net_config import StaticIpv4Manager, validate_static_ipv4, validate_wired_iface
from app.system_ctrl import read_overlayfs_state
from app.tdr import (
    DEFAULT_TICKS_PER_METER,
    load_tdr_calibration,
    save_tdr_calibration,
    ticks_per_meter_for_nvp,
)


def test_tdr_nvp_calibration_and_api(tmp_path: Path, monkeypatch):
    assert ticks_per_meter_for_nvp(69.0) == DEFAULT_TICKS_PER_METER
    assert ticks_per_meter_for_nvp(76.0) < DEFAULT_TICKS_PER_METER

    try:
        ticks_per_meter_for_nvp(40.0)
        raise AssertionError("Expected ValueError for out-of-range NVP")
    except ValueError:
        pass

    cal_path = tmp_path / "tdr_settings.json"
    save_tdr_calibration("Cat6 (72%)", 72.0, path=cal_path)
    lbl, nvp = load_tdr_calibration(path=cal_path)
    assert lbl == "Cat6 (72%)"
    assert nvp == 72.0

    monkeypatch.setattr(
        "app.main.save_tdr_calibration",
        lambda c_lbl, c_nvp: save_tdr_calibration(c_lbl, c_nvp, path=cal_path),
    )

    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = AuditStore(db_path=tmp_path / "v21_cal.db")
        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})

        r_bad = client.post("/api/tdr/calibration", json={"nvp_pct": 95.0})
        assert r_bad.status_code == 400

        r_preset = client.post("/api/tdr/calibration", json={"preset": "cat6a"})
        assert r_preset.status_code == 200
        snap = r_preset.json()
        assert snap["tdr"]["nvp_pct"] == 76.0
        assert snap["tdr"]["cable_type"] == "Cat6A (76%)"


def test_static_ipv4_validation_manager_and_routes(tmp_path: Path):
    assert validate_wired_iface("eth0") == "eth0"
    assert validate_wired_iface("enx00e04c682501") == "enx00e04c682501"
    for bad_if in ("wlan0", "lo", "br0", ""):
        try:
            validate_wired_iface(bad_if)
            raise AssertionError(f"Should reject {bad_if}")
        except ValueError:
            pass

    cidr, gw, dns = validate_static_ipv4("192.168.10.50/24", "192.168.10.1", "1.1.1.1")
    assert cidr == "192.168.10.50/24"
    assert gw == "192.168.10.1"
    assert dns == "1.1.1.1"

    try:
        validate_static_ipv4("192.168.10.50")  # missing /prefix
        raise AssertionError("Should require CIDR prefix")
    except ValueError:
        pass

    mgr = StaticIpv4Manager()
    st = mgr.apply_static("eth0", "10.20.30.40/24", "10.20.30.1", "8.8.8.8", demo_mode=True)
    assert st.mode == "static"
    assert st.ip_cidr == "10.20.30.40/24"
    st_dhcp = mgr.revert_dhcp("eth0", demo_mode=True)
    assert st_dhcp.mode == "dhcp"

    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = AuditStore(db_path=tmp_path / "v21_ip.db")
        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})

        r_bad = client.post("/api/net/ipv4/static", json={"ip_cidr": "not-an-ip"})
        assert r_bad.status_code == 400

        r_ok = client.post(
            "/api/net/ipv4/static",
            json={"ip_cidr": "192.168.55.20/24", "gateway": "192.168.55.1", "dns": "1.1.1.1"},
        )
        assert r_ok.status_code == 200
        assert r_ok.json()["static_ip"]["mode"] == "static"

        r_dhcp = client.post("/api/net/ipv4/dhcp")
        assert r_dhcp.status_code == 200
        assert r_dhcp.json()["static_ip"]["mode"] == "dhcp"


def test_dot1x_parser_manager_and_no_password_leak(tmp_path: Path):
    assert parse_wpa_supplicant_line("eth0: CTRL-EVENT-EAP-STARTED EAP authentication started")[0] == "Authenticating..."
    assert parse_wpa_supplicant_line("eth0: CTRL-EVENT-EAP-SUCCESS EAP authentication completed successfully")[0] == "Authenticated"
    assert parse_wpa_supplicant_line("eth0: CTRL-EVENT-EAP-FAILURE EAP authentication failed")[0] == "Failed"

    secret_pw = "SuperSecretDot1xPw!99"
    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = AuditStore(db_path=tmp_path / "v21_d1x.db")
        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "nac_8021x_locked"})

        r_bad = client.post("/api/dot1x/start", json={"identity": "user1", "password": 'bad"quote'})
        assert r_bad.status_code == 400

        r_ok = client.post(
            "/api/dot1x/start",
            json={"identity": "tech01@corp.lan", "password": secret_pw, "method": "PEAP"},
        )
        assert r_ok.status_code == 200
        body = r_ok.text
        assert secret_pw not in body
        data = r_ok.json()
        assert data["dot1x"]["status"] == "Authenticated"
        assert data["dot1x"]["identity"] == "tech01@corp.lan"
        assert data["dot1x"]["has_password"] is True
        assert "password" not in data["dot1x"]

        r_stop = client.post("/api/dot1x/stop")
        assert r_stop.status_code == 200


def test_speedtest_iface_selector_and_overlayfs_route(tmp_path: Path):
    ro_now, ro_next = read_overlayfs_state()
    assert isinstance(ro_now, bool) and isinstance(ro_next, bool)

    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = AuditStore(db_path=tmp_path / "v21_spd.db")
        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})

        r_wifi = client.post("/api/diag/speedtest", json={"iface_mode": "wifi"})
        assert r_wifi.status_code == 200
        spd_wifi = r_wifi.json()["diagnostics"]["speedtest"]
        assert spd_wifi["iface_mode"] == "wifi"
        assert spd_wifi["egress_iface"] == runtime.wifi_iface
        assert spd_wifi["egress_ip"] == "192.168.0.110"

        r_eth = client.post("/api/diag/speedtest", json={"iface_mode": "eth"})
        assert r_eth.status_code == 200
        spd_eth = r_eth.json()["diagnostics"]["speedtest"]
        assert spd_eth["iface_mode"] == "eth"
        assert spd_eth["egress_iface"] == runtime.iface

        r_ro = client.post("/api/system/overlayfs", json={"enable": True})
        assert r_ro.status_code == 200
        assert r_ro.json()["system"]["reboot_required"] is True
