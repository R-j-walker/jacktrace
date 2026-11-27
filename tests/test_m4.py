import asyncio
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.audit import AuditStore
from app.demo_data import build_demo_snapshot
from app.main import app, runtime
from app.models import AuditPortalState, BlinkState, SavedWallPort, StressTestResult, SystemHealthState
from app.nic_tap import NicTapManager, parse_ethtool_max_speed, validate_eth_iface
from app.printer import (
    BluetoothPrinterManager,
    build_live_receipt,
    build_wall_drop_label,
    parse_bluetoothctl_devices,
)
from app.probes import parse_ethtool_output
from app.sync_client import SyncManager


class _FakeHttpResponse:
    def __init__(self, status: int = 200, body: dict | None = None):
        self.status = status
        self._raw = json.dumps(body or {}).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def _sample_saved_port() -> SavedWallPort:
    return SavedWallPort(
        id=1,
        job_name="Floor 2 Audit",
        drop_label="W-07",
        saved_at="2026-11-25 01:00:00",
        verdict="PASS",
        switch_name="Core PoE",
        switch_model="Grandstream GWN7806P",
        switch_ip="192.168.0.254",
        port_id="Ethernet1/0/49",
        panel_summary="48-Port Switch (Port 49)",
        speed_summary="2500M Full",
        poe_summary="802.3at PoE+ (25.5W)",
        vlan_summary="V108 VoIP:110",
        ip_cidr="192.168.108.50/24",
        gateway_summary="192.168.108.1 (0.9ms)",
        security_grade="A (96)",
        tdr_summary="4 Pairs OK (24.0m)",
        notes="Rack B Patch 07",
    )


def test_escpos_label_receipt_and_bluetooth_parser(tmp_path: Path):
    port = _sample_saved_port()
    raw_lbl, prev_lbl = build_wall_drop_label(port)
    assert raw_lbl.startswith(b"\x1b@")
    assert b"W-07" in raw_lbl
    assert b"Core PoE" in raw_lbl
    assert b"Ethernet1/0/49" in raw_lbl
    assert b"\x1dV\x42\x00" in raw_lbl
    assert "W-07" in prev_lbl
    assert "Rack B Patch 07" in prev_lbl

    snap = build_demo_snapshot("healthy_1g", BlinkState(), StressTestResult(), AuditPortalState(), SystemHealthState())
    raw_rcpt, prev_rcpt = build_live_receipt(snap)
    assert raw_rcpt.startswith(b"\x1b@")
    assert b"JACKTRACE PORT REPORT" in raw_rcpt
    assert b"1/17" in raw_rcpt
    assert "IDF2-SW03" in prev_rcpt

    # Bluetooth device parser sorts thermal printers first and flags paired MACs
    all_out = "\n".join([
        "Device AA:BB:CC:11:22:33 WH-1000XM5 Headphones",
        "Device 00:11:22:33:44:55 MTP-2 Thermal Printer",
        "Device 66:77:88:99:AA:BB RPP02N POS-58",
    ])
    paired_out = "Device 66:77:88:99:AA:BB RPP02N POS-58\n"
    devs = parse_bluetoothctl_devices(all_out, paired_out)
    assert len(devs) == 3
    assert devs[0].name == "RPP02N POS-58" and devs[0].paired is True
    assert devs[1].name == "MTP-2 Thermal Printer" and devs[1].paired is False
    assert devs[2].name == "WH-1000XM5 Headphones"

    pm = BluetoothPrinterManager(settings_path=tmp_path / "prt.json")
    with pytest.raises(ValueError):
        asyncio.run(pm.select_printer("bad-mac", "Bad", 1, demo_mode=True))


def test_sync_manager_queue_masking_and_http_mocks(tmp_path: Path, monkeypatch):
    mgr = SyncManager(
        db_path=tmp_path / "sync.db",
        settings_path=tmp_path / "sync_cfg.json",
    )
    with pytest.raises(ValueError):
        mgr.update_config(webhook_url="ftp://invalid.local/hook")

    st = mgr.update_config(
        webhook_url="http://ha.local:8123/api/webhook/jt",
        webhook_token="super-secret-webhook-token",
        webhook_enabled=True,
        netbox_url="http://netbox.local:8000/",
        netbox_token="super-secret-netbox-token",
        netbox_enabled=True,
        auto_sync_on_save=True,
    )
    assert st.webhook_has_token is True
    assert st.netbox_has_token is True
    dumped = json.dumps(st.model_dump())
    assert "super-secret" not in dumped

    # Token should persist if omitted (None) during later toggle update
    st2 = mgr.update_config(auto_sync_on_save=False)
    assert st2.webhook_has_token is True
    assert st2.netbox_has_token is True

    # 1. Simulate offline webhook failure -> stays retryable FAILED with attempts=1
    port = _sample_saved_port()
    assert mgr.enqueue_port(port) == 2

    calls = []

    def fail_urlopen(req, timeout=6.0):
        calls.append((req.full_url, req.get_method()))
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(urllib.request, "urlopen", fail_urlopen)
    ok_nb, msg_nb = mgr.test_netbox_sync(demo_mode=False)
    assert ok_nb is False
    assert "offline" in msg_nb

    st_fail = asyncio.run(mgr.flush_queue(demo_mode=False))
    assert st_fail.failed_count == 2
    assert st_fail.sent_count == 0
    assert mgr.pending_count() == 2

    # 2. Simulate restored LAN/WAN -> retries cleanly & patches NetBox interface
    patched_bodies = []

    def ok_urlopen(req, timeout=6.0):
        url = req.full_url
        method = req.get_method()
        auth = req.headers.get("Authorization")
        calls.append((url, method, auth))
        if "/api/status/" in url:
            assert auth == "Token super-secret-netbox-token"
            return _FakeHttpResponse(200, {"netbox-version": "4.1.2"})
        if "/api/webhook/" in url:
            assert auth == "Bearer super-secret-webhook-token"
            return _FakeHttpResponse(200, {"ok": True})
        if "/api/dcim/devices/" in url:
            return _FakeHttpResponse(200, {"results": [{"id": 77, "name": "Core PoE"}]})
        if "/api/dcim/interfaces/?" in url:
            return _FakeHttpResponse(200, {"results": [{"id": 901, "name": "Ethernet1/0/49"}]})
        if "/api/dcim/interfaces/901/" in url and method == "PATCH":
            patched_bodies.append(json.loads(req.data.decode("utf-8")))
            return _FakeHttpResponse(200, {"id": 901})
        return _FakeHttpResponse(404, {})

    monkeypatch.setattr(urllib.request, "urlopen", ok_urlopen)
    ok_nb2, msg_nb2 = mgr.test_netbox_sync(demo_mode=False)
    assert ok_nb2 is True and "4.1.2" in msg_nb2

    st_ok = asyncio.run(mgr.flush_queue(demo_mode=False))
    assert st_ok.sent_count == 2
    assert st_ok.failed_count == 0
    assert mgr.pending_count() == 0
    assert len(patched_bodies) == 1
    assert "[W-07]" in patched_bodies[0]["description"]
    assert "Rack B Patch 07" in patched_bodies[0]["description"]


def test_multigig_ethtool_and_nic_tap_guards():
    ethtool_25g = """Settings for eth1:
\tSupported link modes:   100baseT/Full 1000baseT/Full 2500baseT/Full
\tAdvertised link modes:  1000baseT/Full 2500baseT/Full
\tLink partner advertised link modes:  1000baseT/Full 2500baseT/Full
\tSpeed: 2500Mb/s
\tDuplex: Full
\tAuto-negotiation: on
\tLink detected: yes
"""
    assert parse_ethtool_max_speed(ethtool_25g) == 2500
    parsed = parse_ethtool_output(ethtool_25g)
    assert parsed["speed_mbps"] == 2500
    assert parsed["partner_supports_1g"] is True
    assert parsed["local_supports_1g"] is True

    assert validate_eth_iface("eth1") == "eth1"
    for bad in ("wlan0", "br0", "lo", "eth0;rm"):
        with pytest.raises(ValueError):
            validate_eth_iface(bad)

    tap = NicTapManager()
    with pytest.raises(ValueError):
        asyncio.run(tap.enable_tap("eth0", "eth0", demo_mode=True))

    ok, _msg = asyncio.run(tap.enable_tap("eth0", "eth1", demo_mode=True))
    assert ok is True
    assert tap.tap.active is True
    asyncio.run(tap.disable_tap(demo_mode=True))
    assert tap.tap.active is False


def test_m4_api_routes_demo_mode(tmp_path: Path):
    orig_store = runtime.audit_store
    orig_sync = runtime.sync_mgr
    orig_prt = runtime.printer_mgr
    orig_iface = runtime.iface

    runtime.audit_store = AuditStore(db_path=tmp_path / "m4_api.db")
    runtime.sync_mgr = SyncManager(db_path=tmp_path / "m4_api.db", settings_path=tmp_path / "sync.json")
    runtime.printer_mgr = BluetoothPrinterManager(settings_path=tmp_path / "prt.json")

    try:
        with TestClient(app) as client:
            client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g", "iface": "eth0"})

            # Multi-NIC list + 2.5GbE select + Dual-NIC Tap toggle
            r_nics = client.get("/api/nics/list")
            assert r_nics.status_code == 200
            nics = r_nics.json()["nics"]
            assert any(n["iface"] == "eth1" and n["supports_2500"] for n in nics)

            r_sel = client.post("/api/nics/select", json={"iface": "eth1"})
            assert r_sel.status_code == 200
            assert r_sel.json()["link"]["iface"] == "eth1"
            assert r_sel.json()["link"]["speed_mbps"] == 2500

            r_tap = client.post("/api/tap/toggle", json={"enable": True, "nic_a": "eth0", "nic_b": "eth1"})
            assert r_tap.status_code == 200
            assert r_tap.json()["hw_nics"]["tap"]["active"] is True

            # Cannot switch test NIC while tap is active
            assert client.post("/api/nics/select", json={"iface": "eth0"}).status_code == 409

            r_untap = client.post("/api/tap/toggle", json={"enable": False})
            assert r_untap.status_code == 200
            assert r_untap.json()["hw_nics"]["tap"]["active"] is False

            # Save a wall port, check auto-sync + NetBox/Webhook demo flush
            r_cfg = client.post(
                "/api/sync/config",
                json={
                    "webhook_url": "http://192.168.0.50:8123/api/webhook/jt",
                    "webhook_token": "tok123",
                    "webhook_enabled": True,
                    "netbox_url": "http://192.168.0.51:8000",
                    "netbox_token": "nb456",
                    "netbox_enabled": True,
                    "auto_sync_on_save": True,
                },
            )
            assert r_cfg.status_code == 200
            assert r_cfg.json()["sync"]["webhook_has_token"] is True

            r_nb = client.post("/api/sync/test-netbox")
            assert r_nb.status_code == 200
            assert "4.1.2" in r_nb.json()["sync"]["last_status"]

            saved = client.post("/api/audit/save", json={"notes": "M4 drop"}).json()
            assert saved["id"] >= 1

            r_push = client.post("/api/sync/push-job")
            assert r_push.status_code == 200
            assert r_push.json()["sync"]["sent_count"] >= 2

            assert client.post("/api/sync/queue/clear", json={"only_sent": False}).json()["sync"]["sent_count"] == 0

            # BT Printer scan, select, print-live & print-port
            r_pscan = client.post("/api/printer/scan")
            assert r_pscan.status_code == 200
            assert len(r_pscan.json()["printer"]["devices"]) == 2

            r_psel = client.post(
                "/api/printer/select",
                json={"mac": "00:11:22:33:44:55", "name": "MTP-2 58mm", "channel": 1},
            )
            assert r_psel.status_code == 200
            assert r_psel.json()["printer"]["selected_mac"] == "00:11:22:33:44:55"

            r_plive = client.post("/api/printer/print-live")
            assert r_plive.status_code == 200
            assert "JACKTRACE PORT DIAGNOSTIC" in r_plive.json()["printer"]["last_preview"]

            r_pport = client.post(f"/api/printer/print-port/{saved['id']}")
            assert r_pport.status_code == 200
            assert saved["drop_label"] in r_pport.json()["printer"]["last_preview"]
            assert client.post("/api/printer/print-port/99999").status_code == 404
    finally:
        runtime.audit_store = orig_store
        runtime.sync_mgr = orig_sync
        runtime.printer_mgr = orig_prt
        runtime.iface = orig_iface
        runtime.blinker.iface = orig_iface
