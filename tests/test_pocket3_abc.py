from pathlib import Path
from fastapi.testclient import TestClient

from app.audit import AuditStore
from app.main import app
from app.net_config import StaticIpv4Manager
from app.serial_console import (
    SerialConsoleManager,
    list_serial_ports,
    validate_baud_rate,
    validate_serial_port,
)
from app.system_ctrl import set_wayland_flip


def test_static_ipv4_iproute2_fallback_when_unmanaged(monkeypatch):
    calls = []

    def fake_run(cmd, timeout=8.0):
        calls.append(list(cmd))
        if cmd[0] == "nmcli":
            return 4, "Error: Device 'enp1s0' is unmanaged."
        return 0, ""

    monkeypatch.setattr("app.net_config.os.name", "posix")
    monkeypatch.setattr("app.net_config._run_nmcli", fake_run)
    mgr = StaticIpv4Manager()
    st = mgr.apply_static("enp1s0", "192.0.2.50/24", gateway="192.0.2.1", dns="1.1.1.1", demo_mode=False)

    assert st.mode == "static"
    assert "iproute2" in st.status
    assert ["ip", "-4", "addr", "flush", "dev", "enp1s0"] in calls
    assert ["ip", "addr", "add", "192.0.2.50/24", "dev", "enp1s0"] in calls
    assert ["ip", "route", "replace", "default", "via", "192.0.2.1", "dev", "enp1s0"] in calls

    st_dhcp = mgr.revert_dhcp("enp1s0", demo_mode=False)
    assert st_dhcp.mode == "dhcp"


def test_set_wayland_flip_constructs_wlr_randr_cmd(monkeypatch):
    captured = []

    monkeypatch.setattr("app.system_ctrl.os.name", "posix")
    monkeypatch.setattr("app.system_ctrl.shutil.which", lambda name: "/usr/bin/wlr-randr" if name == "wlr-randr" else None)
    monkeypatch.setattr("app.system_ctrl._find_wayland_session", lambda: ("jacktrace", "/run/user/1000", "wayland-0"))

    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured.append(list(cmd))
        return _Proc()

    monkeypatch.setattr("app.system_ctrl.subprocess.run", fake_run)
    ok, msg = set_wayland_flip(True)
    assert ok is True
    assert "90" in msg
    assert "--transform" in captured[0]
    assert "90" in captured[0]

    ok2, msg2 = set_wayland_flip(False)
    assert ok2 is True
    assert "270" in msg2
    assert "270" in captured[1]


def test_serial_validation_and_demo_console_lifecycle():
    assert validate_serial_port("/dev/ttyS0") == "/dev/ttyS0"
    assert validate_serial_port("/dev/ttyUSB0") == "/dev/ttyUSB0"
    assert validate_baud_rate(9600) == 9600

    for bad in ("/etc/passwd", "eth0", "/dev/sda", ""):
        try:
            validate_serial_port(bad)
            raise AssertionError(f"Expected ValueError for {bad}")
        except ValueError:
            pass

    ports = list_serial_ports(demo_mode=True)
    assert any(p.device == "/dev/ttyS0" for p in ports)

    mgr = SerialConsoleManager()
    st = mgr.connect("/dev/ttyS0", 9600, demo_mode=True)
    assert st.connected is True
    assert "Demo Console" in st.status
    assert "SW-CORE-FL2>" in st.recent_output

    mgr.send("show lldp neighbors", append_cr=True)
    st_after = mgr.snapshot(demo_mode=True)
    assert "DIST-SW-01" in st_after.recent_output
    assert st_after.bytes_tx > 0

    mgr.send_break()
    assert "BREAK" in mgr.snapshot(demo_mode=True).recent_output

    mgr.clear_buffer()
    assert mgr.snapshot(demo_mode=True).recent_output == ""

    st_disc = mgr.disconnect()
    assert st_disc.connected is False


def test_serial_api_websocket_and_splash_script(tmp_path: Path):
    splash_script = Path(__file__).resolve().parent.parent / "scripts" / "setup_splash_x86.sh"
    assert splash_script.is_file()
    raw_bytes = splash_script.read_bytes()
    assert b"\r\n" not in raw_bytes

    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = AuditStore(db_path=tmp_path / "abc_test.db")
        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})

        r_ports = client.get("/api/serial/ports")
        assert r_ports.status_code == 200
        assert len(r_ports.json()["ports"]) >= 1

        r_conn = client.post("/api/serial/connect", json={"port": "/dev/ttyS0", "baud": 9600})
        assert r_conn.status_code == 200
        assert r_conn.json()["serial"]["connected"] is True

        with client.websocket_connect("/ws/serial") as ws:
            init_ev = ws.receive_json()
            assert init_ev["type"] == "init"
            ws.send_json({"type": "tx", "data": "show version\r"})
            got_ver = False
            for _ in range(15):
                ev = ws.receive_json()
                if ev.get("type") == "rx" and "Aruba" in ev.get("data", ""):
                    got_ver = True
                    break
            assert got_ver

        r_disc = client.post("/api/serial/disconnect")
        assert r_disc.status_code == 200
        assert r_disc.json()["serial"]["connected"] is False

        r_html = client.get("/")
        assert r_html.status_code == 200
        assert 'id="view-serial"' in r_html.text
        assert 'id="rail-serial"' in r_html.text
        assert 'id="btn-wm-tdr"' in r_html.text


def test_tdr_unsupported_capability_sets_non_tdr_state(monkeypatch):
    from app.models import PlatformCapabilities
    from app.system_ctrl import detect_platform_capabilities

    monkeypatch.setattr("app.system_ctrl.os.name", "posix")
    monkeypatch.setattr("app.system_ctrl.platform.system", lambda: "Linux")
    monkeypatch.setattr("app.system_ctrl.platform.machine", lambda: "x86_64")
    monkeypatch.setattr("app.system_ctrl.detect_is_raspberry_pi", lambda: False)
    monkeypatch.setattr("app.system_ctrl._find_backlight_dir", lambda: "/sys/class/backlight/intel_backlight")
    monkeypatch.setattr("app.system_ctrl._find_wayland_session", lambda: ("jacktrace", "/run/user/1000", "wayland-0"))
    monkeypatch.setattr("app.system_ctrl.shutil.which", lambda name: "/usr/bin/wlr-randr" if name == "wlr-randr" else None)
    monkeypatch.setattr("app.system_ctrl._read_nic_driver_name", lambda _if: "r8169")

    caps: PlatformCapabilities = detect_platform_capabilities("enp1s0", demo_mode=False, battery_pct=52)
    assert caps.platform_kind == "x86_linux"
    assert caps.supports_tdr is False
    assert caps.supports_live_flip is True
    assert caps.has_battery is True
