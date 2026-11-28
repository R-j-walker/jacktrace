from pathlib import Path
from fastapi.testclient import TestClient

from app.audit import AuditStore
from app.config import detect_default_wifi_iface
from app.main import app
from app.pentest_mode import detect_usb_wifi_iface
from app.system_ctrl import read_battery_status, read_cpu_temp_c
from app.tdr import format_phy_uid, run_hardware_tdr_sync
from app.wifi_survey import parse_iw_scan_output


class _FakeNonBroadcomMdio:
    def __init__(self, iface: str, id1: int = 0x001C, id2: int = 0xC816) -> None:
        self.iface = iface
        self.phy_id = 1
        self.id1 = id1
        self.id2 = id2
        self.writes = []
        self.closed = False

    def read_reg(self, reg_num: int) -> int:
        if reg_num == 0x02:
            return self.id1
        if reg_num == 0x03:
            return self.id2
        return 0xFFFF

    def write_reg(self, reg_num: int, val: int) -> None:
        self.writes.append(("reg", reg_num, val))

    def write_exp(self, exp_reg: int, val: int) -> None:
        self.writes.append(("exp", exp_reg, val))

    def close(self) -> None:
        self.closed = True


def test_detect_default_wifi_iface_env_and_sysfs(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NETTESTER_WIFI_IFACE", "wlp0s20f3")
    assert detect_default_wifi_iface(str(tmp_path)) == "wlp0s20f3"
    monkeypatch.delenv("NETTESTER_WIFI_IFACE", raising=False)

    monkeypatch.setattr("app.config.platform.system", lambda: "Linux")
    (tmp_path / "enp2s0").mkdir()
    wlp = tmp_path / "wlp0s20f3"
    wlp.mkdir()
    (wlp / "wireless").mkdir()

    assert detect_default_wifi_iface(str(tmp_path)) == "wlp0s20f3"

    # Prefer wlan0 if present and wireless
    w0 = tmp_path / "wlan0"
    w0.mkdir()
    (w0 / "phy80211").mkdir()
    assert detect_default_wifi_iface(str(tmp_path)) == "wlan0"


def test_tdr_safety_guard_blocks_writes_on_realtek_phy():
    fake = _FakeNonBroadcomMdio("enp2s0", id1=0x001C, id2=0xC816)
    res = run_hardware_tdr_sync("enp2s0", mdio_factory=lambda _if: fake)

    assert res.supported is False
    assert res.overall_verdict == "WARN"
    assert "Realtek" in res.phy_id
    assert "unsupported" in res.summary.lower()
    assert fake.writes == []
    assert fake.closed is True
    assert "Realtek" in format_phy_uid(0x001CC816)


def test_read_battery_status_and_x86_thermal_zone(tmp_path: Path):
    ps_dir = tmp_path / "power_supply"
    ps_dir.mkdir()
    assert read_battery_status(str(ps_dir)) == (None, "")

    bat0 = ps_dir / "BAT0"
    bat0.mkdir()
    (bat0 / "type").write_text("Battery\n", encoding="utf-8")
    (bat0 / "capacity").write_text("82\n", encoding="utf-8")
    (bat0 / "status").write_text("Charging\n", encoding="utf-8")
    assert read_battery_status(str(ps_dir)) == (82, "Charging")

    th_dir = tmp_path / "thermal"
    th_dir.mkdir()
    z0 = th_dir / "thermal_zone0"
    z0.mkdir()
    (z0 / "type").write_text("acpitz\n", encoding="utf-8")
    (z0 / "temp").write_text("31000\n", encoding="utf-8")

    z1 = th_dir / "thermal_zone1"
    z1.mkdir()
    (z1 / "type").write_text("x86_pkg_temp\n", encoding="utf-8")
    (z1 / "temp").write_text("54200\n", encoding="utf-8")

    assert read_cpu_temp_c(str(th_dir)) == 54.2


def test_detect_usb_wifi_excludes_primary_x86_iface(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("app.pentest_mode.platform.system", lambda: "Linux")
    w_primary = tmp_path / "wlp0s20f3"
    w_primary.mkdir()
    (w_primary / "wireless").mkdir()

    assert detect_usb_wifi_iface(False, primary_wifi_iface="wlp0s20f3", net_root=str(tmp_path)) is None

    w_usb = tmp_path / "wlx00c0ca112233"
    w_usb.mkdir()
    (w_usb / "phy80211").mkdir()

    assert detect_usb_wifi_iface(False, primary_wifi_iface="wlp0s20f3", net_root=str(tmp_path)) == "wlx00c0ca112233"


def test_parse_iw_scan_6ghz_channel_and_snapshot_capabilities(tmp_path: Path):
    sample = """
BSS 02:11:22:33:44:55(on wlp0s20f3)
\tfreq: 5975
\tsignal: -54.00 dBm
\tSSID: Lab-6E-Test
\tRSN:
\t\t * Authentication suites: SAE
\tHE capabilities:
"""
    nets = parse_iw_scan_output(sample)
    assert len(nets) == 1
    assert nets[0].band == "6 GHz"
    assert nets[0].channel == 5

    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = AuditStore(db_path=tmp_path / "x86_ui.db")
        r_snap = client.get("/api/snapshot")
        assert r_snap.status_code == 200
        snap = r_snap.json()
        assert "capabilities" in snap["system"]
        assert "wifi_iface" in snap["system"]
        assert "count_6g" in snap["wifi"]

        r_idx = client.get("/")
        assert r_idx.status_code == 200
        html = r_idx.text
        assert 'id="pill-bat"' in html
        assert 'id="btn-kb-keys-toggle"' in html
        assert 'enterAppMode()' in html
