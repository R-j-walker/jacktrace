from pathlib import Path
from typing import Dict
from fastapi.testclient import TestClient

from app.audit import AuditStore
from app.main import app
from app.models import LinkTelemetry, PhyWiringState, TdrReportState
from app.probes import parse_ethtool_output
from app.tdr import (
    BCM54XX_ACCESS_MODE_LEGACY_EN,
    BCM54XX_EXP_ECD_CTRL,
    BCM54XX_EXP_ECD_FAULT_TYPE,
    BCM54XX_EXP_ECD_PAIR_A_LEN,
    BCM54XX_RDB_REG0087,
    BMCR_1G_AN,
    BMCR_1G_AN_RESTART,
    BMCR_RESET,
    MII_ADVERTISE,
    MII_BCM54XX_ESR,
    MII_BCM54XX_EXP_DATA,
    MII_BCM54XX_EXP_SEL,
    MII_BCM54XX_FCS_CNT,
    MII_BCM54XX_RDB_ADDR,
    MII_BCM54XX_RDB_DATA,
    MII_BCM54XX_RERR_CNT,
    MII_BCM54XX_RX_NOT_OK_CNT,
    MII_BMCR,
    MII_CTRL1000,
    MII_PHYSID1,
    MII_PHYSID2,
    MII_STAT1000,
    decode_bcm_ecd_registers,
    decode_phy_wiring_regs,
    read_phy_wiring_sync,
    run_hardware_tdr_sync,
    synthesize_wiremap_verdict,
)


class FakeBroadcomMdio:
    """Simulates a Raspberry Pi 4 Broadcom BCM54213PE PHY over MDIO registers."""

    def __init__(
        self,
        fault_code: int = 0x1112,
        lengths_cm=(3120, 3140, 3110, 1840),
        init_adv: int = 0x01E1,
        init_c1000: int = 0x0300,
        ctrl_after: int = 0x0000,
    ):
        self.phy_id = 1
        self.ctrl_after = ctrl_after
        self.regs: Dict[int, int] = {
            MII_BMCR: 0x1140,
            MII_PHYSID1: 0x600D,
            MII_PHYSID2: 0x84A2,  # BCM54213PE rev 2
            MII_ADVERTISE: init_adv,
            MII_CTRL1000: init_c1000,
        }
        self.exp_regs: Dict[int, int] = {
            BCM54XX_EXP_ECD_CTRL: 0x0000,
            BCM54XX_EXP_ECD_FAULT_TYPE: fault_code,
            BCM54XX_EXP_ECD_PAIR_A_LEN + 0: lengths_cm[0],
            BCM54XX_EXP_ECD_PAIR_A_LEN + 1: lengths_cm[1],
            BCM54XX_EXP_ECD_PAIR_A_LEN + 2: lengths_cm[2],
            BCM54XX_EXP_ECD_PAIR_A_LEN + 3: lengths_cm[3],
        }
        self._exp_sel = 0
        self._rdb_addr = 0
        self.closed = False
        self.triggered_run = False
        self.write_log = []

    def close(self) -> None:
        self.closed = True

    def read_reg(self, reg_num: int) -> int:
        if reg_num == MII_BCM54XX_EXP_DATA:
            return self.exp_regs.get(self._exp_sel, 0)
        return self.regs.get(reg_num, 0)

    def write_reg(self, reg_num: int, val: int) -> None:
        self.write_log.append((reg_num, val))
        if reg_num == MII_BCM54XX_EXP_SEL:
            self._exp_sel = val
        elif reg_num == MII_BCM54XX_EXP_DATA:
            if self._exp_sel == BCM54XX_EXP_ECD_CTRL and val == 0x9000:
                self.triggered_run = True
                # Hardware clears RUN and IN_PROGRESS upon completion, preserving e.g. INVALID bit if FLP collided
                val = self.ctrl_after
            self.exp_regs[self._exp_sel] = val
        elif reg_num == MII_BCM54XX_RDB_ADDR:
            self._rdb_addr = val
            self.regs[reg_num] = val
        else:
            self.regs[reg_num] = val

    def read_exp(self, exp_reg: int) -> int:
        self.write_reg(MII_BCM54XX_EXP_SEL, exp_reg)
        return self.read_reg(MII_BCM54XX_EXP_DATA)

    def write_exp(self, exp_reg: int, val: int) -> None:
        self.write_reg(MII_BCM54XX_EXP_SEL, exp_reg)
        self.write_reg(MII_BCM54XX_EXP_DATA, val)


def test_decode_bcm_ecd_fault_modes():
    # 1. All 4 pairs OK (explicit 100.0 ticks/m -> distance_m must be None, ignoring stale 0x50B8 noise)
    ok_res = decode_bcm_ecd_registers(0x1111, (0x50B8, 0x50B8, 0x50B8, 0x50B8), ticks_per_meter=100.0)
    assert ok_res.overall_verdict == "PASS"
    assert all(p.status == "OK" and p.distance_m is None for p in ok_res.pairs)

    # 2. Unpatched 28.6m drop (explicit 100.0 ticks/m)
    unp = decode_bcm_ecd_registers(0x2222, (2860, 2850, 2870, 2860), ticks_per_meter=100.0)
    assert unp.overall_verdict == "UNPATCHED"
    assert "28.6m" in unp.summary

    # 3. Intra-pair short on Pair B @ 4.2m (explicit 100.0 ticks/m)
    sh = decode_bcm_ecd_registers(0x1311, (3000, 420, 3000, 3000), ticks_per_meter=100.0)
    assert sh.overall_verdict == "FAIL"
    assert sh.pairs[1].status == "SHORT"
    assert sh.pairs[1].distance_m == 4.2

    # 4. Default bench calibration (97.4 ticks/m)
    cal = decode_bcm_ecd_registers(0x2222, (974, 974, 974, 974), ticks_per_meter=97.4)
    assert cal.overall_verdict == "UNPATCHED"
    assert cal.pairs[0].distance_m == 10.0


def test_hardware_tdr_mdio_sequence_and_link_restore():
    fake_phy = FakeBroadcomMdio(
        fault_code=0x1112,
        lengths_cm=(3120, 3140, 3110, 1840),
        init_adv=0x0001,    # Simulate stuck CSMA-only advertisement from earlier interrupted run
        init_c1000=0x0000,
    )
    res = run_hardware_tdr_sync("eth0", mdio_factory=lambda _iface: fake_phy)

    assert fake_phy.triggered_run is True
    assert fake_phy.closed is True
    assert "BCM54213PE" in res.phy_id
    assert "fault=0x1112" in res.raw_debug
    assert res.overall_verdict == "FAIL"
    assert res.pairs[3].status == "OPEN"
    assert res.pairs[3].distance_m == round(1840 / 97.4, 1)

    # Verify strict write order: BMCR reset (0x8000) before BMCR 1G (0x1140), RDB 0x0087->0x8000, and 0x0FC0->0x9000
    idx_reset = fake_phy.write_log.index((MII_BMCR, BMCR_RESET))
    idx_1g = fake_phy.write_log.index((MII_BMCR, BMCR_1G_AN))
    idx_rdb_addr = fake_phy.write_log.index((MII_BCM54XX_RDB_ADDR, BCM54XX_RDB_REG0087))
    idx_rdb_data = fake_phy.write_log.index((MII_BCM54XX_RDB_DATA, BCM54XX_ACCESS_MODE_LEGACY_EN))
    idx_ecd_sel = fake_phy.write_log.index((MII_BCM54XX_EXP_SEL, BCM54XX_EXP_ECD_CTRL))
    idx_ecd_run = fake_phy.write_log.index((MII_BCM54XX_EXP_DATA, 0x9000))
    assert idx_reset < idx_1g < idx_rdb_addr < idx_rdb_data < idx_ecd_sel < idx_ecd_run

    # Verify Gigabit auto-negotiation registers were cleanly restored (never stuck at 0x0001/0x0000)
    assert fake_phy.regs[MII_ADVERTISE] == 0x01E1
    assert fake_phy.regs[MII_CTRL1000] == 0x0300
    assert fake_phy.regs[MII_BMCR] == BMCR_1G_AN_RESTART


def test_live_switch_flp_collision_handling():
    # 1. Reproduce live Grandstream GWN7806P register dump (ctrl=0x0008, fault=0x0001, raw=0xFFFF/0x50B8)
    fake_phy = FakeBroadcomMdio(
        fault_code=0x0001,
        lengths_cm=(0xFFFF, 0xFFFF, 0xFFFF, 0x50B8),
        ctrl_after=0x0008,
    )
    res_1g = run_hardware_tdr_sync(
        "eth0",
        mdio_factory=lambda _iface: fake_phy,
        prev_link_up=True,
        prev_speed_mbps=1000,
    )
    assert "tries=2" in res_1g.raw_debug
    assert res_1g.overall_verdict == "PASS"
    assert all(p.status == "OK" and p.distance_m is None for p in res_1g.pairs)
    assert "link pulses" in res_1g.summary.lower()

    # 2. 100M downshifted link where Pairs A/B collided (0x00) while Pair D reports OPEN @ 18.4m
    res_100m = decode_bcm_ecd_registers(
        fault_reg=0x0012,
        lengths_cm=(0xFFFF, 0xFFFF, 0xFFFF, 1840),
        ticks_per_meter=100.0,
        ctrl_reg=0x0008,
        prev_link_up=True,
        prev_speed_mbps=100,
    )
    assert res_100m.overall_verdict == "FAIL"
    assert res_100m.pairs[0].status == "OK"
    assert res_100m.pairs[1].status == "OK"
    assert res_100m.pairs[2].status == "OK"
    assert res_100m.pairs[3].status == "OPEN"
    assert res_100m.pairs[3].distance_m == 18.4


def test_phase3_api_tdr_and_pdf_column(tmp_path: Path):
    store = AuditStore(db_path=tmp_path / "phase3_audit.db")
    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = store

        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "pair_fault_100m"})
        r_tdr = client.post("/api/tdr/run")
        assert r_tdr.status_code == 200
        snap = r_tdr.json()
        assert snap["tdr"]["overall_verdict"] == "FAIL"
        assert snap["tdr"]["pairs"][3]["distance_m"] == 18.4

        saved = client.post("/api/audit/save", json={}).json()
        assert "PD:OPEN@18.4m" in saved["tdr_summary"]

        r_pdf = client.get("/api/audit/report.pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.content.startswith(b"%PDF-1.")


def test_parse_ethtool_mdix_and_master_slave():
    sample = """Settings for eth1:
\tSpeed: 2500Mb/s
\tDuplex: Full
\tAuto-negotiation: on
\tmaster-slave status: master
\tMDI-X: on (auto)
\tLink detected: yes
"""
    parsed = parse_ethtool_output(sample)
    assert parsed["speed_mbps"] == 2500
    assert parsed["mdix_state"] == "MDI-X"
    assert parsed["master_slave"] == "Master"


def test_decode_and_read_phy_wiring_regs():
    # 1. Clean 1G MDI Slave on live BCM54213PE (0x0A=0x3000, 0x11=0x0301)
    clean = decode_phy_wiring_regs(0x600D84A2, stat1000=0x3000, esr=0x0301, speed_mbps=1000)
    assert clean.supported is True
    assert "BCM54213PE" in clean.phy_name
    assert clean.mdix_state == "MDI"
    assert clean.master_slave == "Slave"
    assert clean.local_rx_ok is True
    assert clean.remote_rx_ok is True
    assert clean.descrambler_locked is True
    assert clean.idle_errors == 0

    # 2. Non-disruptive MDIO read with MDI-X + split-pair noise counters & zero MDIO writes
    fake_phy = FakeBroadcomMdio()
    fake_phy.regs[MII_STAT1000] = 0x7005   # Master + LocOK + RemOK + 5 idle errors
    fake_phy.regs[MII_BCM54XX_ESR] = 0x2301  # MDI-X + Descrambler Lock
    fake_phy.regs[MII_BCM54XX_RERR_CNT] = 12
    fake_phy.regs[MII_BCM54XX_FCS_CNT] = 3
    fake_phy.regs[MII_BCM54XX_RX_NOT_OK_CNT] = (2 << 8) | 1

    noisy = read_phy_wiring_sync(
        "eth0", carrier_up=True, speed_mbps=1000, mdio_factory=lambda _iface: fake_phy
    )
    assert fake_phy.write_log == []
    assert fake_phy.closed is True
    assert noisy.mdix_state == "MDI-X"
    assert noisy.master_slave == "Master"
    assert noisy.idle_errors == 5
    assert noisy.rx_symbol_errors == 12
    assert noisy.false_carrier_errors == 3
    assert noisy.local_rx_not_ok_count == 2
    assert noisy.remote_rx_not_ok_count == 1

    # 3. Non-Broadcom PHY falls back cleanly to ethtool MDI-X / Master-Slave without Broadcom regs
    usb_phy = FakeBroadcomMdio()
    usb_phy.regs[MII_PHYSID1] = 0x001C
    usb_phy.regs[MII_PHYSID2] = 0xC800
    usb_phy.regs[MII_STAT1000] = 0x3000
    usb_pw = read_phy_wiring_sync(
        "eth1",
        carrier_up=True,
        speed_mbps=2500,
        ethtool_mdix="MDI-X",
        ethtool_ms="Master",
        mdio_factory=lambda _iface: usb_phy,
    )
    assert usb_pw.supported is True
    assert usb_pw.mdix_state == "MDI-X"
    assert usb_pw.master_slave == "Master"
    assert usb_pw.rx_symbol_errors == 0


def test_synthesize_wiremap_verdict_and_reset_route(tmp_path: Path):
    # Healthy 1G MDI-X link
    lnk_ok = LinkTelemetry(
        carrier_up=True,
        speed_mbps=1000,
        phy_wiring=PhyWiringState(
            supported=True,
            mdix_state="MDI-X",
            master_slave="Slave",
            local_rx_ok=True,
            remote_rx_ok=True,
            descrambler_locked=True,
        ),
    )
    v, s = synthesize_wiremap_verdict(lnk_ok, TdrReportState())
    assert v == "PASS"
    assert "PHY: MDI-X (Auto)" in s

    # Stale boot-lifetime rx_crc_errors ignored when session_crc_errors=0
    lnk_stale_crc = lnk_ok.model_copy(update={"rx_crc_errors": 5})
    v_sc, s_sc = synthesize_wiremap_verdict(lnk_stale_crc, TdrReportState(), session_crc_errors=0)
    assert v_sc == "PASS"
    assert "0 PHY errors" in s_sc

    # Split-pair / physical noise warning
    lnk_warn = LinkTelemetry(
        carrier_up=True,
        speed_mbps=1000,
        phy_wiring=PhyWiringState(
            supported=True,
            mdix_state="MDI",
            local_rx_ok=True,
            remote_rx_ok=True,
            descrambler_locked=True,
            idle_errors=4,
            rx_symbol_errors=7,
        ),
    )
    vw, sw = synthesize_wiremap_verdict(lnk_warn, TdrReportState())
    assert vw == "WARN"
    assert "Idle: 4" in sw and "Symbol: 7" in sw

    # Receiver NOT OK -> FAIL
    lnk_fail = LinkTelemetry(
        carrier_up=True,
        speed_mbps=1000,
        phy_wiring=PhyWiringState(
            supported=True,
            local_rx_ok=False,
            remote_rx_ok=True,
            descrambler_locked=False,
        ),
    )
    vf, _ = synthesize_wiremap_verdict(lnk_fail, TdrReportState())
    assert vf == "FAIL"

    # API reset-counters endpoint + demo snapshot populated
    store = AuditStore(db_path=tmp_path / "wm_audit.db")
    with TestClient(app) as client:
        from app.main import runtime
        runtime.audit_store = store
        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})
        snap = client.get("/api/snapshot").json()
        assert snap["link"]["phy_wiring"]["supported"] is True
        assert snap["link"]["phy_wiring"]["verdict"] == "PASS"
        r_rst = client.post("/api/phy/reset-counters")
        assert r_rst.status_code == 200
        assert r_rst.json() == {"ok": True}
