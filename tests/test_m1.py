import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.autotest import evaluate_autotest
from app.diagnostics import (
    grade_bufferbloat,
    parse_iperf3_json,
    parse_single_ping_ms,
    parse_traceroute_output,
    validate_host_target,
)
from app.main import app, runtime
from app.models import (
    L3Connectivity,
    LinkTelemetry,
    SecurityReportState,
    SwitchNeighbor,
    TdrReportState,
    VlanAndNacTelemetry,
)


def _clean_l3(internet_ok: bool = True) -> L3Connectivity:
    return L3Connectivity(
        ipv4_address="10.20.1.148",
        subnet_cidr="10.20.1.148/24",
        dhcp_status="Bound (Dynamic)",
        gateway_ip="10.20.1.1",
        gateway_ping_ms=0.9,
        dns_server="10.20.1.10",
        dns_resolve_ms=3.2,
        internet_ok=internet_ok,
        http_probe_ms=14.0 if internet_ok else None,
    )


def test_evaluate_autotest_profiles_and_verdicts():
    link_up = LinkTelemetry(
        carrier_up=True,
        speed_mbps=1000,
        duplex="Full",
        pair_diagnostic_note="All 4 pairs active",
    )
    sw = SwitchNeighbor(detected=True, switch_name="SW-1", model="C2960X", port_id="Gi1/0/24", protocols=["LLDP"])
    vlan = VlanAndNacTelemetry(native_vlan=20)
    tdr = TdrReportState(overall_verdict="PASS")
    sec_ok = SecurityReportState(score=96, grade="A", summary="Healthy")

    # 1. Standard WAN PASS
    res_pass = evaluate_autotest(link_up, sw, vlan, _clean_l3(True), tdr, sec_ok, profile="standard")
    assert res_pass.verdict == "PASS"
    assert res_pass.passed_count == 7
    assert res_pass.total_count == 7

    # 2. Standard fails on WAN offline, whereas LAN-Only skips WAN and passes!
    res_fail_wan = evaluate_autotest(link_up, sw, vlan, _clean_l3(False), tdr, sec_ok, profile="standard")
    assert res_fail_wan.verdict == "FAIL"

    res_lan = evaluate_autotest(link_up, sw, vlan, _clean_l3(False), tdr, sec_ok, profile="lan_only", auto_log=True)
    assert res_lan.verdict == "PASS"
    assert res_lan.auto_log is True
    assert res_lan.total_count == 6
    wan_step = next(s for s in res_lan.steps if s.key == "wan")
    assert wan_step.status == "SKIP"

    # 3. Downshift warning without fail
    link_downshift = link_up.model_copy(update={"speed_mbps": 100, "pair_downshift_suspected": True})
    res_warn = evaluate_autotest(link_downshift, sw, vlan, _clean_l3(True), tdr, sec_ok)
    assert res_warn.verdict == "WARN"

    # 4. Link down -> NO_LINK
    link_down = LinkTelemetry(carrier_up=False)
    res_nolink = evaluate_autotest(link_down, SwitchNeighbor(), vlan, L3Connectivity(), TdrReportState(), SecurityReportState(score=0))
    assert res_nolink.verdict == "NO_LINK"
    assert res_nolink.steps[0].status == "FAIL"


def test_diagnostics_parsers_and_validation():
    # Host validation
    assert validate_host_target(" 192.168.0.1 ") == "192.168.0.1"
    assert validate_host_target("speed.cloudflare.com") == "speed.cloudflare.com"
    for bad in ("", "; rm -rf /", "1.1.1.1 && id", "-c 1", "foo bar"):
        with pytest.raises(ValueError):
            validate_host_target(bad)

    # Ping output parser (Linux + Windows)
    assert parse_single_ping_ms("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.4 ms") == 12.4
    assert parse_single_ping_ms("Reply from 192.168.0.1: bytes=32 time=2ms TTL=64") == 2.0
    assert parse_single_ping_ms("Reply from 192.168.0.1: bytes=32 time<1ms TTL=64") == 0.5
    assert parse_single_ping_ms("Request timed out.") is None

    # Traceroute -n output
    tr_out = """traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 60 byte packets
 1  10.20.1.1  0.842 ms
 2  *
 3  one.one.one.one (1.1.1.1)  11.9 ms
"""
    hops_tr = parse_traceroute_output(tr_out)
    assert len(hops_tr) == 3
    assert hops_tr[0].ip == "10.20.1.1" and hops_tr[0].rtt_ms == 0.84
    assert hops_tr[1].loss is True and hops_tr[1].ip == "*"
    assert hops_tr[2].ip == "1.1.1.1" and hops_tr[2].rtt_ms == 11.9

    # Tracepath -n output
    tp_out = """ 1?: [LOCALHOST]                      pmtu 1500
 1:  192.168.0.254                                         0.510ms
 2:  no reply
 3:  1.1.1.1                                              10.250ms reached
"""
    hops_tp = parse_traceroute_output(tp_out)
    assert len(hops_tp) == 3
    assert hops_tp[0].ip == "192.168.0.254" and hops_tp[0].rtt_ms == 0.51
    assert hops_tp[1].loss is True
    assert hops_tp[2].ip == "1.1.1.1" and hops_tp[2].rtt_ms == 10.25

    # Bufferbloat grade thresholds
    assert grade_bufferbloat(None, 20.0) == "—"
    assert grade_bufferbloat(10.0, 14.0) == "A+"
    assert grade_bufferbloat(10.0, 22.0) == "A"
    assert grade_bufferbloat(10.0, 35.0) == "B"
    assert grade_bufferbloat(10.0, 60.0) == "C"
    assert grade_bufferbloat(10.0, 120.0) == "D"
    assert grade_bufferbloat(10.0, 210.0) == "F"

    # iperf3 JSON parsing
    sample_iperf = json.dumps({
        "end": {
            "sum_sent": {"bits_per_second": 938400000.0, "retransmits": 2},
            "sum_received": {"bits_per_second": 936100000.0},
        }
    })
    tx, rx, retr = parse_iperf3_json(sample_iperf)
    assert tx == 938.4
    assert rx == 936.1
    assert retr == 2


def test_m1_api_endpoints_in_demo_mode(tmp_path: Path):
    orig_settings_path = runtime.diag._settings_path
    runtime.diag._settings_path = tmp_path / "diag_settings.json"
    try:
        with TestClient(app) as client:
            r_mode = client.post(
                "/api/mode",
                json={"demo_mode": True, "demo_scenario": "healthy_1g", "iface": "eth0"},
            )
            assert r_mode.status_code == 200
            snap = r_mode.json()
            assert snap["autotest"]["verdict"] == "PASS"
            assert len(snap["autotest"]["steps"]) == 7

            # AutoTest profile & auto_log config + manual run
            r_cfg = client.post("/api/autotest/config", json={"profile": "lan_only", "auto_log": True})
            assert r_cfg.status_code == 200
            at_cfg = r_cfg.json()["autotest"]
            assert at_cfg["profile"] == "lan_only"
            assert at_cfg["auto_log"] is True
            assert at_cfg["total_count"] == 6

            r_run = client.post("/api/autotest/run")
            assert r_run.status_code == 200
            assert r_run.json()["autotest"]["verdict"] == "PASS"

            # Reject bad target cleanly with 400
            r_bad = client.post("/api/diag/ping/start", json={"target": "1.1.1.1; whoami"})
            assert r_bad.status_code == 400

            # Live ping start + brief wait for sample + stop
            r_pstart = client.post("/api/diag/ping/start", json={"target": "1.1.1.1"})
            assert r_pstart.status_code == 200
            assert r_pstart.json()["diagnostics"]["ping"]["running"] is True
            time.sleep(0.15)
            r_pstop = client.post("/api/diag/ping/stop")
            assert r_pstop.status_code == 200
            assert r_pstop.json()["diagnostics"]["ping"]["running"] is False
            assert r_pstop.json()["diagnostics"]["ping"]["sent"] >= 1

            # Traceroute
            r_tr = client.post("/api/diag/traceroute", json={"target": "1.1.1.1"})
            assert r_tr.status_code == 200
            assert len(r_tr.json()["diagnostics"]["traceroute"]["hops"]) >= 4

            # Speedtest
            r_spd = client.post("/api/diag/speedtest")
            assert r_spd.status_code == 200
            spd = r_spd.json()["diagnostics"]["speedtest"]
            assert spd["download_mbps"] > 100
            assert spd["bufferbloat_grade"] in ("A+", "A")

            # Saved iperf targets + client + server
            r_tgts = client.post("/api/diag/iperf/targets", json={"targets": ["192.168.0.1", "10.20.1.99"]})
            assert r_tgts.status_code == 200
            assert r_tgts.json()["diagnostics"]["iperf"]["saved_targets"] == ["192.168.0.1", "10.20.1.99"]

            r_icli = client.post("/api/diag/iperf/client", json={"target": "10.20.1.99", "duration_sec": 5})
            assert r_icli.status_code == 200
            assert r_icli.json()["diagnostics"]["iperf"]["tx_mbps"] > 900

            r_isrv = client.post("/api/diag/iperf/server", json={"enable": True})
            assert r_isrv.status_code == 200
            assert r_isrv.json()["diagnostics"]["iperf"]["server_running"] is True
            r_isrv_off = client.post("/api/diag/iperf/server", json={"enable": False})
            assert r_isrv_off.status_code == 200
            assert r_isrv_off.json()["diagnostics"]["iperf"]["server_running"] is False

            # MTU probe
            r_mtu = client.post("/api/diag/mtu", json={"target": "1.1.1.1"})
            assert r_mtu.status_code == 200
            assert r_mtu.json()["diagnostics"]["mtu"]["max_mtu"] == 1500
    finally:
        runtime.diag._settings_path = orig_settings_path
