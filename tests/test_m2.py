import time

from fastapi.testclient import TestClient

from app.main import app
from app.wifi_survey import (
    dbm_to_quality_pct,
    freq_to_channel,
    normalize_bssid,
    parse_iw_info,
    parse_iw_link,
    parse_iw_scan_output,
    recommend_best_24g_channel,
)


def test_freq_channel_quality_and_bssid():
    assert freq_to_channel(2412) == (1, "2.4 GHz")
    assert freq_to_channel(2437) == (6, "2.4 GHz")
    assert freq_to_channel(2484) == (14, "2.4 GHz")
    assert freq_to_channel(5180) == (36, "5 GHz")
    assert freq_to_channel(5300) == (60, "5 GHz")
    assert freq_to_channel(5745) == (149, "5 GHz")

    assert dbm_to_quality_pct(-100) == 0
    assert dbm_to_quality_pct(-70) == 60
    assert dbm_to_quality_pct(-45) == 100

    assert normalize_bssid("02-00-00-00-00-02") == "02:00:00:00:00:02"


def test_parse_iw_info_and_link():
    managed_txt = """Interface wlan0
\tifindex 3
\twdev 0x1
\taddr 02:11:22:33:44:55
\tssid Corp-Office-5G
\ttype managed
\twiphy 0
\tchannel 60 (5300 MHz), width: 80 MHz, center1: 5290 MHz
\ttxpower 31.00 dBm
"""
    info = parse_iw_info(managed_txt)
    assert info["type"] == "managed"
    assert info["ssid"] == "Corp-Office-5G"
    assert info["channel"] == 60
    assert info["freq_mhz"] == 5300
    assert info["width_mhz"] == 80

    ap_txt = "Interface wlan0\n\ttype AP\n\tssid JackTrace-AP\n"
    assert parse_iw_info(ap_txt)["type"] == "AP"

    lnk_txt = """Connected to 02:00:00:00:00:02 (on wlan0)
\tSSID: Corp-Office-5G
\tfreq: 5300.0
\tsignal: -55 dBm
\trx bitrate: 433.3 MBit/s
\ttx bitrate: 351.0 MBit/s
"""
    lnk = parse_iw_link(lnk_txt)
    assert lnk["connected"] is True
    assert lnk["bssid"] == "02:00:00:00:00:02"
    assert lnk["channel"] == 60
    assert lnk["band"] == "5 GHz"
    assert lnk["signal_dbm"] == -55
    assert lnk["rx_mbps"] == 433.3
    assert lnk["tx_mbps"] == 351.0
    assert parse_iw_link("Not connected.")["connected"] is False


def test_parse_iw_scan_output_and_channel_recommendation():
    scan_txt = """BSS 02:00:00:00:00:02(on wlan0) -- associated
\tfreq: 5300.0
\tcapability: ESS Privacy ShortPreamble ShortSlotTime (0x0431)
\tsignal: -56.00 dBm
\tSSID: Corp-Office-5G
\tRSN:\t * Version: 1
\t\t * Authentication suites: PSK SAE
\tHT operation:
\t\t * primary channel: 60
\t\t * secondary channel offset: above
\tVHT capabilities:
\tVHT operation:
\t\t * channel width: 1 (80 MHz)
\t\t * center freq segment 1: 58
\tHE capabilities:
BSS 02:00:00:00:00:01(on wlan0)
\tfreq: 2437.0
\tcapability: ESS Privacy (0x0431)
\tsignal: -57.00 dBm
\tSSID: Corp-Office-5G
\tDS Parameter set: channel 6
\tRSN:\t * Version: 1
\t\t * Authentication suites: PSK
\tHT operation:
\t\t * primary channel: 6
\t\t * secondary channel offset: no secondary
\tVHT operation:
\t\t * channel width: 0 (20 or 40 MHz)
\t\t * center freq segment 1: 6
BSS 02:00:00:00:00:03(on wlan0)
\tfreq: 2412.0
\tcapability: ESS (0x0421)
\tsignal: -61.00 dBm
\tSSID: \\x00\\x00\\x00
\tHT capabilities:
\tHT operation:
\t\t * primary channel: 1
\t\t * secondary channel offset: above
"""
    nets = parse_iw_scan_output(scan_txt)
    assert len(nets) == 3

    # Sorted descending by signal (-56, -57, -61)
    assert nets[0].bssid == "02:00:00:00:00:02"
    assert nets[0].associated is True
    assert nets[0].channel == 60
    assert nets[0].width_mhz == 80
    assert nets[0].center_channel == 58
    assert nets[0].wifi_gen == "Wi-Fi 6"
    assert nets[0].security == "WPA2/WPA3"

    assert nets[1].ssid == "Corp-Office-5G"
    assert nets[1].band == "2.4 GHz"
    assert nets[1].channel == 6
    assert nets[1].width_mhz == 20
    assert nets[1].security == "WPA2"

    assert nets[2].ssid == "<Hidden>"
    assert nets[2].security == "Open"
    assert nets[2].width_mhz == 40
    assert nets[2].center_channel == 3

    # Channels 1 and 6 have strong/overlapping APs, so Ch 11 is cleanest!
    assert recommend_best_24g_channel(nets) == 11


def test_m2_wifi_api_routes_in_demo_mode():
    with TestClient(app) as client:
        client.post("/api/mode", json={"demo_mode": True, "demo_scenario": "healthy_1g"})

        r_scan = client.post("/api/wifi/scan")
        assert r_scan.status_code == 200
        wf = r_scan.json()["wifi"]
        assert wf["total_count"] == 10
        assert wf["count_24g"] >= 4
        assert wf["count_5g"] >= 4
        assert wf["best_24g_channel"] in (1, 6, 11)

        # Bad BSSID returns 400
        r_bad = client.post("/api/wifi/walk/start", json={"bssid": "not-a-mac"})
        assert r_bad.status_code == 400

        # Valid Walk start -> brief tick -> Walk stop
        bssid = wf["networks"][0]["bssid"]
        r_wstart = client.post("/api/wifi/walk/start", json={"bssid": bssid})
        assert r_wstart.status_code == 200
        assert r_wstart.json()["wifi"]["walk"]["running"] is True
        time.sleep(0.15)

        r_wstop = client.post("/api/wifi/walk/stop")
        assert r_wstop.status_code == 200
        walk = r_wstop.json()["wifi"]["walk"]
        assert walk["running"] is False
        assert len(walk["samples"]) >= 1
        assert walk["current_dbm"] is not None
