import asyncio
import ipaddress
import os
import struct
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set

from fastapi import Body, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .audit import DATA_DIR, AuditStore, toggle_wlan_hotspot
from .autotest import evaluate_autotest
from .blinker import PortLedBlinker, _exec_net_cmd
from .config import settings
from .demo_data import build_demo_snapshot, build_demo_tdr
from .diagnostics import DiagnosticsManager, validate_host_target
from .dot1x import Dot1xTestManager
from .host_inspect import inspect_host_deep, send_wol_packet
from .models import (
    AutoTestState,
    DhcpOfferInfo,
    DiagnosticsState,
    Dot1xTestState,
    HostInspectResult,
    L3Connectivity,
    LinkTelemetry,
    NetworkHardwareState,
    PassiveExposureState,
    PentestState,
    PoeTelemetry,
    SavedWallPort,
    SecurityReportState,
    SnmpSwitchState,
    StaticIpState,
    StressTestResult,
    SubnetScanState,
    SwitchNeighbor,
    TailcatState,
    TdrReportState,
    TesterSnapshot,
    VlanAndNacTelemetry,
    VlanProbeState,
    WifiClientState,
    WifiSurveyState,
)
from .net_config import StaticIpv4Manager, validate_wired_iface
from .nic_tap import NicTapManager, validate_eth_iface
from .pentest_mode import PentestModeManager
from .pentest_nac import MacSpoofManager, generate_random_local_mac
from .pentest_recon import PentestReconManager
from .pentest_wifi import WifiAuditManager
from .printer import BluetoothPrinterManager, build_live_receipt, build_wall_drop_label
from .probes import probe_l3_connectivity, query_switch_and_vlans, read_link_telemetry, run_line_stress_test
from .scanner import sweep_subnet
from .security import evaluate_security_posture, probe_dhcp_servers_sync
from .sniffer import PassiveL2Sniffer
from .snmp_client import SnmpSwitchManager
from .sync_client import SyncManager
from .system_ctrl import (
    read_dsi_flipped,
    read_system_health,
    set_dsi_backlight,
    set_dsi_flipped,
    set_overlayfs_enabled,
    trigger_power_action,
)
from .tailcat_mgr import TailcatManager
from .tdr import (
    TDR_CABLE_PRESETS,
    load_tdr_calibration,
    run_hardware_tdr_sync,
    save_tdr_calibration,
    synthesize_wiremap_verdict,
)
from .vlan_probe import VlanTrunkProber
from .wifi_client import WifiClientManager
from .wifi_survey import WifiSurveyManager

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


class BlinkRequest(BaseModel):
    mode: str = "speed-cycle"


class ModeRequest(BaseModel):
    demo_mode: bool
    demo_scenario: str = "healthy_1g"
    iface: Optional[str] = None


class StressRequest(BaseModel):
    count: int = 20


class SavePortRequest(BaseModel):
    custom_label: Optional[str] = None
    notes: str = ""


class JobMetaRequest(BaseModel):
    job_name: str
    next_drop: Optional[int] = None
    clear_ports: bool = False


class HotspotRequest(BaseModel):
    enable: bool


class PcapRequest(BaseModel):
    duration_sec: float = 15.0


class BacklightRequest(BaseModel):
    pct: int


class PowerRequest(BaseModel):
    action: str  # "reboot" or "shutdown"


class AutoTestConfigRequest(BaseModel):
    profile: str = "standard"
    auto_log: bool = False


class TargetRequest(BaseModel):
    target: str


class IperfClientRequest(BaseModel):
    target: str
    duration_sec: int = 5


class IperfServerRequest(BaseModel):
    enable: bool


class IperfTargetsRequest(BaseModel):
    targets: List[str]


class WifiWalkRequest(BaseModel):
    bssid: str


class WifiConnectRequest(BaseModel):
    ssid: str = ""
    password: Optional[str] = None
    hidden: bool = False
    profile_name: Optional[str] = None


class WifiForgetRequest(BaseModel):
    uuid: str = ""
    name: str = ""


class VlanProbeRequest(BaseModel):
    vlans: Optional[List[int]] = None


class VlanPresetsRequest(BaseModel):
    vlans: List[int]


class SnmpQueryRequest(BaseModel):
    target_ip: Optional[str] = None
    community: str = "public"


class HostInspectRequest(BaseModel):
    ip: str


class HostWolRequest(BaseModel):
    ip: str
    mac: str


class AuditPrefixRequest(BaseModel):
    prefix: str


class AuditJobSwitchRequest(BaseModel):
    job_name: str
    prefix: Optional[str] = None


class AuditPortNotesRequest(BaseModel):
    notes: str = ""


class OrientationRequest(BaseModel):
    flipped: bool


class SyncConfigRequest(BaseModel):
    webhook_url: Optional[str] = None
    webhook_token: Optional[str] = None
    webhook_enabled: Optional[bool] = None
    netbox_url: Optional[str] = None
    netbox_token: Optional[str] = None
    netbox_enabled: Optional[bool] = None
    auto_sync_on_save: Optional[bool] = None


class SyncQueueClearRequest(BaseModel):
    only_sent: bool = False


class PrinterSelectRequest(BaseModel):
    mac: str
    name: str = "BT Thermal"
    channel: int = 1


class NicSelectRequest(BaseModel):
    iface: str


class TapToggleRequest(BaseModel):
    enable: bool
    nic_a: str = "eth0"
    nic_b: str = "eth1"


class SpeedTestRequest(BaseModel):
    iface_mode: str = "auto"


class StaticIpRequest(BaseModel):
    ip_cidr: str
    gateway: str = ""
    dns: str = ""


class TdrCalibrationRequest(BaseModel):
    preset: Optional[str] = None
    nvp_pct: Optional[float] = None


class Dot1xStartRequest(BaseModel):
    identity: str
    password: str
    method: str = "PEAP"


class OverlayFsRequest(BaseModel):
    enable: bool


class PentestModeRequest(BaseModel):
    enable: bool
    authorized_ack: bool = False


class TailcatStartRequest(BaseModel):
    mode: str = "web_ui"
    iface: Optional[str] = None


class ReconStartRequest(BaseModel):
    profile: str = "quick_banners"
    target: Optional[str] = None


class MacSpoofRequest(BaseModel):
    mac: Optional[str] = None
    random_local: bool = False
    label: str = ""


class WifiWatchRequest(BaseModel):
    ssid: str = ""


class TesterRuntime:
    def __init__(self) -> None:
        self.iface: str = settings.iface
        self.wifi_iface: str = settings.wifi_iface
        self.demo_mode: bool = settings.demo_mode
        self.demo_scenario: str = "healthy_1g"
        self.port_session_id: int = 1
        self._prev_carrier: bool = False
        self._link_up_started: float = time.monotonic()
        self._autotest_duration: float = 0.0
        self._last_l3_probe_ts: float = 0.0
        self._cached_l3: L3Connectivity = L3Connectivity()

        # Phase 2 + Phase 3 state
        self.stress_state: StressTestResult = StressTestResult()
        self.tdr_cable_type, self.tdr_nvp_pct = load_tdr_calibration()
        self.tdr_state: TdrReportState = TdrReportState(
            cable_type=self.tdr_cable_type,
            nvp_pct=self.tdr_nvp_pct,
        )
        self._tdr_grace_until: float = 0.0
        self._phy_err_iface: str = self.iface
        self._phy_err_totals = {"idle": 0, "rerr": 0, "fcs": 0, "loc_nok": 0, "rem_nok": 0}
        self._phy_err_settle_until: float = time.monotonic() + 3.5
        self._phy_crc_baseline: Optional[int] = None
        self.static_ip_mgr = StaticIpv4Manager(on_change=self.trigger_push)
        self.dot1x_mgr = Dot1xTestManager(on_change=self.trigger_push)
        self.screen_flipped: bool = read_dsi_flipped() if os.name != "nt" else False
        self._orientation_reboot_required: bool = False
        self.scan_state: SubnetScanState = SubnetScanState()
        self.dhcp_offers: List[DhcpOfferInfo] = []
        self._dhcp_probing: bool = False
        self._auto_scanned_session: int = 0
        self.audit_store = AuditStore()

        # Milestone 1 state
        self.autotest_profile: str = "standard"
        self.autotest_auto_log: bool = False
        self._auto_logged_session: int = 0

        self.clients: Set[WebSocket] = set()
        self._push_event = asyncio.Event()
        self.diag = DiagnosticsManager(on_change=self.trigger_push)
        self.wifi_mgr = WifiSurveyManager(iface=self.wifi_iface, on_change=self.trigger_push)
        self.wifi_client = WifiClientManager(iface=self.wifi_iface, on_change=self.trigger_push)
        self._last_wcli_poll_ts: float = 0.0
        self.vlan_prober = VlanTrunkProber(on_change=self.trigger_push)
        self.snmp_mgr = SnmpSwitchManager(on_change=self.trigger_push)
        self.sync_mgr = SyncManager(on_change=self.trigger_push)
        self.printer_mgr = BluetoothPrinterManager(on_change=self.trigger_push)
        self.nic_tap = NicTapManager(on_change=self.trigger_push)
        self.pentest_mgr = PentestModeManager(on_change=self.trigger_push)
        self.tailcat_mgr = TailcatManager(web_port=settings.port, on_change=self.trigger_push)
        self.recon_mgr = PentestReconManager(on_change=self.trigger_push)
        self.mac_mgr = MacSpoofManager(on_change=self.trigger_push)
        self.wifi_audit_mgr = WifiAuditManager(on_change=self.trigger_push)
        self._last_nic_poll_ts: float = 0.0
        self._cached_hw_nics: NetworkHardwareState = self.nic_tap.build_state(
            self.iface, demo_mode=self.demo_mode
        )

        self.sniffer = PassiveL2Sniffer(self.iface)
        self.blinker = PortLedBlinker(
            iface=self.iface,
            default_timeout_sec=settings.blink_timeout_sec,
            on_change=lambda: self._push_event.set(),
        )
        audit_init = self.audit_store.build_portal_state(
            port=settings.port,
            eth_ip="—",
            pcap_dict=self.sniffer.pcap_status(),
            wifi_iface=self.wifi_iface,
        )
        sys_init = read_system_health(
            self.screen_flipped,
            self._orientation_reboot_required,
            wifi_iface=self.wifi_iface,
            active_iface=self.iface,
            demo_mode=self.demo_mode,
        )
        self.latest_snapshot: TesterSnapshot = build_demo_snapshot(
            self.demo_scenario,
            self.blinker.state(),
            self.stress_state,
            audit_init,
            sys_init,
            None,
            self.port_session_id,
            self.autotest_profile,
            self.autotest_auto_log,
            self.diag.snapshot(),
            self.wifi_mgr.snapshot(demo_mode=self.demo_mode),
            self.vlan_prober.snapshot(),
            self.snmp_mgr.snapshot(),
            self.sync_mgr.snapshot(),
            self.printer_mgr.snapshot(),
            self._cached_hw_nics,
            self.wifi_client.snapshot(demo_mode=self.demo_mode),
            self.static_ip_mgr.snapshot(),
            self.dot1x_mgr.snapshot(),
        )
        self.latest_snapshot.pentest = self.build_pentest_state(
            self.latest_snapshot.link.mac_address,
            self.latest_snapshot.security.forensics.exposure,
            self.latest_snapshot.wifi,
        )
        self.latest_snapshot.tailcat = self.tailcat_mgr.snapshot(demo_mode=self.demo_mode)

    def build_pentest_state(
        self,
        link_mac: str = "—",
        exposure: Optional[PassiveExposureState] = None,
        wifi_state: Optional[WifiSurveyState] = None,
    ) -> PentestState:
        active_if = "br0" if self.nic_tap.tap.active else self.iface
        passive_hits = (
            (exposure.llmnr_count + exposure.nbns_count + exposure.wpad_count)
            if exposure is not None
            else 0
        )
        cleartext_alerts = len(exposure.cleartext_alerts) if exposure is not None else 0
        recon_st = self.recon_mgr.snapshot(demo_mode=self.demo_mode)
        mac_st = self.mac_mgr.snapshot(self.iface, link_mac or "—")
        wifi_audit_st = self.wifi_audit_mgr.evaluate(
            wifi_state if wifi_state is not None else self.wifi_mgr.snapshot(demo_mode=self.demo_mode)
        )
        eff_mac = mac_st.current_mac if mac_st.spoofed else (link_mac or "—")
        high_recon = sum(1 for f in recon_st.findings if f.severity in ("CRITICAL", "HIGH", "WARN"))
        recon_cnt = high_recon if high_recon > 0 else len(recon_st.findings)
        return self.pentest_mgr.snapshot(
            active_iface=active_if,
            active_mac=eff_mac,
            demo_mode=self.demo_mode,
            passive_hits=passive_hits,
            cleartext_alerts=cleartext_alerts,
            mac_spoofed=mac_st.spoofed,
            recon_findings=recon_cnt,
            recon=recon_st,
            mac_spoof=mac_st,
            wifi_audit=wifi_audit_st,
            primary_wifi_iface=self.wifi_iface,
        )

    def trigger_push(self) -> None:
        self._push_event.set()

    def reset_phy_error_counters(self) -> None:
        self._phy_err_iface = self.iface
        self._phy_err_totals = {"idle": 0, "rerr": 0, "fcs": 0, "loc_nok": 0, "rem_nok": 0}
        self._phy_crc_baseline = self.latest_snapshot.link.rx_crc_errors
        self._phy_err_settle_until = time.monotonic() + 0.5
        self._push_event.set()

    async def _get_wifi_client(self, force: bool = False) -> WifiClientState:
        if self.demo_mode:
            return self.wifi_client.snapshot(demo_mode=True)
        now_m = time.monotonic()
        if (force or (now_m - self._last_wcli_poll_ts) >= 10.0) and not self.wifi_client.state.busy:
            self._last_wcli_poll_ts = now_m
            return await self.wifi_client.refresh_status(demo_mode=False, rescan=False)
        return self.wifi_client.snapshot(demo_mode=False)

    async def _get_hw_nics(self, force: bool = False) -> NetworkHardwareState:
        now_m = time.monotonic()
        if force or self.demo_mode or (now_m - self._last_nic_poll_ts) >= 5.0:
            self._cached_hw_nics = await asyncio.to_thread(
                self.nic_tap.build_state, self.iface, self.demo_mode
            )
            self._last_nic_poll_ts = now_m
        return self._cached_hw_nics

    async def collect_snapshot(
        self, force_l3: bool = False, force_nics: bool = False, force_wcli: bool = False
    ) -> TesterSnapshot:
        pcap_info = self.sniffer.pcap_status()
        eth_ip_hint = self._cached_l3.ipv4_address if not self.demo_mode else "172.24.10.84"
        audit_state = await asyncio.to_thread(
            self.audit_store.build_portal_state,
            settings.port,
            eth_ip_hint,
            pcap_info,
            self.wifi_iface,
        )
        sys_state = await asyncio.to_thread(
            read_system_health,
            self.screen_flipped,
            self._orientation_reboot_required,
            self.wifi_iface,
            self.iface,
            self.demo_mode,
        )
        wifi_state = self.wifi_mgr.snapshot(demo_mode=self.demo_mode)
        vp_state = self.vlan_prober.snapshot()
        snmp_state = self.snmp_mgr.snapshot()
        sync_state = self.sync_mgr.snapshot()
        printer_state = self.printer_mgr.snapshot()
        hw_nics = await self._get_hw_nics(force=force_nics)
        wcli_state = await self._get_wifi_client(force=force_wcli)

        if self.demo_mode:
            snap = build_demo_snapshot(
                self.demo_scenario,
                self.blinker.state(),
                self.stress_state,
                audit_state,
                sys_state,
                self.tdr_state if self.tdr_state.running else None,
                self.port_session_id,
                self.autotest_profile,
                self.autotest_auto_log,
                self.diag.snapshot(bind_ip=eth_ip_hint),
                wifi_state,
                vp_state,
                snmp_state,
                sync_state,
                printer_state,
                hw_nics,
                wcli_state,
                self.static_ip_mgr.snapshot(),
                self.dot1x_mgr.snapshot(),
            )
            snap.tdr.cable_type = self.tdr_cable_type
            snap.tdr.nvp_pct = self.tdr_nvp_pct
            snap.diagnostics.iperf.server_bind_ip = snap.l3.ipv4_address
            snap.pentest = self.build_pentest_state(
                snap.link.mac_address,
                snap.security.forensics.exposure,
                snap.wifi,
            )
            snap.tailcat = self.tailcat_mgr.snapshot(demo_mode=True)
            self.latest_snapshot = snap
            return snap

        # While actively blinking eth0 OR pulsing TDR, freeze link/L3 state churn
        if self.blinker.state().active or self.tdr_state.running:
            self._phy_err_settle_until = time.monotonic() + 4.0
            frozen = self.latest_snapshot.model_copy(
                update={
                    "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                    "blink": self.blinker.state(),
                    "stress": self.stress_state,
                    "tdr": self.tdr_state,
                    "system": sys_state,
                    "audit": audit_state,
                    "diagnostics": self.diag.snapshot(bind_ip=self._cached_l3.ipv4_address),
                    "wifi": wifi_state,
                    "vlan_probe": vp_state,
                    "snmp": snmp_state,
                    "sync": sync_state,
                    "printer": printer_state,
                    "hw_nics": hw_nics,
                    "wifi_client": wcli_state,
                    "static_ip": self.static_ip_mgr.snapshot(),
                    "dot1x": self.dot1x_mgr.snapshot(),
                    "pentest": self.build_pentest_state(
                        self.latest_snapshot.link.mac_address,
                        self.latest_snapshot.security.forensics.exposure,
                        wifi_state,
                    ),
                    "tailcat": self.tailcat_mgr.snapshot(demo_mode=False),
                }
            )
            self.latest_snapshot = frozen
            return frozen

        link: LinkTelemetry = await asyncio.to_thread(read_link_telemetry, self.iface)
        now_m = time.monotonic()
        in_tdr_grace = now_m < self._tdr_grace_until

        if self.iface != self._phy_err_iface:
            self._phy_err_iface = self.iface
            self._phy_err_totals = {"idle": 0, "rerr": 0, "fcs": 0, "loc_nok": 0, "rem_nok": 0}
            self._phy_crc_baseline = link.rx_crc_errors
            self._phy_err_settle_until = now_m + 3.5

        # Detect fresh cable plug-in (ignoring brief carrier dip caused by manual TDR pulse)
        if not in_tdr_grace:
            if link.carrier_up and not self._prev_carrier:
                self.port_session_id += 1
                self._link_up_started = now_m
                self._autotest_duration = 0.0
                self.sniffer.reset_session()
                self.stress_state = StressTestResult()
                self.tdr_state = TdrReportState()
                self.scan_state = SubnetScanState()
                self.dhcp_offers = []
                self.diag.reset_for_link_change()
                self._phy_err_totals = {"idle": 0, "rerr": 0, "fcs": 0, "loc_nok": 0, "rem_nok": 0}
                self._phy_crc_baseline = link.rx_crc_errors
                self._phy_err_settle_until = now_m + 3.5
                force_l3 = True
            elif not link.carrier_up and self._prev_carrier:
                self._cached_l3 = L3Connectivity(dhcp_status="Link Down")
                self._autotest_duration = 0.0
                self.diag.reset_for_link_change()
                self._phy_err_totals = {"idle": 0, "rerr": 0, "fcs": 0, "loc_nok": 0, "rem_nok": 0}
                self._phy_crc_baseline = None

            self._prev_carrier = link.carrier_up

        # Accumulate read-to-clear PHY error registers once post-plugin settle window finishes
        in_phy_settle = in_tdr_grace or (now_m < self._phy_err_settle_until)
        if link.carrier_up:
            if in_phy_settle or self._phy_crc_baseline is None:
                # Flush startup contact-bounce / link-training transients without accumulating
                self._phy_crc_baseline = link.rx_crc_errors
            else:
                self._phy_err_totals["idle"] += link.phy_wiring.idle_errors
                self._phy_err_totals["rerr"] += link.phy_wiring.rx_symbol_errors
                self._phy_err_totals["fcs"] += link.phy_wiring.false_carrier_errors
                self._phy_err_totals["loc_nok"] += link.phy_wiring.local_rx_not_ok_count
                self._phy_err_totals["rem_nok"] += link.phy_wiring.remote_rx_not_ok_count
        link.phy_wiring.idle_errors = self._phy_err_totals["idle"]
        link.phy_wiring.rx_symbol_errors = self._phy_err_totals["rerr"]
        link.phy_wiring.false_carrier_errors = self._phy_err_totals["fcs"]
        link.phy_wiring.local_rx_not_ok_count = self._phy_err_totals["loc_nok"]
        link.phy_wiring.remote_rx_not_ok_count = self._phy_err_totals["rem_nok"]
        session_crc = (
            max(0, link.rx_crc_errors - (self._phy_crc_baseline or 0))
            if link.carrier_up
            else 0
        )
        wm_verdict, wm_summary = synthesize_wiremap_verdict(
            link, self.tdr_state, session_crc_errors=session_crc
        )
        link.phy_wiring.verdict = wm_verdict
        link.phy_wiring.summary = wm_summary

        if not link.carrier_up:
            sw_down = SwitchNeighbor()
            vlan_down = VlanAndNacTelemetry(nac_status="N/A (Link Down)")
            l3_down = L3Connectivity(dhcp_status="Link Down")
            sec_down = SecurityReportState(score=0, grade="—", summary="Link Down")
            autotest_down = evaluate_autotest(
                link,
                sw_down,
                vlan_down,
                l3_down,
                self.tdr_state,
                sec_down,
                profile=self.autotest_profile,
                auto_log=self.autotest_auto_log,
                duration_s=0.0,
            )
            snap = TesterSnapshot(
                timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S"),
                mode="live",
                demo_scenario=self.demo_scenario,
                autotest_verdict="NO_LINK",
                autotest_duration_s=0.0,
                port_session_id=self.port_session_id,
                link=link,
                poe=PoeTelemetry(),
                switch=sw_down,
                vlan=vlan_down,
                l3=l3_down,
                blink=self.blinker.state(),
                stress=self.stress_state,
                tdr=self.tdr_state,
                system=sys_state,
                scan=self.scan_state,
                security=sec_down,
                audit=audit_state,
                autotest=autotest_down,
                diagnostics=self.diag.snapshot(bind_ip="—"),
                wifi=wifi_state,
                vlan_probe=vp_state,
                snmp=snmp_state,
                sync=sync_state,
                printer=printer_state,
                hw_nics=hw_nics,
                wifi_client=wcli_state,
                static_ip=self.static_ip_mgr.snapshot(),
                dot1x=self.dot1x_mgr.snapshot(),
                pentest=self.build_pentest_state(link.mac_address, sec_down.forensics.exposure, wifi_state),
                tailcat=self.tailcat_mgr.snapshot(demo_mode=False),
            )
            self.latest_snapshot = snap
            return snap

        sniffer_data = self.sniffer.snapshot()
        switch_nb, poe_info, vlan_info = await asyncio.to_thread(
            query_switch_and_vlans, self.iface, sniffer_data
        )
        probed_live_vlans = [
            e.vlan_id for e in vp_state.results if e.status == "LIVE_DHCP"
        ]
        if probed_live_vlans:
            vlan_info.tagged_vlans = sorted(set(vlan_info.tagged_vlans) | set(probed_live_vlans))

        if (
            force_l3
            or (now_m - self._last_l3_probe_ts) >= 6.0
            or self._cached_l3.ipv4_address in ("—", "")
        ):
            self._cached_l3 = await asyncio.to_thread(
                probe_l3_connectivity, self.iface, link.carrier_up
            )
            self._last_l3_probe_ts = now_m

        if (
            self.static_ip_mgr.state.mode == "static"
            and self.static_ip_mgr.state.iface == self.iface
            and link.carrier_up
            and self._cached_l3.ipv4_address not in ("—", "")
        ):
            self._cached_l3.dhcp_status = f"Static ({self.static_ip_mgr.state.ip_cidr})"

        if (
            self._auto_scanned_session != self.port_session_id
            and self._cached_l3.ipv4_address not in ("—", "")
            and not self._cached_l3.ipv4_address.startswith("169.254.")
        ):
            self._auto_scanned_session = self.port_session_id
            asyncio.create_task(self.run_subnet_scan())
            asyncio.create_task(self.run_dhcp_security_probe())

        if self._autotest_duration == 0.0 and (
            switch_nb.detected or self._cached_l3.ipv4_address not in ("—", "")
        ):
            self._autotest_duration = round(now_m - self._link_up_started, 1)

        sec_state = evaluate_security_posture(
            self.dhcp_offers,
            sniffer_data,
            vlan_info,
            self._cached_l3,
            self.scan_state,
        )
        sec_state.probing = self._dhcp_probing

        autotest = evaluate_autotest(
            link,
            switch_nb,
            vlan_info,
            self._cached_l3,
            self.tdr_state,
            sec_state,
            profile=self.autotest_profile,
            auto_log=self.autotest_auto_log,
            duration_s=self._autotest_duration,
        )

        snap = TesterSnapshot(
            timestamp=datetime.now(timezone.utc).strftime("%H:%M:%S"),
            mode="live",
            demo_scenario=self.demo_scenario,
            autotest_verdict=autotest.verdict,
            autotest_duration_s=self._autotest_duration,
            port_session_id=self.port_session_id,
            link=link,
            poe=poe_info,
            switch=switch_nb,
            vlan=vlan_info,
            l3=self._cached_l3,
            blink=self.blinker.state(),
            stress=self.stress_state,
            tdr=self.tdr_state,
            system=sys_state,
            scan=self.scan_state,
            security=sec_state,
            audit=audit_state,
            autotest=autotest,
            diagnostics=self.diag.snapshot(bind_ip=self._cached_l3.ipv4_address),
            wifi=wifi_state,
            vlan_probe=vp_state,
            snmp=snmp_state,
            sync=sync_state,
            printer=printer_state,
            hw_nics=hw_nics,
            wifi_client=wcli_state,
            static_ip=self.static_ip_mgr.snapshot(),
            dot1x=self.dot1x_mgr.snapshot(),
            pentest=self.build_pentest_state(link.mac_address, sec_state.forensics.exposure, wifi_state),
            tailcat=self.tailcat_mgr.snapshot(demo_mode=False),
        )

        if (
            self.autotest_auto_log
            and not self.demo_mode
            and self._auto_logged_session != self.port_session_id
            and link.carrier_up
            and autotest.verdict in ("PASS", "WARN")
            and (switch_nb.detected or self._cached_l3.ipv4_address not in ("—", ""))
        ):
            self._auto_logged_session = self.port_session_id
            saved_auto = await asyncio.to_thread(
                self.audit_store.save_snapshot, snap, None, "Auto-logged by AutoTest"
            )
            if self.sync_mgr.auto_sync_on_save:
                queued = await asyncio.to_thread(self.sync_mgr.enqueue_port, saved_auto)
                if queued > 0:
                    asyncio.create_task(self.sync_mgr.flush_queue(self.demo_mode))
            audit_refreshed = await asyncio.to_thread(
                self.audit_store.build_portal_state,
                settings.port,
                self._cached_l3.ipv4_address,
                pcap_info,
                self.wifi_iface,
            )
            snap.audit = audit_refreshed
            snap.sync = self.sync_mgr.snapshot()

        self.latest_snapshot = snap
        return snap

    async def run_tdr_pulse(self) -> None:
        if self.tdr_state.running:
            return
        if self.blinker.state().active:
            await self.blinker.stop(demo_mode=self.demo_mode)

        prev_link_up = self.latest_snapshot.link.carrier_up
        prev_speed = self.latest_snapshot.link.speed_mbps

        self.tdr_state = self.tdr_state.model_copy(
            update={"running": True, "summary": f"Firing Cable TDR pulse on {self.iface}..."}
        )
        self._tdr_grace_until = time.monotonic() + 8.5
        self.trigger_push()

        try:
            if self.demo_mode:
                await asyncio.sleep(0.55)
                self.tdr_state = build_demo_tdr(self.demo_scenario).model_copy(
                    update={"cable_type": self.tdr_cable_type, "nvp_pct": self.tdr_nvp_pct}
                )
            else:
                res = await asyncio.to_thread(
                    run_hardware_tdr_sync,
                    self.iface,
                    None,
                    prev_link_up,
                    prev_speed,
                    self.tdr_nvp_pct,
                    self.tdr_cable_type,
                )
                self.tdr_state = res
                self._tdr_grace_until = time.monotonic() + 5.0
        finally:
            self.tdr_state.running = False
            self._phy_err_totals = {"idle": 0, "rerr": 0, "fcs": 0, "loc_nok": 0, "rem_nok": 0}
            self._phy_err_settle_until = time.monotonic() + 5.0
            self._phy_crc_baseline = None
            self.trigger_push()

    async def run_subnet_scan(self) -> None:
        if self.scan_state.scanning or self.demo_mode:
            return
        cidr = self._cached_l3.subnet_cidr
        if not cidr or "/" not in cidr:
            return
        self.scan_state = self.scan_state.model_copy(update={"scanning": True, "subnet": cidr})
        self.trigger_push()
        try:
            res = await sweep_subnet(
                iface=self.iface,
                subnet_cidr=cidr,
                local_ip=self._cached_l3.ipv4_address,
                local_mac=self.latest_snapshot.link.mac_address,
                gateway_ip=self._cached_l3.gateway_ip,
                switch_ip=self.latest_snapshot.switch.mgmt_ip,
            )
            self.scan_state = res
        finally:
            self.scan_state.scanning = False
            self.trigger_push()

    async def run_dhcp_security_probe(self) -> None:
        if self._dhcp_probing or self.demo_mode:
            return
        self._dhcp_probing = True
        self.trigger_push()
        try:
            offers = await asyncio.to_thread(
                probe_dhcp_servers_sync,
                self.iface,
                self.latest_snapshot.link.mac_address,
                self._cached_l3.gateway_ip,
                2.4,
            )
            if offers:
                self.dhcp_offers = offers
        finally:
            self._dhcp_probing = False
            self.trigger_push()

    async def broadcast(self, snap: TesterSnapshot) -> None:
        if not self.clients:
            return
        payload = snap.model_dump_json()
        dead: Set[WebSocket] = set()
        for ws in list(self.clients):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        self.clients -= dead


runtime = TesterRuntime()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    if not runtime.demo_mode:
        runtime.sniffer.start()

    stop_flag = asyncio.Event()

    async def poll_worker():
        while not stop_flag.is_set():
            snap = await runtime.collect_snapshot()
            await runtime.broadcast(snap)
            try:
                await asyncio.wait_for(
                    runtime._push_event.wait(), timeout=settings.poll_interval_sec
                )
                runtime._push_event.clear()
            except asyncio.TimeoutError:
                pass

    async def sync_retry_worker():
        while not stop_flag.is_set():
            try:
                await asyncio.sleep(30.0)
                if not runtime.demo_mode and runtime.sync_mgr.pending_count() > 0:
                    await runtime.sync_mgr.flush_queue(demo_mode=False)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    worker_task = asyncio.create_task(poll_worker())
    sync_task = asyncio.create_task(sync_retry_worker())
    try:
        yield
    finally:
        stop_flag.set()
        worker_task.cancel()
        sync_task.cancel()
        await runtime.blinker.stop(demo_mode=runtime.demo_mode)
        await runtime.dot1x_mgr.stop_test()
        await runtime.recon_mgr.stop()
        await runtime.mac_mgr.restore_mac(demo_mode=runtime.demo_mode, notify=False)
        await runtime.tailcat_mgr.stop(notify=False)
        runtime.pentest_mgr.disable()
        runtime.sniffer.stop()
        runtime.diag.shutdown()
        runtime.wifi_mgr.shutdown()
        runtime.nic_tap.shutdown()


app = FastAPI(
    title="JackTrace Network Tester (v2.0 M4)",
    version="2.0.4",
    lifespan=lifespan,
)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/snapshot", response_model=TesterSnapshot)
async def get_snapshot():
    return await runtime.collect_snapshot()


@app.post("/api/rescan", response_model=TesterSnapshot)
async def rescan_port():
    if not runtime.demo_mode:
        await asyncio.to_thread(_exec_net_cmd, ["lldpcli", "update"])
    snap = await runtime.collect_snapshot(force_l3=True)
    await runtime.broadcast(snap)
    return snap


def _client_on_test_subnet(client_host: Optional[str], cidr: str) -> bool:
    if not client_host or client_host in ("127.0.0.1", "::1", "localhost"):
        return False
    if not cidr or "/" not in cidr:
        return False
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        ip_obj = ipaddress.ip_address(client_host)
        return ip_obj in net
    except ValueError:
        return False


@app.post("/api/blink/toggle", response_model=TesterSnapshot)
async def toggle_blink(req: BlinkRequest, request: Request):
    client_ip = request.client.host if request.client else None
    same_sub = _client_on_test_subnet(client_ip, runtime.latest_snapshot.l3.subnet_cidr)
    await runtime.blinker.toggle(
        mode=req.mode,
        demo_mode=runtime.demo_mode,
        same_subnet_client=same_sub,
    )
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/stress", response_model=TesterSnapshot)
async def trigger_stress(req: StressRequest):
    if runtime.stress_state.running:
        return runtime.latest_snapshot

    snap_now = runtime.latest_snapshot
    target = (
        snap_now.l3.gateway_ip
        if snap_now.l3.gateway_ip != "—"
        else snap_now.switch.mgmt_ip
    )
    count = max(5, min(req.count, 50))

    if runtime.demo_mode:
        runtime.stress_state = StressTestResult(
            running=True, target_ip=target or "172.24.10.1", packets_sent=count, verdict="Running..."
        )
        runtime.trigger_push()

        async def _sim_stress():
            await asyncio.sleep(1.0)
            if runtime.demo_scenario == "unpatched_dead":
                runtime.stress_state = StressTestResult(
                    running=False,
                    completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                    target_ip="—",
                    packets_sent=count,
                    packets_received=0,
                    loss_percent=100.0,
                    verdict="FAIL (Link Down)",
                )
            else:
                runtime.stress_state = StressTestResult(
                    running=False,
                    completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                    target_ip=target or "172.24.10.1",
                    packets_sent=count,
                    packets_received=count,
                    loss_percent=0.0,
                    min_ms=0.62,
                    avg_ms=0.84,
                    max_ms=1.41,
                    crc_delta=0,
                    verdict="PASS (0% Loss, 0 CRC Errors)",
                )
            runtime.trigger_push()

        asyncio.create_task(_sim_stress())
        return await runtime.collect_snapshot()

    if not target or target == "—":
        runtime.stress_state = StressTestResult(
            running=False,
            completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            target_ip="—",
            verdict="No Gateway or Switch IP to ping",
        )
        return await runtime.collect_snapshot()

    runtime.stress_state = StressTestResult(
        running=True, target_ip=target, packets_sent=count, verdict="Running burst..."
    )
    runtime.trigger_push()

    async def _real_stress():
        res = await asyncio.to_thread(run_line_stress_test, runtime.iface, target, count)
        runtime.stress_state = res
        runtime.trigger_push()

    asyncio.create_task(_real_stress())
    return await runtime.collect_snapshot()


# ==========================================
# PHASE 3 ROUTES: HARDWARE TDR & PI SYSTEM
# ==========================================


@app.post("/api/tdr/run", response_model=TesterSnapshot)
async def api_run_tdr():
    await runtime.run_tdr_pulse()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/system/backlight", response_model=TesterSnapshot)
async def api_set_backlight(req: BacklightRequest):
    await asyncio.to_thread(set_dsi_backlight, req.pct)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/system/power")
async def api_system_power(req: PowerRequest):
    if req.action not in ("reboot", "shutdown"):
        raise HTTPException(status_code=400, detail="Invalid power action")
    ok = await asyncio.to_thread(trigger_power_action, req.action)
    return {"ok": ok, "action": req.action}


# ==========================================
# PHASE 2 ROUTES: SCAN, SECURITY, AUDIT, PDF
# ==========================================


@app.post("/api/scan/start", response_model=TesterSnapshot)
async def api_start_scan():
    if not runtime.demo_mode:
        asyncio.create_task(runtime.run_subnet_scan())
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/security/probe", response_model=TesterSnapshot)
async def api_probe_security():
    if not runtime.demo_mode:
        asyncio.create_task(runtime.run_dhcp_security_probe())
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/audit/save", response_model=SavedWallPort)
async def api_save_wall_port(req: SavePortRequest):
    snap = await runtime.collect_snapshot()
    saved = await asyncio.to_thread(
        runtime.audit_store.save_snapshot, snap, req.custom_label, req.notes
    )
    if runtime.sync_mgr.auto_sync_on_save:
        queued = await asyncio.to_thread(runtime.sync_mgr.enqueue_port, saved)
        if queued > 0:
            asyncio.create_task(runtime.sync_mgr.flush_queue(runtime.demo_mode))
    updated = await runtime.collect_snapshot()
    await runtime.broadcast(updated)
    return saved


@app.delete("/api/audit/port/{row_id}", response_model=TesterSnapshot)
async def api_delete_wall_port(row_id: int):
    await asyncio.to_thread(runtime.audit_store.delete_port, row_id)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/audit/job", response_model=TesterSnapshot)
async def api_update_job(req: JobMetaRequest):
    await asyncio.to_thread(
        runtime.audit_store.set_job_meta, req.job_name, req.next_drop, req.clear_ports
    )
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.get("/api/audit/report.pdf")
async def api_download_pdf():
    snap = await runtime.collect_snapshot()
    pdf_bytes = await asyncio.to_thread(
        runtime.audit_store.generate_pdf_bytes, snap.security, snap.scan
    )
    safe_job = "".join(c if c.isalnum() or c in "-_" else "_" for c in snap.audit.job_name).strip("_") or "audit"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="JackTrace_{safe_job}.pdf"'},
    )


@app.post("/api/audit/pcap/start", response_model=TesterSnapshot)
async def api_start_pcap(req: PcapRequest):
    continuous = req.duration_sec <= 0
    dur = 0.0 if continuous else max(3.0, min(req.duration_sec, 60.0))
    ts = datetime.now(timezone.utc).strftime("%H%M%S")
    out_file = DATA_DIR / f"jacktrace_{ts}.pcap"

    if runtime.demo_mode:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        demo_eth = b"\xff\xff\xff\xff\xff\xff\xdc\xa6\x32\x8f\x14\x2b\x08\x06" + b"\x00" * 28
        now_t = int(time.time())
        if continuous:
            runtime.sniffer.start_pcap_capture(str(out_file), duration_sec=0.0)
            with runtime.sniffer._lock:
                if runtime.sniffer._pcap_fh is not None:
                    runtime.sniffer._pcap_fh.write(
                        struct.pack("<IIII", now_t, 0, len(demo_eth), len(demo_eth)) + demo_eth
                    )
                    runtime.sniffer._pcap_fh.flush()
                    runtime.sniffer._pcap_packets = 1
                    runtime.sniffer._pcap_bytes = 24 + 16 + len(demo_eth)
        else:
            runtime.sniffer.stop_pcap_capture()
            with open(out_file, "wb") as fh:
                fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                fh.write(struct.pack("<IIII", now_t, 0, len(demo_eth), len(demo_eth)) + demo_eth)
            runtime.sniffer._pcap_path = str(out_file)
            runtime.sniffer._pcap_packets = 1
            runtime.sniffer._pcap_bytes = 24 + 16 + len(demo_eth)
            runtime.sniffer._pcap_completed_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    else:
        runtime.sniffer.start_pcap_capture(str(out_file), duration_sec=dur)

    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/audit/pcap/stop", response_model=TesterSnapshot)
async def api_stop_pcap():
    runtime.sniffer.stop_pcap_capture()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/sniffer/clear-exposure", response_model=TesterSnapshot)
async def api_clear_exposure():
    runtime.sniffer.clear_exposure()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.get("/api/audit/latest.pcap")
async def api_download_pcap():
    st = runtime.sniffer.pcap_status()
    path = st.get("path")
    if not path or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="No PCAP capture recorded yet.")
    return FileResponse(
        path,
        media_type="application/vnd.tcpdump.pcap",
        filename=os.path.basename(path),
    )


@app.post("/api/audit/hotspot", response_model=TesterSnapshot)
async def api_toggle_hotspot(req: HotspotRequest):
    await asyncio.to_thread(toggle_wlan_hotspot, req.enable, runtime.wifi_iface)
    snap = await runtime.collect_snapshot(force_wcli=True)
    await runtime.broadcast(snap)
    return snap


# ==========================================
# MILESTONE 1 ROUTES: AUTOTEST & DIAGNOSTICS
# ==========================================


@app.post("/api/autotest/config", response_model=TesterSnapshot)
async def api_autotest_config(req: AutoTestConfigRequest):
    runtime.autotest_profile = "lan_only" if req.profile == "lan_only" else "standard"
    runtime.autotest_auto_log = bool(req.auto_log)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/autotest/run", response_model=TesterSnapshot)
async def api_autotest_run():
    if not runtime.demo_mode:
        await asyncio.to_thread(_exec_net_cmd, ["lldpcli", "update"])
        if runtime._cached_l3.ipv4_address not in ("—", "") and not runtime._cached_l3.ipv4_address.startswith("169.254."):
            asyncio.create_task(runtime.run_dhcp_security_probe())
    snap = await runtime.collect_snapshot(force_l3=True)
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/ping/start", response_model=TesterSnapshot)
async def api_diag_ping_start(req: TargetRequest):
    try:
        validate_host_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await runtime.diag.start_ping(req.target, runtime.iface, runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/ping/stop", response_model=TesterSnapshot)
async def api_diag_ping_stop():
    runtime.diag.stop_ping()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/traceroute", response_model=TesterSnapshot)
async def api_diag_traceroute(req: TargetRequest):
    try:
        validate_host_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await runtime.diag.run_traceroute(req.target, runtime.iface, runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/speedtest", response_model=TesterSnapshot)
async def api_diag_speedtest(req: Optional[SpeedTestRequest] = Body(default=None)):
    iface_mode = req.iface_mode if req else "auto"
    await runtime.diag.run_speedtest(
        runtime.iface,
        runtime.demo_mode,
        iface_mode=iface_mode,
        wifi_iface=runtime.wifi_iface,
    )
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/iperf/client", response_model=TesterSnapshot)
async def api_diag_iperf_client(req: IperfClientRequest):
    try:
        validate_host_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await runtime.diag.run_iperf_client(req.target, req.duration_sec, runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/iperf/server", response_model=TesterSnapshot)
async def api_diag_iperf_server(req: IperfServerRequest):
    bind_ip = runtime.latest_snapshot.l3.ipv4_address
    await asyncio.to_thread(runtime.diag.toggle_iperf_server, req.enable, bind_ip, runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/iperf/targets", response_model=TesterSnapshot)
async def api_diag_iperf_targets(req: IperfTargetsRequest):
    try:
        await asyncio.to_thread(runtime.diag.set_iperf_targets, req.targets)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/diag/mtu", response_model=TesterSnapshot)
async def api_diag_mtu(req: TargetRequest):
    try:
        validate_host_target(req.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await runtime.diag.run_mtu_test(req.target, runtime.iface, runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


# ==========================================
# MILESTONE 2 ROUTES: WI-FI SURVEY & WALK
# ==========================================


@app.post("/api/wifi/scan", response_model=TesterSnapshot)
async def api_wifi_scan():
    await runtime.wifi_mgr.scan(demo_mode=runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/wifi/walk/start", response_model=TesterSnapshot)
async def api_wifi_walk_start(req: WifiWalkRequest):
    try:
        await runtime.wifi_mgr.start_walk(req.bssid, demo_mode=runtime.demo_mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/wifi/walk/stop", response_model=TesterSnapshot)
async def api_wifi_walk_stop():
    runtime.wifi_mgr.stop_walk()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.get("/api/wifi/client/status", response_model=WifiClientState)
async def api_wifi_client_status():
    return await runtime._get_wifi_client(force=True)


@app.post("/api/wifi/client/scan", response_model=TesterSnapshot)
async def api_wifi_client_scan():
    await runtime.wifi_client.refresh_status(demo_mode=runtime.demo_mode, rescan=True)
    runtime._last_wcli_poll_ts = time.monotonic()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/wifi/client/connect", response_model=TesterSnapshot)
async def api_wifi_client_connect(req: WifiConnectRequest):
    runtime.wifi_mgr.stop_walk(notify=False)
    try:
        await runtime.wifi_client.connect(
            ssid=req.ssid,
            password=req.password,
            hidden=req.hidden,
            profile_name=req.profile_name,
            demo_mode=runtime.demo_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    runtime._last_wcli_poll_ts = time.monotonic()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/wifi/client/disconnect", response_model=TesterSnapshot)
async def api_wifi_client_disconnect():
    await runtime.wifi_client.disconnect(demo_mode=runtime.demo_mode)
    runtime._last_wcli_poll_ts = time.monotonic()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/wifi/client/forget", response_model=TesterSnapshot)
async def api_wifi_client_forget(req: WifiForgetRequest):
    try:
        await runtime.wifi_client.forget_profile(
            uuid=req.uuid, name=req.name, demo_mode=runtime.demo_mode
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    runtime._last_wcli_poll_ts = time.monotonic()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


# ==========================================
# MILESTONE 3 ROUTES: VLAN, SNMP, HOST, MULTI-JOB, ORIENTATION
# ==========================================


@app.post("/api/vlan/presets", response_model=TesterSnapshot)
async def api_vlan_presets(req: VlanPresetsRequest):
    try:
        await asyncio.to_thread(runtime.vlan_prober.set_presets, req.vlans)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/vlan/probe", response_model=TesterSnapshot)
async def api_vlan_probe(req: VlanProbeRequest):
    cur = runtime.latest_snapshot
    try:
        await runtime.vlan_prober.run_probe(
            iface=runtime.iface,
            local_mac=cur.link.mac_address,
            observed_vlans=cur.vlan.tagged_vlans,
            demo_mode=runtime.demo_mode,
            override_presets=req.vlans,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/snmp/query", response_model=TesterSnapshot)
async def api_snmp_query(req: SnmpQueryRequest):
    cur = runtime.latest_snapshot
    target = (req.target_ip or cur.switch.mgmt_ip or "").strip()
    await runtime.snmp_mgr.query(
        target_ip=target,
        community=req.community,
        port_id=cur.switch.port_id,
        port_number=cur.switch.panel.port_number,
        demo_mode=runtime.demo_mode,
    )
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/host/inspect", response_model=HostInspectResult)
async def api_host_inspect(req: HostInspectRequest):
    try:
        clean_ip = validate_host_target(req.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    existing = next((h for h in runtime.latest_snapshot.scan.hosts if h.ip == clean_ip), None)
    return await inspect_host_deep(clean_ip, existing, runtime.demo_mode)


@app.post("/api/host/wol")
async def api_host_wol(req: HostWolRequest):
    try:
        if runtime.demo_mode:
            from .host_inspect import build_wol_magic_packet
            build_wol_magic_packet(req.mac)
            ok = True
        else:
            ok = await asyncio.to_thread(send_wol_packet, req.mac)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "ok": ok,
        "ip": req.ip,
        "mac": req.mac,
        "sent_at": datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
    }


@app.post("/api/audit/prefix", response_model=TesterSnapshot)
async def api_audit_prefix(req: AuditPrefixRequest):
    await asyncio.to_thread(runtime.audit_store.set_prefix, req.prefix)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/audit/job/switch", response_model=TesterSnapshot)
async def api_audit_job_switch(req: AuditJobSwitchRequest):
    await asyncio.to_thread(runtime.audit_store.switch_or_create_job, req.job_name, req.prefix)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.delete("/api/audit/job/{job_name}", response_model=TesterSnapshot)
async def api_audit_job_delete(job_name: str):
    await asyncio.to_thread(runtime.audit_store.delete_job, job_name)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/audit/port/{row_id}/notes", response_model=TesterSnapshot)
async def api_audit_port_notes(row_id: int, req: AuditPortNotesRequest):
    await asyncio.to_thread(runtime.audit_store.update_port_notes, row_id, req.notes)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.get("/api/audit/report.csv")
async def api_download_csv():
    snap = await runtime.collect_snapshot()
    csv_text = await asyncio.to_thread(runtime.audit_store.generate_csv_text)
    safe_job = "".join(c if c.isalnum() or c in "-_" else "_" for c in snap.audit.job_name).strip("_") or "audit"
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="JackTrace_{safe_job}.csv"'},
    )


@app.get("/api/audit/report.json")
async def api_download_json():
    snap = await runtime.collect_snapshot()
    payload = await asyncio.to_thread(
        runtime.audit_store.generate_json_dict, snap.security, snap.scan
    )
    safe_job = "".join(c if c.isalnum() or c in "-_" else "_" for c in snap.audit.job_name).strip("_") or "audit"
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="JackTrace_{safe_job}.json"'},
    )


@app.post("/api/system/orientation", response_model=TesterSnapshot)
async def api_system_orientation(req: OrientationRequest):
    if os.name != "nt":
        ok, msg = await asyncio.to_thread(set_dsi_flipped, req.flipped)
        if not ok:
            raise HTTPException(status_code=500, detail=msg)
    runtime.screen_flipped = bool(req.flipped)
    runtime._orientation_reboot_required = True
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


# ==========================================
# MILESTONE 4 ROUTES: SYNC, BT PRINTER & MULTI-NIC TAP
# ==========================================


@app.post("/api/sync/config", response_model=TesterSnapshot)
async def api_sync_config(req: SyncConfigRequest):
    try:
        await asyncio.to_thread(
            runtime.sync_mgr.update_config,
            req.webhook_url,
            req.webhook_token,
            req.webhook_enabled,
            req.netbox_url,
            req.netbox_token,
            req.netbox_enabled,
            req.auto_sync_on_save,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/sync/test-netbox", response_model=TesterSnapshot)
async def api_sync_test_netbox():
    await asyncio.to_thread(runtime.sync_mgr.test_netbox_sync, runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/sync/push-job", response_model=TesterSnapshot)
async def api_sync_push_job():
    ports = list(reversed(await asyncio.to_thread(runtime.audit_store.list_all_ports)))
    added = await asyncio.to_thread(runtime.sync_mgr.enqueue_ports, ports)
    if added > 0:
        await runtime.sync_mgr.flush_queue(runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/sync/flush", response_model=TesterSnapshot)
async def api_sync_flush():
    await runtime.sync_mgr.flush_queue(runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/sync/queue/clear", response_model=TesterSnapshot)
async def api_sync_queue_clear(req: SyncQueueClearRequest):
    await asyncio.to_thread(runtime.sync_mgr.clear_queue, req.only_sent)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/printer/scan", response_model=TesterSnapshot)
async def api_printer_scan():
    await runtime.printer_mgr.scan(demo_mode=runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/printer/select", response_model=TesterSnapshot)
async def api_printer_select(req: PrinterSelectRequest):
    try:
        await runtime.printer_mgr.select_printer(
            req.mac, req.name, req.channel, demo_mode=runtime.demo_mode
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/printer/print-live", response_model=TesterSnapshot)
async def api_printer_print_live():
    snap_now = await runtime.collect_snapshot()
    raw, preview = build_live_receipt(snap_now)
    await runtime.printer_mgr.print_payload(raw, preview, demo_mode=runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/printer/print-port/{row_id}", response_model=TesterSnapshot)
async def api_printer_print_port(row_id: int):
    try:
        port_rec = await asyncio.to_thread(runtime.audit_store.get_port_by_id, row_id)
    except (TypeError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=404, detail="Saved wall port not found") from exc
    raw, preview = build_wall_drop_label(port_rec)
    await runtime.printer_mgr.print_payload(raw, preview, demo_mode=runtime.demo_mode)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/phy/reset-counters")
async def api_phy_reset_counters():
    runtime.reset_phy_error_counters()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return {"ok": True}


@app.post("/api/net/ipv4/static", response_model=TesterSnapshot)
async def api_net_ipv4_static(req: StaticIpRequest):
    try:
        validate_wired_iface(runtime.iface)
        await asyncio.to_thread(
            runtime.static_ip_mgr.apply_static,
            runtime.iface,
            req.ip_cidr,
            req.gateway,
            req.dns,
            runtime.demo_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot(force_l3=True)
    await runtime.broadcast(snap)
    return snap


@app.post("/api/net/ipv4/dhcp", response_model=TesterSnapshot)
async def api_net_ipv4_dhcp():
    try:
        validate_wired_iface(runtime.iface)
        await asyncio.to_thread(runtime.static_ip_mgr.revert_dhcp, runtime.iface, runtime.demo_mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot(force_l3=True)
    await runtime.broadcast(snap)
    return snap


@app.post("/api/tdr/calibration", response_model=TesterSnapshot)
async def api_tdr_calibration(req: TdrCalibrationRequest):
    preset_key = (req.preset or "").strip().lower()
    if preset_key in TDR_CABLE_PRESETS:
        label, nvp = TDR_CABLE_PRESETS[preset_key]
    elif req.nvp_pct is not None:
        nvp = float(req.nvp_pct)
        label = f"Custom ({nvp:g}%)"
    else:
        raise HTTPException(status_code=400, detail="Provide cable preset or nvp_pct (55–85)")
    try:
        saved_lbl, saved_nvp = await asyncio.to_thread(save_tdr_calibration, label, nvp)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    runtime.tdr_cable_type = saved_lbl
    runtime.tdr_nvp_pct = saved_nvp
    runtime.tdr_state = runtime.tdr_state.model_copy(
        update={"cable_type": saved_lbl, "nvp_pct": saved_nvp}
    )
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/dot1x/start", response_model=TesterSnapshot)
async def api_dot1x_start(req: Dot1xStartRequest):
    try:
        await runtime.dot1x_mgr.start_test(
            runtime.iface,
            req.identity,
            req.password,
            method=req.method,
            demo_mode=runtime.demo_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/dot1x/stop", response_model=TesterSnapshot)
async def api_dot1x_stop():
    await runtime.dot1x_mgr.stop_test()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/system/overlayfs", response_model=TesterSnapshot)
async def api_system_overlayfs(req: OverlayFsRequest):
    if runtime.demo_mode or os.name == "nt":
        runtime._orientation_reboot_required = True
    else:
        ok, msg = await asyncio.to_thread(set_overlayfs_enabled, req.enable)
        if not ok:
            raise HTTPException(status_code=500, detail=msg)
        runtime._orientation_reboot_required = True
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.get("/api/nics/list", response_model=NetworkHardwareState)
async def api_nics_list():
    return await runtime._get_hw_nics(force=True)


@app.post("/api/nics/select", response_model=TesterSnapshot)
async def api_nics_select(req: NicSelectRequest):
    if runtime.nic_tap.tap.active:
        raise HTTPException(status_code=409, detail="Stop Dual-NIC Inline Tap before switching test NIC")
    try:
        clean_if = validate_eth_iface(req.iface)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if runtime.blinker.state().active:
        await runtime.blinker.stop(demo_mode=runtime.demo_mode)

    if clean_if != runtime.iface:
        if runtime.tailcat_mgr.state.running and runtime.tailcat_mgr.state.mode == "pcap_stream":
            await runtime.tailcat_mgr.stop(notify=False)
        if runtime.mac_mgr.state.spoofed:
            await runtime.mac_mgr.restore_mac(demo_mode=runtime.demo_mode, notify=False)
        await runtime.dot1x_mgr.stop_test()
        runtime.sniffer.stop()
        runtime.iface = clean_if
        runtime.blinker.iface = clean_if
        runtime.sniffer = PassiveL2Sniffer(clean_if)
        runtime.port_session_id += 1
        runtime._cached_l3 = L3Connectivity()
        runtime._last_l3_probe_ts = 0.0
        if not runtime.demo_mode and os.name != "nt":
            runtime.sniffer.start()

    snap = await runtime.collect_snapshot(force_l3=True, force_nics=True)
    await runtime.broadcast(snap)
    return snap


@app.post("/api/tap/toggle", response_model=TesterSnapshot)
async def api_tap_toggle(req: TapToggleRequest):
    if runtime.tailcat_mgr.state.running and runtime.tailcat_mgr.state.mode == "pcap_stream":
        await runtime.tailcat_mgr.stop(notify=False)
    if req.enable:
        if runtime.mac_mgr.state.spoofed:
            await runtime.mac_mgr.restore_mac(demo_mode=runtime.demo_mode, notify=False)
        if runtime.blinker.state().active:
            await runtime.blinker.stop(demo_mode=runtime.demo_mode)
        await runtime.dot1x_mgr.stop_test()
        runtime.sniffer.stop()
        try:
            ok, _msg = await runtime.nic_tap.enable_tap(req.nic_a, req.nic_b, demo_mode=runtime.demo_mode)
        except ValueError as exc:
            if not runtime.demo_mode and os.name != "nt":
                runtime.sniffer = PassiveL2Sniffer(runtime.iface)
                runtime.sniffer.start()
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if ok:
            if not runtime.demo_mode and os.name != "nt":
                runtime.sniffer = PassiveL2Sniffer("br0")
                runtime.sniffer.start()
        elif not runtime.demo_mode and os.name != "nt":
            runtime.sniffer = PassiveL2Sniffer(runtime.iface)
            runtime.sniffer.start()
    else:
        runtime.sniffer.stop()
        await runtime.nic_tap.disable_tap(demo_mode=runtime.demo_mode)
        runtime.sniffer = PassiveL2Sniffer(runtime.iface)
        if not runtime.demo_mode and os.name != "nt":
            runtime.sniffer.start()

    snap = await runtime.collect_snapshot(force_nics=True)
    await runtime.broadcast(snap)
    return snap


@app.post("/api/mode", response_model=TesterSnapshot)
async def set_mode(req: ModeRequest):
    if runtime.blinker.state().active:
        await runtime.blinker.stop(demo_mode=runtime.demo_mode)

    if runtime.tailcat_mgr.state.running and runtime.tailcat_mgr.state.mode == "pcap_stream":
        await runtime.tailcat_mgr.stop(notify=False)

    if runtime.mac_mgr.state.spoofed:
        await runtime.mac_mgr.restore_mac(demo_mode=runtime.demo_mode, notify=False)

    if runtime.nic_tap.tap.active:
        runtime.sniffer.stop()
        await runtime.nic_tap.disable_tap(demo_mode=runtime.demo_mode)
        runtime.sniffer = PassiveL2Sniffer(runtime.iface)

    if req.iface and req.iface != runtime.iface:
        try:
            validate_eth_iface(req.iface)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        runtime.sniffer.stop()
        runtime.iface = req.iface
        runtime.blinker.iface = req.iface
        runtime.sniffer = PassiveL2Sniffer(req.iface)

    runtime.demo_mode = req.demo_mode
    runtime.demo_scenario = req.demo_scenario
    runtime.port_session_id += 1
    runtime.stress_state = StressTestResult()
    runtime.tdr_state = TdrReportState(
        cable_type=runtime.tdr_cable_type,
        nvp_pct=runtime.tdr_nvp_pct,
    )
    await runtime.dot1x_mgr.stop_test()
    runtime.diag.reset_for_link_change()
    runtime.wifi_mgr.stop_walk(notify=False)
    runtime.vlan_prober.state.results.clear()
    runtime.snmp_mgr.state.error = ""

    if not runtime.demo_mode and os.name != "nt":
        runtime.sniffer.start()

    snap = await runtime.collect_snapshot(force_l3=True, force_nics=True)
    await runtime.broadcast(snap)
    return snap


def _require_pentest_mode() -> None:
    if not runtime.pentest_mgr.enabled:
        raise HTTPException(
            status_code=403,
            detail="Pentest Mode is disabled — enable Pentest Mode first",
        )


@app.get("/api/pentest/status", response_model=PentestState)
async def api_pentest_status():
    return runtime.build_pentest_state(
        runtime.latest_snapshot.link.mac_address,
        runtime.latest_snapshot.security.forensics.exposure,
        runtime.latest_snapshot.wifi,
    )


@app.post("/api/pentest/mode", response_model=TesterSnapshot)
async def api_pentest_mode(req: PentestModeRequest):
    if req.enable:
        try:
            runtime.pentest_mgr.enable(req.authorized_ack)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:
        await runtime.recon_mgr.stop()
        await runtime.mac_mgr.restore_mac(demo_mode=runtime.demo_mode, notify=False)
        runtime.pentest_mgr.disable()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/pentest/preflight")
async def api_pentest_preflight():
    _require_pentest_mode()
    return {
        "ok": True,
        "pentest": runtime.build_pentest_state(
            runtime.latest_snapshot.link.mac_address,
            runtime.latest_snapshot.security.forensics.exposure,
            runtime.latest_snapshot.wifi,
        ).model_dump(),
    }


@app.post("/api/pentest/recon/start", response_model=TesterSnapshot)
async def api_pentest_recon_start(req: ReconStartRequest):
    _require_pentest_mode()
    snap_cur = runtime.latest_snapshot
    target = (req.target or "").strip()
    if not target:
        if snap_cur.scan.subnet and "/" in snap_cur.scan.subnet:
            target = snap_cur.scan.subnet
        elif snap_cur.l3.subnet_cidr and "/" in snap_cur.l3.subnet_cidr:
            target = snap_cur.l3.subnet_cidr
        elif snap_cur.l3.gateway_ip not in ("", "—"):
            target = snap_cur.l3.gateway_ip
        else:
            raise HTTPException(status_code=400, detail="No subnet or target IP available — enter a target IPv4/CIDR")

    discovered = [h.ip for h in snap_cur.scan.hosts]
    try:
        await runtime.recon_mgr.run_profile(
            req.profile,
            target,
            discovered_ips=discovered,
            demo_mode=runtime.demo_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/pentest/recon/stop", response_model=TesterSnapshot)
async def api_pentest_recon_stop():
    _require_pentest_mode()
    await runtime.recon_mgr.stop()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/pentest/recon/clear", response_model=TesterSnapshot)
async def api_pentest_recon_clear():
    _require_pentest_mode()
    runtime.recon_mgr.clear()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/pentest/mac/spoof", response_model=TesterSnapshot)
async def api_pentest_mac_spoof(req: MacSpoofRequest):
    _require_pentest_mode()
    if runtime.nic_tap.tap.active:
        raise HTTPException(status_code=409, detail="Stop Dual-NIC Inline Tap before changing interface MAC")

    new_mac = generate_random_local_mac() if req.random_local else (req.mac or "")
    lbl = req.label or ("Random Local" if req.random_local else "Custom MAC")
    try:
        await runtime.mac_mgr.apply_mac(
            runtime.iface,
            new_mac,
            label=lbl,
            demo_mode=runtime.demo_mode,
            fallback_orig_mac=runtime.latest_snapshot.link.mac_address,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    snap = await runtime.collect_snapshot(force_l3=True)
    await runtime.broadcast(snap)
    return snap


@app.post("/api/pentest/mac/restore", response_model=TesterSnapshot)
async def api_pentest_mac_restore():
    await runtime.mac_mgr.restore_mac(demo_mode=runtime.demo_mode, notify=False)
    snap = await runtime.collect_snapshot(force_l3=True)
    await runtime.broadcast(snap)
    return snap


@app.post("/api/pentest/wifi/watch", response_model=TesterSnapshot)
async def api_pentest_wifi_watch(req: WifiWatchRequest):
    runtime.wifi_audit_mgr.set_watch_ssid(req.ssid)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.get("/api/tailcat/status", response_model=TailcatState)
async def api_tailcat_status():
    return runtime.tailcat_mgr.snapshot(demo_mode=runtime.demo_mode)


@app.post("/api/tailcat/start", response_model=TesterSnapshot)
async def api_tailcat_start(req: TailcatStartRequest):
    target_iface = req.iface or ("br0" if runtime.nic_tap.tap.active else runtime.iface)
    try:
        await runtime.tailcat_mgr.start(
            req.mode,
            iface=target_iface,
            demo_mode=runtime.demo_mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/tailcat/stop", response_model=TesterSnapshot)
async def api_tailcat_stop():
    await runtime.tailcat_mgr.stop()
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.post("/api/tailcat/webhook", response_model=TesterSnapshot)
async def api_tailcat_webhook():
    tc = runtime.tailcat_mgr.state
    if not tc.running or not tc.address:
        raise HTTPException(status_code=400, detail="Start a Tailcat tunnel before pushing to Webhook")
    ok, msg = await asyncio.to_thread(
        runtime.sync_mgr.push_webhook_event,
        "jacktrace.tailcat_session",
        {
            "mode": tc.mode,
            "address": tc.address,
            "client_cmd": tc.client_cmd,
            "iface": tc.iface,
            "hostname": runtime.latest_snapshot.system.hostname,
        },
        runtime.demo_mode,
    )
    runtime.tailcat_mgr.record_webhook_result(ok, msg)
    snap = await runtime.collect_snapshot()
    await runtime.broadcast(snap)
    return snap


@app.websocket("/ws")
async def websocket_stream(ws: WebSocket):
    await ws.accept()
    runtime.clients.add(ws)
    try:
        await ws.send_text(runtime.latest_snapshot.model_dump_json())
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text(runtime.latest_snapshot.model_dump_json())
    except WebSocketDisconnect:
        pass
    finally:
        runtime.clients.discard(ws)
