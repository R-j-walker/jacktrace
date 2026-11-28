from typing import List, Optional
from pydantic import BaseModel, Field


class PhysicalPanelLocation(BaseModel):
    port_number: Optional[int] = None
    total_ports: int = 24
    row_label: str = "Unknown Row"
    pair_column: Optional[int] = None
    summary: str = "Standard Switch Port"
    active_peer_ports: List[int] = Field(default_factory=list)


class PhyWiringState(BaseModel):
    supported: bool = False
    phy_name: str = "—"
    mdix_state: str = "Unknown"  # "MDI", "MDI-X", "Unknown"
    master_slave: str = "Unknown"  # "Master", "Slave", "Unknown"
    local_rx_ok: Optional[bool] = None
    remote_rx_ok: Optional[bool] = None
    descrambler_locked: Optional[bool] = None
    idle_errors: int = 0
    rx_symbol_errors: int = 0
    false_carrier_errors: int = 0
    local_rx_not_ok_count: int = 0
    remote_rx_not_ok_count: int = 0
    verdict: str = "IDLE"  # "PASS", "WARN", "FAIL", "UNPATCHED", "IDLE"
    summary: str = "Waiting for link or TDR pulse"


class LinkTelemetry(BaseModel):
    iface: str = "eth0"
    carrier_up: bool = False
    operstate: str = "down"
    mac_address: str = "00:00:00:00:00:00"
    speed_mbps: Optional[int] = None
    duplex: str = "Unknown"
    autoneg: bool = True
    partner_supports_1g: bool = False
    local_supports_1g: bool = True
    pair_downshift_suspected: bool = False
    pair_diagnostic_note: str = "Waiting for link..."
    rx_crc_errors: int = 0
    rx_packets: int = 0
    tx_packets: int = 0
    phy_wiring: PhyWiringState = Field(default_factory=PhyWiringState)


class PoeTelemetry(BaseModel):
    supported: bool = False
    enabled: bool = False
    standard: str = "None Detected"
    power_class: str = "—"
    allocated_watts: Optional[float] = None
    requested_watts: Optional[float] = None
    power_pairs: str = "—"
    source_protocol: str = "None"


class SwitchNeighbor(BaseModel):
    detected: bool = False
    protocols: List[str] = Field(default_factory=list)
    confidence: str = "NONE"
    switch_name: str = "No Switch Detected"
    model: str = "Waiting for LLDP / CDP..."
    vendor: str = "—"
    raw_descr: str = ""
    mgmt_ip: str = "—"
    chassis_mac: str = "—"
    port_id: str = "—"
    port_descr: str = "—"
    panel: PhysicalPanelLocation = Field(default_factory=PhysicalPanelLocation)


class VlanAndNacTelemetry(BaseModel):
    native_vlan: Optional[int] = None
    native_vlan_name: str = "Untagged / Unknown"
    voice_vlan: Optional[int] = None
    tagged_vlans: List[int] = Field(default_factory=list)
    eapol_8021x_seen: bool = False
    nac_status: str = "Open (No EAPOL Challenge)"


class L3Connectivity(BaseModel):
    ipv4_address: str = "—"
    subnet_cidr: str = "—"
    dhcp_status: str = "Waiting"
    gateway_ip: str = "—"
    gateway_ping_ms: Optional[float] = None
    dns_server: str = "—"
    dns_resolve_ms: Optional[float] = None
    internet_ok: bool = False
    http_probe_ms: Optional[float] = None
    captive_portal: bool = False


class BlinkState(BaseModel):
    active: bool = False
    mode: str = "speed-cycle"
    phase: str = "idle"
    remaining_seconds: int = 0
    warning: str = ""


class StressTestResult(BaseModel):
    running: bool = False
    completed_at: Optional[str] = None
    target_ip: str = "—"
    packets_sent: int = 0
    packets_received: int = 0
    loss_percent: float = 0.0
    min_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    max_ms: Optional[float] = None
    crc_delta: int = 0
    verdict: str = "Not Run"


# ==========================================
# PHASE 3: BROADCOM BCM54213PE HARDWARE TDR
# ==========================================


class TdrPairResult(BaseModel):
    pair_name: str       # "Pair A"
    pins: str            # "Pins 1–2"
    wire_colors: str     # "White/Orange • Orange"
    status: str          # "OK", "OPEN", "SHORT", "CROSS_SHORT", "UNPROBED"
    distance_m: Optional[float] = None
    detail: str = "Not pulsed yet"


class TdrReportState(BaseModel):
    running: bool = False
    supported: bool = True
    method: str = "BCM54213PE MDIO ECD"
    phy_id: str = "—"
    tested_at: Optional[str] = None
    cable_type: str = "Cat5e (69%)"
    nvp_pct: float = 69.0
    overall_verdict: str = "NOT_RUN"  # "PASS", "WARN", "FAIL", "UNPATCHED", "NOT_RUN"
    summary: str = "Tap PULSE TDR to measure 4-pair cable length & faults"
    raw_debug: str = ""
    pairs: List[TdrPairResult] = Field(default_factory=list)


class PlatformCapabilities(BaseModel):
    platform_kind: str = "generic_linux"  # "raspberry_pi" | "x86_linux" | "generic_linux" | "demo"
    arch: str = ""
    is_raspberry_pi: bool = False
    has_battery: bool = False
    supports_backlight: bool = False
    supports_dsi_flip: bool = False
    supports_overlayfs: bool = False
    supports_tdr: bool = True


class SystemHealthState(BaseModel):
    hostname: str = "jacktrace"
    cpu_temp_c: Optional[float] = None
    uptime_str: str = "—"
    backlight_pct: Optional[int] = None
    battery_pct: Optional[int] = None
    battery_status: str = ""
    wifi_iface: str = "wlan0"
    screen_flipped: bool = False
    reboot_required: bool = False
    overlayfs_active: bool = False
    overlayfs_pending_enable: bool = False
    capabilities: PlatformCapabilities = Field(default_factory=PlatformCapabilities)


# ==========================================
# PHASE 2: SUBNET SCANNER, SECURITY & AUDIT
# ==========================================


class DiscoveredHost(BaseModel):
    ip: str
    hostname: str = "—"
    mac: str = "—"
    vendor: str = "Unknown"
    open_ports: List[int] = Field(default_factory=list)
    role: str = "Host"
    rtt_ms: Optional[float] = None


class SubnetScanState(BaseModel):
    scanning: bool = False
    subnet: str = "—"
    last_scan_at: Optional[str] = None
    duration_s: float = 0.0
    active_count: int = 0
    hosts: List[DiscoveredHost] = Field(default_factory=list)


class DhcpOfferInfo(BaseModel):
    server_ip: str
    offered_ip: str = "—"
    server_mac: str = "—"
    vendor: str = "Unknown"
    router_ip: str = "—"
    dns_ip: str = "—"
    authorized: bool = True
    subnet_mask: str = "—"
    lease_time_s: Optional[int] = None
    domain_name: str = "—"
    ntp_server: str = "—"
    tftp_server: str = "—"
    boot_file: str = "—"
    vendor_opt43: str = "—"
    wpad_url: str = "—"


class StpBpduInfo(BaseModel):
    detected: bool = False
    protocol: str = "None"
    root_priority: Optional[int] = None
    root_mac: str = "—"
    root_path_cost: Optional[int] = None
    bridge_mac: str = "—"
    port_id: str = "—"
    bpdu_count: int = 0


class Ipv6RaSender(BaseModel):
    src_mac: str
    src_ipv6: str
    vendor: str = "Unknown"
    router_lifetime_s: int = 0
    count: int = 1


class ExposureTalker(BaseModel):
    protocol: str          # "LLMNR" | "NBT-NS" | "mDNS" | "WPAD"
    src_ip: str
    src_mac: str = "—"
    vendor: str = "Unknown"
    query: str = "—"
    risk: str = "HIGH"     # "HIGH" | "INFO"
    count: int = 1
    last_seen: str = ""


class CleartextAlert(BaseModel):
    severity: str          # "CRITICAL" | "HIGH" | "WARN"
    protocol: str          # "HTTP-BASIC" | "HTTP-AUTH" | "FTP" | "TELNET" | "SNMPv2c" | "NTLMSSP" | "SMBv1" | "MAIL" | "MQTT" | "SIP"
    src_ip: str
    dst_ip: str
    dst_port: int = 0
    detail: str
    count: int = 1
    last_seen: str = ""


class PassiveExposureState(BaseModel):
    llmnr_count: int = 0
    nbns_count: int = 0
    mdns_count: int = 0
    wpad_count: int = 0
    cleartext_count: int = 0
    talkers: List[ExposureTalker] = Field(default_factory=list)
    cleartext_alerts: List[CleartextAlert] = Field(default_factory=list)


class L2ForensicsState(BaseModel):
    stp: StpBpduInfo = Field(default_factory=StpBpduInfo)
    bcast_pps: float = 0.0
    mcast_pps: float = 0.0
    storm_detected: bool = False
    ipv6_ra_senders: List[Ipv6RaSender] = Field(default_factory=list)
    rogue_ra_detected: bool = False
    exposure: PassiveExposureState = Field(default_factory=PassiveExposureState)


class SecurityFinding(BaseModel):
    severity: str
    title: str
    detail: str


class SecurityMetricBar(BaseModel):
    name: str
    score: int
    max_score: int
    status: str


class SecurityReportState(BaseModel):
    probing: bool = False
    last_checked_at: Optional[str] = None
    score: int = 96
    grade: str = "A"
    summary: str = "Protected"
    dhcp_offers: List[DhcpOfferInfo] = Field(default_factory=list)
    rogue_dhcp_detected: bool = False
    arp_frames_checked: int = 0
    arp_conflicts: List[str] = Field(default_factory=list)
    arp_status: str = "PROTECTED"
    metrics: List[SecurityMetricBar] = Field(default_factory=list)
    findings: List[SecurityFinding] = Field(default_factory=list)
    forensics: L2ForensicsState = Field(default_factory=L2ForensicsState)


class SavedWallPort(BaseModel):
    id: int
    job_name: str
    drop_label: str
    saved_at: str
    verdict: str
    switch_name: str
    switch_model: str
    switch_ip: str
    port_id: str
    panel_summary: str
    speed_summary: str
    poe_summary: str
    vlan_summary: str
    ip_cidr: str
    gateway_summary: str
    security_grade: str
    tdr_summary: str = "—"
    notes: str = ""


class PcapCaptureState(BaseModel):
    capturing: bool = False
    filename: str = "—"
    packets_captured: int = 0
    size_bytes: int = 0
    completed_at: Optional[str] = None


class AuditJobSummary(BaseModel):
    name: str
    count: int = 0
    prefix: str = "W"
    next_drop: int = 1


class AuditPortalState(BaseModel):
    job_name: str = "Site Floor Audit"
    drop_prefix: str = "W"
    next_drop_number: int = 1
    next_drop_label: str = "W-01"
    total_saved: int = 0
    pass_count: int = 0
    warn_fail_count: int = 0
    portal_url: str = "http://localhost:8080"
    pdf_url: str = "http://localhost:8080/api/audit/report.pdf"
    csv_url: str = "http://localhost:8080/api/audit/report.csv"
    qr_svg_data_uri: str = ""
    wifi_ap_active: bool = False
    wifi_ssid: str = "Client Wi-Fi"
    wifi_ip: str = "—"
    pcap: PcapCaptureState = Field(default_factory=PcapCaptureState)
    recent_ports: List[SavedWallPort] = Field(default_factory=list)
    jobs: List[AuditJobSummary] = Field(default_factory=list)


# ==========================================
# MILESTONE 1: AUTOTEST & SPEED/PATH DIAG
# ==========================================


class AutoTestStep(BaseModel):
    key: str
    label: str
    status: str  # "PASS", "WARN", "FAIL", "SKIP", "WAIT"
    value: str = "—"
    detail: str = ""


class AutoTestState(BaseModel):
    profile: str = "standard"  # "standard" or "lan_only"
    auto_log: bool = False
    running: bool = False
    verdict: str = "WAITING"
    summary: str = "Plug into wall port to start AutoTest"
    passed_count: int = 0
    total_count: int = 7
    duration_s: float = 0.0
    last_run_at: Optional[str] = None
    steps: List[AutoTestStep] = Field(default_factory=list)


class PingSample(BaseModel):
    seq: int
    ts: str
    rtt_ms: Optional[float] = None
    ok: bool = False


class PingMonitorState(BaseModel):
    running: bool = False
    target: str = "—"
    sent: int = 0
    received: int = 0
    loss_percent: float = 0.0
    min_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    max_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    samples: List[PingSample] = Field(default_factory=list)


class TracerouteHop(BaseModel):
    hop: int
    host: str = "*"
    ip: str = "*"
    rtt_ms: Optional[float] = None
    loss: bool = False


class TracerouteState(BaseModel):
    running: bool = False
    target: str = "—"
    completed_at: Optional[str] = None
    error: str = ""
    hops: List[TracerouteHop] = Field(default_factory=list)


class SpeedTestState(BaseModel):
    running: bool = False
    provider: str = "Cloudflare Edge"
    iface_mode: str = "auto"  # "auto" | "eth" | "wifi"
    egress_iface: str = "—"
    egress_ip: str = "—"
    completed_at: Optional[str] = None
    download_mbps: Optional[float] = None
    upload_mbps: Optional[float] = None
    unloaded_ms: Optional[float] = None
    loaded_ms: Optional[float] = None
    bufferbloat_grade: str = "—"
    status: str = "Ready"


class StaticIpState(BaseModel):
    iface: str = "eth0"
    mode: str = "dhcp"  # "dhcp" | "static"
    ip_cidr: str = ""
    gateway: str = ""
    dns: str = ""
    status: str = "DHCP (Auto)"
    error: str = ""


class Dot1xTestState(BaseModel):
    supported: bool = True
    active: bool = False
    iface: str = "eth0"
    method: str = "PEAP"
    identity: str = ""
    has_password: bool = False
    status: str = "Idle"  # "Idle" | "Authenticating..." | "Authenticated" | "Failed" | "Stopped"
    detail: str = "Test 802.1X EAP-PEAP on locked switch ports"


class IperfState(BaseModel):
    client_running: bool = False
    server_running: bool = False
    server_bind_ip: str = "—"
    server_port: int = 5201
    target: str = "—"
    saved_targets: List[str] = Field(default_factory=lambda: ["192.168.0.1"])
    completed_at: Optional[str] = None
    tx_mbps: Optional[float] = None
    rx_mbps: Optional[float] = None
    retransmits: Optional[int] = None
    status: str = "Ready"
    error: str = ""


class MtuTestState(BaseModel):
    running: bool = False
    target: str = "—"
    completed_at: Optional[str] = None
    max_mtu: Optional[int] = None
    jumbo_supported: bool = False
    status: str = "Ready"


class DiagnosticsState(BaseModel):
    ping: PingMonitorState = Field(default_factory=PingMonitorState)
    traceroute: TracerouteState = Field(default_factory=TracerouteState)
    speedtest: SpeedTestState = Field(default_factory=SpeedTestState)
    iperf: IperfState = Field(default_factory=IperfState)
    mtu: MtuTestState = Field(default_factory=MtuTestState)


# ==========================================
# MILESTONE 2: WI-FI SITE SURVEY & ANALYZER
# ==========================================


class WifiNetwork(BaseModel):
    bssid: str
    ssid: str = "<Hidden>"
    vendor: str = "Unknown"
    freq_mhz: int = 2412
    channel: int = 1
    band: str = "2.4 GHz"
    width_mhz: int = 20
    center_channel: int = 1
    signal_dbm: int = -90
    quality_pct: int = 0
    security: str = "Open"
    wifi_gen: str = "Wi-Fi 4"
    associated: bool = False


class WifiWalkSample(BaseModel):
    seq: int
    ts: str
    signal_dbm: Optional[int] = None
    rx_mbps: Optional[float] = None
    tx_mbps: Optional[float] = None


class WifiWalkState(BaseModel):
    running: bool = False
    bssid: str = "—"
    ssid: str = "—"
    band: str = "—"
    channel: int = 0
    freq_mhz: int = 0
    current_dbm: Optional[int] = None
    min_dbm: Optional[int] = None
    max_dbm: Optional[int] = None
    avg_dbm: Optional[float] = None
    rx_mbps: Optional[float] = None
    tx_mbps: Optional[float] = None
    samples: List[WifiWalkSample] = Field(default_factory=list)


class WifiSurveyState(BaseModel):
    scanning: bool = False
    ap_mode_blocked: bool = False
    iface: str = "wlan0"
    connected_ssid: str = "—"
    connected_bssid: str = "—"
    connected_dbm: Optional[int] = None
    connected_channel: Optional[int] = None
    last_scan_at: Optional[str] = None
    total_count: int = 0
    count_24g: int = 0
    count_5g: int = 0
    count_6g: int = 0
    best_24g_channel: Optional[int] = None
    error: str = ""
    networks: List[WifiNetwork] = Field(default_factory=list)
    walk: WifiWalkState = Field(default_factory=WifiWalkState)


class WifiClientNetwork(BaseModel):
    ssid: str
    bssid: str = "—"
    signal_pct: int = 0
    band: str = "2.4 GHz"
    security: str = "Open"
    in_use: bool = False
    saved: bool = False
    profile_name: str = ""


class WifiSavedProfile(BaseModel):
    name: str
    ssid: str
    uuid: str
    active: bool = False
    autoconnect: bool = True


class WifiClientState(BaseModel):
    available: bool = True
    iface: str = "wlan0"
    connected: bool = False
    ap_mode_active: bool = False
    active_ssid: str = "—"
    active_profile: str = ""
    ipv4: str = "—"
    signal_pct: Optional[int] = None
    busy: bool = False
    status: str = "Ready"
    error: str = ""
    last_scan_at: Optional[str] = None
    saved_profiles: List[WifiSavedProfile] = Field(default_factory=list)
    available_networks: List[WifiClientNetwork] = Field(default_factory=list)


# ==========================================
# MILESTONE 3: VLAN PROBER, SNMP & TAP HOST
# ==========================================


class VlanProbeEntry(BaseModel):
    vlan_id: int
    source: str = "preset"
    status: str = "NO_REPLY"
    dhcp_server_ip: str = "—"
    offered_ip: str = "—"
    router_ip: str = "—"
    dns_ip: str = "—"
    subnet_mask: str = "—"


class VlanProbeState(BaseModel):
    running: bool = False
    last_run_at: Optional[str] = None
    preset_vlans: List[int] = Field(default_factory=lambda: [10, 20, 30, 50, 99, 100, 200])
    results: List[VlanProbeEntry] = Field(default_factory=list)
    error: str = ""


class SnmpSwitchState(BaseModel):
    running: bool = False
    community: str = "public"
    target_ip: str = "—"
    last_run_at: Optional[str] = None
    sys_name: str = "—"
    sys_descr: str = "—"
    uptime_str: str = "—"
    matched_port: str = "—"
    if_in_errors: Optional[int] = None
    if_out_errors: Optional[int] = None
    poe_budget_w: Optional[float] = None
    poe_draw_w: Optional[float] = None
    error: str = ""


class HostInspectResult(BaseModel):
    ip: str
    hostname: str = "—"
    mac: str = "—"
    vendor: str = "Unknown"
    role: str = "Host"
    rtt_ms: Optional[float] = None
    open_ports: List[int] = Field(default_factory=list)
    port_services: List[str] = Field(default_factory=list)
    http_title: str = ""
    mdns_services: List[str] = Field(default_factory=list)
    wol_sent_at: Optional[str] = None
    scanned_at: Optional[str] = None


# ==========================================
# MILESTONE 4: SYNC, BT PRINTER & MULTI-NIC TAP
# ==========================================


class SyncQueueEntry(BaseModel):
    id: int
    target: str
    drop_label: str
    job_name: str
    status: str  # "PENDING", "SENT", "FAILED"
    attempts: int = 0
    created_at: str
    last_error: str = ""


class SyncState(BaseModel):
    webhook_url: str = ""
    webhook_has_token: bool = False
    webhook_enabled: bool = False
    netbox_url: str = ""
    netbox_has_token: bool = False
    netbox_enabled: bool = False
    auto_sync_on_save: bool = False
    syncing: bool = False
    pending_count: int = 0
    sent_count: int = 0
    failed_count: int = 0
    last_sync_at: Optional[str] = None
    last_status: str = "Not configured"
    recent_queue: List[SyncQueueEntry] = Field(default_factory=list)


class BluetoothPrinterDevice(BaseModel):
    mac: str
    name: str
    paired: bool = False
    connected: bool = False
    rssi: Optional[int] = None


class PrinterState(BaseModel):
    bt_available: bool = True
    scanning: bool = False
    printing: bool = False
    selected_mac: str = ""
    selected_name: str = "Not Paired"
    rfcomm_channel: int = 1
    devices: List[BluetoothPrinterDevice] = Field(default_factory=list)
    last_print_at: Optional[str] = None
    last_status: str = "Tap Scan to find 58mm BT thermal printer"
    last_preview: str = ""


class NicInterfaceInfo(BaseModel):
    iface: str
    mac: str = "—"
    carrier_up: bool = False
    operstate: str = "down"
    speed_mbps: Optional[int] = None
    max_speed_mbps: int = 1000
    driver: str = "unknown"
    is_usb: bool = False
    supports_2500: bool = False
    active: bool = False


class InlineTapState(BaseModel):
    active: bool = False
    bridge_iface: str = "br0"
    nic_a: str = "eth0"
    nic_b: str = ""
    eapol_lldp_passthrough: bool = True
    rx_packets: int = 0
    tx_packets: int = 0
    status: str = "Inactive"
    error: str = ""


class NetworkHardwareState(BaseModel):
    active_iface: str = "eth0"
    nics: List[NicInterfaceInfo] = Field(default_factory=list)
    tap: InlineTapState = Field(default_factory=InlineTapState)


class ReconFinding(BaseModel):
    severity: str          # "CRITICAL" | "HIGH" | "WARN" | "INFO"
    profile: str           # "quick_banners" | "smb_signing" | "tls_audit" | "snmp_defaults"
    host_ip: str
    port: int = 0
    service: str = "—"
    title: str
    detail: str


class ReconAuditState(BaseModel):
    running: bool = False
    nmap_installed: bool = False
    active_profile: str = "quick_banners"
    target: str = "—"
    last_run_at: Optional[str] = None
    duration_s: float = 0.0
    status: str = "Ready"
    error: str = ""
    findings: List[ReconFinding] = Field(default_factory=list)


class MacSpoofState(BaseModel):
    spoofed: bool = False
    iface: str = "eth0"
    original_mac: str = "—"
    current_mac: str = "—"
    cloned_label: str = ""
    status: str = "Original Hardware MAC"
    error: str = ""


class RogueApFinding(BaseModel):
    severity: str          # "CRITICAL" | "HIGH" | "WARN"
    ssid: str
    bssid: str
    vendor: str = "Unknown"
    channel: int = 0
    security: str = "—"
    signal_dbm: int = -90
    reason: str


class WifiAuditState(BaseModel):
    watch_ssid: str = ""
    rogue_count: int = 0
    weak_sec_count: int = 0
    findings: List[RogueApFinding] = Field(default_factory=list)


class PentestState(BaseModel):
    enabled: bool = False
    enabled_at: Optional[str] = None
    authorized_ack: bool = False
    active_iface: str = "eth0"
    active_mac: str = "—"
    mac_spoofed: bool = False
    usb_wifi_iface: Optional[str] = None
    passive_hits: int = 0
    cleartext_alerts: int = 0
    recon_findings: int = 0
    recon: ReconAuditState = Field(default_factory=ReconAuditState)
    mac_spoof: MacSpoofState = Field(default_factory=MacSpoofState)
    wifi_audit: WifiAuditState = Field(default_factory=WifiAuditState)


class TailcatState(BaseModel):
    installed: bool = False
    binary_path: str = ""
    running: bool = False
    mode: str = "idle"  # "idle" | "web_ui" | "pcap_stream" | "iperf" | "ssh"
    iface: str = "eth0"
    address: str = ""
    client_cmd: str = ""
    qr_svg_data_uri: str = ""
    started_at: Optional[str] = None
    status: str = "Idle"
    error: str = ""
    webhook_pushed_at: Optional[str] = None
    webhook_status: str = ""


class TesterSnapshot(BaseModel):
    timestamp: str
    mode: str = "live"
    demo_scenario: str = "healthy_1g"
    autotest_verdict: str = "WAITING"
    autotest_duration_s: float = 0.0
    port_session_id: int = 1
    link: LinkTelemetry
    poe: PoeTelemetry
    switch: SwitchNeighbor
    vlan: VlanAndNacTelemetry
    l3: L3Connectivity
    blink: BlinkState
    stress: StressTestResult
    tdr: TdrReportState = Field(default_factory=TdrReportState)
    system: SystemHealthState = Field(default_factory=SystemHealthState)
    scan: SubnetScanState = Field(default_factory=SubnetScanState)
    security: SecurityReportState = Field(default_factory=SecurityReportState)
    audit: AuditPortalState = Field(default_factory=AuditPortalState)
    autotest: AutoTestState = Field(default_factory=AutoTestState)
    diagnostics: DiagnosticsState = Field(default_factory=DiagnosticsState)
    wifi: WifiSurveyState = Field(default_factory=WifiSurveyState)
    vlan_probe: VlanProbeState = Field(default_factory=VlanProbeState)
    snmp: SnmpSwitchState = Field(default_factory=SnmpSwitchState)
    sync: SyncState = Field(default_factory=SyncState)
    printer: PrinterState = Field(default_factory=PrinterState)
    hw_nics: NetworkHardwareState = Field(default_factory=NetworkHardwareState)
    wifi_client: WifiClientState = Field(default_factory=WifiClientState)
    static_ip: StaticIpState = Field(default_factory=StaticIpState)
    dot1x: Dot1xTestState = Field(default_factory=Dot1xTestState)
    pentest: PentestState = Field(default_factory=PentestState)
    tailcat: TailcatState = Field(default_factory=TailcatState)
