from datetime import datetime, timezone
from .autotest import evaluate_autotest
from .models import (
    AuditPortalState,
    BlinkState,
    DhcpOfferInfo,
    DiagnosticsState,
    DiscoveredHost,
    Dot1xTestState,
    L3Connectivity,
    LinkTelemetry,
    NetworkHardwareState,
    PhyWiringState,
    PoeTelemetry,
    PrinterState,
    SnmpSwitchState,
    StaticIpState,
    StressTestResult,
    SubnetScanState,
    SwitchNeighbor,
    SyncState,
    SystemHealthState,
    TdrPairResult,
    TdrReportState,
    TesterSnapshot,
    VlanAndNacTelemetry,
    VlanProbeState,
    WifiClientState,
    WifiSurveyState,
)
from .port_mapper import map_port_to_panel
from .security import evaluate_security_posture
from .tdr import synthesize_wiremap_verdict


def build_demo_tdr(scenario: str) -> TdrReportState:
    phy = "Broadcom BCM54213PE (0x600d84a2 rev 2)"
    if scenario == "pair_fault_100m":
        return TdrReportState(
            running=False,
            supported=True,
            method="BCM54213PE Hardware TDR",
            phy_id=phy,
            tested_at="Demo Pulse",
            overall_verdict="FAIL",
            summary="BROKEN PAIR FAULT: Pair D (Pins 7–8) OPEN @ 18.4m while Pairs A, B, C terminated!",
            pairs=[
                TdrPairResult(pair_name="Pair A", pins="Pins 1–2", wire_colors="White/Orange • Orange", status="OK", distance_m=24.8, detail="100Ω Terminated (24.8m)"),
                TdrPairResult(pair_name="Pair B", pins="Pins 3–6", wire_colors="White/Green • Green", status="OK", distance_m=25.1, detail="100Ω Terminated (25.1m)"),
                TdrPairResult(pair_name="Pair C", pins="Pins 4–5", wire_colors="Blue • White/Blue", status="OK", distance_m=24.7, detail="100Ω Terminated (24.7m)"),
                TdrPairResult(pair_name="Pair D", pins="Pins 7–8", wire_colors="White/Brown • Brown", status="OPEN", distance_m=18.4, detail="Open Reflection @ 18.4m"),
            ],
        )

    if scenario == "unpatched_dead":
        return TdrReportState(
            running=False,
            supported=True,
            method="BCM54213PE Hardware TDR",
            phy_id=phy,
            tested_at="Demo Pulse",
            overall_verdict="UNPATCHED",
            summary="Unpatched Wall Drop: All 4 pairs intact to ~28.6m (open at comms patch panel)",
            pairs=[
                TdrPairResult(pair_name="Pair A", pins="Pins 1–2", wire_colors="White/Orange • Orange", status="OPEN", distance_m=28.6, detail="Open Reflection @ 28.6m"),
                TdrPairResult(pair_name="Pair B", pins="Pins 3–6", wire_colors="White/Green • Green", status="OPEN", distance_m=28.5, detail="Open Reflection @ 28.5m"),
                TdrPairResult(pair_name="Pair C", pins="Pins 4–5", wire_colors="Blue • White/Blue", status="OPEN", distance_m=28.7, detail="Open Reflection @ 28.7m"),
                TdrPairResult(pair_name="Pair D", pins="Pins 7–8", wire_colors="White/Brown • Brown", status="OPEN", distance_m=28.6, detail="Open Reflection @ 28.6m"),
            ],
        )

    return TdrReportState(
        running=False,
        supported=True,
        method="BCM54213PE Hardware TDR",
        phy_id=phy,
        tested_at="Demo Pulse",
        overall_verdict="PASS",
        summary="All 4 TIA-568B pairs intact & 100Ω terminated at switch (~24.9m)",
        pairs=[
            TdrPairResult(pair_name="Pair A", pins="Pins 1–2", wire_colors="White/Orange • Orange", status="OK", distance_m=24.8, detail="100Ω Terminated (24.8m)"),
            TdrPairResult(pair_name="Pair B", pins="Pins 3–6", wire_colors="White/Green • Green", status="OK", distance_m=25.1, detail="100Ω Terminated (25.1m)"),
            TdrPairResult(pair_name="Pair C", pins="Pins 4–5", wire_colors="Blue • White/Blue", status="OK", distance_m=24.7, detail="100Ω Terminated (24.7m)"),
            TdrPairResult(pair_name="Pair D", pins="Pins 7–8", wire_colors="White/Brown • Brown", status="OK", distance_m=24.9, detail="100Ω Terminated (24.9m)"),
        ],
    )


def build_demo_scan(scenario: str) -> SubnetScanState:
    if scenario == "unpatched_dead":
        return SubnetScanState(subnet="—", active_count=0, hosts=[])

    hosts = [
        DiscoveredHost(ip="172.24.10.1", hostname="rtr-edge-west.lan", mac="00:09:0F:44:12:A8", vendor="Fortinet Inc.", open_ports=[22, 443], role="Gateway / Firewall", rtt_ms=0.6),
        DiscoveredHost(ip="172.24.10.2", hostname="idf2-sw03.lan", mac="94:F1:28:6C:19:40", vendor="HPE / Aruba", open_ports=[22, 23, 443], role="Managed Switch", rtt_ms=1.0),
        DiscoveredHost(ip="172.24.10.5", hostname="dc-west-01.lan", mac="D8:9E:F3:22:71:05", vendor="Dell Inc.", open_ports=[53, 88, 389, 445], role="Domain Controller", rtt_ms=0.9),
        DiscoveredHost(ip="172.24.10.18", hostname="ap-west-conf.lan", mac="F0:9F:C2:31:8A:12", vendor="Ubiquiti Inc.", open_ports=[22, 443], role="Switch / Wi-Fi AP", rtt_ms=1.6),
        DiscoveredHost(ip="172.24.10.31", hostname="nas-media-02.lan", mac="24:5E:BE:60:14:9C", vendor="QNAP Systems", open_ports=[445, 5001], role="NAS Storage", rtt_ms=1.3),
        DiscoveredHost(ip="172.24.10.64", hostname="mfp-studio-01.lan", mac="00:80:77:92:1B:44", vendor="Brother Ind.", open_ports=[80, 9100], role="Network Printer", rtt_ms=2.1),
    ]
    if scenario == "pair_fault_100m":
        hosts.append(
            DiscoveredHost(ip="192.168.0.1", hostname="archer-c6-desk", mac="D8:07:B6:44:9E:12", vendor="TP-Link Tech", open_ports=[53, 80], role="Rogue Router!", rtt_ms=1.7)
        )
    return SubnetScanState(
        scanning=False,
        subnet="172.24.10.0/24",
        last_scan_at="Demo Sweep",
        duration_s=1.9,
        active_count=len(hosts),
        hosts=hosts,
    )


def build_demo_snapshot(
    scenario: str,
    blink: BlinkState,
    stress: StressTestResult,
    audit: AuditPortalState,
    system: SystemHealthState,
    tdr_override: TdrReportState | None = None,
    session_id: int = 1,
    autotest_profile: str = "standard",
    autotest_auto_log: bool = False,
    diagnostics: DiagnosticsState | None = None,
    wifi: WifiSurveyState | None = None,
    vlan_probe: VlanProbeState | None = None,
    snmp: SnmpSwitchState | None = None,
    sync: SyncState | None = None,
    printer: PrinterState | None = None,
    hw_nics: NetworkHardwareState | None = None,
    wifi_client: WifiClientState | None = None,
    static_ip: StaticIpState | None = None,
    dot1x: Dot1xTestState | None = None,
) -> TesterSnapshot:
    now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
    scan = build_demo_scan(scenario)
    tdr = tdr_override if (tdr_override and tdr_override.running) else build_demo_tdr(scenario)
    diag = diagnostics or DiagnosticsState()
    wifi_state = wifi or WifiSurveyState()
    vp_state = vlan_probe or VlanProbeState()
    snmp_state = snmp or SnmpSwitchState()
    sync_state = sync or SyncState()
    printer_state = printer or PrinterState()
    hw_state = hw_nics or NetworkHardwareState()
    wcli_state = wifi_client or WifiClientState()
    static_state = static_ip or StaticIpState()
    dot1x_state = dot1x or Dot1xTestState()

    if scenario == "pair_fault_100m":
        panel = map_port_to_panel("1/19", "WW-FL2-DESK-19", "Aruba 2930F-24G-PoE+", "JL255A")
        panel.active_peer_ports = [1, 2, 3, 5, 6, 8, 10, 11, 14, 15, 17, 19, 22, 24]
        vlan = VlanAndNacTelemetry(
            native_vlan=40,
            native_vlan_name="VLAN 40 (STAFF_DATA)",
            voice_vlan=140,
            tagged_vlans=[40, 140],
            eapol_8021x_seen=False,
            nac_status="Open (No EAPOL Challenge)",
        )
        l3 = L3Connectivity(
            ipv4_address="172.24.10.85",
            subnet_cidr="172.24.10.85/24",
            dhcp_status="Bound (Dynamic)",
            gateway_ip="172.24.10.1",
            gateway_ping_ms=0.9,
            dns_server="172.24.10.5",
            dns_resolve_ms=3.8,
            internet_ok=True,
            http_probe_ms=16.2,
        )
        offers = [
            DhcpOfferInfo(
                server_ip="172.24.10.1",
                offered_ip="172.24.10.85",
                server_mac="00:09:0F:44:12:A8",
                vendor="Fortinet Inc.",
                router_ip="172.24.10.1",
                dns_ip="172.24.10.5",
                authorized=True,
                subnet_mask="255.255.255.0",
                lease_time_s=86400,
                domain_name="westwing.lan",
                ntp_server="172.24.10.5",
            ),
            DhcpOfferInfo(
                server_ip="192.168.0.1",
                offered_ip="192.168.0.104",
                server_mac="D8:07:B6:44:9E:12",
                vendor="TP-Link Tech",
                router_ip="192.168.0.1",
                dns_ip="192.168.0.1",
                authorized=False,
                subnet_mask="255.255.255.0",
                lease_time_s=3600,
                wpad_url="http://192.168.0.1/wpad.dat",
            ),
        ]
        sniffer_demo = {
            "arp_frames_checked": 412,
            "arp_conflicts": [],
            "bcast_pps": 4.1,
            "mcast_pps": 9.8,
            "stp": {
                "detected": True,
                "protocol": "RSTP",
                "root_priority": 32768,
                "root_mac": "94:F1:28:6C:19:40",
                "root_path_cost": 4,
                "bridge_mac": "94:F1:28:6C:19:40",
                "port_id": "0x8013 (#19)",
                "bpdu_count": 11,
            },
            "ipv6_ra_senders": [
                {
                    "src_mac": "00:09:0F:44:12:A8",
                    "src_ipv6": "fe80::209:fff:fe44:12a8",
                    "router_lifetime_s": 1800,
                    "count": 2,
                }
            ],
            "exposure": {
                "llmnr_count": 1,
                "nbns_count": 1,
                "mdns_count": 1,
                "wpad_count": 1,
                "cleartext_count": 2,
                "talkers": [
                    {
                        "protocol": "WPAD",
                        "src_ip": "172.24.10.42",
                        "src_mac": "3C:52:82:1A:44:10",
                        "vendor": "Hewlett Packard",
                        "query": "WPAD",
                        "risk": "HIGH",
                        "count": 4,
                        "last_seen": now_str,
                    },
                    {
                        "protocol": "LLMNR",
                        "src_ip": "172.24.10.42",
                        "src_mac": "3C:52:82:1A:44:10",
                        "vendor": "Hewlett Packard",
                        "query": "filesrv-old",
                        "risk": "HIGH",
                        "count": 3,
                        "last_seen": now_str,
                    },
                    {
                        "protocol": "NBT-NS",
                        "src_ip": "172.24.10.64",
                        "src_mac": "00:80:77:92:1B:44",
                        "vendor": "Brother Ind.",
                        "query": "PRINT-SPOOL",
                        "risk": "HIGH",
                        "count": 2,
                        "last_seen": now_str,
                    },
                    {
                        "protocol": "mDNS",
                        "src_ip": "172.24.10.18",
                        "src_mac": "F0:9F:C2:31:8A:12",
                        "vendor": "Ubiquiti Inc.",
                        "query": "_ssh._tcp.local",
                        "risk": "INFO",
                        "count": 5,
                        "last_seen": now_str,
                    },
                ],
                "cleartext_alerts": [
                    {
                        "severity": "CRITICAL",
                        "protocol": "HTTP-BASIC",
                        "src_ip": "172.24.10.42",
                        "dst_ip": "172.24.10.2",
                        "dst_port": 80,
                        "detail": "HTTP Basic Auth user 'admin' (password len 11, redacted)",
                        "count": 1,
                        "last_seen": now_str,
                    },
                    {
                        "severity": "HIGH",
                        "protocol": "SNMPv2c",
                        "src_ip": "172.24.10.5",
                        "dst_ip": "172.24.10.2",
                        "dst_port": 161,
                        "detail": "Cleartext SNMPv2c community: default 'public'",
                        "count": 6,
                        "last_seen": now_str,
                    },
                ],
            },
        }
        sec = evaluate_security_posture(offers, sniffer_demo, vlan, l3, scan)
        link = LinkTelemetry(
            iface="eth0",
            carrier_up=True,
            operstate="up",
            mac_address="DC:A6:32:8F:14:2B",
            speed_mbps=100,
            duplex="Full",
            autoneg=True,
            partner_supports_1g=True,
            local_supports_1g=True,
            pair_downshift_suspected=True,
            pair_diagnostic_note="FAULT SUSPECTED: Switch advertises 1GbE but link downshifted to 100M (Pair D open @ 18.4m)",
            rx_packets=1842,
            tx_packets=619,
            phy_wiring=PhyWiringState(
                supported=True,
                phy_name="Broadcom BCM54213PE (0x600d84a2 rev 2)",
                mdix_state="MDI-X",
                master_slave="Unknown",
                descrambler_locked=True,
                rx_symbol_errors=14,
                false_carrier_errors=3,
            ),
        )
        v_str, s_str = synthesize_wiremap_verdict(link, tdr)
        link.phy_wiring.verdict = v_str
        link.phy_wiring.summary = s_str
        sw = SwitchNeighbor(
            detected=True,
            protocols=["LLDP", "CDP"],
            confidence="HIGH",
            switch_name="IDF2-SW03",
            model="Aruba 2930F-24G-PoE+",
            vendor="HPE / Aruba",
            raw_descr="Aruba JL255A 2930F-24G-PoE+-4SFP+ Switch",
            mgmt_ip="172.24.10.2",
            chassis_mac="94:F1:28:6C:19:40",
            port_id="1/19",
            port_descr="WW-FL2-DESK-19",
            panel=panel,
        )
        autotest = evaluate_autotest(
            link, sw, vlan, l3, tdr, sec,
            profile=autotest_profile, auto_log=autotest_auto_log, duration_s=3.4,
        )
        return TesterSnapshot(
            timestamp=now_str,
            mode="demo",
            demo_scenario=scenario,
            autotest_verdict="WARN",
            autotest_duration_s=3.4,
            port_session_id=session_id,
            link=link,
            poe=PoeTelemetry(
                supported=True,
                enabled=True,
                standard="802.3af PoE",
                power_class="class-3",
                allocated_watts=15.4,
                requested_watts=12.9,
                power_pairs="signal",
                source_protocol="LLDP MDI-Power TLV",
            ),
            switch=sw,
            vlan=vlan,
            l3=l3,
            blink=blink,
            stress=stress,
            tdr=tdr,
            system=system,
            scan=scan,
            security=sec,
            audit=audit,
            autotest=autotest,
            diagnostics=diag,
            wifi=wifi_state,
            vlan_probe=vp_state,
            snmp=snmp_state,
            sync=sync_state,
            printer=printer_state,
            hw_nics=hw_state,
            wifi_client=wcli_state,
            static_ip=static_state,
            dot1x=dot1x_state,
        )

    if scenario == "nac_8021x_locked":
        panel = map_port_to_panel("ge-0/0/8", "CONF-ROOM-B04", "Juniper EX2300-48P", "EX2300-48P")
        panel.active_peer_ports = [1, 2, 4, 8, 11, 15, 22, 24, 30, 36, 44, 48]
        vlan = VlanAndNacTelemetry(
            native_vlan=999,
            native_vlan_name="VLAN 999 (UNAUTH_QUARANTINE)",
            eapol_8021x_seen=True,
            nac_status="802.1X Required (EAPOL Challenge Seen!)",
        )
        l3 = L3Connectivity(
            ipv4_address="169.254.88.14",
            subnet_cidr="169.254.88.14/16",
            dhcp_status="Blocked by 802.1X Port NAC",
            gateway_ip="—",
        )
        sec = evaluate_security_posture([], {"arp_frames_checked": 18, "arp_conflicts": []}, vlan, l3, SubnetScanState())
        link = LinkTelemetry(
            iface="eth0",
            carrier_up=True,
            operstate="up",
            mac_address="DC:A6:32:8F:14:2B",
            speed_mbps=1000,
            duplex="Full",
            autoneg=True,
            partner_supports_1g=True,
            local_supports_1g=True,
            pair_diagnostic_note="All 4 TIA-568B pairs active (1000BASE-T verified)",
            rx_packets=64,
            tx_packets=29,
            phy_wiring=PhyWiringState(
                supported=True,
                phy_name="Broadcom BCM54213PE (0x600d84a2 rev 2)",
                mdix_state="MDI",
                master_slave="Slave",
                local_rx_ok=True,
                remote_rx_ok=True,
                descrambler_locked=True,
            ),
        )
        v_str, s_str = synthesize_wiremap_verdict(link, tdr)
        link.phy_wiring.verdict = v_str
        link.phy_wiring.summary = s_str
        sw = SwitchNeighbor(
            detected=True,
            protocols=["LLDP"],
            confidence="CONFIRMED",
            switch_name="IDF1-EXEC-SW04",
            model="Juniper EX2300-48P",
            vendor="Juniper Networks",
            raw_descr="Juniper Networks, Inc. ex2300-48p Ethernet Switch, Junos 22.4R3",
            mgmt_ip="172.24.99.4",
            chassis_mac="2C:6B:F5:41:08:20",
            port_id="ge-0/0/8",
            port_descr="CONF-ROOM-B04",
            panel=panel,
        )
        autotest = evaluate_autotest(
            link, sw, vlan, l3, tdr, sec,
            profile=autotest_profile, auto_log=autotest_auto_log, duration_s=4.2,
        )
        return TesterSnapshot(
            timestamp=now_str,
            mode="demo",
            demo_scenario=scenario,
            autotest_verdict="WARN",
            autotest_duration_s=4.2,
            port_session_id=session_id,
            link=link,
            poe=PoeTelemetry(
                supported=True,
                enabled=True,
                standard="802.3at PoE+",
                power_class="class-4",
                allocated_watts=25.5,
                requested_watts=13.0,
                power_pairs="signal",
                source_protocol="LLDP MDI-Power TLV",
            ),
            switch=sw,
            vlan=vlan,
            l3=l3,
            blink=blink,
            stress=stress,
            tdr=tdr,
            system=system,
            scan=SubnetScanState(subnet="Quarantined"),
            security=sec,
            audit=audit,
            autotest=autotest,
            diagnostics=diag,
            wifi=wifi_state,
            vlan_probe=vp_state,
            snmp=snmp_state,
            sync=sync_state,
            printer=printer_state,
            hw_nics=hw_state,
            wifi_client=wcli_state,
            static_ip=static_state,
            dot1x=dot1x_state,
        )

    if scenario == "unpatched_dead":
        link = LinkTelemetry(
            iface="eth0",
            carrier_up=False,
            operstate="down",
            mac_address="DC:A6:32:8F:14:2B",
            duplex="Down",
            pair_diagnostic_note="No link carrier — TDR measures 28.6m intact copper run to unpatched panel",
            phy_wiring=PhyWiringState(
                supported=True,
                phy_name="Broadcom BCM54213PE (0x600d84a2 rev 2)",
            ),
        )
        v_str, s_str = synthesize_wiremap_verdict(link, tdr)
        link.phy_wiring.verdict = v_str
        link.phy_wiring.summary = s_str
        sw = SwitchNeighbor()
        vlan = VlanAndNacTelemetry(nac_status="N/A (Link Down)")
        l3 = L3Connectivity(dhcp_status="Link Down")
        sec = SecurityReportState(score=0, grade="—", summary="Link Down")
        autotest = evaluate_autotest(
            link, sw, vlan, l3, tdr, sec,
            profile=autotest_profile, auto_log=autotest_auto_log, duration_s=0.5,
        )
        return TesterSnapshot(
            timestamp=now_str,
            mode="demo",
            demo_scenario=scenario,
            autotest_verdict="NO_LINK",
            autotest_duration_s=0.5,
            port_session_id=session_id,
            link=link,
            poe=PoeTelemetry(),
            switch=sw,
            vlan=vlan,
            l3=l3,
            blink=blink,
            stress=stress,
            tdr=tdr,
            system=system,
            scan=SubnetScanState(),
            security=sec,
            audit=audit,
            autotest=autotest,
            diagnostics=diag,
            wifi=wifi_state,
            vlan_probe=vp_state,
            snmp=snmp_state,
            sync=sync_state,
            printer=printer_state,
            hw_nics=hw_state,
            wifi_client=wcli_state,
            static_ip=static_state,
            dot1x=dot1x_state,
        )

    panel = map_port_to_panel("1/17", "WW-FL2-STUDIO-04", "Aruba 2930F-24G-PoE+", "JL255A")
    panel.active_peer_ports = [1, 2, 3, 5, 6, 8, 10, 11, 14, 15, 17, 19, 22, 24]
    vlan = VlanAndNacTelemetry(
        native_vlan=40,
        native_vlan_name="VLAN 40 (STAFF_DATA)",
        voice_vlan=140,
        tagged_vlans=[40, 140, 210],
        nac_status="Open (No EAPOL Challenge)",
    )
    l3 = L3Connectivity(
        ipv4_address="172.24.10.84",
        subnet_cidr="172.24.10.84/24",
        dhcp_status="Bound (Dynamic)",
        gateway_ip="172.24.10.1",
        gateway_ping_ms=0.6,
        dns_server="172.24.10.5",
        dns_resolve_ms=3.1,
        internet_ok=True,
        http_probe_ms=12.8,
    )
    offers = [
        DhcpOfferInfo(
            server_ip="172.24.10.1",
            offered_ip="172.24.10.84",
            server_mac="00:09:0F:44:12:A8",
            vendor="Fortinet Inc.",
            router_ip="172.24.10.1",
            dns_ip="172.24.10.5",
            authorized=True,
            subnet_mask="255.255.255.0",
            lease_time_s=86400,
            domain_name="westwing.lan",
            ntp_server="172.24.10.5",
            tftp_server="172.24.10.12",
            boot_file="pxelinux.0",
        )
    ]
    clean_hosts = [h.model_copy(update={"open_ports": [p for p in h.open_ports if p != 23]}) for h in scan.hosts]
    clean_scan = scan.model_copy(update={"hosts": clean_hosts})
    sniffer_clean = {
        "arp_frames_checked": 524,
        "arp_conflicts": [],
        "bcast_pps": 3.2,
        "mcast_pps": 8.4,
        "stp": {
            "detected": True,
            "protocol": "RSTP",
            "root_priority": 32768,
            "root_mac": "94:F1:28:6C:19:40",
            "root_path_cost": 4,
            "bridge_mac": "94:F1:28:6C:19:40",
            "port_id": "0x8011 (#17)",
            "bpdu_count": 14,
        },
        "ipv6_ra_senders": [
            {
                "src_mac": "00:09:0F:44:12:A8",
                "src_ipv6": "fe80::209:fff:fe44:12a8",
                "router_lifetime_s": 1800,
                "count": 3,
            }
        ],
    }
    sec = evaluate_security_posture(offers, sniffer_clean, vlan, l3, clean_scan)
    is_2500 = hw_state.active_iface == "eth1"
    link = LinkTelemetry(
        iface=hw_state.active_iface or "eth0",
        carrier_up=True,
        operstate="up",
        mac_address="00:E0:4C:68:25:01" if is_2500 else "DC:A6:32:8F:14:2B",
        speed_mbps=2500 if is_2500 else 1000,
        duplex="Full",
        autoneg=True,
        partner_supports_1g=True,
        local_supports_1g=True,
        pair_diagnostic_note=(
            "All 4 TIA-568B pairs active (2.5GBASE-T multi-gig verified)"
            if is_2500
            else "All 4 TIA-568B pairs active (1000BASE-T verified)"
        ),
        rx_packets=4290,
        tx_packets=1412,
        phy_wiring=PhyWiringState(
            supported=True,
            phy_name=(
                "USB 2.5GbE PHY (ethtool)"
                if is_2500
                else "Broadcom BCM54213PE (0x600d84a2 rev 2)"
            ),
            mdix_state="MDI",
            master_slave="Slave",
            local_rx_ok=True,
            remote_rx_ok=True,
            descrambler_locked=True,
        ),
    )
    v_str, s_str = synthesize_wiremap_verdict(link, tdr)
    link.phy_wiring.verdict = v_str
    link.phy_wiring.summary = s_str
    sw = SwitchNeighbor(
        detected=True,
        protocols=["LLDP", "CDP"],
        confidence="HIGH",
        switch_name="IDF2-SW03",
        model="Aruba 2930F-24G-PoE+",
        vendor="HPE / Aruba",
        raw_descr="Aruba JL255A 2930F-24G-PoE+-4SFP+ Switch",
        mgmt_ip="172.24.10.2",
        chassis_mac="94:F1:28:6C:19:40",
        port_id="1/17",
        port_descr="WW-FL2-STUDIO-04",
        panel=panel,
    )
    autotest = evaluate_autotest(
        link, sw, vlan, l3, tdr, sec,
        profile=autotest_profile, auto_log=autotest_auto_log, duration_s=2.6,
    )

    return TesterSnapshot(
        timestamp=now_str,
        mode="demo",
        demo_scenario="healthy_1g",
        autotest_verdict="PASS",
        autotest_duration_s=2.6,
        port_session_id=session_id,
        link=link,
        poe=PoeTelemetry(
            supported=True,
            enabled=True,
            standard="802.3at PoE+",
            power_class="class-4",
            allocated_watts=25.5,
            requested_watts=13.0,
            power_pairs="signal",
            source_protocol="LLDP-MED + CDP Power TLV",
        ),
        switch=sw,
        vlan=vlan,
        l3=l3,
        blink=blink,
        stress=stress,
        tdr=tdr,
        system=system,
        scan=clean_scan,
        security=sec,
        audit=audit,
        autotest=autotest,
        diagnostics=diag,
        wifi=wifi_state,
        vlan_probe=vp_state,
        snmp=snmp_state,
        sync=sync_state,
        printer=printer_state,
        hw_nics=hw_state,
        wifi_client=wcli_state,
        static_ip=static_state,
        dot1x=dot1x_state,
    )
