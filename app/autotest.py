from datetime import datetime, timezone
from typing import List

from .models import (
    AutoTestState,
    AutoTestStep,
    L3Connectivity,
    LinkTelemetry,
    SecurityReportState,
    SwitchNeighbor,
    TdrReportState,
    VlanAndNacTelemetry,
)


def evaluate_autotest(
    link: LinkTelemetry,
    switch: SwitchNeighbor,
    vlan: VlanAndNacTelemetry,
    l3: L3Connectivity,
    tdr: TdrReportState,
    security: SecurityReportState,
    profile: str = "standard",
    auto_log: bool = False,
    duration_s: float = 0.0,
) -> AutoTestState:
    """Evaluate all 7 AutoTest stages into a unified pass/warn/fail checklist."""
    norm_profile = "lan_only" if profile == "lan_only" else "standard"
    steps: List[AutoTestStep] = []

    # 1. Physical Link
    if not link.carrier_up:
        steps.append(
            AutoTestStep(
                key="link",
                label="Physical Link",
                status="FAIL",
                value="Link Down",
                detail=link.pair_diagnostic_note,
            )
        )
    elif link.pair_downshift_suspected or tdr.overall_verdict == "FAIL":
        spd = f"{link.speed_mbps or '?'} Mbps {link.duplex}"
        detail = tdr.summary if tdr.overall_verdict == "FAIL" else link.pair_diagnostic_note
        steps.append(
            AutoTestStep(
                key="link",
                label="Physical Link",
                status="WARN",
                value=spd,
                detail=detail,
            )
        )
    elif link.phy_wiring.verdict in ("WARN", "FAIL"):
        steps.append(
            AutoTestStep(
                key="link",
                label="Physical Link",
                status="WARN",
                value=f"{link.speed_mbps or '?'} Mbps {link.duplex}",
                detail=link.phy_wiring.summary,
            )
        )
    else:
        steps.append(
            AutoTestStep(
                key="link",
                label="Physical Link",
                status="PASS",
                value=f"{link.speed_mbps or '?'} Mbps {link.duplex}",
                detail=link.pair_diagnostic_note,
            )
        )

    # 2. Switch ID (LLDP / CDP)
    if not link.carrier_up:
        steps.append(
            AutoTestStep(
                key="switch",
                label="Switch ID (LLDP/CDP)",
                status="WAIT",
                value="No Carrier",
                detail="Plug into live switch port",
            )
        )
    elif switch.detected:
        protos = "/".join(switch.protocols) if switch.protocols else "LLDP"
        steps.append(
            AutoTestStep(
                key="switch",
                label="Switch ID (LLDP/CDP)",
                status="PASS",
                value=f"{switch.switch_name} • {switch.port_id}",
                detail=f"{switch.model} ({protos})",
            )
        )
    else:
        steps.append(
            AutoTestStep(
                key="switch",
                label="Switch ID (LLDP/CDP)",
                status="WARN",
                value="Unmanaged / Listening",
                detail="No LLDP or CDP neighbor frame received yet",
            )
        )

    # 3. IPv4 / DHCP
    if not link.carrier_up:
        steps.append(
            AutoTestStep(
                key="dhcp",
                label="IPv4 / DHCP",
                status="WAIT",
                value="No Carrier",
                detail="Waiting for Ethernet link",
            )
        )
    elif l3.ipv4_address in ("—", "") or l3.ipv4_address.startswith("169.254."):
        steps.append(
            AutoTestStep(
                key="dhcp",
                label="IPv4 / DHCP",
                status="FAIL",
                value=l3.ipv4_address if l3.ipv4_address not in ("—", "") else "No Lease",
                detail=l3.dhcp_status or "No DHCP lease acquired",
            )
        )
    else:
        steps.append(
            AutoTestStep(
                key="dhcp",
                label="IPv4 / DHCP",
                status="PASS",
                value=l3.subnet_cidr if l3.subnet_cidr != "—" else l3.ipv4_address,
                detail=l3.dhcp_status,
            )
        )

    # 4. Default Gateway
    if not link.carrier_up:
        steps.append(
            AutoTestStep(
                key="gateway",
                label="Default Gateway",
                status="WAIT",
                value="—",
                detail="Waiting for Ethernet link",
            )
        )
    elif l3.gateway_ip in ("—", "") or l3.gateway_ping_ms is None:
        steps.append(
            AutoTestStep(
                key="gateway",
                label="Default Gateway",
                status="FAIL",
                value=l3.gateway_ip if l3.gateway_ip != "—" else "Unreachable",
                detail="Gateway did not respond to ICMP ping",
            )
        )
    elif l3.gateway_ping_ms > 50.0:
        steps.append(
            AutoTestStep(
                key="gateway",
                label="Default Gateway",
                status="WARN",
                value=f"{l3.gateway_ip} ({l3.gateway_ping_ms}ms)",
                detail="High local gateway latency (> 50ms)",
            )
        )
    else:
        steps.append(
            AutoTestStep(
                key="gateway",
                label="Default Gateway",
                status="PASS",
                value=f"{l3.gateway_ip} ({l3.gateway_ping_ms}ms)",
                detail="ICMP gateway reachable",
            )
        )

    # 5. DNS Resolver
    if not link.carrier_up:
        steps.append(
            AutoTestStep(
                key="dns",
                label="DNS Resolver",
                status="WAIT",
                value="—",
                detail="Waiting for Ethernet link",
            )
        )
    elif norm_profile == "lan_only" and l3.dns_server in ("—", ""):
        steps.append(
            AutoTestStep(
                key="dns",
                label="DNS Resolver",
                status="SKIP",
                value="Skipped",
                detail="No DNS configured (LAN-Only profile)",
            )
        )
    elif l3.dns_resolve_ms is None:
        steps.append(
            AutoTestStep(
                key="dns",
                label="DNS Resolver",
                status="FAIL",
                value=l3.dns_server if l3.dns_server != "—" else "Failed",
                detail="DNS lookup timed out or refused",
            )
        )
    else:
        steps.append(
            AutoTestStep(
                key="dns",
                label="DNS Resolver",
                status="PASS",
                value=f"{l3.dns_server} ({l3.dns_resolve_ms}ms)",
                detail="Forward DNS resolution verified",
            )
        )

    # 6. Internet & Portal
    if norm_profile == "lan_only":
        steps.append(
            AutoTestStep(
                key="wan",
                label="Internet & Portal",
                status="SKIP",
                value="Skipped",
                detail="Skipped in LAN-Only profile",
            )
        )
    elif not link.carrier_up:
        steps.append(
            AutoTestStep(
                key="wan",
                label="Internet & Portal",
                status="WAIT",
                value="—",
                detail="Waiting for Ethernet link",
            )
        )
    elif l3.captive_portal:
        steps.append(
            AutoTestStep(
                key="wan",
                label="Internet & Portal",
                status="WARN",
                value="Captive Portal",
                detail="HTTP redirect intercepted WAN probe",
            )
        )
    elif not l3.internet_ok:
        steps.append(
            AutoTestStep(
                key="wan",
                label="Internet & Portal",
                status="FAIL",
                value="Offline",
                detail="WAN HTTP 204 reachability check failed",
            )
        )
    else:
        steps.append(
            AutoTestStep(
                key="wan",
                label="Internet & Portal",
                status="PASS",
                value=f"204 OK ({l3.http_probe_ms}ms)",
                detail="Clean Internet egress without portal",
            )
        )

    # 7. Security Posture
    if not link.carrier_up:
        steps.append(
            AutoTestStep(
                key="security",
                label="Security Posture",
                status="WAIT",
                value="—",
                detail="Waiting for Ethernet link",
            )
        )
    elif security.rogue_dhcp_detected or bool(security.arp_conflicts):
        detail = "Rogue DHCP offer detected" if security.rogue_dhcp_detected else "ARP MAC conflict observed"
        steps.append(
            AutoTestStep(
                key="security",
                label="Security Posture",
                status="FAIL",
                value=f"Grade {security.grade} ({security.score}/100)",
                detail=detail,
            )
        )
    elif vlan.eapol_8021x_seen or security.score < 80:
        detail = "802.1X EAPOL NAC challenge" if vlan.eapol_8021x_seen else security.summary
        steps.append(
            AutoTestStep(
                key="security",
                label="Security Posture",
                status="WARN",
                value=f"Grade {security.grade} ({security.score}/100)",
                detail=detail,
            )
        )
    else:
        steps.append(
            AutoTestStep(
                key="security",
                label="Security Posture",
                status="PASS",
                value=f"Grade {security.grade} ({security.score}/100)",
                detail=security.summary,
            )
        )

    active_steps = [s for s in steps if s.status != "SKIP"]
    passed_count = sum(1 for s in active_steps if s.status == "PASS")
    total_count = len(active_steps)

    if not link.carrier_up:
        verdict = "NO_LINK"
        summary = "No Ethernet carrier — plug eth0 into a wall socket"
    elif any(s.status == "FAIL" for s in active_steps):
        failed = [s.label for s in active_steps if s.status == "FAIL"]
        verdict = "FAIL"
        summary = f"Failed: {', '.join(failed[:2])}" + ("..." if len(failed) > 2 else "")
    elif any(s.status == "WARN" for s in active_steps):
        warned = [s.label for s in active_steps if s.status == "WARN"]
        verdict = "WARN"
        summary = f"Warnings on: {', '.join(warned[:2])}"
    elif active_steps and all(s.status == "PASS" for s in active_steps):
        verdict = "PASS"
        summary = (
            f"All {passed_count}/{total_count} checks passed"
            + (" (LAN-Only)" if norm_profile == "lan_only" else " (Standard WAN)")
        )
    else:
        verdict = "TESTING"
        summary = f"Running checks ({passed_count}/{total_count} passed)..."

    return AutoTestState(
        profile=norm_profile,
        auto_log=auto_log,
        running=False,
        verdict=verdict,
        summary=summary,
        passed_count=passed_count,
        total_count=total_count,
        duration_s=round(duration_s, 1),
        last_run_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        steps=steps,
    )
