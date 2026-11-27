import asyncio
import re
import socket
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .diagnostics import validate_host_target
from .models import DiscoveredHost, HostInspectResult

COMMON_SCAN_PORTS = (
    21, 22, 23, 53, 80, 139, 161, 443, 445, 554, 1883, 3389, 5000, 5001, 8080, 8443, 9100
)

PORT_SERVICE_MAP: Dict[int, str] = {
    21: "21:FTP",
    22: "22:SSH",
    23: "23:Telnet",
    53: "53:DNS",
    80: "80:HTTP",
    139: "139:NetBIOS",
    161: "161:SNMP",
    443: "443:HTTPS",
    445: "445:SMB",
    554: "554:RTSP",
    1883: "1883:MQTT",
    3389: "3389:RDP",
    5000: "5000:UPnP/DSM",
    5001: "5001:Synology-HTTPS",
    8080: "8080:HTTP-Alt",
    8443: "8443:HTTPS-Alt",
    9100: "9100:JetDirect",
}

_MAC_HEX_RE = re.compile(r"^[0-9A-Fa-f]{12}$")


def build_wol_magic_packet(mac: str) -> bytes:
    """Validate MAC address and build a 102-byte Wake-on-LAN magic packet."""
    clean = re.sub(r"[:\-.]", "", (mac or "").strip())
    if not _MAC_HEX_RE.match(clean):
        raise ValueError(f"Invalid MAC address for Wake-on-LAN: {mac!r}")
    mac_bytes = bytes.fromhex(clean)
    return b"\xff" * 6 + mac_bytes * 16


def send_wol_packet(mac: str, broadcast_ip: str = "255.255.255.255") -> bool:
    """Send UDP Wake-on-LAN magic packet on port 9."""
    pkt = build_wol_magic_packet(mac)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(pkt, (broadcast_ip, 9))
        return True
    except OSError:
        return False
    finally:
        sock.close()


async def _tcp_probe(ip: str, port: int, timeout_s: float = 0.35) -> Optional[int]:
    try:
        fut = asyncio.open_connection(ip, port)
        _reader, writer = await asyncio.wait_for(fut, timeout=timeout_s)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port
    except Exception:
        return None


def _fetch_http_title_sync(ip: str, ports: List[int]) -> str:
    for p in (80, 8080):
        if p not in ports:
            continue
        url = f"http://{ip}:{p}/" if p != 80 else f"http://{ip}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "JackTrace/1.0"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                raw = resp.read(8192).decode("utf-8", errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()
                if title:
                    return title[:60]
        except Exception:
            continue
    return ""


def _infer_mdns_hints(open_ports: List[int], hostname: str) -> List[str]:
    hints: List[str] = []
    if 22 in open_ports:
        hints.append("_ssh._tcp")
    if 80 in open_ports or 443 in open_ports or 8080 in open_ports:
        hints.append("_http._tcp")
    if 445 in open_ports:
        hints.append("_smb._tcp")
    if 9100 in open_ports:
        hints.append("_pdl-datastream._tcp")
    if hostname.endswith(".local"):
        hints.append(f"mDNS: {hostname}")
    return hints


async def inspect_host_deep(
    ip: str,
    existing_host: Optional[DiscoveredHost],
    demo_mode: bool,
) -> HostInspectResult:
    clean_ip = validate_host_target(ip)
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    base_host = existing_host.hostname if existing_host else "—"
    base_mac = existing_host.mac if existing_host else "—"
    base_vendor = existing_host.vendor if existing_host else "Unknown"
    base_role = existing_host.role if existing_host else "Host"
    base_rtt = existing_host.rtt_ms if existing_host else None

    if demo_mode:
        await asyncio.sleep(0.15)
        ports = list(existing_host.open_ports) if (existing_host and existing_host.open_ports) else [22, 80, 443]
        svcs = [PORT_SERVICE_MAP.get(p, f"{p}:TCP") for p in ports]
        title = f"{base_vendor} Management Portal" if (80 in ports or 443 in ports) else ""
        return HostInspectResult(
            ip=clean_ip,
            hostname=base_host,
            mac=base_mac,
            vendor=base_vendor,
            role=base_role,
            rtt_ms=base_rtt if base_rtt is not None else 1.2,
            open_ports=ports,
            port_services=svcs,
            http_title=title,
            mdns_services=_infer_mdns_hints(ports, base_host),
            scanned_at=ts,
        )

    probes = await asyncio.gather(*[_tcp_probe(clean_ip, p, 0.35) for p in COMMON_SCAN_PORTS])
    open_ports = sorted([p for p in probes if p is not None])
    port_services = [PORT_SERVICE_MAP.get(p, f"{p}:TCP") for p in open_ports]
    http_title = await asyncio.to_thread(_fetch_http_title_sync, clean_ip, open_ports) if open_ports else ""

    return HostInspectResult(
        ip=clean_ip,
        hostname=base_host,
        mac=base_mac,
        vendor=base_vendor,
        role=base_role,
        rtt_ms=base_rtt,
        open_ports=open_ports,
        port_services=port_services,
        http_title=http_title,
        mdns_services=_infer_mdns_hints(open_ports, base_host),
        scanned_at=ts,
    )
