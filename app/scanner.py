import asyncio
import ipaddress
import json
import re
import socket
import struct
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from .models import DiscoveredHost, SubnetScanState
from .oui_db import lookup_mac_vendor

PROBE_PORTS = (22, 23, 53, 80, 88, 139, 389, 443, 445, 554, 3389, 5000, 5001, 8006, 8080, 8443, 9100)


def infer_host_role(
    ip: str,
    gateway_ip: str,
    switch_ip: str,
    vendor: str,
    open_ports: List[int],
) -> str:
    pset = set(open_ports)
    vlow = vendor.lower()

    if ip == gateway_ip:
        return "Gateway / Firewall"
    if ip == switch_ip or ("cisco" in vlow and (22 in pset or 23 in pset)):
        return "Managed Switch"
    if 88 in pset and (389 in pset or 53 in pset):
        return "Domain Controller"
    if 9100 in pset or "brother" in vlow or ("hp inc" in vlow and 80 in pset):
        return "Network Printer"
    if 5000 in pset or 5001 in pset or "synology" in vlow or "qnap" in vlow:
        return "NAS Storage"
    if 8006 in pset or "proxmox" in vlow or "vmware" in vlow:
        return "Hypervisor"
    if 554 in pset or "hikvision" in vlow or "axis" in vlow:
        return "IP Camera / NVR"
    if "ubiquiti" in vlow or "aruba" in vlow or "meraki" in vlow:
        return "Switch / Wi-Fi AP"
    if 53 in pset:
        return "DNS / Infra"
    if 3389 in pset or 445 in pset or 139 in pset:
        return "Windows / SMB Host"
    if 22 in pset or 443 in pset or 80 in pset:
        return "Linux / Web Device"
    return "Active Host"


def _query_netbios_name(ip: str, timeout: float = 0.35) -> str:
    """Send a 50-byte UDP 137 NetBIOS Node Status (NBSTAT) query for Windows/NAS hostnames."""
    pkt = (
        b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(pkt, (ip, 137))
            data, _ = s.recvfrom(512)
        # Parse NBSTAT response: header(12) + qname(34) + type/class/ttl/rdlen(10) + num_names(1)
        if len(data) > 57:
            num_names = data[56]
            offset = 57
            for _ in range(num_names):
                if offset + 18 > len(data):
                    break
                raw_name = data[offset : offset + 15].decode("ascii", errors="ignore").strip()
                suffix = data[offset + 15]
                flags = struct.unpack("!H", data[offset + 16 : offset + 18])[0]
                is_group = bool(flags & 0x8000)
                if suffix in (0x00, 0x20) and not is_group and raw_name:
                    return raw_name.lower()
                offset += 18
    except OSError:
        pass
    return ""


def _resolve_hostname_sync(ip: str) -> str:
    # 1. Reverse DNS (PTR)
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        if name and name != ip:
            return name
    except OSError:
        pass

    # 2. NetBIOS NBSTAT fallback
    nb = _query_netbios_name(ip)
    if nb:
        return nb
    return "—"


def _run_arp_scan(iface: str, cidr: str) -> Dict[str, Tuple[str, Optional[float]]]:
    """
    Use `arp-scan` if installed on Linux for fast, complete L2 host + MAC + RTT discovery.
    Returns dict: ip -> (mac, rtt_ms)
    """
    found: Dict[str, Tuple[str, Optional[float]]] = {}
    for prefix in ([], ["sudo", "-n"]):
        try:
            proc = subprocess.run(
                prefix
                + [
                    "arp-scan",
                    f"--interface={iface}",
                    "--numeric",
                    "--quiet",
                    "--retry=2",
                    "--timeout=250",
                    cidr,
                ],
                capture_output=True,
                text=True,
                timeout=8.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    m = re.match(
                        r"^(\d+\.\d+\.\d+\.\d+)\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})(?:\s+([\d.]+)\s*ms)?",
                        line.strip(),
                    )
                    if m:
                        ip_s = m.group(1)
                        mac_s = m.group(2).upper()
                        rtt = float(m.group(4)) if m.group(4) else None
                        found[ip_s] = (mac_s, rtt)
                return found
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return found


def _read_kernel_arp_neighbors(iface: str) -> Dict[str, str]:
    """Fallback: read kernel ARP neighbor table via `ip -j -4 neigh`."""
    out_map: Dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["ip", "-j", "-4", "neigh", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=2.5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            rows = json.loads(proc.stdout)
            for r in rows:
                dst = r.get("dst", "")
                lladdr = r.get("lladdr", "")
                state = r.get("state", [])
                if dst and lladdr and "FAILED" not in state:
                    out_map[dst] = lladdr.upper()
    except Exception:
        pass
    return out_map


async def _tcp_probe_port(ip: str, port: int, timeout: float = 0.32) -> bool:
    try:
        fut = asyncio.open_connection(ip, port)
        _r, writer = await asyncio.wait_for(fut, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _nudge_host(ip: str, sem: asyncio.Semaphore) -> None:
    """Light TCP SYN nudge to populate Linux kernel ARP cache when arp-scan is absent."""
    async with sem:
        await _tcp_probe_port(ip, 80, timeout=0.18)


async def _enrich_host(
    ip: str,
    mac: str,
    rtt: Optional[float],
    gateway_ip: str,
    switch_ip: str,
    sem: asyncio.Semaphore,
) -> DiscoveredHost:
    async with sem:
        hostname_task = asyncio.to_thread(_resolve_hostname_sync, ip)
        port_tasks = [_tcp_probe_port(ip, p, timeout=0.35) for p in PROBE_PORTS]
        results = await asyncio.gather(hostname_task, *port_tasks)
        hostname = results[0]
        open_ports = [p for p, is_open in zip(PROBE_PORTS, results[1:]) if is_open]
        vendor = lookup_mac_vendor(mac)
        role = infer_host_role(ip, gateway_ip, switch_ip, vendor, open_ports)
        return DiscoveredHost(
            ip=ip,
            hostname=hostname,
            mac=mac,
            vendor=vendor,
            open_ports=open_ports,
            role=role,
            rtt_ms=rtt,
        )


def clamp_scan_cidr(subnet_cidr: str) -> Optional[ipaddress.IPv4Network]:
    """Clamp large networks (e.g. /16) to the local /24 around our interface IP for fast scans."""
    if not subnet_cidr or "/" not in subnet_cidr:
        return None
    try:
        iface_ip = ipaddress.IPv4Interface(subnet_cidr)
        if iface_ip.network.prefixlen < 24:
            return ipaddress.IPv4Network(f"{iface_ip.ip}/24", strict=False)
        return iface_ip.network
    except ValueError:
        return None


async def sweep_subnet(
    iface: str,
    subnet_cidr: str,
    local_ip: str,
    local_mac: str,
    gateway_ip: str = "—",
    switch_ip: str = "—",
) -> SubnetScanState:
    t0 = time.monotonic()
    net = clamp_scan_cidr(subnet_cidr)
    if net is None:
        return SubnetScanState(
            scanning=False,
            subnet=subnet_cidr,
            last_scan_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            duration_s=0.0,
            active_count=0,
            hosts=[],
        )

    cidr_str = str(net)
    arp_map = await asyncio.to_thread(_run_arp_scan, iface, cidr_str)

    if not arp_map:
        # Fallback: nudge all hosts in /24 concurrently then read kernel ARP table
        nudge_sem = asyncio.Semaphore(64)
        await asyncio.gather(
            *[_nudge_host(str(h), nudge_sem) for h in net.hosts() if str(h) != local_ip]
        )
        neigh = await asyncio.to_thread(_read_kernel_arp_neighbors, iface)
        for ip_s, mac_s in neigh.items():
            try:
                if ipaddress.IPv4Address(ip_s) in net:
                    arp_map[ip_s] = (mac_s, None)
            except ValueError:
                pass

    # Include local tester IP if bound
    if local_ip and local_ip != "—" and not local_ip.startswith("169.254."):
        arp_map.setdefault(local_ip, (local_mac, 0.1))

    enrich_sem = asyncio.Semaphore(24)
    hosts = await asyncio.gather(
        *[
            _enrich_host(ip_s, mac_s, rtt_v, gateway_ip, switch_ip, enrich_sem)
            for ip_s, (mac_s, rtt_v) in arp_map.items()
        ]
    )

    hosts_sorted = sorted(hosts, key=lambda h: tuple(int(x) for x in h.ip.split(".")))
    dur = round(time.monotonic() - t0, 2)

    return SubnetScanState(
        scanning=False,
        subnet=cidr_str,
        last_scan_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
        duration_s=dur,
        active_count=len(hosts_sorted),
        hosts=hosts_sorted,
    )
