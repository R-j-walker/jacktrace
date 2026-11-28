import ipaddress
import os
import re
import subprocess
from typing import Callable, Optional, Tuple

from .models import StaticIpState

VALID_WIRED_IFACE_RE = re.compile(r"^(eth|enx|enp|eno)[A-Za-z0-9_.-]{0,16}$")


def validate_wired_iface(iface: str) -> str:
    """Allow only wired Ethernet interfaces; never allow wlan*, lo, or br*."""
    clean = (iface or "").strip()
    if not clean or not VALID_WIRED_IFACE_RE.match(clean):
        raise ValueError(f"Static IPv4 / 802.1X is restricted to wired NICs (got '{clean}')")
    return clean


def validate_static_ipv4(
    ip_cidr: str,
    gateway: str = "",
    dns: str = "",
) -> Tuple[str, str, str]:
    """Validate manual IPv4 CIDR, optional gateway, and optional DNS address."""
    raw_cidr = (ip_cidr or "").strip()
    if "/" not in raw_cidr:
        raise ValueError("IP/CIDR must include subnet prefix length (e.g. 192.168.1.50/24)")
    try:
        iface_net = ipaddress.IPv4Interface(raw_cidr)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4/CIDR '{raw_cidr}'") from exc

    if iface_net.network.prefixlen < 1 or iface_net.network.prefixlen > 32:
        raise ValueError("Subnet prefix must be /1 to /32")
    if iface_net.ip.is_loopback or iface_net.ip.is_multicast or iface_net.ip.is_unspecified:
        raise ValueError(f"Unsupported host IPv4 address: {iface_net.ip}")

    clean_gw = ""
    if (gateway or "").strip():
        try:
            gw_addr = ipaddress.IPv4Address(gateway.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid gateway IP '{gateway}'") from exc
        if gw_addr.is_loopback or gw_addr.is_multicast or gw_addr.is_unspecified:
            raise ValueError(f"Invalid gateway IP '{gateway}'")
        clean_gw = str(gw_addr)

    clean_dns = ""
    if (dns or "").strip():
        try:
            dns_addr = ipaddress.IPv4Address(dns.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid DNS IP '{dns}'") from exc
        if dns_addr.is_loopback or dns_addr.is_multicast or dns_addr.is_unspecified:
            raise ValueError(f"Invalid DNS IP '{dns}'")
        clean_dns = str(dns_addr)

    return str(iface_net), clean_gw, clean_dns


def _run_nmcli(args: list[str], timeout: float = 8.0) -> Tuple[int, str]:
    for prefix in ([], ["sudo", "-n"]):
        try:
            proc = subprocess.run(
                prefix + args,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            msg = (proc.stderr or proc.stdout or "").strip()
            if proc.returncode == 0:
                return 0, msg
            if "not authorized" in msg.lower() or "permission" in msg.lower():
                continue
            return proc.returncode, msg
        except FileNotFoundError:
            return 127, "nmcli not installed"
        except subprocess.TimeoutExpired:
            return 124, "nmcli timed out"
        except OSError as exc:
            return 1, str(exc)
    return 1, "nmcli permission denied"


def _is_nm_unmanaged_error(msg: str) -> bool:
    low = (msg or "").lower()
    return any(
        tok in low
        for tok in (
            "unmanaged",
            "not managed",
            "not installed",
            "no active connection",
            "not running",
            "could not find connection",
        )
    )


def _apply_static_iproute2(
    iface: str,
    ip_cidr: str,
    gateway: str = "",
    dns: str = "",
) -> Tuple[bool, str]:
    rc, msg = _run_nmcli(["ip", "-4", "addr", "flush", "dev", iface])
    if rc != 0:
        return False, msg or f"ip addr flush failed ({rc})"
    rc, msg = _run_nmcli(["ip", "addr", "add", ip_cidr, "dev", iface])
    if rc != 0:
        return False, msg or f"ip addr add failed ({rc})"
    _run_nmcli(["ip", "link", "set", "dev", iface, "up"])
    if gateway:
        rc_gw, msg_gw = _run_nmcli(["ip", "route", "replace", "default", "via", gateway, "dev", iface])
        if rc_gw != 0:
            return False, msg_gw or f"ip route replace failed ({rc_gw})"
    if dns:
        _run_nmcli(["resolvectl", "dns", iface, dns], timeout=3.0)
    return True, f"Static {ip_cidr} (iproute2)"


def _revert_dhcp_iproute2(iface: str) -> Tuple[bool, str]:
    _run_nmcli(["ip", "-4", "addr", "flush", "dev", iface])
    _run_nmcli(["ip", "link", "set", "dev", iface, "up"])
    for cmd in (["dhclient", "-1", iface], ["dhcpcd", "-n", iface]):
        rc, msg = _run_nmcli(cmd, timeout=10.0)
        if rc == 0:
            return True, "DHCP (iproute2)"
        if rc != 127:
            return False, msg or f"{cmd[0]} failed ({rc})"
    return True, "DHCP flushed (reconnect cable or restart networking)"


class StaticIpv4Manager:
    """Manages temporary non-persistent Static IPv4 overrides on the active wired NIC."""

    def __init__(self, on_change: Optional[Callable[[], None]] = None) -> None:
        self._on_change = on_change or (lambda: None)
        self.state = StaticIpState()

    def snapshot(self) -> StaticIpState:
        return self.state.model_copy(deep=True)

    def apply_static(
        self,
        iface: str,
        ip_cidr: str,
        gateway: str = "",
        dns: str = "",
        demo_mode: bool = False,
    ) -> StaticIpState:
        clean_if = validate_wired_iface(iface)
        clean_cidr, clean_gw, clean_dns = validate_static_ipv4(ip_cidr, gateway, dns)

        if demo_mode or os.name == "nt":
            self.state = StaticIpState(
                iface=clean_if,
                mode="static",
                ip_cidr=clean_cidr,
                gateway=clean_gw,
                dns=clean_dns,
                status=f"Static {clean_cidr} (Demo)" if demo_mode else f"Static {clean_cidr}",
                error="",
            )
            self._on_change()
            return self.snapshot()

        cmd = [
            "nmcli",
            "dev",
            "modify",
            clean_if,
            "ipv4.method",
            "manual",
            "ipv4.addresses",
            clean_cidr,
            "ipv4.gateway",
            clean_gw,
            "ipv4.dns",
            clean_dns,
        ]
        rc, msg = _run_nmcli(cmd)
        status_txt = f"Static {clean_cidr}"
        if rc != 0:
            if _is_nm_unmanaged_error(msg):
                ok_fb, msg_fb = _apply_static_iproute2(clean_if, clean_cidr, clean_gw, clean_dns)
                if ok_fb:
                    status_txt = msg_fb
                else:
                    self.state = self.state.model_copy(
                        update={
                            "iface": clean_if,
                            "error": msg_fb or msg or f"Static apply failed ({rc})",
                            "status": "Static Apply Failed",
                        }
                    )
                    self._on_change()
                    raise RuntimeError(self.state.error)
            else:
                self.state = self.state.model_copy(
                    update={
                        "iface": clean_if,
                        "error": msg or f"nmcli modify failed ({rc})",
                        "status": "Static Apply Failed",
                    }
                )
                self._on_change()
                raise RuntimeError(self.state.error)

        self.state = StaticIpState(
            iface=clean_if,
            mode="static",
            ip_cidr=clean_cidr,
            gateway=clean_gw,
            dns=clean_dns,
            status=status_txt,
            error="",
        )
        self._on_change()
        return self.snapshot()

    def revert_dhcp(self, iface: str, demo_mode: bool = False) -> StaticIpState:
        clean_if = validate_wired_iface(iface)

        if demo_mode or os.name == "nt":
            self.state = StaticIpState(
                iface=clean_if,
                mode="dhcp",
                ip_cidr="",
                gateway="",
                dns="",
                status="DHCP (Auto)",
                error="",
            )
            self._on_change()
            return self.snapshot()

        rc, msg = _run_nmcli(
            [
                "nmcli",
                "dev",
                "modify",
                clean_if,
                "ipv4.method",
                "auto",
                "ipv4.addresses",
                "",
                "ipv4.gateway",
                "",
                "ipv4.dns",
                "",
            ]
        )
        if rc == 0:
            _run_nmcli(["nmcli", "dev", "reapply", clean_if], timeout=6.0)
            status_txt = "DHCP (Auto)"
        elif _is_nm_unmanaged_error(msg):
            ok_fb, msg_fb = _revert_dhcp_iproute2(clean_if)
            if not ok_fb:
                self.state = self.state.model_copy(
                    update={"iface": clean_if, "error": msg_fb or msg or f"DHCP revert failed ({rc})"}
                )
                self._on_change()
                raise RuntimeError(self.state.error)
            status_txt = msg_fb
        else:
            self.state = self.state.model_copy(
                update={"iface": clean_if, "error": msg or f"DHCP revert failed ({rc})"}
            )
            self._on_change()
            raise RuntimeError(self.state.error)

        self.state = StaticIpState(
            iface=clean_if,
            mode="dhcp",
            ip_cidr="",
            gateway="",
            dns="",
            status=status_txt,
            error="",
        )
        self._on_change()
        return self.snapshot()
