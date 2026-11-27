import os
import platform
import socket
import struct
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from .pentest_sniffer import PassiveExposureMonitor

SOL_PACKET = getattr(socket, "SOL_PACKET", 263)
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6
MAX_CONTINUOUS_PCAP_BYTES = 100 * 1024 * 1024


def extract_auxdata_vlan(ancdata: Any) -> Optional[Tuple[int, int]]:
    """Extract (tpid, vlan_tci) from Linux AF_PACKET PACKET_AUXDATA cmsg ancillary data."""
    for lvl, ctype, cdata in ancdata or ():
        if lvl == SOL_PACKET and ctype == PACKET_AUXDATA and len(cdata) >= 20:
            status, _ln, _netoff, _mac, vlan_tci, vlan_tpid = struct.unpack("=IIIIHH", cdata[:20])
            if status & TP_STATUS_VLAN_VALID:
                tpid = vlan_tpid if (status & TP_STATUS_VLAN_TPID_VALID and vlan_tpid) else 0x8100
                return tpid, vlan_tci
    return None


def reinsert_vlan_tag(frame: bytes, tpid: int, vlan_tci: int) -> bytes:
    """Reinsert kernel-stripped 802.1Q/802.1ad tag header after src MAC."""
    if len(frame) < 14:
        return frame
    return frame[:12] + struct.pack("!HH", tpid, vlan_tci) + frame[12:]


class PassiveL2Sniffer:
    """
    Lightweight pure-Python AF_PACKET listener on Linux.
    Passively observes Ethernet frames on the test port to detect:
      1. Tagged 802.1Q / 802.1ad VLAN IDs
      2. 802.1X EAPOL authentication challenges (0x888e)
      3. Direct LLDP (0x88cc) and Cisco CDP (SNAP 0x2000) frames
      4. Passive ARP spoofing / duplicate IPv4 MAC conflicts (0x0806)
      5. On-demand standard libpcap (.pcap) packet capture
    """

    def __init__(self, iface: str):
        self.iface = iface
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._tagged_vlans: Set[int] = set()
        self._eapol_seen: bool = False
        self._raw_neighbor: Dict[str, str] = {}

        # Phase 2: Passive ARP guard
        self._arp_frames_checked: int = 0
        self._arp_ip_macs: Dict[str, Set[str]] = {}

        # Milestone 3: Deep L2 forensics (STP/RSTP, Broadcast/Multicast PPS, IPv6 RA)
        self._bcast_ts: Deque[float] = deque()
        self._mcast_ts: Deque[float] = deque()
        self._stp_info: Dict[str, Any] = {}
        self._ipv6_ra: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._exposure = PassiveExposureMonitor()

        # Phase 2: On-demand PCAP writer
        self._pcap_path: Optional[str] = None
        self._pcap_end_mono: float = 0.0
        self._pcap_continuous: bool = False
        self._pcap_packets: int = 0
        self._pcap_bytes: int = 0
        self._pcap_completed_at: Optional[str] = None
        self._pcap_fh = None

    def start(self) -> None:
        if platform.system() != "Linux" or not hasattr(socket, "AF_PACKET"):
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="l2-sniffer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._lock:
            self._close_pcap_locked()

    def reset_session(self) -> None:
        with self._lock:
            self._tagged_vlans.clear()
            self._eapol_seen = False
            self._raw_neighbor.clear()
            self._arp_frames_checked = 0
            self._arp_ip_macs.clear()
            self._bcast_ts.clear()
            self._mcast_ts.clear()
            self._stp_info.clear()
            self._ipv6_ra.clear()
        self._exposure.reset()

    def clear_exposure(self) -> None:
        self._exposure.reset()

    def start_pcap_capture(self, out_path: str, duration_sec: float = 15.0) -> None:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with self._lock:
            self._close_pcap_locked()
            fh = open(out_path, "wb")
            # Standard libpcap global header (magic, v2.4, tz=0, sigfigs=0, snaplen=65535, Ethernet=1)
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            fh.flush()
            self._pcap_fh = fh
            self._pcap_path = out_path
            self._pcap_packets = 0
            self._pcap_bytes = 24
            self._pcap_completed_at = None
            self._pcap_continuous = duration_sec <= 0
            self._pcap_end_mono = float("inf") if self._pcap_continuous else (time.monotonic() + duration_sec)

    def stop_pcap_capture(self) -> None:
        with self._lock:
            self._close_pcap_locked()

    def _close_pcap_locked(self) -> None:
        self._pcap_continuous = False
        if self._pcap_fh is not None:
            try:
                self._pcap_fh.flush()
                self._pcap_fh.close()
            except OSError:
                pass
            self._pcap_fh = None
            self._pcap_completed_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")

    def pcap_status(self) -> dict:
        with self._lock:
            if (
                self._pcap_fh is not None
                and not self._pcap_continuous
                and time.monotonic() >= self._pcap_end_mono
            ):
                self._close_pcap_locked()
            return {
                "capturing": self._pcap_fh is not None,
                "continuous": self._pcap_continuous,
                "filename": os.path.basename(self._pcap_path) if self._pcap_path else "—",
                "path": self._pcap_path,
                "packets_captured": self._pcap_packets,
                "size_bytes": self._pcap_bytes,
                "completed_at": self._pcap_completed_at,
            }

    def snapshot(self) -> dict:
        with self._lock:
            if (
                self._pcap_fh is not None
                and not self._pcap_continuous
                and time.monotonic() >= self._pcap_end_mono
            ):
                self._close_pcap_locked()

            cutoff = time.monotonic() - 10.0
            while self._bcast_ts and self._bcast_ts[0] < cutoff:
                self._bcast_ts.popleft()
            while self._mcast_ts and self._mcast_ts[0] < cutoff:
                self._mcast_ts.popleft()

            bcast_pps = round(len(self._bcast_ts) / 10.0, 1)
            mcast_pps = round(len(self._mcast_ts) / 10.0, 1)

            conflicts: List[str] = []
            for ip_s, macs in sorted(self._arp_ip_macs.items()):
                if len(macs) > 1:
                    conflicts.append(f"{ip_s} claimed by {', '.join(sorted(macs))}")

            return {
                "tagged_vlans": sorted(self._tagged_vlans),
                "eapol_seen": self._eapol_seen,
                "raw_neighbor": dict(self._raw_neighbor),
                "arp_frames_checked": self._arp_frames_checked,
                "arp_conflicts": conflicts,
                "bcast_pps": bcast_pps,
                "mcast_pps": mcast_pps,
                "storm_detected": bcast_pps >= 100.0,
                "stp": dict(self._stp_info),
                "ipv6_ra_senders": list(self._ipv6_ra.values()),
                "exposure": self._exposure.snapshot(),
            }

    def _run(self) -> None:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            try:
                sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
            except OSError:
                pass
            sock.bind((self.iface, 0))
            sock.settimeout(0.5)
        except OSError:
            return

        with sock:
            while not self._stop_event.is_set():
                try:
                    frame, ancdata, _flags, addr = sock.recvmsg(4096, 1024)
                except socket.timeout:
                    # Check pcap expiry even if quiet
                    with self._lock:
                        if (
                            self._pcap_fh is not None
                            and not self._pcap_continuous
                            and time.monotonic() >= self._pcap_end_mono
                        ):
                            self._close_pcap_locked()
                    continue
                except OSError:
                    break

                vlan_meta = extract_auxdata_vlan(ancdata)
                if vlan_meta is not None:
                    frame = reinsert_vlan_tag(frame, vlan_meta[0], vlan_meta[1])

                # Record to active PCAP (both RX and TX frames)
                self._record_pcap_frame(frame)

                # Ignore outgoing packets transmitted by us (PACKET_OUTGOING == 4) for L2 neighbor/ARP checks
                if len(addr) >= 3 and addr[2] == 4:
                    continue
                self._inspect_frame(frame)

    def _record_pcap_frame(self, frame: bytes) -> None:
        with self._lock:
            if self._pcap_fh is None:
                return
            if (not self._pcap_continuous and time.monotonic() >= self._pcap_end_mono) or (
                self._pcap_bytes >= MAX_CONTINUOUS_PCAP_BYTES
            ):
                self._close_pcap_locked()
                return
            now = time.time()
            sec = int(now)
            usec = int((now - sec) * 1_000_000)
            incl = len(frame)
            hdr = struct.pack("<IIII", sec, usec, incl, incl)
            try:
                self._pcap_fh.write(hdr)
                self._pcap_fh.write(frame)
                self._pcap_packets += 1
                self._pcap_bytes += 16 + incl
            except OSError:
                self._close_pcap_locked()

    def _inspect_frame(self, frame: bytes) -> None:
        if len(frame) < 14:
            return

        dst_mac = frame[0:6]
        src_mac = frame[6:12]
        eth_type_or_len = struct.unpack("!H", frame[12:14])[0]
        offset = 14

        now_m = time.monotonic()
        with self._lock:
            cutoff = now_m - 10.0
            while self._bcast_ts and self._bcast_ts[0] < cutoff:
                self._bcast_ts.popleft()
            while self._mcast_ts and self._mcast_ts[0] < cutoff:
                self._mcast_ts.popleft()
            if dst_mac == b"\xff\xff\xff\xff\xff\xff":
                self._bcast_ts.append(now_m)
            elif dst_mac[0] & 0x01:
                self._mcast_ts.append(now_m)

        # Check 802.1Q / 802.1ad VLAN tags
        while eth_type_or_len in (0x8100, 0x88A8, 0x9100) and len(frame) >= offset + 4:
            tci, inner_proto = struct.unpack("!HH", frame[offset : offset + 4])
            vid = tci & 0x0FFF
            if 1 <= vid <= 4094:
                with self._lock:
                    self._tagged_vlans.add(vid)
            eth_type_or_len = inner_proto
            offset += 4

        # Check ARP (0x0806)
        if eth_type_or_len == 0x0806 and len(frame) >= offset + 28:
            arp_pkt = frame[offset : offset + 28]
            htype, ptype, hlen, plen, _oper = struct.unpack("!HHBBH", arp_pkt[:8])
            if htype == 1 and ptype == 0x0800 and hlen == 6 and plen == 4:
                sha = ":".join(f"{b:02X}" for b in arp_pkt[8:14])
                spa = socket.inet_ntoa(arp_pkt[14:18])
                with self._lock:
                    self._arp_frames_checked += 1
                    if spa != "0.0.0.0" and not spa.startswith("169.254."):
                        s_set = self._arp_ip_macs.setdefault(spa, set())
                        if len(s_set) < 6:
                            s_set.add(sha)
            return

        # Check IPv4 (0x0800) for passive exposure & cleartext leaks
        if eth_type_or_len == 0x0800 and len(frame) >= offset + 20:
            self._exposure.inspect_ipv4(frame[offset:], src_mac)
            return

        # Check IPv6 Router Advertisement (ICMPv6 Type 134) & UDP/TCP exposure
        if eth_type_or_len == 0x86DD and len(frame) >= offset + 40:
            next_hdr = frame[offset + 6]
            if next_hdr == 58 and len(frame) >= offset + 48:
                icmp = frame[offset + 40 :]
                if len(icmp) >= 8 and icmp[0] == 134:
                    lifetime_s = struct.unpack("!H", icmp[6:8])[0]
                    src_mac_str = ":".join(f"{b:02X}" for b in src_mac)
                    src_ipv6_str = socket.inet_ntop(socket.AF_INET6, frame[offset + 8 : offset + 24])
                    key = (src_mac_str, src_ipv6_str)
                    with self._lock:
                        prev = self._ipv6_ra.get(key)
                        cnt = (int(prev["count"]) + 1) if prev else 1
                        self._ipv6_ra[key] = {
                            "src_mac": src_mac_str,
                            "src_ipv6": src_ipv6_str,
                            "router_lifetime_s": lifetime_s,
                            "count": cnt,
                        }
            elif next_hdr in (6, 17):
                self._exposure.inspect_ipv6(frame[offset:], src_mac)
            return

        # Check 802.1X EAPOL (0x888E)
        if eth_type_or_len == 0x888E:
            with self._lock:
                self._eapol_seen = True
            return

        # Check LLDP (EtherType 0x88CC)
        if eth_type_or_len == 0x88CC:
            self._parse_lldp(frame[offset:], src_mac)
            return

        # Check STP / RSTP / PVST+ BPDUs over 802.3 LLC (42 42 03)
        if dst_mac in (b"\x01\x80\xc2\x00\x00\x00", b"\x01\x00\x0c\xcc\xcc\xcd") and eth_type_or_len <= 1500:
            if len(frame) >= offset + 3 + 35 and frame[offset : offset + 3] == b"\x42\x42\x03":
                self._parse_stp_bpdu(frame[offset + 3 :])
                return

        # Check Cisco CDP over 802.3 LLC/SNAP
        if dst_mac == b"\x01\x00\x0c\xcc\xcc\xcc" and eth_type_or_len <= 1500:
            if len(frame) >= offset + 8:
                llc_snap = frame[offset : offset + 8]
                if llc_snap == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
                    self._parse_cdp(frame[offset + 8 :], src_mac)

    def _parse_stp_bpdu(self, payload: bytes) -> None:
        if len(payload) < 35:
            return
        proto_id, version, bpdu_type = struct.unpack("!HBB", payload[0:4])
        if proto_id != 0 or bpdu_type not in (0x00, 0x02):
            return
        root_id_hi = struct.unpack("!H", payload[5:7])[0]
        root_priority = root_id_hi & 0xF000
        root_mac = ":".join(f"{b:02X}" for b in payload[7:13])
        root_path_cost = struct.unpack("!I", payload[13:17])[0]
        bridge_mac = ":".join(f"{b:02X}" for b in payload[19:25])
        port_raw = struct.unpack("!H", payload[25:27])[0]
        port_id = f"0x{port_raw:04X} (#{port_raw & 0x0FFF})"
        protocol = "RSTP" if version >= 2 else "STP"

        with self._lock:
            cnt = int(self._stp_info.get("bpdu_count", 0)) + 1
            self._stp_info = {
                "detected": True,
                "protocol": protocol,
                "root_priority": root_priority,
                "root_mac": root_mac,
                "root_path_cost": root_path_cost,
                "bridge_mac": bridge_mac,
                "port_id": port_id,
                "bpdu_count": cnt,
            }

    def _parse_lldp(self, payload: bytes, src_mac: bytes) -> None:
        idx = 0
        info: Dict[str, str] = {
            "protocol": "LLDP",
            "chassis_mac": ":".join(f"{b:02X}" for b in src_mac),
        }
        while idx + 2 <= len(payload):
            header = struct.unpack("!H", payload[idx : idx + 2])[0]
            tlv_type = (header >> 9) & 0x7F
            tlv_len = header & 0x01FF
            idx += 2
            if tlv_type == 0 or idx + tlv_len > len(payload):
                break
            val = payload[idx : idx + tlv_len]
            idx += tlv_len

            if tlv_type == 1 and len(val) >= 2 and val[0] == 4:
                info["chassis_mac"] = ":".join(f"{b:02X}" for b in val[1:7])
            elif tlv_type == 2 and len(val) >= 2:
                sub = val[0]
                if sub in (1, 2, 5, 7):
                    info["port_id"] = val[1:].decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 4:
                info["port_descr"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 5:
                info["switch_name"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 6:
                info["raw_descr"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 8 and len(val) >= 6 and val[1] == 1:
                info["mgmt_ip"] = socket.inet_ntoa(val[2:6])
            elif tlv_type == 127 and len(val) >= 6:
                oui = val[0:3]
                sub = val[3]
                if oui == b"\x00\x80\xc2" and sub == 1 and len(val) >= 6:
                    pvid = struct.unpack("!H", val[4:6])[0]
                    if 1 <= pvid <= 4094:
                        info["native_vlan"] = str(pvid)

        if info.get("switch_name") or info.get("port_id"):
            with self._lock:
                self._raw_neighbor.update(info)

    def _parse_cdp(self, payload: bytes, src_mac: bytes) -> None:
        if len(payload) < 4:
            return
        idx = 4
        info: Dict[str, str] = {
            "protocol": "CDP",
            "chassis_mac": ":".join(f"{b:02X}" for b in src_mac),
        }
        while idx + 4 <= len(payload):
            tlv_type, tlv_len = struct.unpack("!HH", payload[idx : idx + 4])
            if tlv_len < 4 or idx + tlv_len > len(payload):
                break
            val = payload[idx + 4 : idx + tlv_len]
            idx += tlv_len

            if tlv_type == 0x0001:
                info["switch_name"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 0x0002 and len(val) >= 13:
                addr_len = struct.unpack("!H", val[7:9])[0]
                if addr_len == 4 and len(val) >= 13:
                    info["mgmt_ip"] = socket.inet_ntoa(val[9:13])
            elif tlv_type == 0x0003:
                info["port_id"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 0x0005:
                info["raw_descr"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 0x0006:
                info["model"] = val.decode("utf-8", errors="ignore").strip("\x00 ")
            elif tlv_type == 0x000A and len(val) == 2:
                pvid = struct.unpack("!H", val)[0]
                if 1 <= pvid <= 4094:
                    info["native_vlan"] = str(pvid)
            elif tlv_type == 0x000E and len(val) >= 3:
                vvid = struct.unpack("!H", val[1:3])[0]
                if 1 <= vvid <= 4094:
                    info["voice_vlan"] = str(vvid)

        if info.get("switch_name") or info.get("port_id"):
            with self._lock:
                self._raw_neighbor.update(info)
