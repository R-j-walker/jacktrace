import asyncio
import json
import random
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .models import SnmpSwitchState

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SNMP_SETTINGS_PATH = BASE_DIR / "data" / "snmp_settings.json"


def _enc_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    chunks: List[int] = []
    n = length
    while n > 0:
        chunks.append(n & 0xFF)
        n >>= 8
    chunks.reverse()
    return bytes([0x80 | len(chunks)]) + bytes(chunks)


def _dec_len(buf: bytes, idx: int) -> Tuple[int, int]:
    if idx >= len(buf):
        raise ValueError("Truncated BER length")
    first = buf[idx]
    idx += 1
    if (first & 0x80) == 0:
        return first, idx
    num_bytes = first & 0x7F
    if num_bytes == 0 or idx + num_bytes > len(buf):
        raise ValueError("Invalid BER extended length")
    val = int.from_bytes(buf[idx : idx + num_bytes], "big")
    return val, idx + num_bytes


def _enc_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def _enc_int(val: int) -> bytes:
    if val == 0:
        return _enc_tlv(0x02, b"\x00")
    raw: List[int] = []
    v = val
    negative = v < 0
    while True:
        raw.append(v & 0xFF)
        v >>= 8
        if (not negative and v == 0 and (raw[-1] & 0x80) == 0) or (
            negative and v == -1 and (raw[-1] & 0x80) != 0
        ):
            break
    raw.reverse()
    return _enc_tlv(0x02, bytes(raw))


def encode_oid(oid_str: str) -> bytes:
    """Encode a dotted OID string (e.g. '1.3.6.1.2.1.1.1.0') into an ASN.1 BER OID TLV."""
    parts = [int(x) for x in oid_str.strip().lstrip(".").split(".") if x != ""]
    if len(parts) < 2:
        raise ValueError(f"Invalid OID: {oid_str!r}")
    out = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        if arc < 0:
            raise ValueError(f"Negative OID arc in {oid_str!r}")
        if arc == 0:
            out.append(0)
            continue
        subs: List[int] = []
        v = arc
        while v > 0:
            subs.append(v & 0x7F)
            v >>= 7
        subs.reverse()
        for i, b in enumerate(subs):
            out.append(b | (0x80 if i < len(subs) - 1 else 0))
    return _enc_tlv(0x06, bytes(out))


def decode_oid(raw: bytes) -> str:
    """Decode either a BER OID TLV (starting with 0x06) or raw OID value bytes into dotted string."""
    if not raw:
        return ""
    val = raw
    if raw[0] == 0x06 and len(raw) >= 2:
        ln, start = _dec_len(raw, 1)
        if start + ln <= len(raw):
            val = raw[start : start + ln]
    if not val:
        return ""
    arcs = [val[0] // 40, val[0] % 40]
    cur = 0
    for b in val[1:]:
        cur = (cur << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            arcs.append(cur)
            cur = 0
    return ".".join(str(a) for a in arcs)


def _dec_tlv(buf: bytes, idx: int) -> Tuple[int, bytes, int]:
    if idx >= len(buf):
        raise ValueError("Truncated BER TLV")
    tag = buf[idx]
    ln, val_start = _dec_len(buf, idx + 1)
    val_end = val_start + ln
    if val_end > len(buf):
        raise ValueError("Truncated BER value")
    return tag, buf[val_start:val_end], val_end


def _dec_ber_value(tag: int, val: bytes) -> Any:
    if tag == 0x02:  # Signed INTEGER
        return int.from_bytes(val, "big", signed=True) if val else 0
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32, Gauge32, TimeTicks, Counter64
        return int.from_bytes(val, "big", signed=False) if val else 0
    if tag == 0x04:  # OCTET STRING
        return val.decode("utf-8", errors="replace").strip("\x00 ")
    if tag == 0x06:  # OBJECT IDENTIFIER
        return decode_oid(val)
    if tag in (0x05, 0x80, 0x81, 0x82):  # NULL, noSuchObject, noSuchInstance, endOfMibView
        return None
    return val


def encode_snmp_v2c_request(
    community: str,
    oids: List[str],
    req_id: int = 1,
    pdu_tag: int = 0xA0,
) -> bytes:
    """Build an SNMPv2c GET (0xA0) or GETNEXT (0xA1) packet."""
    vbs = b"".join(_enc_tlv(0x30, encode_oid(oid) + b"\x05\x00") for oid in oids)
    vb_list = _enc_tlv(0x30, vbs)
    pdu_body = _enc_int(req_id) + _enc_int(0) + _enc_int(0) + vb_list
    pdu = _enc_tlv(pdu_tag, pdu_body)
    comm_tlv = _enc_tlv(0x04, community.encode("utf-8"))
    msg_body = _enc_int(1) + comm_tlv + pdu  # version = 1 -> SNMPv2c
    return _enc_tlv(0x30, msg_body)


def decode_snmp_v2c_response(data: bytes) -> Tuple[int, int, int, List[Tuple[str, Any]]]:
    """Decode an SNMPv2c GetResponse packet into (req_id, err_status, err_index, [(oid, value)])."""
    tag, msg_body, _ = _dec_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("Expected SNMP SEQUENCE")
    pos = 0
    _, _ver, pos = _dec_tlv(msg_body, pos)
    _, _comm, pos = _dec_tlv(msg_body, pos)
    pdu_tag, pdu_body, _ = _dec_tlv(msg_body, pos)
    if pdu_tag != 0xA2:
        raise ValueError(f"Expected GetResponse PDU (0xA2), got 0x{pdu_tag:02x}")

    ppos = 0
    t_req, v_req, ppos = _dec_tlv(pdu_body, ppos)
    req_id = _dec_ber_value(t_req, v_req)
    t_err, v_err, ppos = _dec_tlv(pdu_body, ppos)
    err_status = _dec_ber_value(t_err, v_err)
    t_idx, v_idx, ppos = _dec_tlv(pdu_body, ppos)
    err_index = _dec_ber_value(t_idx, v_idx)
    _, vbl_body, _ = _dec_tlv(pdu_body, ppos)

    pairs: List[Tuple[str, Any]] = []
    vpos = 0
    while vpos < len(vbl_body):
        _, vb_body, vpos = _dec_tlv(vbl_body, vpos)
        _, oid_raw, bpos = _dec_tlv(vb_body, 0)
        v_tag, v_raw, _ = _dec_tlv(vb_body, bpos)
        pairs.append((decode_oid(oid_raw), _dec_ber_value(v_tag, v_raw)))

    return req_id, err_status, err_index, pairs


def format_timeticks(ticks: Optional[int]) -> str:
    if ticks is None:
        return "—"
    total_sec = max(0, int(ticks) // 100)
    days, rem = divmod(total_sec, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}d {hours}h {mins}m"
    if hours > 0:
        return f"{hours}h {mins}m"
    return f"{mins}m {secs}s"


def _snmp_udp_roundtrip(sock: socket.socket, ip: str, community: str, oids: List[str], pdu_tag: int) -> List[Tuple[str, Any]]:
    req_id = random.randint(1000, 999999)
    pkt = encode_snmp_v2c_request(community, oids, req_id=req_id, pdu_tag=pdu_tag)
    sock.sendto(pkt, (ip, 161))
    data, _ = sock.recvfrom(4096)
    _rid, _err_s, _err_i, pairs = decode_snmp_v2c_response(data)
    return pairs


def _match_if_descr(if_map: Dict[int, str], port_id: str, port_number: Optional[int]) -> Tuple[Optional[int], str]:
    if not if_map:
        return None, "—"
    pid_low = (port_id or "").strip().lower()
    for idx, descr in if_map.items():
        if pid_low and pid_low == descr.strip().lower():
            return idx, descr
    if pid_low:
        for idx, descr in if_map.items():
            d_low = descr.strip().lower()
            if pid_low in d_low or (pid_low.startswith("gi") and pid_low[2:] in d_low):
                return idx, descr
    if port_number is not None:
        pat = re.compile(rf"(?:^|[/:.\s]|port\s*)0*{port_number}$", re.IGNORECASE)
        for idx, descr in if_map.items():
            if pat.search(descr.strip()):
                return idx, descr
    return None, "—"


class SnmpSwitchManager:
    def __init__(
        self,
        on_change: Optional[Callable[[], None]] = None,
        settings_path: Path = DEFAULT_SNMP_SETTINGS_PATH,
    ) -> None:
        self._on_change = on_change or (lambda: None)
        self._settings_path = Path(settings_path)
        self._community = self._load_community()
        self.state = SnmpSwitchState(community=self._community)

    def _load_community(self) -> str:
        try:
            if self._settings_path.is_file():
                data = json.loads(self._settings_path.read_text(encoding="utf-8"))
                comm = str(data.get("community", "")).strip()
                if comm:
                    return comm[:32]
        except Exception:
            pass
        return "public"

    def _save_community(self, comm: str) -> str:
        clean = (comm or "public").strip()[:32] or "public"
        self._community = clean
        try:
            self._settings_path.parent.mkdir(parents=True, exist_ok=True)
            self._settings_path.write_text(json.dumps({"community": clean}, indent=2), encoding="utf-8")
        except OSError:
            pass
        return clean

    def snapshot(self) -> SnmpSwitchState:
        return self.state.model_copy(deep=True)

    async def query(
        self,
        target_ip: str,
        community: str,
        port_id: str,
        port_number: Optional[int],
        demo_mode: bool,
    ) -> SnmpSwitchState:
        if self.state.running:
            return self.snapshot()

        comm = self._save_community(community)
        clean_ip = (target_ip or "").strip()
        self.state = SnmpSwitchState(
            running=True,
            community=comm,
            target_ip=clean_ip or "—",
        )
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.2)
            demo_ip = clean_ip if (clean_ip and clean_ip != "—") else "172.24.10.2"
            demo_port = port_id if (port_id and port_id != "—") else "1/17"
            self.state = SnmpSwitchState(
                running=False,
                community=comm,
                target_ip=demo_ip,
                last_run_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                sys_name="IDF2-SW03",
                sys_descr="ArubaOS-Switch WC.16.11, 2930F-24G-PoE+",
                uptime_str="42d 7h 18m",
                matched_port=demo_port,
                if_in_errors=0,
                if_out_errors=0,
                poe_budget_w=370.0,
                poe_draw_w=68.4,
                error="",
            )
            self._on_change()
            return self.snapshot()

        if not clean_ip or clean_ip == "—":
            self.state = SnmpSwitchState(
                running=False,
                community=comm,
                target_ip="—",
                last_run_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                error="No Switch Management IP available yet (wait for LLDP/CDP or enter target IP)",
            )
            self._on_change()
            return self.snapshot()

        def _exec_live_snmp() -> SnmpSwitchState:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.8)
            try:
                # 1. sysDescr, sysUpTime, sysName
                pairs = _snmp_udp_roundtrip(
                    sock,
                    clean_ip,
                    comm,
                    ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"],
                    0xA0,
                )
                vals = {oid: v for oid, v in pairs}
                sys_descr = str(vals.get("1.3.6.1.2.1.1.1.0") or "—")
                uptime_raw = vals.get("1.3.6.1.2.1.1.3.0")
                uptime_str = format_timeticks(uptime_raw if isinstance(uptime_raw, int) else None)
                sys_name = str(vals.get("1.3.6.1.2.1.1.5.0") or "—")

                # 2. Walk ifDescr (1.3.6.1.2.1.2.2.1.2) up to 64 interfaces
                if_map: Dict[int, str] = {}
                cur_oid = "1.3.6.1.2.1.2.2.1.2"
                for _ in range(64):
                    nxt = _snmp_udp_roundtrip(sock, clean_ip, comm, [cur_oid], 0xA1)
                    if not nxt:
                        break
                    r_oid, r_val = nxt[0]
                    if r_val is None or not r_oid.startswith("1.3.6.1.2.1.2.2.1.2."):
                        break
                    try:
                        if_idx = int(r_oid.rsplit(".", 1)[-1])
                        if_map[if_idx] = str(r_val)
                    except ValueError:
                        pass
                    cur_oid = r_oid

                matched_idx, matched_name = _match_if_descr(if_map, port_id, port_number)
                in_err: Optional[int] = None
                out_err: Optional[int] = None
                if matched_idx is not None:
                    ep = _snmp_udp_roundtrip(
                        sock,
                        clean_ip,
                        comm,
                        [f"1.3.6.1.2.1.2.2.1.14.{matched_idx}", f"1.3.6.1.2.1.2.2.1.20.{matched_idx}"],
                        0xA0,
                    )
                    ev = {o: v for o, v in ep}
                    vi = ev.get(f"1.3.6.1.2.1.2.2.1.14.{matched_idx}")
                    vo = ev.get(f"1.3.6.1.2.1.2.2.1.20.{matched_idx}")
                    if isinstance(vi, int):
                        in_err = vi
                    if isinstance(vo, int):
                        out_err = vo

                # 3. Optional POWER-ETHERNET-MIB (pethMainPsePower & ConsumptionPower)
                poe_budget: Optional[float] = None
                poe_draw: Optional[float] = None
                try:
                    pp = _snmp_udp_roundtrip(
                        sock,
                        clean_ip,
                        comm,
                        ["1.3.6.1.2.1.105.1.3.1.1.2.1", "1.3.6.1.2.1.105.1.3.1.1.4.1"],
                        0xA0,
                    )
                    pv = {o: v for o, v in pp}
                    pb = pv.get("1.3.6.1.2.1.105.1.3.1.1.2.1")
                    pd = pv.get("1.3.6.1.2.1.105.1.3.1.1.4.1")
                    if isinstance(pb, int) and pb > 0:
                        poe_budget = float(pb)
                    if isinstance(pd, int) and pd >= 0:
                        poe_draw = float(pd)
                except Exception:
                    pass

                return SnmpSwitchState(
                    running=False,
                    community=comm,
                    target_ip=clean_ip,
                    last_run_at=ts,
                    sys_name=sys_name,
                    sys_descr=sys_descr,
                    uptime_str=uptime_str,
                    matched_port=matched_name,
                    if_in_errors=in_err,
                    if_out_errors=out_err,
                    poe_budget_w=poe_budget,
                    poe_draw_w=poe_draw,
                    error="",
                )
            except socket.timeout:
                return SnmpSwitchState(
                    running=False,
                    community=comm,
                    target_ip=clean_ip,
                    last_run_at=ts,
                    error=f"SNMPv2c timeout from {clean_ip}:161 (check community '{comm}' / ACL)",
                )
            except Exception as exc:
                return SnmpSwitchState(
                    running=False,
                    community=comm,
                    target_ip=clean_ip,
                    last_run_at=ts,
                    error=str(exc)[:80],
                )
            finally:
                sock.close()

        self.state = await asyncio.to_thread(_exec_live_snmp)
        self._on_change()
        return self.snapshot()
