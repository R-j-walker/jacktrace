import asyncio
import http.client
import json
import os
import random
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .models import (
    DiagnosticsState,
    IperfState,
    MtuTestState,
    PingMonitorState,
    PingSample,
    SpeedTestState,
    TracerouteHop,
    TracerouteState,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DIAG_SETTINGS_PATH = BASE_DIR / "data" / "diag_settings.json"
DEFAULT_IPERF_TARGETS = ["192.168.0.1", "172.24.10.5"]

_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:]+$")
_PING_MS_RE = re.compile(r"time\s*([<=])\s*(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)
_IP_TOKEN_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:]+)")
_HOP_RTT_RE = re.compile(r"(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)


def validate_host_target(target: str) -> str:
    """Validate and normalize an IP address or hostname, rejecting shell metacharacters."""
    cleaned = (target or "").strip()
    if not cleaned or len(cleaned) > 253 or cleaned.startswith("-") or not _HOST_RE.match(cleaned):
        raise ValueError(f"Invalid target host or IP: {target!r}")
    return cleaned


def parse_single_ping_ms(output: str) -> Optional[float]:
    """Extract RTT in ms from Linux or Windows single-ping stdout."""
    if not output:
        return None
    m = _PING_MS_RE.search(output)
    if not m:
        return None
    op, num = m.group(1), float(m.group(2))
    if op == "<" and num <= 1.0:
        return 0.5
    return round(num, 2)


def parse_traceroute_output(text: str) -> List[TracerouteHop]:
    """Parse `traceroute -n` and `tracepath -n` output into structured hops."""
    hops: List[TracerouteHop] = []
    if not text:
        return hops

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or "[LOCALHOST]" in line or line.lower().startswith("traceroute to"):
            continue

        m = re.match(r"^(\d+)(?:\??:)?\s+(.+)$", line)
        if not m:
            continue

        hop_num = int(m.group(1))
        rest = m.group(2).strip()
        low = rest.lower()
        if rest.startswith("*") or "no reply" in low:
            hops.append(TracerouteHop(hop=hop_num, host="*", ip="*", rtt_ms=None, loss=True))
            continue

        # Extract host/ip token and RTT
        first_tok = rest.split()[0]
        ip_m = _IP_TOKEN_RE.search(rest)
        ip_str = ip_m.group(1) if ip_m else first_tok
        host_str = first_tok if first_tok != ip_str and not first_tok.startswith("(") else ip_str

        rtt_m = _HOP_RTT_RE.search(rest)
        rtt_val = round(float(rtt_m.group(1)), 2) if rtt_m else None

        hops.append(TracerouteHop(hop=hop_num, host=host_str, ip=ip_str, rtt_ms=rtt_val, loss=False))

    return hops


def get_iface_ipv4(iface: str) -> str:
    """Return the first IPv4 address assigned to `iface` on Linux, else '—'."""
    if os.name == "nt" or not iface:
        return "—"
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", proc.stdout or "")
        return m.group(1) if m else "—"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "—"


def resolve_egress_route(target_ip: str = "1.1.1.1") -> Tuple[str, str]:
    """Return `(egress_iface, src_ip)` selected by Linux routing table for `target_ip`."""
    if os.name == "nt":
        return "—", "—"
    try:
        proc = subprocess.run(
            ["ip", "route", "get", target_ip],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
        out = proc.stdout or ""
        m_dev = re.search(r"\bdev\s+(\S+)", out)
        m_src = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", out)
        return (m_dev.group(1) if m_dev else "—", m_src.group(1) if m_src else "—")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "—", "—"


class BoundHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection pinned to a specific Linux interface (`SO_BINDTODEVICE`) and source IP."""

    def __init__(self, host: str, bind_iface: Optional[str] = None, **kwargs):
        self._bind_iface = bind_iface
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self.timeout is not None:
                sock.settimeout(self.timeout)
            if self._bind_iface and hasattr(socket, "SO_BINDTODEVICE"):
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    self._bind_iface.encode("utf-8") + b"\x00",
                )
            if self.source_address:
                sock.bind(self.source_address)
            sock.connect((self.host, self.port))
            if self._tunnel_host:
                self.sock = sock
                self._tunnel()
                server_hostname = self._tunnel_host
            else:
                server_hostname = self.host
            ctx = getattr(self, "_context", None) or ssl.create_default_context()
            self.sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        except Exception:
            sock.close()
            raise


def grade_bufferbloat(unloaded_ms: Optional[float], loaded_ms: Optional[float]) -> str:
    """Grade loaded latency inflation (A+ through F) matching Waveform/Cloudflare convention."""
    if unloaded_ms is None or loaded_ms is None:
        return "—"
    delta = max(0.0, loaded_ms - unloaded_ms)
    if delta <= 5.0:
        return "A+"
    if delta <= 15.0:
        return "A"
    if delta <= 30.0:
        return "B"
    if delta <= 60.0:
        return "C"
    if delta <= 150.0:
        return "D"
    return "F"


def parse_iperf3_json(raw_json: str) -> Tuple[Optional[float], Optional[float], Optional[int]]:
    """Extract (tx_mbps, rx_mbps, retransmits) from `iperf3 -J` JSON stdout."""
    data = json.loads(raw_json)
    end = data.get("end", {})
    sent = end.get("sum_sent", {}) or {}
    recv = end.get("sum_received", {}) or {}

    tx_bps = sent.get("bits_per_second")
    rx_bps = recv.get("bits_per_second")
    retrans = sent.get("retransmits")

    tx_mbps = round(float(tx_bps) / 1_000_000.0, 1) if tx_bps is not None else None
    rx_mbps = round(float(rx_bps) / 1_000_000.0, 1) if rx_bps is not None else None
    retrans_int = int(retrans) if retrans is not None else None
    return tx_mbps, rx_mbps, retrans_int


def _sync_single_ping(target: str, iface: str, timeout_s: float = 1.2) -> Optional[float]:
    if os.name == "nt":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), target]
    else:
        cmd = ["ping", "-I", iface, "-c", "1", "-W", str(max(1, int(round(timeout_s)))), target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 1.0, check=False)
        if proc.returncode != 0 and "time" not in proc.stdout.lower():
            return None
        return parse_single_ping_ms(proc.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _sync_df_ping(target: str, iface: str, payload_size: int) -> bool:
    """Send 1 Do-Not-Fragment ICMP packet of given payload size."""
    if os.name == "nt":
        cmd = ["ping", "-f", "-n", "1", "-w", "1000", "-l", str(payload_size), target]
    else:
        cmd = ["ping", "-I", iface, "-M", "do", "-c", "1", "-W", "1", "-s", str(payload_size), target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2.5, check=False)
        return proc.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


class DiagnosticsManager:
    def __init__(
        self,
        on_change: Optional[Callable[[], None]] = None,
        settings_path: Path = DEFAULT_DIAG_SETTINGS_PATH,
    ) -> None:
        self._on_change = on_change or (lambda: None)
        self._settings_path = Path(settings_path)
        self._saved_iperf_targets: List[str] = self._load_targets()

        self.ping = PingMonitorState()
        self.traceroute = TracerouteState()
        self.speedtest = SpeedTestState()
        self.iperf = IperfState(saved_targets=list(self._saved_iperf_targets))
        self.mtu = MtuTestState()

        self._ping_task: Optional[asyncio.Task] = None
        self._iperf_proc: Optional[subprocess.Popen] = None
        self._iperf_proc_lock = threading.Lock()

    def _load_targets(self) -> List[str]:
        try:
            if self._settings_path.is_file():
                data = json.loads(self._settings_path.read_text(encoding="utf-8"))
                raw = data.get("iperf_targets", [])
                valid: List[str] = []
                for item in raw:
                    try:
                        t = validate_host_target(str(item))
                        if t not in valid:
                            valid.append(t)
                    except ValueError:
                        continue
                if valid:
                    return valid[:8]
        except Exception:
            pass
        return list(DEFAULT_IPERF_TARGETS)

    def _save_targets(self, targets: List[str]) -> List[str]:
        cleaned: List[str] = []
        for item in targets:
            t = validate_host_target(item)
            if t not in cleaned:
                cleaned.append(t)
        cleaned = cleaned[:8]
        self._saved_iperf_targets = cleaned
        self.iperf.saved_targets = list(cleaned)
        try:
            self._settings_path.parent.mkdir(parents=True, exist_ok=True)
            self._settings_path.write_text(
                json.dumps({"iperf_targets": cleaned}, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass
        self._on_change()
        return cleaned

    def set_iperf_targets(self, targets: List[str]) -> List[str]:
        return self._save_targets(targets)

    def snapshot(self, bind_ip: str = "—") -> DiagnosticsState:
        with self._iperf_proc_lock:
            if self._iperf_proc is not None and self._iperf_proc.poll() is not None:
                self._iperf_proc = None
                self.iperf.server_running = False
        self.iperf.server_bind_ip = bind_ip or "—"
        return DiagnosticsState(
            ping=self.ping.model_copy(deep=True),
            traceroute=self.traceroute.model_copy(deep=True),
            speedtest=self.speedtest.model_copy(deep=True),
            iperf=self.iperf.model_copy(deep=True),
            mtu=self.mtu.model_copy(deep=True),
        )

    def reset_for_link_change(self) -> None:
        self.stop_ping(notify=False)
        self.traceroute = TracerouteState()
        self.mtu = MtuTestState()

    def stop_ping(self, notify: bool = True) -> None:
        if self._ping_task is not None and not self._ping_task.done():
            self._ping_task.cancel()
        self._ping_task = None
        self.ping.running = False
        if notify:
            self._on_change()

    async def start_ping(self, target: str, iface: str, demo_mode: bool) -> None:
        clean_target = validate_host_target(target)
        self.stop_ping(notify=False)

        self.ping = PingMonitorState(
            running=True,
            target=clean_target,
            sent=0,
            received=0,
            loss_percent=0.0,
            samples=[],
        )
        self._on_change()

        async def _loop() -> None:
            seq = 0
            base_rtt = 0.9 if (clean_target.startswith("10.") or clean_target.startswith("192.168.")) else 13.4
            try:
                while seq < 300 and self.ping.running:
                    seq += 1
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    if demo_mode:
                        await asyncio.sleep(0.05 if seq == 1 else 0.95)
                        # Occasional tiny packet drop ~2% for realism after a few packets
                        if seq > 10 and random.random() < 0.02:
                            rtt = None
                        else:
                            rtt = round(max(0.2, base_rtt + random.uniform(-0.35, 1.4)), 2)
                    else:
                        t0 = time.monotonic()
                        rtt = await asyncio.to_thread(_sync_single_ping, clean_target, iface, 1.0)
                        elapsed = time.monotonic() - t0
                        if elapsed < 1.0:
                            await asyncio.sleep(1.0 - elapsed)

                    if not self.ping.running:
                        break

                    samples = list(self.ping.samples)
                    samples.append(PingSample(seq=seq, ts=ts, rtt_ms=rtt, ok=(rtt is not None)))
                    if len(samples) > 40:
                        samples = samples[-40:]

                    sent = self.ping.sent + 1
                    received = self.ping.received + (1 if rtt is not None else 0)
                    loss_pct = round(((sent - received) / sent) * 100.0, 1)

                    rtts = [s.rtt_ms for s in samples if s.rtt_ms is not None]
                    if rtts:
                        mn = round(min(rtts), 2)
                        mx = round(max(rtts), 2)
                        av = round(sum(rtts) / len(rtts), 2)
                        diffs = [abs(rtts[i] - rtts[i - 1]) for i in range(1, len(rtts))]
                        jit = round(sum(diffs) / len(diffs), 2) if diffs else 0.0
                    else:
                        mn = mx = av = jit = None

                    self.ping = PingMonitorState(
                        running=True,
                        target=clean_target,
                        sent=sent,
                        received=received,
                        loss_percent=loss_pct,
                        min_ms=mn,
                        avg_ms=av,
                        max_ms=mx,
                        jitter_ms=jit,
                        samples=samples,
                    )
                    self._on_change()
            except asyncio.CancelledError:
                pass
            finally:
                self.ping.running = False
                self._on_change()

        self._ping_task = asyncio.create_task(_loop())

    async def run_traceroute(self, target: str, iface: str, demo_mode: bool) -> TracerouteState:
        clean_target = validate_host_target(target)
        self.traceroute = TracerouteState(running=True, target=clean_target)
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.25)
            hops = [
                TracerouteHop(hop=1, host="172.24.10.1", ip="172.24.10.1", rtt_ms=0.6),
                TracerouteHop(hop=2, host="100.64.0.1", ip="100.64.0.1", rtt_ms=4.3),
                TracerouteHop(hop=3, host="195.66.224.1", ip="195.66.224.1", rtt_ms=9.7),
                TracerouteHop(hop=4, host="*", ip="*", rtt_ms=None, loss=True),
                TracerouteHop(hop=5, host=clean_target, ip=clean_target, rtt_ms=13.4),
            ]
            self.traceroute = TracerouteState(
                running=False,
                target=clean_target,
                completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                hops=hops,
            )
            self._on_change()
            return self.traceroute

        def _exec() -> TracerouteState:
            out_text = ""
            err_msg = ""
            cmds = (
                [["tracert", "-d", "-h", "15", "-w", "1000", clean_target]]
                if os.name == "nt"
                else [
                    ["traceroute", "-n", "-i", iface, "-q", "1", "-w", "2", "-m", "15", clean_target],
                    ["tracepath", "-n", "-m", "15", clean_target],
                ]
            )
            for cmd in cmds:
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=22.0, check=False)
                    out_text = proc.stdout.strip()
                    if out_text:
                        err_msg = ""
                        break
                    err_msg = proc.stderr.strip() or f"{cmd[0]} returned no output"
                except FileNotFoundError:
                    err_msg = f"{cmd[0]} not installed"
                    continue
                except subprocess.TimeoutExpired:
                    err_msg = f"{cmd[0]} timed out"
                    break

            hops = parse_traceroute_output(out_text)
            return TracerouteState(
                running=False,
                target=clean_target,
                completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                error=err_msg if not hops else "",
                hops=hops,
            )

        self.traceroute = await asyncio.to_thread(_exec)
        self._on_change()
        return self.traceroute

    async def run_speedtest(
        self,
        eth_iface: str,
        demo_mode: bool,
        iface_mode: str = "auto",
        wifi_iface: str = "wlan0",
    ) -> SpeedTestState:
        if self.speedtest.running:
            return self.speedtest

        norm_mode = iface_mode if iface_mode in ("auto", "eth", "wifi") else "auto"
        if demo_mode or os.name == "nt":
            eg_if = wifi_iface if norm_mode == "wifi" else eth_iface
            eg_ip = "192.168.0.110" if norm_mode == "wifi" else "172.24.10.84"
        elif norm_mode == "eth":
            eg_if = eth_iface
            eg_ip = await asyncio.to_thread(get_iface_ipv4, eth_iface)
        elif norm_mode == "wifi":
            eg_if = wifi_iface
            eg_ip = await asyncio.to_thread(get_iface_ipv4, wifi_iface)
        else:
            eg_if, eg_ip = await asyncio.to_thread(resolve_egress_route, "1.1.1.1")
            if eg_if == "—":
                eg_if = eth_iface

        self.speedtest = SpeedTestState(
            running=True,
            provider="Cloudflare Edge",
            iface_mode=norm_mode,
            egress_iface=eg_if,
            egress_ip=eg_ip,
            status=f"Testing via {eg_if} ({eg_ip})...",
        )
        self._on_change()

        if demo_mode or (norm_mode in ("eth", "wifi") and os.name == "nt"):
            await asyncio.sleep(0.35)
            dl = 148.2 if norm_mode == "wifi" else 421.6
            ul = 62.5 if norm_mode == "wifi" else 112.4
            unloaded = 14.8 if norm_mode == "wifi" else 11.4
            loaded = 26.5 if norm_mode == "wifi" else 18.2
            self.speedtest = SpeedTestState(
                running=False,
                provider="Cloudflare Edge",
                iface_mode=norm_mode,
                egress_iface=eg_if,
                egress_ip=eg_ip,
                completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                download_mbps=dl,
                upload_mbps=ul,
                unloaded_ms=unloaded,
                loaded_ms=loaded,
                bufferbloat_grade=grade_bufferbloat(unloaded, loaded),
                status=f"Completed via {eg_if} ({eg_ip})",
            )
            self._on_change()
            return self.speedtest

        if norm_mode in ("eth", "wifi") and eg_ip in ("—", ""):
            self.speedtest = SpeedTestState(
                running=False,
                provider="Cloudflare Edge",
                iface_mode=norm_mode,
                egress_iface=eg_if,
                egress_ip="—",
                completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                status=f"No IPv4 on {eg_if}",
            )
            self._on_change()
            return self.speedtest

        force_bind = norm_mode in ("eth", "wifi")

        def _probe_loaded_pings(stop_ev: threading.Event, out_samples: List[float]) -> None:
            while not stop_ev.is_set() and len(out_samples) < 6:
                rtt = _sync_single_ping("1.1.1.1", eg_if, timeout_s=1.0)
                if rtt is not None:
                    out_samples.append(rtt)
                stop_ev.wait(0.35)

        def _exec() -> SpeedTestState:
            # 1. Unloaded latency baseline (3 quick pings to 1.1.1.1)
            unloaded_samples: List[float] = []
            for _ in range(3):
                r = _sync_single_ping("1.1.1.1", eg_if, timeout_s=1.0)
                if r is not None:
                    unloaded_samples.append(r)
            unloaded_ms = round(sum(unloaded_samples) / len(unloaded_samples), 1) if unloaded_samples else None

            loaded_samples: List[float] = []
            dl_mbps: Optional[float] = None
            ul_mbps: Optional[float] = None

            try:
                # 2. Download 10 MB while sampling loaded latency
                stop_ev = threading.Event()
                bg = threading.Thread(target=_probe_loaded_pings, args=(stop_ev, loaded_samples), daemon=True)
                bg.start()
                try:
                    t0 = time.monotonic()
                    bytes_rx = 0
                    if force_bind and eg_ip not in ("—", ""):
                        conn = BoundHTTPSConnection(
                            "speed.cloudflare.com",
                            bind_iface=eg_if,
                            source_address=(eg_ip, 0),
                            timeout=15.0,
                        )
                        try:
                            conn.request("GET", "/__down?bytes=10000000", headers={"User-Agent": "JackTrace/1.0"})
                            resp = conn.getresponse()
                            while True:
                                chunk = resp.read(65536)
                                if not chunk:
                                    break
                                bytes_rx += len(chunk)
                        finally:
                            conn.close()
                    else:
                        req = urllib.request.Request(
                            "https://speed.cloudflare.com/__down?bytes=10000000",
                            headers={"User-Agent": "JackTrace/1.0"},
                        )
                        with urllib.request.urlopen(req, timeout=15.0) as resp:
                            while True:
                                chunk = resp.read(65536)
                                if not chunk:
                                    break
                                bytes_rx += len(chunk)
                    elapsed_dl = max(0.05, time.monotonic() - t0)
                    dl_mbps = round((bytes_rx * 8) / (elapsed_dl * 1_000_000.0), 1)
                finally:
                    stop_ev.set()
                    bg.join(timeout=1.5)

                # 3. Upload 4 MB while sampling loaded latency
                stop_ev_ul = threading.Event()
                bg_ul = threading.Thread(target=_probe_loaded_pings, args=(stop_ev_ul, loaded_samples), daemon=True)
                bg_ul.start()
                try:
                    payload = b"\x00" * 4_000_000
                    t1 = time.monotonic()
                    if force_bind and eg_ip not in ("—", ""):
                        conn_ul = BoundHTTPSConnection(
                            "speed.cloudflare.com",
                            bind_iface=eg_if,
                            source_address=(eg_ip, 0),
                            timeout=15.0,
                        )
                        try:
                            conn_ul.request(
                                "POST",
                                "/__up",
                                body=payload,
                                headers={
                                    "User-Agent": "JackTrace/1.0",
                                    "Content-Type": "application/octet-stream",
                                },
                            )
                            conn_ul.getresponse().read()
                        finally:
                            conn_ul.close()
                    else:
                        req_ul = urllib.request.Request(
                            "https://speed.cloudflare.com/__up",
                            data=payload,
                            method="POST",
                            headers={
                                "User-Agent": "JackTrace/1.0",
                                "Content-Type": "application/octet-stream",
                            },
                        )
                        with urllib.request.urlopen(req_ul, timeout=15.0) as resp:
                            resp.read()
                    elapsed_ul = max(0.05, time.monotonic() - t1)
                    ul_mbps = round((len(payload) * 8) / (elapsed_ul * 1_000_000.0), 1)
                finally:
                    stop_ev_ul.set()
                    bg_ul.join(timeout=1.5)

                loaded_ms = round(sum(loaded_samples) / len(loaded_samples), 1) if loaded_samples else unloaded_ms
                grade = grade_bufferbloat(unloaded_ms, loaded_ms)
                return SpeedTestState(
                    running=False,
                    provider="Cloudflare Edge",
                    iface_mode=norm_mode,
                    egress_iface=eg_if,
                    egress_ip=eg_ip,
                    completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                    download_mbps=dl_mbps,
                    upload_mbps=ul_mbps,
                    unloaded_ms=unloaded_ms,
                    loaded_ms=loaded_ms,
                    bufferbloat_grade=grade,
                    status=f"Completed via {eg_if} ({eg_ip})",
                )
            except Exception as exc:
                loaded_ms = round(sum(loaded_samples) / len(loaded_samples), 1) if loaded_samples else None
                return SpeedTestState(
                    running=False,
                    provider="Cloudflare Edge",
                    iface_mode=norm_mode,
                    egress_iface=eg_if,
                    egress_ip=eg_ip,
                    completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                    download_mbps=dl_mbps,
                    upload_mbps=ul_mbps,
                    unloaded_ms=unloaded_ms,
                    loaded_ms=loaded_ms,
                    bufferbloat_grade=grade_bufferbloat(unloaded_ms, loaded_ms),
                    status=f"Error ({eg_if}): {str(exc)[:54]}",
                )

        self.speedtest = await asyncio.to_thread(_exec)
        self._on_change()
        return self.speedtest

    async def run_iperf_client(self, target: str, duration_sec: int, demo_mode: bool) -> IperfState:
        clean_target = validate_host_target(target)
        dur = max(2, min(int(duration_sec), 20))
        self.iperf.client_running = True
        self.iperf.target = clean_target
        self.iperf.status = f"Testing {clean_target} ({dur}s)..."
        self.iperf.error = ""
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.3)
            self.iperf.client_running = False
            self.iperf.completed_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            self.iperf.tx_mbps = 938.4
            self.iperf.rx_mbps = 936.1
            self.iperf.retransmits = 0
            self.iperf.status = "PASS (Line-Rate 1GbE)"
            self._on_change()
            return self.iperf

        def _exec() -> Tuple[Optional[float], Optional[float], Optional[int], str]:
            try:
                proc = subprocess.run(
                    ["iperf3", "-J", "-c", clean_target, "-t", str(dur), "--connect-timeout", "3000"],
                    capture_output=True,
                    text=True,
                    timeout=dur + 10,
                    check=False,
                )
                if proc.stdout:
                    try:
                        data = json.loads(proc.stdout)
                        if "error" in data:
                            return None, None, None, str(data["error"])
                        tx, rx, ret = parse_iperf3_json(proc.stdout)
                        return tx, rx, ret, ""
                    except json.JSONDecodeError:
                        pass
                err = proc.stderr.strip() or f"iperf3 failed (exit {proc.returncode})"
                return None, None, None, err
            except FileNotFoundError:
                return None, None, None, "iperf3 not installed — run sudo bash scripts/setup_pi.sh"
            except subprocess.TimeoutExpired:
                return None, None, None, "iperf3 connection timed out"

        tx, rx, ret, err = await asyncio.to_thread(_exec)
        self.iperf.client_running = False
        self.iperf.completed_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        self.iperf.tx_mbps = tx
        self.iperf.rx_mbps = rx
        self.iperf.retransmits = ret
        self.iperf.error = err
        self.iperf.status = f"Error: {err[:48]}" if err else f"Completed TX {tx} / RX {rx} Mbps"
        self._on_change()
        return self.iperf

    def toggle_iperf_server(self, enable: bool, bind_ip: str, demo_mode: bool) -> IperfState:
        self.iperf.server_bind_ip = bind_ip or "—"
        if demo_mode:
            self.iperf.server_running = enable
            self.iperf.error = ""
            self.iperf.status = "Demo iperf3 Server Listening (:5201)" if enable else "Ready"
            self._on_change()
            return self.iperf

        with self._iperf_proc_lock:
            if self._iperf_proc is not None:
                try:
                    self._iperf_proc.terminate()
                    self._iperf_proc.wait(timeout=2.0)
                except Exception:
                    try:
                        self._iperf_proc.kill()
                    except Exception:
                        pass
                self._iperf_proc = None

            if enable:
                try:
                    self._iperf_proc = subprocess.Popen(
                        ["iperf3", "-s", "-p", str(self.iperf.server_port)],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    self.iperf.server_running = True
                    self.iperf.error = ""
                    self.iperf.status = f"Server listening on :5201"
                except FileNotFoundError:
                    self.iperf.server_running = False
                    self.iperf.error = "iperf3 not installed — run sudo bash scripts/setup_pi.sh"
                    self.iperf.status = "iperf3 Missing"
            else:
                self.iperf.server_running = False
                self.iperf.status = "Server Stopped"

        self._on_change()
        return self.iperf

    async def run_mtu_test(self, target: str, iface: str, demo_mode: bool) -> MtuTestState:
        clean_target = validate_host_target(target)
        self.mtu = MtuTestState(running=True, target=clean_target, status=f"Probing PMTU to {clean_target}...")
        self._on_change()

        if demo_mode:
            await asyncio.sleep(0.2)
            self.mtu = MtuTestState(
                running=False,
                target=clean_target,
                completed_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                max_mtu=1500,
                jumbo_supported=False,
                status="1500 B Standard Ethernet Clean (Jumbo blocked)",
            )
            self._on_change()
            return self.mtu

        def _exec() -> MtuTestState:
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            if _sync_df_ping(clean_target, iface, 8972):
                return MtuTestState(
                    running=False,
                    target=clean_target,
                    completed_at=ts,
                    max_mtu=9000,
                    jumbo_supported=True,
                    status="9000 B Jumbo Frames Supported",
                )
            if _sync_df_ping(clean_target, iface, 1472):
                return MtuTestState(
                    running=False,
                    target=clean_target,
                    completed_at=ts,
                    max_mtu=1500,
                    jumbo_supported=False,
                    status="1500 B Standard Ethernet Clean",
                )

            # Binary search between 548 (576 MTU) and 1471
            low, high = 548, 1471
            best = 0
            while low <= high:
                mid = (low + high) // 2
                if _sync_df_ping(clean_target, iface, mid):
                    best = mid
                    low = mid + 1
                else:
                    high = mid - 1

            if best == 0:
                return MtuTestState(
                    running=False,
                    target=clean_target,
                    completed_at=ts,
                    max_mtu=None,
                    jumbo_supported=False,
                    status=f"No DF ICMP reply from {clean_target}",
                )
            mtu_val = best + 28
            return MtuTestState(
                running=False,
                target=clean_target,
                completed_at=ts,
                max_mtu=mtu_val,
                jumbo_supported=False,
                status=f"Fragmented path: Max MTU {mtu_val} B (PPPoE/VPN overhead)",
            )

        self.mtu = await asyncio.to_thread(_exec)
        self._on_change()
        return self.mtu

    def shutdown(self) -> None:
        self.stop_ping(notify=False)
        with self._iperf_proc_lock:
            if self._iperf_proc is not None:
                try:
                    self._iperf_proc.terminate()
                    self._iperf_proc.wait(timeout=1.5)
                except Exception:
                    try:
                        self._iperf_proc.kill()
                    except Exception:
                        pass
                self._iperf_proc = None
