import asyncio
import contextlib
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .audit import make_qr_data_uri
from .models import TailcatState
from .nic_tap import validate_eth_iface

TAILCAT_MODES = ("web_ui", "pcap_stream", "iperf", "ssh")
TAILCAT_ADDR_RE = re.compile(r"\b(tc[A-Za-z0-9_-]{16,})\b")


def find_tailcat_binary() -> Optional[str]:
    """Locate the `tailcat` binary in PATH or standard Linux install locations."""
    found = shutil.which("tailcat")
    if found:
        return found
    for candidate in (
        "/usr/local/bin/tailcat",
        "/usr/bin/tailcat",
        str(Path.home() / "go" / "bin" / "tailcat"),
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def find_ssh_authorized_keys() -> Optional[str]:
    """Locate an existing non-empty SSH authorized_keys file for public-key auth."""
    candidates = [Path.home() / ".ssh" / "authorized_keys"]
    home_root = Path("/home")
    if home_root.is_dir():
        candidates.extend(sorted(home_root.glob("*/.ssh/authorized_keys")))
    candidates.append(Path("/root/.ssh/authorized_keys"))

    seen = set()
    for cand in candidates:
        cand_str = str(cand)
        if cand_str in seen:
            continue
        seen.add(cand_str)
        try:
            if cand.is_file() and cand.stat().st_size > 0:
                return cand_str
        except OSError:
            continue
    return None


def parse_tailcat_address(text: str) -> Optional[str]:
    """Extract an ephemeral `tc...` address token from tailcat stderr output."""
    if not text:
        return None
    m = TAILCAT_ADDR_RE.search(text)
    return m.group(1) if m else None


def build_tailcat_client_cmd(mode: str, address: str, web_port: int = 8080) -> str:
    """Build the copy-ready laptop client command for the active tailcat mode."""
    addr = (address or "").strip()
    if not addr:
        return ""
    if mode == "web_ui":
        return f"tailcat forward {addr} 18080:{web_port}"
    if mode == "pcap_stream":
        return f"tailcat {addr} | wireshark -k -i -"
    if mode == "iperf":
        return f"tailcat forward {addr} 5201:5201"
    if mode == "ssh":
        return f"tailcat ssh {addr}"
    return f"tailcat {addr}"


def validate_capture_iface(iface: str) -> str:
    """Allow `br0` inline tap bridge or a validated physical Ethernet interface."""
    clean = (iface or "").strip()
    if clean == "br0":
        return "br0"
    return validate_eth_iface(clean)


async def _terminate_proc(proc: Optional[asyncio.subprocess.Process]) -> None:
    if proc is None or proc.returncode is not None:
        return
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), timeout=1.0)
    except (ProcessLookupError, OSError):
        pass


class TailcatManager:
    """Manages ephemeral userspace WireGuard/DERP tunnels via `tailcat`."""

    def __init__(
        self,
        web_port: int = 8080,
        on_change: Optional[Callable[[], None]] = None,
    ) -> None:
        self.web_port = web_port
        self.on_change = on_change
        bin_path = find_tailcat_binary()
        self.state = TailcatState(
            installed=bool(bin_path),
            binary_path=bin_path or "",
        )
        self._tailcat_proc: Optional[asyncio.subprocess.Process] = None
        self._tcpdump_proc: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task] = None

    def _notify(self) -> None:
        if self.on_change:
            self.on_change()

    async def start(
        self,
        mode: str,
        iface: str = "eth0",
        demo_mode: bool = False,
    ) -> TailcatState:
        clean_mode = (mode or "").strip().lower()
        if clean_mode not in TAILCAT_MODES:
            raise ValueError(f"Unsupported Tailcat mode '{mode}'; expected one of {', '.join(TAILCAT_MODES)}")

        target_iface = validate_capture_iface(iface) if clean_mode == "pcap_stream" else (iface or "eth0")
        await self.stop(notify=False)

        if demo_mode or os.name == "nt":
            demo_addr = f"tcDemoJackTrace{clean_mode.upper()}WireGuardKey9xQ2mK7vP4nR8s"
            self.state = TailcatState(
                installed=True,
                binary_path=self.state.binary_path or "/usr/local/bin/tailcat",
                running=True,
                mode=clean_mode,
                iface=target_iface,
                address=demo_addr,
                client_cmd=build_tailcat_client_cmd(clean_mode, demo_addr, web_port=self.web_port),
                qr_svg_data_uri=make_qr_data_uri(demo_addr),
                started_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
                status=f"Demo Tunnel Active ({clean_mode})",
                error="",
            )
            self._notify()
            return self.snapshot(demo_mode=demo_mode)

        bin_path = find_tailcat_binary()
        if not bin_path:
            self.state.installed = False
            self.state.binary_path = ""
            self.state.status = "Not Installed"
            self.state.error = "tailcat binary not found (run scripts/setup_pi.sh or install tailcat)"
            self._notify()
            raise RuntimeError(self.state.error)

        self.state.installed = True
        self.state.binary_path = bin_path

        try:
            if clean_mode == "web_ui":
                self._tailcat_proc = await asyncio.create_subprocess_exec(
                    bin_path,
                    "serve",
                    str(self.web_port),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
            elif clean_mode == "iperf":
                self._tailcat_proc = await asyncio.create_subprocess_exec(
                    bin_path,
                    "serve",
                    "5201",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
            elif clean_mode == "ssh":
                ak_path = find_ssh_authorized_keys()
                if not ak_path:
                    msg = "No SSH authorized_keys found — add a public key before enabling Tailcat SSH"
                    self.state.status = "SSH Key Required"
                    self.state.error = msg
                    self._notify()
                    raise RuntimeError(msg)
                self._tailcat_proc = await asyncio.create_subprocess_exec(
                    bin_path,
                    "serve",
                    f"--ssh-authorized-keys={ak_path}",
                    "ssh",
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )
            elif clean_mode == "pcap_stream":
                r_fd, w_fd = os.pipe()
                try:
                    self._tcpdump_proc = await asyncio.create_subprocess_exec(
                        "tcpdump",
                        "-i",
                        target_iface,
                        "-U",
                        "-s",
                        "0",
                        "-w",
                        "-",
                        stdout=w_fd,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    self._tailcat_proc = await asyncio.create_subprocess_exec(
                        bin_path,
                        stdin=r_fd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.PIPE,
                    )
                finally:
                    with contextlib.suppress(OSError):
                        os.close(r_fd)
                    with contextlib.suppress(OSError):
                        os.close(w_fd)
        except RuntimeError:
            await self.stop(notify=False)
            raise
        except Exception as exc:
            err_msg = f"Failed to launch tailcat ({clean_mode}): {exc}"
            await self.stop(notify=False)
            self.state.error = err_msg
            self.state.status = "Start Failed"
            self._notify()
            raise RuntimeError(err_msg) from exc

        addr: Optional[str] = None
        last_err_line = ""
        deadline = asyncio.get_running_loop().time() + 10.0

        while self._tailcat_proc and self._tailcat_proc.stderr:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            try:
                raw_line = await asyncio.wait_for(
                    self._tailcat_proc.stderr.readline(),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                break
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").strip()
            if line:
                last_err_line = line
            parsed = parse_tailcat_address(line)
            if parsed:
                addr = parsed
                break

        if not addr:
            await self.stop(notify=False)
            err_msg = last_err_line or f"Timed out waiting for tailcat address ({clean_mode})"
            self.state.error = err_msg[:160]
            self.state.status = "Address Timeout"
            self._notify()
            raise RuntimeError(self.state.error)

        self.state = TailcatState(
            installed=True,
            binary_path=bin_path,
            running=True,
            mode=clean_mode,
            iface=target_iface,
            address=addr,
            client_cmd=build_tailcat_client_cmd(clean_mode, addr, web_port=self.web_port),
            qr_svg_data_uri=make_qr_data_uri(addr),
            started_at=datetime.now(timezone.utc).strftime("%H:%M:%S UTC"),
            status=f"Listening ({clean_mode})",
            error="",
        )
        self._reader_task = asyncio.create_task(self._watch_process())
        self._notify()
        return self.snapshot(demo_mode=False)

    async def _watch_process(self) -> None:
        proc = self._tailcat_proc
        if proc is None:
            return
        try:
            if proc.stderr:
                while True:
                    line = await proc.stderr.readline()
                    if not line:
                        break
            rc = await proc.wait()
        except asyncio.CancelledError:
            return
        except Exception:
            return

        # Only clear state if this is still the active process
        if self._tailcat_proc is proc:
            await _terminate_proc(self._tcpdump_proc)
            self._tcpdump_proc = None
            self._tailcat_proc = None
            self._reader_task = None
            self.state.running = False
            self.state.mode = "idle"
            self.state.address = ""
            self.state.client_cmd = ""
            self.state.qr_svg_data_uri = ""
            self.state.started_at = None
            self.state.status = "Exited" if rc != 0 else "Idle"
            self.state.error = f"tailcat exited with code {rc}" if rc not in (0, -15, None) else ""
            self._notify()

    async def stop(self, notify: bool = True) -> TailcatState:
        task = self._reader_task
        self._reader_task = None
        if task and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

        tc_proc = self._tailcat_proc
        td_proc = self._tcpdump_proc
        self._tailcat_proc = None
        self._tcpdump_proc = None

        await _terminate_proc(td_proc)
        await _terminate_proc(tc_proc)

        self.state = TailcatState(
            installed=self.state.installed,
            binary_path=self.state.binary_path,
            running=False,
            mode="idle",
            iface="eth0",
            address="",
            client_cmd="",
            qr_svg_data_uri="",
            started_at=None,
            status="Idle",
            error="",
            webhook_pushed_at=None,
            webhook_status="",
        )
        if notify:
            self._notify()
        return self.snapshot()

    def record_webhook_result(self, ok: bool, msg: str) -> None:
        if ok:
            self.state.webhook_pushed_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
        self.state.webhook_status = msg
        self._notify()

    def snapshot(self, demo_mode: bool = False) -> TailcatState:
        snap = self.state.model_copy()
        if demo_mode:
            snap.installed = True
        return snap
