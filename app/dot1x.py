import asyncio
import os
import shutil
import tempfile
from typing import Callable, Optional, Tuple

from .models import Dot1xTestState
from .net_config import validate_wired_iface


def resolve_wpa_supplicant_bin() -> Optional[str]:
    for cand in ("/sbin/wpa_supplicant", "/usr/sbin/wpa_supplicant", shutil.which("wpa_supplicant")):
        if cand and os.path.isfile(cand):
            return cand
    return None


def _validate_eap_cred(val: str, label: str) -> str:
    clean = (val or "").strip()
    if not clean:
        raise ValueError(f"{label} is required")
    if len(clean) > 128:
        raise ValueError(f"{label} exceeds 128 characters")
    if any(ch in clean for ch in ('\r', '\n', '\x00', '"', '\\')):
        raise ValueError(f"{label} contains unsupported characters")
    return clean


def parse_wpa_supplicant_line(line: str) -> Optional[Tuple[str, str]]:
    """Map wpa_supplicant wired stdout lines to (status, detail)."""
    txt = (line or "").strip()
    if not txt:
        return None
    if "CTRL-EVENT-EAP-SUCCESS" in txt or "CTRL-EVENT-CONNECTED" in txt:
        return "Authenticated", "802.1X EAP authentication succeeded"
    if "CTRL-EVENT-EAP-FAILURE" in txt:
        return "Failed", "802.1X EAP authentication rejected (check credentials/RADIUS)"
    if "CTRL-EVENT-EAP-STARTED" in txt:
        return "Authenticating...", "EAP identity/PEAP handshake in progress"
    if "CTRL-EVENT-DISCONNECTED" in txt:
        return "Failed", "802.1X supplicant disconnected before completion"
    return None


class Dot1xTestManager:
    """ephemeral wired 802.1X EAP-PEAP tester using `wpa_supplicant -D wired`."""

    def __init__(self, on_change: Optional[Callable[[], None]] = None) -> None:
        self._on_change = on_change or (lambda: None)
        self._task: Optional[asyncio.Task] = None
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._tmp_conf: Optional[str] = None
        self.state = Dot1xTestState(supported=(os.name == "nt" or bool(resolve_wpa_supplicant_bin())))

    def snapshot(self) -> Dot1xTestState:
        return self.state.model_copy(deep=True)

    def _cleanup_conf(self) -> None:
        if self._tmp_conf:
            try:
                if os.path.exists(self._tmp_conf):
                    os.unlink(self._tmp_conf)
            except OSError:
                pass
            self._tmp_conf = None

    async def stop_test(self) -> Dot1xTestState:
        if self._task and not self._task.done():
            self._task.cancel()
        self._task = None
        if self._proc and self._proc.returncode is None:
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=2.0)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    self._proc.kill()
                except ProcessLookupError:
                    pass
        self._proc = None
        self._cleanup_conf()
        if self.state.active or self.state.status == "Authenticating...":
            self.state = self.state.model_copy(
                update={
                    "active": False,
                    "status": "Stopped",
                    "detail": "802.1X supplicant stopped",
                }
            )
            self._on_change()
        return self.snapshot()

    async def start_test(
        self,
        iface: str,
        identity: str,
        password: str,
        method: str = "PEAP",
        demo_mode: bool = False,
    ) -> Dot1xTestState:
        clean_if = validate_wired_iface(iface)
        clean_id = _validate_eap_cred(identity, "802.1X Identity")
        clean_pw = _validate_eap_cred(password, "802.1X Password")
        clean_method = "PEAP" if (method or "PEAP").upper() not in ("PEAP", "TTLS") else method.upper()

        await self.stop_test()

        self.state = Dot1xTestState(
            supported=True,
            active=True,
            iface=clean_if,
            method=clean_method,
            identity=clean_id,
            has_password=bool(clean_pw),
            status="Authenticating...",
            detail=f"Sending EAPOL-Start on {clean_if} as {clean_id}...",
        )
        self._on_change()

        if demo_mode or os.name == "nt":
            async def _demo_run() -> None:
                try:
                    await asyncio.sleep(0.35)
                    self.state = self.state.model_copy(
                        update={
                            "active": False,
                            "status": "Authenticated",
                            "detail": f"Demo EAP-{clean_method} accepted for {clean_id}",
                        }
                    )
                    self._on_change()
                except asyncio.CancelledError:
                    pass

            self._task = asyncio.create_task(_demo_run())
            await asyncio.sleep(0.45)
            return self.snapshot()

        wpa_bin = resolve_wpa_supplicant_bin()
        if not wpa_bin:
            self.state = self.state.model_copy(
                update={
                    "supported": False,
                    "active": False,
                    "status": "Failed",
                    "detail": "wpa_supplicant binary not found on system",
                }
            )
            self._on_change()
            return self.snapshot()

        conf_text = (
            "ctrl_interface=/run/wpa_supplicant_jacktrace\n"
            "eapol_version=1\n"
            "ap_scan=0\n"
            "network={\n"
            "  key_mgmt=IEEE8021X\n"
            f"  eap={clean_method}\n"
            f'  identity="{clean_id}"\n'
            f'  password="{clean_pw}"\n'
            '  phase2="auth=MSCHAPV2"\n'
            "}\n"
        )
        fd, tmp_path = tempfile.mkstemp(prefix="jt_8021x_", suffix=".conf", dir="/tmp")
        os.close(fd)
        os.chmod(tmp_path, 0o600)
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(conf_text)
        self._tmp_conf = tmp_path

        async def _live_run() -> None:
            try:
                self._proc = await asyncio.create_subprocess_exec(
                    wpa_bin,
                    "-D",
                    "wired",
                    "-i",
                    clean_if,
                    "-c",
                    tmp_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                deadline = asyncio.get_running_loop().time() + 20.0
                while True:
                    rem = deadline - asyncio.get_running_loop().time()
                    if rem <= 0:
                        if self.state.status == "Authenticating...":
                            self.state = self.state.model_copy(
                                update={
                                    "active": False,
                                    "status": "Failed",
                                    "detail": "Timed out waiting for switch 802.1X authenticator (20s)",
                                }
                            )
                        break
                    if not self._proc.stdout:
                        break
                    try:
                        raw = await asyncio.wait_for(self._proc.stdout.readline(), timeout=min(rem, 1.5))
                    except asyncio.TimeoutError:
                        if self._proc.returncode is not None:
                            break
                        continue
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace").strip()
                    parsed = parse_wpa_supplicant_line(line)
                    if parsed:
                        st, det = parsed
                        done = st in ("Authenticated", "Failed")
                        self.state = self.state.model_copy(
                            update={"active": not done, "status": st, "detail": det}
                        )
                        self._on_change()
                        if done:
                            break
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                self.state = self.state.model_copy(
                    update={"active": False, "status": "Failed", "detail": str(exc)[:100]}
                )
                self._on_change()
            finally:
                if self._proc and self._proc.returncode is None:
                    try:
                        self._proc.terminate()
                    except ProcessLookupError:
                        pass
                self._proc = None
                self._cleanup_conf()
                if self.state.active:
                    self.state = self.state.model_copy(update={"active": False})
                self._on_change()

        self._task = asyncio.create_task(_live_run())
        return self.snapshot()
