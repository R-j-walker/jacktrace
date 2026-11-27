import asyncio
import subprocess
import time
from typing import Callable, List, Optional

from .models import BlinkState


def _exec_net_cmd(args: List[str]) -> bool:
    """Execute an ethtool/ip command directly or via non-interactive sudo."""
    for prefix in ([], ["sudo", "-n"]):
        try:
            res = subprocess.run(
                prefix + args,
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
            if res.returncode == 0:
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return False


class PortLedBlinker:
    """
    Flashes the upstream switch port LED in a distinct human-identifiable cadence
    without requiring switch SSH/SNMP credentials, and guarantees clean autoneg
    restoration on stop or shutdown.
    """

    def __init__(
        self,
        iface: str,
        default_timeout_sec: int = 180,
        on_change: Optional[Callable[[], None]] = None,
    ):
        self.iface = iface
        self.default_timeout_sec = default_timeout_sec
        self._on_change = on_change
        self._task: Optional[asyncio.Task] = None
        self._active = False
        self._mode = "speed-cycle"
        self._phase = "idle"
        self._end_time = 0.0
        self._warning = ""

    def state(self) -> BlinkState:
        rem = max(0, int(round(self._end_time - time.monotonic()))) if self._active else 0
        return BlinkState(
            active=self._active,
            mode=self._mode,
            phase=self._phase,
            remaining_seconds=rem,
            warning=self._warning,
        )

    async def toggle(
        self,
        mode: str = "speed-cycle",
        demo_mode: bool = False,
        same_subnet_client: bool = False,
    ) -> BlinkState:
        if self._active:
            await self.stop(demo_mode=demo_mode)
            return self.state()
        await self.start(mode=mode, demo_mode=demo_mode, same_subnet_client=same_subnet_client)
        return self.state()

    async def start(
        self,
        mode: str = "speed-cycle",
        demo_mode: bool = False,
        same_subnet_client: bool = False,
    ) -> None:
        await self.stop(demo_mode=demo_mode)
        self._mode = mode if mode in ("speed-cycle", "link-pulse") else "speed-cycle"
        # Shorter safety cap (30s) if user triggered blink over eth0 itself during bench testing
        duration = 30 if (same_subnet_client and not demo_mode) else self.default_timeout_sec
        self._warning = (
            "Bench safety: connected over test port — auto-restoring in 30s."
            if (same_subnet_client and not demo_mode)
            else ""
        )
        self._active = True
        self._end_time = time.monotonic() + duration
        self._task = asyncio.create_task(self._loop(demo_mode=demo_mode))
        self._notify()

    async def stop(self, demo_mode: bool = False) -> None:
        was_active = self._active
        self._active = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        self._phase = "idle"
        self._warning = ""
        if was_active and not demo_mode:
            await asyncio.to_thread(self._restore_link)
        if was_active:
            self._notify()

    def _restore_link(self) -> None:
        _exec_net_cmd(["ip", "link", "set", "dev", self.iface, "up"])
        _exec_net_cmd(["ethtool", "-s", self.iface, "autoneg", "on"])

    def _notify(self) -> None:
        if self._on_change:
            try:
                self._on_change()
            except Exception:
                pass

    async def _loop(self, demo_mode: bool) -> None:
        try:
            while self._active and time.monotonic() < self._end_time:
                if self._mode == "speed-cycle":
                    # Step 1: 1000M (Green LED on dual-color switches)
                    self._phase = "1G GREEN"
                    if not demo_mode:
                        await asyncio.to_thread(
                            _exec_net_cmd, ["ip", "link", "set", "dev", self.iface, "up"]
                        )
                        await asyncio.to_thread(
                            _exec_net_cmd,
                            ["ethtool", "-s", self.iface, "speed", "1000", "duplex", "full", "autoneg", "on"],
                        )
                    self._notify()
                    await asyncio.sleep(1.8)

                    # Step 2: 100M (Amber/Orange LED on dual-color switches)
                    self._phase = "100M AMBER"
                    if not demo_mode:
                        await asyncio.to_thread(
                            _exec_net_cmd,
                            ["ethtool", "-s", self.iface, "speed", "100", "duplex", "full", "autoneg", "on"],
                        )
                    self._notify()
                    await asyncio.sleep(1.8)

                    # Step 3: Carrier Down (LED Off)
                    self._phase = "LED OFF"
                    if not demo_mode:
                        await asyncio.to_thread(
                            _exec_net_cmd, ["ip", "link", "set", "dev", self.iface, "down"]
                        )
                    self._notify()
                    await asyncio.sleep(1.1)
                else:
                    # Pure link pulse
                    self._phase = "LINK ON"
                    if not demo_mode:
                        await asyncio.to_thread(
                            _exec_net_cmd, ["ip", "link", "set", "dev", self.iface, "up"]
                        )
                    self._notify()
                    await asyncio.sleep(1.8)

                    self._phase = "LED OFF"
                    if not demo_mode:
                        await asyncio.to_thread(
                            _exec_net_cmd, ["ip", "link", "set", "dev", self.iface, "down"]
                        )
                    self._notify()
                    await asyncio.sleep(1.2)
        except asyncio.CancelledError:
            raise
        finally:
            self._active = False
            self._phase = "idle"
            if not demo_mode:
                await asyncio.to_thread(self._restore_link)
            self._notify()
