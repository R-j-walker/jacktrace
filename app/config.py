import os
import platform
from dataclasses import dataclass


def detect_default_wired_iface() -> str:
    """Auto-detect the primary physical Ethernet interface on Linux (e.g. eth0 or end0)."""
    env_iface = os.getenv("NETTESTER_IFACE")
    if env_iface:
        return env_iface

    if platform.system() != "Linux":
        return "eth0"

    net_root = "/sys/class/net"
    if not os.path.isdir(net_root):
        return "eth0"

    candidates = sorted(os.listdir(net_root))
    for preferred in ("eth0", "end0", "enabcm6e4ei0"):
        if preferred in candidates:
            return preferred

    for name in candidates:
        if name == "lo":
            continue
        iface_dir = os.path.join(net_root, name)
        # Skip wireless interfaces
        if os.path.exists(os.path.join(iface_dir, "wireless")) or os.path.exists(
            os.path.join(iface_dir, "phy80211")
        ):
            continue
        # Skip virtual interfaces (docker, veth, bridges, etc.)
        real = os.path.realpath(iface_dir)
        if "/virtual/" in real.replace("\\", "/"):
            continue
        return name

    return "eth0"


@dataclass
class Settings:
    iface: str = detect_default_wired_iface()
    host: str = os.getenv("NETTESTER_HOST", "0.0.0.0")
    port: int = int(os.getenv("NETTESTER_PORT", "8080"))
    demo_mode: bool = os.getenv("NETTESTER_DEMO", "").lower() in ("1", "true", "yes") or (
        platform.system() != "Linux"
    )
    poll_interval_sec: float = float(os.getenv("NETTESTER_POLL_SEC", "2.0"))
    blink_timeout_sec: int = int(os.getenv("NETTESTER_BLINK_MAX_SEC", "180"))


settings = Settings()
