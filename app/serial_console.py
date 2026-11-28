import asyncio
import os
import re
import threading
import time
from typing import Callable, List, Optional, Set

try:
    import serial  # type: ignore
    import serial.tools.list_ports  # type: ignore
except ImportError:  # pragma: no cover - graceful fallback if pyserial missing
    serial = None  # type: ignore

from .models import SerialConsoleState, SerialPortInfo

ALLOWED_BAUD_RATES = (9600, 19200, 38400, 57600, 115200)
_VALID_PORT_RE = re.compile(
    r"^(/dev/tty(USB|ACM|S|AMA)[0-9]{1,3}|/dev/serial/by-id/[A-Za-z0-9_.:-]+|COM[0-9]{1,3})$"
)
_MAX_BUFFER_CHARS = 32768
_SNAPSHOT_TAIL_CHARS = 16384


def validate_serial_port(port: str) -> str:
    clean = (port or "").strip()
    if not clean or not _VALID_PORT_RE.match(clean):
        raise ValueError(f"Unsupported serial device path: '{clean}'")
    return clean


def validate_baud_rate(baud: int) -> int:
    val = int(baud)
    if val not in ALLOWED_BAUD_RATES:
        raise ValueError(f"Unsupported baud rate {val}; expected one of {ALLOWED_BAUD_RATES}")
    return val


def list_serial_ports(demo_mode: bool = False) -> List[SerialPortInfo]:
    if demo_mode or os.name == "nt":
        return [
            SerialPortInfo(
                device="/dev/ttyS0",
                description="GPD Pocket 3 RS-232 Module (Demo)",
                hwid="PNP0501",
                is_usb=False,
            ),
            SerialPortInfo(
                device="/dev/ttyUSB0",
                description="FTDI USB-RJ45 Switch Console (Demo)",
                hwid="USB VID:PID=0403:6001",
                is_usb=True,
            ),
        ]

    if serial is None:
        return []

    ports: List[SerialPortInfo] = []
    try:
        for p in sorted(serial.tools.list_ports.comports(), key=lambda x: x.device):
            dev = str(p.device or "")
            hwid = str(p.hwid or "")
            desc = str(p.description or "")
            is_usb = ("USB" in hwid.upper()) or ("/ttyUSB" in dev) or ("/ttyACM" in dev)
            # Filter out unbacked PC dummy ttyS4..31 when hwid == n/a
            if dev.startswith("/dev/ttyS") and hwid.lower() == "n/a" and dev != "/dev/ttyS0":
                continue
            ports.append(
                SerialPortInfo(
                    device=dev,
                    description=desc if desc and desc != "n/a" else dev,
                    hwid=hwid if hwid != "n/a" else "",
                    is_usb=is_usb,
                )
            )
    except Exception:
        pass
    return ports


class SerialConsoleManager:
    """Thread-safe serial port manager with async WebSocket output fan-out and demo CLI."""

    def __init__(self, on_change: Optional[Callable[[], None]] = None) -> None:
        self._on_change = on_change or (lambda: None)
        self._lock = threading.Lock()
        self._ser = None
        self._stop_event = threading.Event()
        self._reader_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._subscribers: Set[asyncio.Queue] = set()

        self._connected = False
        self._demo_session = False
        self._port = ""
        self._baud = 9600
        self._bytes_rx = 0
        self._bytes_tx = 0
        self._status = "Disconnected"
        self._error = ""
        self._buffer = ""
        self._demo_line = ""
        self._demo_priv = False

    def set_event_loop(self, loop: Optional[asyncio.AbstractEventLoop]) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers.discard(q)

    def _emit_chunk(self, text: str) -> None:
        if not text:
            return
        with self._lock:
            self._buffer = (self._buffer + text)[-_MAX_BUFFER_CHARS:]
            subs = list(self._subscribers)
            loop = self._loop

        if loop and not loop.is_closed():
            for q in subs:
                def _put(queue=q, payload=text):
                    if queue.full():
                        try:
                            queue.get_nowait()
                        except asyncio.QueueEmpty:
                            pass
                    try:
                        queue.put_nowait({"type": "rx", "data": payload})
                    except asyncio.QueueFull:
                        pass
                loop.call_soon_threadsafe(_put)

    def _append_rx(self, text: str) -> None:
        with self._lock:
            self._bytes_rx += len(text.encode("utf-8", errors="replace"))
        self._emit_chunk(text)

    def connect(self, port: str, baud: int = 9600, demo_mode: bool = False) -> SerialConsoleState:
        clean_port = validate_serial_port(port)
        clean_baud = validate_baud_rate(baud)
        self.disconnect()

        if demo_mode or os.name == "nt":
            with self._lock:
                self._connected = True
                self._demo_session = True
                self._port = clean_port
                self._baud = clean_baud
                self._bytes_rx = 0
                self._bytes_tx = 0
                self._error = ""
                self._demo_line = ""
                self._demo_priv = False
                self._status = f"Demo Console {clean_port} @ {clean_baud}"
            banner = (
                f"\r\n[JackTrace Serial Console — {clean_port} @ {clean_baud} 8N1 (Demo)]\r\n"
                "Aruba-2930F-24G-PoEP Switch# type 'help' or 'show lldp neighbors'\r\n"
                "SW-CORE-FL2> "
            )
            self._append_rx(banner)
            self._on_change()
            return self.snapshot(demo_mode=demo_mode)

        if serial is None:
            raise RuntimeError("pyserial is not installed in .venv")

        try:
            ser = serial.Serial(
                port=clean_port,
                baudrate=clean_baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
                write_timeout=1.5,
            )
        except Exception as exc:
            msg = f"Failed to open {clean_port}: {exc}"
            with self._lock:
                self._connected = False
                self._error = msg[:140]
                self._status = "Connect Failed"
            self._on_change()
            raise RuntimeError(self._error) from exc

        with self._lock:
            self._ser = ser
            self._connected = True
            self._demo_session = False
            self._port = clean_port
            self._baud = clean_baud
            self._bytes_rx = 0
            self._bytes_tx = 0
            self._error = ""
            self._status = f"Connected {clean_port} @ {clean_baud}"
            self._stop_event.clear()

        t = threading.Thread(target=self._reader_loop, name="jacktrace-serial-rx", daemon=True)
        self._reader_thread = t
        t.start()
        self._emit_chunk(f"\r\n[Opened {clean_port} @ {clean_baud} 8N1]\r\n")
        self._on_change()
        return self.snapshot(demo_mode=False)

    def _reader_loop(self) -> None:
        while not self._stop_event.is_set():
            ser = self._ser
            if ser is None:
                break
            try:
                waiting = ser.in_waiting
                chunk = ser.read(waiting if waiting > 0 else 1)
                if chunk:
                    txt = chunk.decode("utf-8", errors="replace")
                    with self._lock:
                        self._bytes_rx += len(chunk)
                    self._emit_chunk(txt)
            except Exception as exc:
                if not self._stop_event.is_set():
                    with self._lock:
                        self._error = f"Serial read error: {exc}"[:140]
                        self._connected = False
                        self._status = "Disconnected (Error)"
                    self._emit_chunk(f"\r\n[Serial disconnected: {exc}]\r\n")
                    self._on_change()
                break

    def disconnect(self) -> SerialConsoleState:
        self._stop_event.set()
        ser = None
        thread = None
        with self._lock:
            ser = self._ser
            self._ser = None
            thread = self._reader_thread
            self._reader_thread = None
            was_conn = self._connected
            self._connected = False
            self._demo_session = False
            self._status = "Disconnected"

        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=0.5)
        if ser is not None:
            try:
                ser.close()
            except Exception:
                pass
        if was_conn:
            self._emit_chunk("\r\n[Serial port closed]\r\n")
            self._on_change()
        return self.snapshot()

    def _handle_demo_input(self, data: str) -> None:
        for ch in data:
            if ch in ("\r", "\n"):
                cmd = self._demo_line.strip()
                self._demo_line = ""
                prompt = "SW-CORE-FL2# " if self._demo_priv else "SW-CORE-FL2> "
                out = "\r\n"
                low = cmd.lower()
                if low in ("enable", "en"):
                    self._demo_priv = True
                    prompt = "SW-CORE-FL2# "
                elif low in ("disable", "exit") and self._demo_priv:
                    self._demo_priv = False
                    prompt = "SW-CORE-FL2> "
                elif low in ("?", "help"):
                    out += (
                        "Available demo commands:\r\n"
                        "  show version         show int status\r\n"
                        "  show lldp neighbors  show vlan\r\n"
                        "  enable / exit\r\n"
                    )
                elif low.startswith("show ver"):
                    out += (
                        "ArubaOS-Switch WC.16.11.0014 | Aruba 2930F-24G-PoEP (JL255A)\r\n"
                        "Uptime: 42 days, 11 hours, 18 mins | Boot ROM: WC.16.01.0008\r\n"
                    )
                elif low.startswith("show int"):
                    out += (
                        "Port   Name               Status   Vlan  Duplex  Speed   Type\r\n"
                        "1      UPLINK-TRUNK       up       Trunk Full    1000    1000BASE-T\r\n"
                        "24     FL2-OPEN-DESK-13   up       20    Full    1000    1000BASE-T\r\n"
                    )
                elif low.startswith("show lldp"):
                    out += (
                        "LocalPort | ChassisId         | PortId   | SysName\r\n"
                        "1         | 00:1e:f7:4a:9c:01 | Gi1/0/1  | DIST-SW-01\r\n"
                        "24        | 02:00:00:00:00:10 | enp1s0   | jacktrace-deb\r\n"
                    )
                elif low.startswith("show vlan"):
                    out += (
                        "VLAN Name                             Status    Ports\r\n"
                        "1    DEFAULT_VLAN                     active    2-23\r\n"
                        "20   CORP_DATA                        active    1,24\r\n"
                        "110  VOICE_SIP                        active    1,24\r\n"
                    )
                elif cmd:
                    out += f"% Unknown command '{cmd}' (try 'show lldp neighbors')\r\n"
                self._append_rx(out + prompt)
            elif ch in ("\x08", "\x7f"):
                if self._demo_line:
                    self._demo_line = self._demo_line[:-1]
                    self._append_rx("\b \b")
            elif ch == "\x03":
                self._demo_line = ""
                prompt = "SW-CORE-FL2# " if self._demo_priv else "SW-CORE-FL2> "
                self._append_rx("^C\r\n" + prompt)
            elif ord(ch) >= 32 or ch == "\t":
                self._demo_line += ch
                self._append_rx(ch)

    def send(self, data: str, append_cr: bool = False) -> None:
        if not self._connected:
            raise RuntimeError("Serial port is not connected")
        payload = (data or "") + ("\r" if append_cr else "")
        if not payload:
            return
        raw = payload.encode("utf-8", errors="replace")
        with self._lock:
            self._bytes_tx += len(raw)
        if self._demo_session:
            self._handle_demo_input(payload)
            return
        ser = self._ser
        if ser is None:
            raise RuntimeError("Serial port closed")
        ser.write(raw)
        ser.flush()

    def send_break(self) -> None:
        if not self._connected:
            raise RuntimeError("Serial port is not connected")
        if self._demo_session:
            self._append_rx("\r\n[BREAK 250ms sent]\r\nSW-CORE-FL2> ")
            return
        ser = self._ser
        if ser is not None:
            ser.send_break(duration=0.25)

    def clear_buffer(self) -> None:
        with self._lock:
            self._buffer = ""
            subs = list(self._subscribers)
            loop = self._loop
        if loop and not loop.is_closed():
            for q in subs:
                loop.call_soon_threadsafe(lambda queue=q: queue.put_nowait({"type": "clear"}))
        self._on_change()

    def snapshot(self, demo_mode: bool = False, refresh_ports: bool = False) -> SerialConsoleState:
        ports = list_serial_ports(demo_mode=demo_mode) if (refresh_ports or not self._connected) else []
        with self._lock:
            if not ports and self._port:
                ports = [SerialPortInfo(device=self._port, description=self._port)]
            return SerialConsoleState(
                available=(serial is not None) or demo_mode or os.name == "nt",
                connected=self._connected,
                port=self._port,
                baud=self._baud,
                bytes_rx=self._bytes_rx,
                bytes_tx=self._bytes_tx,
                status=self._status,
                error=self._error,
                ports=ports,
                recent_output=self._buffer[-_SNAPSHOT_TAIL_CHARS:],
            )

    def shutdown(self) -> None:
        self.disconnect()
