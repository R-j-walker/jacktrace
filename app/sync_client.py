import asyncio
import json
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .audit import DATA_DIR, DEFAULT_DB_PATH
from .models import SavedWallPort, SyncQueueEntry, SyncState

DEFAULT_SYNC_SETTINGS_PATH = DATA_DIR / "sync_settings.json"
MAX_SYNC_ATTEMPTS = 5


def _now_utc_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _validate_http_url(url: str, label: str) -> str:
    clean = (url or "").strip()
    if not clean:
        return ""
    parsed = urllib.parse.urlparse(clean)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"{label} must start with http:// or https:// and include a host")
    return clean


def _json_http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    payload: Optional[dict] = None,
    timeout: float = 6.0,
) -> Tuple[int, str]:
    body: Optional[bytes] = None
    req_headers = {"User-Agent": "JackTrace/2.0", "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return int(getattr(resp, "status", 200)), raw
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")[:160]
        except Exception:
            pass
        return int(exc.code), (err_body or str(exc.reason or exc.code))


def _post_webhook_sync(url: str, token: str, payload: dict, timeout: float = 6.0) -> Tuple[bool, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        code, detail = _json_http_request(url, method="POST", headers=headers, payload=payload, timeout=timeout)
        if 200 <= code < 300:
            return True, f"HTTP {code}"
        return False, f"HTTP {code}: {detail[:90]}"
    except Exception as exc:
        return False, str(exc)[:110]


def _push_netbox_sync(url: str, token: str, payload: dict, timeout: float = 6.0) -> Tuple[bool, str]:
    base = url.rstrip("/")
    headers = {"Authorization": f"Token {token}"} if token else {}
    port_data = payload.get("port", {})
    switch_name = str(port_data.get("switch_name") or "").strip()
    port_id = str(port_data.get("port_id") or "").strip()
    drop_label = str(port_data.get("drop_label") or "DROP").strip()

    if not switch_name or switch_name.startswith("UNPATCHED"):
        return False, f"{drop_label}: no managed switch neighbor to map in NetBox"
    if not port_id or port_id == "—":
        return False, f"{drop_label}: missing switch port ID"

    try:
        q_name = urllib.parse.quote(switch_name)
        code, raw = _json_http_request(f"{base}/api/dcim/devices/?name={q_name}", method="GET", headers=headers, timeout=timeout)
        if not (200 <= code < 300):
            return False, f"NetBox device lookup HTTP {code}: {raw[:80]}"
        results = (json.loads(raw) or {}).get("results", [])
        if not results:
            code, raw = _json_http_request(f"{base}/api/dcim/devices/?q={q_name}", method="GET", headers=headers, timeout=timeout)
            if 200 <= code < 300:
                results = (json.loads(raw) or {}).get("results", [])
        if not results:
            return False, f"Device '{switch_name}' not found in NetBox"

        dev_id = results[0]["id"]
        q_port = urllib.parse.quote(port_id)
        code, raw = _json_http_request(
            f"{base}/api/dcim/interfaces/?device_id={dev_id}&name={q_port}",
            method="GET",
            headers=headers,
            timeout=timeout,
        )
        if not (200 <= code < 300):
            return False, f"NetBox interface lookup HTTP {code}: {raw[:80]}"
        if_results = (json.loads(raw) or {}).get("results", [])
        if not if_results:
            return False, f"Interface '{port_id}' not found on {switch_name}"

        if_id = if_results[0]["id"]
        parts = [
            f"[{drop_label}]",
            str(port_data.get("vlan_summary") or "Untagged"),
            str(port_data.get("tdr_summary") or "—"),
            str(port_data.get("speed_summary") or "—"),
        ]
        notes = str(port_data.get("notes") or "").strip()
        if notes:
            parts.append(notes)
        desc = " | ".join(parts)[:200]

        code, raw = _json_http_request(
            f"{base}/api/dcim/interfaces/{if_id}/",
            method="PATCH",
            headers=headers,
            payload={"description": desc},
            timeout=timeout,
        )
        if 200 <= code < 300:
            return True, f"Patched {switch_name}:{port_id}"
        return False, f"NetBox PATCH HTTP {code}: {raw[:80]}"
    except Exception as exc:
        return False, str(exc)[:110]


class SyncManager:
    """Offline-capable SQLite sync queue for Webhook (JSON) and NetBox DCIM API."""

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        settings_path: Path = DEFAULT_SYNC_SETTINGS_PATH,
        on_change: Optional[Callable[[], None]] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.settings_path = Path(settings_path)
        self.on_change = on_change
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.settings_path.parent.mkdir(parents=True, exist_ok=True)

        self._syncing: bool = False
        self._last_sync_at: Optional[str] = None
        self._last_status: str = "Not configured"
        self._config: dict = {
            "webhook_url": "",
            "webhook_token": "",
            "webhook_enabled": False,
            "netbox_url": "",
            "netbox_token": "",
            "netbox_enabled": False,
            "auto_sync_on_save": False,
        }
        self._init_db()
        self._load_settings()

    def _notify(self) -> None:
        if self.on_change:
            self.on_change()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    drop_label TEXT NOT NULL,
                    job_name TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_error TEXT NOT NULL DEFAULT ''
                )
                """
            )
            conn.commit()

    def _load_settings(self) -> None:
        if not self.settings_path.is_file():
            return
        try:
            raw = json.loads(self.settings_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for key in self._config:
                    if key in raw:
                        self._config[key] = raw[key]
                if self._config["webhook_enabled"] or self._config["netbox_enabled"]:
                    self._last_status = "Ready"
        except Exception:
            pass

    def _save_settings(self) -> None:
        self.settings_path.write_text(json.dumps(self._config, indent=2), encoding="utf-8")

    @property
    def auto_sync_on_save(self) -> bool:
        return bool(self._config.get("auto_sync_on_save", False))

    def update_config(
        self,
        webhook_url: Optional[str] = None,
        webhook_token: Optional[str] = None,
        webhook_enabled: Optional[bool] = None,
        netbox_url: Optional[str] = None,
        netbox_token: Optional[str] = None,
        netbox_enabled: Optional[bool] = None,
        auto_sync_on_save: Optional[bool] = None,
    ) -> SyncState:
        if webhook_url is not None:
            self._config["webhook_url"] = _validate_http_url(webhook_url, "Webhook URL")
        if webhook_token is not None:
            self._config["webhook_token"] = webhook_token.strip()
        if webhook_enabled is not None:
            self._config["webhook_enabled"] = bool(webhook_enabled)

        if netbox_url is not None:
            self._config["netbox_url"] = _validate_http_url(netbox_url, "NetBox URL").rstrip("/")
        if netbox_token is not None:
            self._config["netbox_token"] = netbox_token.strip()
        if netbox_enabled is not None:
            self._config["netbox_enabled"] = bool(netbox_enabled)

        if auto_sync_on_save is not None:
            self._config["auto_sync_on_save"] = bool(auto_sync_on_save)

        self._save_settings()
        self._last_status = "Sync configuration saved"
        self._notify()
        return self.snapshot()

    @staticmethod
    def build_port_payload(port: SavedWallPort) -> dict:
        return {
            "event": "jacktrace.wall_port",
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "port": port.model_dump(),
        }

    def enqueue_port(self, port: SavedWallPort) -> int:
        targets: List[str] = []
        if self._config.get("webhook_enabled") and self._config.get("webhook_url"):
            targets.append("webhook")
        if self._config.get("netbox_enabled") and self._config.get("netbox_url"):
            targets.append("netbox")
        if not targets:
            return 0

        payload_json = json.dumps(self.build_port_payload(port))
        now = _now_utc_str()
        added = 0
        with self._connect() as conn:
            for tgt in targets:
                conn.execute(
                    """
                    INSERT INTO sync_queue (
                        target, drop_label, job_name, payload_json,
                        status, attempts, created_at, updated_at, last_error
                    ) VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?, '')
                    """,
                    (tgt, port.drop_label, port.job_name, payload_json, now, now),
                )
                added += 1
            conn.commit()
        if added:
            self._last_status = f"Queued {added} item(s) for {port.drop_label}"
        return added

    def enqueue_ports(self, ports: List[SavedWallPort]) -> int:
        total = 0
        for p in ports:
            total += self.enqueue_port(p)
        if total == 0:
            self._last_status = "Enable Webhook or NetBox URL first"
        self._notify()
        return total

    def clear_queue(self, only_sent: bool = False) -> None:
        with self._connect() as conn:
            if only_sent:
                conn.execute("DELETE FROM sync_queue WHERE status='SENT'")
            else:
                conn.execute("DELETE FROM sync_queue")
            conn.commit()
        self._last_status = "Cleared delivered items" if only_sent else "Sync queue cleared"
        self._notify()

    def pending_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM sync_queue WHERE status='PENDING' OR (status='FAILED' AND attempts < ?)",
                (MAX_SYNC_ATTEMPTS,),
            ).fetchone()
            return int(row["cnt"]) if row else 0

    def test_netbox_sync(self, demo_mode: bool) -> Tuple[bool, str]:
        if demo_mode:
            ok, msg = True, "Demo NetBox v4.1.2 connected (Token OK)"
            self._last_sync_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            self._last_status = msg
            self._notify()
            return ok, msg

        url = str(self._config.get("netbox_url") or "").strip().rstrip("/")
        token = str(self._config.get("netbox_token") or "").strip()
        if not url:
            msg = "NetBox URL not configured"
            self._last_status = msg
            self._notify()
            return False, msg

        headers = {"Authorization": f"Token {token}"} if token else {}
        try:
            code, raw = _json_http_request(f"{url}/api/status/", method="GET", headers=headers, timeout=6.0)
            if 200 <= code < 300:
                info = json.loads(raw) if raw else {}
                ver = info.get("netbox-version", "OK")
                msg = f"NetBox v{ver} connected"
                self._last_sync_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
                self._last_status = msg
                self._notify()
                return True, msg
            msg = f"NetBox HTTP {code}: {raw[:80]}"
        except Exception as exc:
            msg = f"NetBox test failed: {str(exc)[:80]}"

        self._last_status = msg
        self._notify()
        return False, msg

    def _deliver_row_sync(self, row: dict, demo_mode: bool) -> Tuple[bool, str]:
        target = row["target"]
        if demo_mode:
            return True, f"Demo {target} delivered"

        payload = json.loads(row["payload_json"])
        if target == "webhook":
            url = str(self._config.get("webhook_url") or "").strip()
            token = str(self._config.get("webhook_token") or "").strip()
            if not url:
                return False, "Webhook URL missing"
            return _post_webhook_sync(url, token, payload)

        if target == "netbox":
            url = str(self._config.get("netbox_url") or "").strip()
            token = str(self._config.get("netbox_token") or "").strip()
            if not url:
                return False, "NetBox URL missing"
            return _push_netbox_sync(url, token, payload)

        return False, f"Unknown sync target: {target}"

    async def flush_queue(self, demo_mode: bool) -> SyncState:
        if self._syncing:
            return self.snapshot()

        self._syncing = True
        self._notify()
        sent_now = 0
        failed_now = 0
        last_err = ""

        try:
            with self._connect() as conn:
                rows = [
                    dict(r)
                    for r in conn.execute(
                        """
                        SELECT * FROM sync_queue
                        WHERE status='PENDING' OR (status='FAILED' AND attempts < ?)
                        ORDER BY id ASC
                        LIMIT 25
                        """,
                        (MAX_SYNC_ATTEMPTS,),
                    ).fetchall()
                ]

            if not rows:
                self._last_status = "Queue empty — nothing to sync"
                return self.snapshot()

            for row in rows:
                ok, msg = await asyncio.to_thread(self._deliver_row_sync, row, demo_mode)
                now = _now_utc_str()
                next_attempts = int(row["attempts"]) + 1
                next_status = "SENT" if ok else "FAILED"
                err_txt = "" if ok else msg
                if ok:
                    sent_now += 1
                else:
                    failed_now += 1
                    last_err = msg

                with self._connect() as conn:
                    conn.execute(
                        """
                        UPDATE sync_queue
                        SET status=?, attempts=?, updated_at=?, last_error=?
                        WHERE id=?
                        """,
                        (next_status, next_attempts, now, err_txt, row["id"]),
                    )
                    conn.commit()

            self._last_sync_at = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            if failed_now == 0:
                self._last_status = f"Synced {sent_now} item(s) cleanly"
            else:
                self._last_status = f"Sent {sent_now}, {failed_now} retryable ({last_err[:55]})"
        finally:
            self._syncing = False
            self._notify()

        return self.snapshot()

    def push_webhook_event(
        self, event: str, data: dict, demo_mode: bool = False
    ) -> Tuple[bool, str]:
        """Synchronously post a custom JSON event payload to the configured Webhook URL."""
        if demo_mode:
            return True, "Demo webhook delivered"

        url = str(self._config.get("webhook_url") or "").strip()
        token = str(self._config.get("webhook_token") or "").strip()
        if not url:
            return False, "Configure Webhook URL in LOG → Sync first"

        payload = {
            "event": event,
            "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            **(data or {}),
        }
        return _post_webhook_sync(url, token, payload)

    def snapshot(self) -> SyncState:
        with self._connect() as conn:
            counts_rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM sync_queue GROUP BY status"
            ).fetchall()
            counts = {r["status"]: int(r["cnt"]) for r in counts_rows}
            recent = [
                SyncQueueEntry(
                    id=int(r["id"]),
                    target=str(r["target"]),
                    drop_label=str(r["drop_label"]),
                    job_name=str(r["job_name"]),
                    status=str(r["status"]),
                    attempts=int(r["attempts"]),
                    created_at=str(r["created_at"]),
                    last_error=str(r["last_error"] or ""),
                )
                for r in conn.execute(
                    "SELECT * FROM sync_queue ORDER BY id DESC LIMIT 8"
                ).fetchall()
            ]

        return SyncState(
            webhook_url=str(self._config.get("webhook_url") or ""),
            webhook_has_token=bool(self._config.get("webhook_token")),
            webhook_enabled=bool(self._config.get("webhook_enabled")),
            netbox_url=str(self._config.get("netbox_url") or ""),
            netbox_has_token=bool(self._config.get("netbox_token")),
            netbox_enabled=bool(self._config.get("netbox_enabled")),
            auto_sync_on_save=bool(self._config.get("auto_sync_on_save")),
            syncing=self._syncing,
            pending_count=counts.get("PENDING", 0),
            sent_count=counts.get("SENT", 0),
            failed_count=counts.get("FAILED", 0),
            last_sync_at=self._last_sync_at,
            last_status=self._last_status,
            recent_queue=recent,
        )
