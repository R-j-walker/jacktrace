import base64
import csv
import io
import json
import os
import re
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

import segno
from fpdf import FPDF

from .models import (
    AuditJobSummary,
    AuditPortalState,
    PcapCaptureState,
    SavedWallPort,
    SecurityReportState,
    SubnetScanState,
    TesterSnapshot,
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_DB_PATH = DATA_DIR / "jacktrace_audit.db"


def _pdf_safe(text: str) -> str:
    """Sanitize Unicode punctuation to Latin-1 safe equivalents for built-in PDF fonts."""
    if not text:
        return "-"
    repl = (
        text.replace("•", "|")
        .replace("—", "-")
        .replace("–", "-")
        .replace("→", "->")
        .replace("◄", "<")
        .replace("▸", ">")
        .replace("⚠", "[!]")
        .replace("✓", "[OK]")
        .replace("Ω", "Ohm")
    )
    return repl.encode("latin-1", errors="replace").decode("latin-1")


def make_qr_data_uri(url: str) -> str:
    qr = segno.make(url, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=3, border=1, dark="#0f172a", light="#ffffff")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{b64}"


def detect_wlan_portal_info(
    port: int = 8080,
    fallback_eth_ip: str = "—",
    wifi_iface: str = "wlan0",
) -> Tuple[bool, str, str, str]:
    wifi_ip = ""
    ap_active = False
    ssid = "Wi-Fi"
    w_if = (wifi_iface or "wlan0").strip() or "wlan0"

    if os.name != "nt":
        try:
            proc = subprocess.run(
                ["ip", "-j", "-4", "addr", "show", "dev", w_if],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                arr = json.loads(proc.stdout)
                for item in arr:
                    for ai in item.get("addr_info", []):
                        if ai.get("local"):
                            wifi_ip = ai["local"]
                            break
        except Exception:
            pass

        try:
            iw = subprocess.run(
                ["iw", "dev", w_if, "info"],
                capture_output=True,
                text=True,
                timeout=1.5,
                check=False,
            )
            if iw.returncode == 0 and iw.stdout:
                for line in iw.stdout.splitlines():
                    s = line.strip()
                    if s.startswith("type "):
                        ap_active = "AP" in s.upper()
                    elif s.startswith("ssid "):
                        ssid = s[5:].strip()
        except Exception:
            pass

    host_for_url = wifi_ip
    if not host_for_url:
        if fallback_eth_ip and fallback_eth_ip != "—" and not fallback_eth_ip.startswith("169.254."):
            host_for_url = fallback_eth_ip
        else:
            host_for_url = "localhost"

    portal_url = f"http://{host_for_url}:{port}"
    return ap_active, ssid, (wifi_ip or "—"), portal_url


def toggle_wlan_hotspot(enable_ap: bool, wifi_iface: str = "wlan0") -> Tuple[bool, str]:
    w_if = (wifi_iface or "wlan0").strip() or "wlan0"
    if os.name == "nt":
        return False, f"Hotspot toggle requires Linux {w_if} hardware."

    if enable_ap:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"], capture_output=True, check=False)
        res = subprocess.run(
            [
                "nmcli",
                "device",
                "wifi",
                "hotspot",
                "ifname",
                w_if,
                "con-name",
                "JackTrace-Hotspot",
                "ssid",
                "JackTrace-AP",
                "password",
                "jacktrace",
            ],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
        )
        if res.returncode == 0:
            return True, "Hotspot JackTrace-AP (pass: jacktrace) active"
        return False, (res.stderr.strip() or "nmcli hotspot failed")
    else:
        subprocess.run(["nmcli", "connection", "down", "JackTrace-Hotspot"], capture_output=True, timeout=6.0, check=False)
        subprocess.run(["nmcli", "connection", "delete", "JackTrace-Hotspot"], capture_output=True, timeout=6.0, check=False)
        subprocess.run(["nmcli", "device", "connect", w_if], capture_output=True, timeout=8.0, check=False)
        return True, f"Reconnected {w_if} to client Wi-Fi"


class AuditStore:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _sanitize_prefix(prefix: Optional[str]) -> str:
        clean = re.sub(r"[^A-Za-z0-9]", "", (prefix or "").upper())[:6]
        return clean or "W"

    def _init_db(self) -> None:
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS meta_kv (
                    k TEXT PRIMARY KEY,
                    v TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_jobs (
                    name TEXT PRIMARY KEY,
                    prefix TEXT NOT NULL DEFAULT 'W',
                    next_drop INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS wall_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_name TEXT NOT NULL,
                    drop_label TEXT NOT NULL,
                    saved_at TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    switch_name TEXT NOT NULL,
                    switch_model TEXT NOT NULL,
                    switch_ip TEXT NOT NULL,
                    port_id TEXT NOT NULL,
                    panel_summary TEXT NOT NULL,
                    speed_summary TEXT NOT NULL,
                    poe_summary TEXT NOT NULL,
                    vlan_summary TEXT NOT NULL,
                    ip_cidr TEXT NOT NULL,
                    gateway_summary TEXT NOT NULL,
                    security_grade TEXT NOT NULL,
                    tdr_summary TEXT NOT NULL DEFAULT '—',
                    notes TEXT NOT NULL DEFAULT ''
                )
                """
            )
            # Seamless schema upgrade from Phase 2 DBs
            try:
                conn.execute("ALTER TABLE wall_ports ADD COLUMN tdr_summary TEXT NOT NULL DEFAULT '—'")
            except sqlite3.OperationalError:
                pass

            conn.execute("INSERT OR IGNORE INTO meta_kv (k, v) VALUES ('job_name', 'West Wing Audit')")
            conn.execute("INSERT OR IGNORE INTO meta_kv (k, v) VALUES ('next_drop', '1')")

            r_job = conn.execute("SELECT v FROM meta_kv WHERE k='job_name'").fetchone()
            r_nxt = conn.execute("SELECT v FROM meta_kv WHERE k='next_drop'").fetchone()
            active_job = r_job["v"] if r_job else "West Wing Audit"
            active_nxt = int(r_nxt["v"]) if (r_nxt and str(r_nxt["v"]).isdigit()) else 1

            conn.execute(
                "INSERT OR IGNORE INTO audit_jobs (name, prefix, next_drop, created_at) VALUES (?, 'W', ?, ?)",
                (active_job, max(1, active_nxt), now_ts),
            )
            # Register any legacy jobs found in wall_ports
            legacy_rows = conn.execute(
                "SELECT job_name, COUNT(*) AS cnt FROM wall_ports GROUP BY job_name"
            ).fetchall()
            for lr in legacy_rows:
                conn.execute(
                    "INSERT OR IGNORE INTO audit_jobs (name, prefix, next_drop, created_at) VALUES (?, 'W', ?, ?)",
                    (lr["job_name"], max(1, int(lr["cnt"]) + 1), now_ts),
                )
            conn.commit()

    def get_job_full_meta(self) -> Tuple[str, str, int]:
        with self._connect() as conn:
            r_job = conn.execute("SELECT v FROM meta_kv WHERE k='job_name'").fetchone()
            job = r_job["v"] if r_job else "West Wing Audit"
            jr = conn.execute("SELECT prefix, next_drop FROM audit_jobs WHERE name=?", (job,)).fetchone()
            if jr:
                return job, self._sanitize_prefix(jr["prefix"]), max(1, int(jr["next_drop"]))
            r_nxt = conn.execute("SELECT v FROM meta_kv WHERE k='next_drop'").fetchone()
            nxt = int(r_nxt["v"]) if (r_nxt and str(r_nxt["v"]).isdigit()) else 1
            return job, "W", max(1, nxt)

    def get_job_meta(self) -> Tuple[str, int]:
        job, _prefix, nxt = self.get_job_full_meta()
        return job, nxt

    def set_job_meta(self, job_name: str, next_drop: Optional[int] = None, clear_ports: bool = False) -> None:
        old_job, old_prefix, old_nxt = self.get_job_full_meta()
        clean_name = (job_name or "").strip()[:48] or old_job
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            if clean_name != old_job:
                existing = conn.execute("SELECT name FROM audit_jobs WHERE name=?", (clean_name,)).fetchone()
                if not existing:
                    # Rename active job + migrate its rows cleanly
                    conn.execute(
                        "UPDATE audit_jobs SET name=? WHERE name=?", (clean_name, old_job)
                    )
                    conn.execute(
                        "UPDATE wall_ports SET job_name=? WHERE job_name=?", (clean_name, old_job)
                    )
                conn.execute("INSERT OR IGNORE INTO audit_jobs (name, prefix, next_drop, created_at) VALUES (?, ?, ?, ?)", (clean_name, old_prefix, old_nxt, now_ts))
                conn.execute("INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('job_name', ?)", (clean_name,))

            if next_drop is not None and next_drop >= 1:
                conn.execute("UPDATE audit_jobs SET next_drop=? WHERE name=?", (int(next_drop), clean_name))
                conn.execute("INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('next_drop', ?)", (str(next_drop),))

            if clear_ports:
                conn.execute("DELETE FROM wall_ports WHERE job_name=?", (clean_name,))
                conn.execute("UPDATE audit_jobs SET next_drop=1 WHERE name=?", (clean_name,))
                conn.execute("INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('next_drop', '1')")
            conn.commit()

    def switch_or_create_job(self, job_name: str, prefix: Optional[str] = None) -> None:
        clean_name = (job_name or "").strip()[:48] or "Site Audit"
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            existing = conn.execute("SELECT prefix, next_drop FROM audit_jobs WHERE name=?", (clean_name,)).fetchone()
            if not existing:
                clean_pref = self._sanitize_prefix(prefix)
                nxt = 1
                conn.execute(
                    "INSERT INTO audit_jobs (name, prefix, next_drop, created_at) VALUES (?, ?, 1, ?)",
                    (clean_name, clean_pref, now_ts),
                )
            else:
                nxt = max(1, int(existing["next_drop"]))
                if prefix:
                    conn.execute(
                        "UPDATE audit_jobs SET prefix=? WHERE name=?",
                        (self._sanitize_prefix(prefix), clean_name),
                    )
            conn.execute("INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('job_name', ?)", (clean_name,))
            conn.execute("INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('next_drop', ?)", (str(nxt),))
            conn.commit()

    def delete_job(self, job_name: str) -> None:
        clean = (job_name or "").strip()
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            conn.execute("DELETE FROM wall_ports WHERE job_name=?", (clean,))
            conn.execute("DELETE FROM audit_jobs WHERE name=?", (clean,))
            remaining = conn.execute("SELECT name, next_drop FROM audit_jobs ORDER BY created_at ASC").fetchall()
            if not remaining:
                conn.execute(
                    "INSERT INTO audit_jobs (name, prefix, next_drop, created_at) VALUES ('West Wing Audit', 'W', 1, ?)",
                    (now_ts,),
                )
                nxt_job, nxt_num = "West Wing Audit", 1
            else:
                cur_meta = conn.execute("SELECT v FROM meta_kv WHERE k='job_name'").fetchone()
                cur_name = cur_meta["v"] if cur_meta else ""
                match = next((r for r in remaining if r["name"] == cur_name), remaining[0])
                nxt_job, nxt_num = match["name"], max(1, int(match["next_drop"]))
            conn.execute("INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('job_name', ?)", (nxt_job,))
            conn.execute("INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('next_drop', ?)", (str(nxt_num),))
            conn.commit()

    def set_prefix(self, prefix: str) -> str:
        clean_pref = self._sanitize_prefix(prefix)
        job_name, _old_p, _nxt = self.get_job_full_meta()
        with self._connect() as conn:
            conn.execute("UPDATE audit_jobs SET prefix=? WHERE name=?", (clean_pref, job_name))
            conn.commit()
        return clean_pref

    def update_port_notes(self, row_id: int, notes: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE wall_ports SET notes=? WHERE id=?", ((notes or "").strip()[:160], row_id))
            conn.commit()

    def list_jobs(self) -> List[AuditJobSummary]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT j.name, j.prefix, j.next_drop, COUNT(w.id) AS cnt
                FROM audit_jobs j
                LEFT JOIN wall_ports w ON w.job_name = j.name
                GROUP BY j.name
                ORDER BY j.created_at ASC, j.name ASC
                """
            ).fetchall()
            return [
                AuditJobSummary(
                    name=r["name"],
                    prefix=self._sanitize_prefix(r["prefix"]),
                    next_drop=max(1, int(r["next_drop"])),
                    count=int(r["cnt"]),
                )
                for r in rows
            ]

    @staticmethod
    def _compact_tdr_summary(snap: TesterSnapshot) -> str:
        tdr = snap.tdr
        if tdr.overall_verdict == "NOT_RUN" or not tdr.pairs:
            if snap.link.speed_mbps and snap.link.speed_mbps >= 1000:
                return "4 Pairs OK (1G)"
            if snap.link.pair_downshift_suspected:
                return "2-Pair 100M!"
            return "—"
        if tdr.overall_verdict == "PASS":
            d0 = next((p.distance_m for p in tdr.pairs if p.distance_m is not None), None)
            return f"4 Pairs OK ({d0}m)" if d0 else "4 Pairs OK"
        if tdr.overall_verdict == "UNPATCHED":
            dists = [p.distance_m for p in tdr.pairs if p.distance_m is not None]
            if dists:
                avg = round(sum(dists) / len(dists), 1)
                return f"Open ~{avg}m"
            return "Open"
        bad = [
            f"{p.pair_name.replace('Pair ', 'P')}:{p.status}" + (f"@{p.distance_m}m" if p.distance_m is not None else "")
            for p in tdr.pairs
            if p.status != "OK"
        ]
        return " ".join(bad[:2]) if bad else tdr.overall_verdict

    def save_snapshot(
        self,
        snap: TesterSnapshot,
        custom_label: Optional[str] = None,
        notes: str = "",
    ) -> SavedWallPort:
        job_name, prefix, next_num = self.get_job_full_meta()
        drop_label = (custom_label or "").strip() or f"{prefix}-{next_num:02d}"
        saved_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        spd_summary = (
            f"{snap.link.speed_mbps or '?'}M {snap.link.duplex}"
            if snap.link.carrier_up
            else "NO LINK"
        )
        if snap.poe.supported:
            w = f" ({snap.poe.allocated_watts}W)" if snap.poe.allocated_watts else ""
            poe_summary = f"{snap.poe.standard}{w}"
        else:
            poe_summary = "None"

        vlan_parts: List[str] = []
        if snap.vlan.native_vlan is not None:
            vlan_parts.append(f"V{snap.vlan.native_vlan}")
        if snap.vlan.voice_vlan is not None:
            vlan_parts.append(f"VoIP:{snap.vlan.voice_vlan}")
        if snap.vlan.tagged_vlans:
            vlan_parts.append(f"Tag:{','.join(str(x) for x in snap.vlan.tagged_vlans)}")
        vlan_summary = " ".join(vlan_parts) if vlan_parts else "Untagged"

        gw_sum = (
            f"{snap.l3.gateway_ip} ({snap.l3.gateway_ping_ms}ms)"
            if (snap.l3.gateway_ip != "—" and snap.l3.gateway_ping_ms is not None)
            else snap.l3.gateway_ip
        )
        sec_grade = f"{snap.security.grade} ({snap.security.score})"
        tdr_sum = self._compact_tdr_summary(snap)

        sw_name = snap.switch.switch_name if snap.switch.detected else "UNPATCHED / UNKNOWN"
        sw_model = snap.switch.model if snap.switch.detected else "—"
        sw_ip = snap.switch.mgmt_ip if snap.switch.detected else "—"
        port_id = snap.switch.port_id if snap.switch.detected else "—"
        panel_sum = snap.switch.panel.summary if snap.switch.detected else snap.link.pair_diagnostic_note[:38]

        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO wall_ports (
                    job_name, drop_label, saved_at, verdict,
                    switch_name, switch_model, switch_ip, port_id, panel_summary,
                    speed_summary, poe_summary, vlan_summary, ip_cidr, gateway_summary,
                    security_grade, tdr_summary, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_name,
                    drop_label,
                    saved_at,
                    snap.autotest_verdict,
                    sw_name,
                    sw_model,
                    sw_ip,
                    port_id,
                    panel_sum,
                    spd_summary,
                    poe_summary,
                    vlan_summary,
                    snap.l3.subnet_cidr,
                    gw_sum,
                    sec_grade,
                    tdr_sum,
                    notes.strip(),
                ),
            )
            row_id = int(cur.lastrowid)
            if not custom_label:
                conn.execute(
                    "UPDATE audit_jobs SET next_drop=? WHERE name=?",
                    (next_num + 1, job_name),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO meta_kv (k, v) VALUES ('next_drop', ?)",
                    (str(next_num + 1),),
                )
            conn.commit()

        return self.get_port_by_id(row_id)

    def get_port_by_id(self, row_id: int) -> SavedWallPort:
        with self._connect() as conn:
            r = conn.execute("SELECT * FROM wall_ports WHERE id=?", (row_id,)).fetchone()
            return SavedWallPort(**dict(r))

    def delete_port(self, row_id: int) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM wall_ports WHERE id=?", (row_id,))
            conn.commit()

    def list_all_ports(self, job_name: Optional[str] = None) -> List[SavedWallPort]:
        target_job = job_name if job_name is not None else self.get_job_full_meta()[0]
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM wall_ports WHERE job_name=? ORDER BY id DESC",
                (target_job,),
            ).fetchall()
            return [SavedWallPort(**dict(r)) for r in rows]

    def generate_csv_text(self, job_name: Optional[str] = None) -> str:
        ports = list(reversed(self.list_all_ports(job_name=job_name)))
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "Drop",
                "Job",
                "Saved At",
                "Verdict",
                "Switch",
                "Model",
                "Switch IP",
                "Port",
                "Panel Location",
                "Speed",
                "PoE",
                "VLANs",
                "TDR",
                "Client IP",
                "Gateway",
                "Security",
                "Notes",
            ]
        )
        for r in ports:
            writer.writerow(
                [
                    r.drop_label,
                    r.job_name,
                    r.saved_at,
                    r.verdict,
                    r.switch_name,
                    r.switch_model,
                    r.switch_ip,
                    r.port_id,
                    r.panel_summary,
                    r.speed_summary,
                    r.poe_summary,
                    r.vlan_summary,
                    r.tdr_summary,
                    r.ip_cidr,
                    r.gateway_summary,
                    r.security_grade,
                    r.notes,
                ]
            )
        return buf.getvalue()

    def generate_json_dict(
        self,
        security: SecurityReportState,
        scan: SubnetScanState,
        job_name: Optional[str] = None,
    ) -> dict:
        active_job, prefix, _nxt = self.get_job_full_meta()
        target = job_name or active_job
        ports = list(reversed(self.list_all_ports(job_name=target)))
        return {
            "job_name": target,
            "drop_prefix": prefix,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_saved": len(ports),
            "security": security.model_dump(),
            "scan": scan.model_dump(),
            "ports": [p.model_dump() for p in ports],
        }

    def build_portal_state(
        self,
        port: int,
        eth_ip: str,
        pcap_dict: dict,
        wifi_iface: str = "wlan0",
    ) -> AuditPortalState:
        job_name, drop_prefix, next_num = self.get_job_full_meta()
        all_rows = self.list_all_ports(job_name=job_name)
        pass_cnt = sum(1 for r in all_rows if r.verdict == "PASS")
        fail_cnt = len(all_rows) - pass_cnt

        ap_active, ssid, wifi_ip, portal_url = detect_wlan_portal_info(
            port=port,
            fallback_eth_ip=eth_ip,
            wifi_iface=wifi_iface,
        )
        pdf_url = f"{portal_url}/api/audit/report.pdf"
        csv_url = f"{portal_url}/api/audit/report.csv"
        qr_uri = make_qr_data_uri(pdf_url)

        pcap_state = PcapCaptureState(
            capturing=bool(pcap_dict.get("capturing", False)),
            filename=str(pcap_dict.get("filename", "—")),
            packets_captured=int(pcap_dict.get("packets_captured", 0)),
            size_bytes=int(pcap_dict.get("size_bytes", 0)),
            completed_at=pcap_dict.get("completed_at"),
        )

        return AuditPortalState(
            job_name=job_name,
            drop_prefix=drop_prefix,
            next_drop_number=next_num,
            next_drop_label=f"{drop_prefix}-{next_num:02d}",
            total_saved=len(all_rows),
            pass_count=pass_cnt,
            warn_fail_count=fail_cnt,
            portal_url=portal_url,
            pdf_url=pdf_url,
            csv_url=csv_url,
            qr_svg_data_uri=qr_uri,
            wifi_ap_active=ap_active,
            wifi_ssid=ssid,
            wifi_ip=wifi_ip,
            pcap=pcap_state,
            recent_ports=all_rows[:25],
            jobs=self.list_jobs(),
        )

    def generate_pdf_bytes(
        self,
        security: SecurityReportState,
        scan: SubnetScanState,
    ) -> bytes:
        job_name, _ = self.get_job_meta()
        ports = list(reversed(self.list_all_ports()))
        pass_cnt = sum(1 for r in ports if r.verdict == "PASS")
        warn_cnt = len(ports) - pass_cnt
        generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        pdf = FPDF(orientation="L", unit="mm", format="A4")
        pdf.set_auto_page_break(auto=True, margin=12)
        pdf.add_page()

        # Bench Instrument Header Banner (Matte Graphite + Safety Amber Accent)
        pdf.set_fill_color(17, 18, 20)
        pdf.rect(10, 10, 277, 21, style="F")
        pdf.set_fill_color(245, 158, 11)
        pdf.rect(10, 10, 3.2, 21, style="F")
        pdf.rect(10, 30.2, 277, 0.8, style="F")

        pdf.set_xy(17, 12.8)
        pdf.set_font("Helvetica", "B", 15)
        pdf.set_text_color(245, 158, 11)
        pdf.cell(36, 7, "JACKTRACE", new_x="RIGHT", new_y="TOP")
        pdf.set_text_color(244, 244, 245)
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(155, 7, "  //  FIELD PORT & NETWORK AUDIT REPORT", new_x="RIGHT", new_y="TOP")

        pdf.set_font("Courier", "B", 8.5)
        pdf.set_text_color(161, 161, 170)
        pdf.set_xy(210, 14)
        pdf.cell(72, 5, _pdf_safe(generated_ts), align="R")

        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(212, 212, 216)
        pdf.set_xy(17, 21.8)
        pdf.cell(
            265,
            5.5,
            _pdf_safe(f"Site / Job: {job_name}   |   Analyzer: JackTrace Bench Instrument"),
            new_x="LMARGIN",
            new_y="NEXT",
        )

        # Executive 4-Box Telemetry Summary Strip
        kpi_y = 35
        kpi_w = 66.25
        kpi_h = 14.5
        kpis = [
            ("AUDIT JOB / SITE", job_name[:26], (24, 26, 31)),
            ("LOGGED WALL DROPS", f"{len(ports)} Total ({pass_cnt} Pass / {warn_cnt} Warn)", (21, 128, 61) if warn_cnt == 0 else (180, 83, 9)),
            ("L2 SECURITY POSTURE", f"Grade {security.grade} ({security.score}/100)", (21, 128, 61) if security.score >= 85 else (185, 28, 28)),
            ("SUBNET DISCOVERY", f"{scan.active_count} Hosts | {scan.subnet}", (24, 26, 31)),
        ]
        for idx_k, (lbl, val, val_rgb) in enumerate(kpis):
            kx = 10 + idx_k * (kpi_w + 4.0)
            pdf.set_fill_color(246, 247, 249)
            pdf.set_draw_color(214, 218, 224)
            pdf.rect(kx, kpi_y, kpi_w, kpi_h, style="DF")
            pdf.set_fill_color(245, 158, 11)
            pdf.rect(kx, kpi_y, kpi_w, 1.0, style="F")
            pdf.set_xy(kx + 3, kpi_y + 2.3)
            pdf.set_font("Helvetica", "B", 7)
            pdf.set_text_color(113, 113, 122)
            pdf.cell(kpi_w - 6, 3.8, _pdf_safe(lbl))
            pdf.set_xy(kx + 3, kpi_y + 7.2)
            pdf.set_font("Courier", "B", 9.5)
            pdf.set_text_color(*val_rgb)
            pdf.cell(kpi_w - 6, 5.5, _pdf_safe(val)[:28])

        pdf.set_xy(10, kpi_y + kpi_h + 4.5)

        cols = [
            ("DROP", 16),
            ("STATUS", 16),
            ("SWITCH HOST & MODEL", 52),
            ("PORT", 22),
            ("LINK", 21),
            ("CABLE / TDR", 34),
            ("PoE", 30),
            ("VLANs", 33),
            ("MGMT IP", 24),
            ("CLIENT IP", 29),
        ]
        pdf.set_draw_color(205, 210, 218)
        pdf.set_fill_color(30, 32, 38)
        pdf.set_text_color(245, 158, 11)
        pdf.set_font("Helvetica", "B", 7.8)
        for cname, cw in cols:
            pdf.cell(cw, 8, cname, border=1, fill=True, align="C")
        pdf.ln()

        pdf.set_font("Courier", "", 7.5)
        if not ports:
            pdf.set_fill_color(249, 249, 251)
            pdf.set_text_color(100, 104, 114)
            pdf.cell(
                277,
                10,
                "No wall ports logged yet. Tap SAVE DROP on JackTrace to record sockets into this audit job.",
                border=1,
                fill=True,
                new_x="LMARGIN",
                new_y="NEXT",
                align="C",
            )
        else:
            for idx, r in enumerate(ports):
                if idx % 2 == 0:
                    pdf.set_fill_color(252, 252, 253)
                else:
                    pdf.set_fill_color(242, 243, 246)

                pdf.set_text_color(24, 26, 31)
                pdf.set_font("Courier", "B", 7.5)
                pdf.cell(16, 7, _pdf_safe(r.drop_label)[:7], border=1, fill=True, align="C")

                if r.verdict == "PASS":
                    pdf.set_text_color(21, 128, 61)
                elif r.verdict == "WARN":
                    pdf.set_text_color(180, 83, 9)
                else:
                    pdf.set_text_color(190, 18, 60)
                pdf.cell(16, 7, _pdf_safe(r.verdict)[:7], border=1, fill=True, align="C")
                pdf.set_font("Courier", "", 7.5)
                pdf.set_text_color(24, 26, 31)

                sw_combo = f"{r.switch_name} ({r.switch_model})" if r.switch_model != "—" else r.switch_name
                pdf.cell(52, 7, _pdf_safe(sw_combo)[:31], border=1, fill=True)
                pdf.cell(22, 7, _pdf_safe(r.port_id)[:12], border=1, fill=True, align="C")
                pdf.cell(21, 7, _pdf_safe(r.speed_summary)[:11], border=1, fill=True, align="C")
                pdf.cell(34, 7, _pdf_safe(r.tdr_summary)[:19], border=1, fill=True, align="C")
                pdf.cell(30, 7, _pdf_safe(r.poe_summary)[:18], border=1, fill=True, align="C")
                pdf.cell(33, 7, _pdf_safe(r.vlan_summary)[:20], border=1, fill=True, align="C")
                pdf.cell(24, 7, _pdf_safe(r.switch_ip)[:15], border=1, fill=True, align="C")
                pdf.cell(29, 7, _pdf_safe(r.ip_cidr)[:17], border=1, fill=True, align="C")
                pdf.ln()

        pdf.ln(5.5)
        sec_y = pdf.get_y()
        pdf.set_fill_color(245, 158, 11)
        pdf.rect(10, sec_y + 1, 2.0, 5.2, style="F")
        pdf.set_x(14)
        pdf.set_font("Helvetica", "B", 10.5)
        pdf.set_text_color(24, 26, 31)
        pdf.cell(
            273,
            7,
            _pdf_safe(
                f"Subnet Security Summary - Grade {security.grade} ({security.score}/100) | Active Subnet Hosts: {scan.active_count}"
            ),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_font("Helvetica", "", 8.8)
        pdf.set_text_color(63, 66, 76)
        for f in security.findings:
            pdf.set_x(10)
            pdf.multi_cell(
                277,
                5.2,
                _pdf_safe(f"[{f.severity}] {f.title}: {f.detail}"),
                new_x="LMARGIN",
                new_y="NEXT",
            )

        if scan.hosts:
            pdf.ln(3.5)
            host_y = pdf.get_y()
            pdf.set_fill_color(245, 158, 11)
            pdf.rect(10, host_y + 0.8, 2.0, 4.8, style="F")
            pdf.set_x(14)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(24, 26, 31)
            pdf.cell(
                273,
                6,
                _pdf_safe(f"Discovered Subnet Hosts ({scan.subnet}) - Top {min(12, len(scan.hosts))} Shown:"),
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.set_font("Courier", "", 7.8)
            pdf.set_text_color(45, 48, 56)
            for h in scan.hosts[:12]:
                ports_s = ",".join(str(p) for p in h.open_ports) if h.open_ports else "none"
                pdf.cell(
                    277,
                    4.8,
                    _pdf_safe(f"  {h.ip:<15} | {h.hostname:<24} | {h.vendor:<18} | {h.role:<20} | Ports: {ports_s}"),
                    new_x="LMARGIN",
                    new_y="NEXT",
                )

        return bytes(pdf.output())
