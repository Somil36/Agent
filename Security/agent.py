"""
agent.py
--------
Unified monitoring agent for QVPN.
Handles local threat detection, system resource polling, and database synchronisation.
Records are logged to a single local JSONL file, then synced to:
 - Local SQLite  (security_alerts, system_metrics)
 - Supabase PostgreSQL  (qvpn_alerts, system_metrics)
"""
import json
import logging
import os
import shutil
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Callable
from http.server import HTTPServer, BaseHTTPRequestHandler

import psutil
import psycopg2
import psycopg2.extras
import pythoncom
import subprocess
import wmi
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------------------------
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PACKAGE_DIR = Path(__file__).parent
LOG_DIR = PACKAGE_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOCAL_SQLITE_LOG_FILE = LOG_DIR / "sqlite_logs.json"
SUPABASE_LOG_FILE     = LOG_DIR / "supabase_logs.jsonb"
SQLITE_DB_FILE        = PACKAGE_DIR / "local_test.db"

# Agent Client ID — identifies this QVPN client device in both tables
AGENT_CLIENT_ID = "ee9d8156-09d8-49ad-957d-cd1ea8ad6d84"

# Polling configuration
SYSTEM_POLL_INTERVAL_SECONDS = 1.0    # Collect metric every 1 second
METRIC_AVERAGE_WINDOW_TICKS  = 30     # Push average after 30 ticks (30 seconds)
SYNC_INTERVAL_SECONDS        = 60.0   # Heartbeat / Sync interval

# Thresholds
BRUTE_FORCE_THRESHOLD      = 5
BRUTE_FORCE_WINDOW_SECONDS = 300
DOS_THRESHOLD              = 20
DOS_WINDOW_SECONDS         = 60
THREAT_RESOLVE_SECONDS     = 300  # Threats auto-resolve after 5 mins of silence

CPU_WARNING_THRESHOLD_PCT  = 75.0
CPU_HIGH_THRESHOLD_PCT     = 85.0
CPU_CRITICAL_THRESHOLD_PCT = 95.0

RAM_HIGH_THRESHOLD_PCT     = 85.0
RAM_CRITICAL_THRESHOLD_PCT = 95.0

DISK_HIGH_THRESHOLD_PCT    = 85.0
DISK_CRITICAL_THRESHOLD_PCT = 95.0

RESTRICTED_PROCESSES = ["cmd.exe", "powershell.exe", "pwsh.exe", "wt.exe", "bash.exe", "wsl.exe"]

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
@dataclass
class SecurityAlert:
    id: str          = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str   = AGENT_CLIENT_ID
    severity: str    = "LOW"
    description: str = ""
    status: str      = "open"
    timestamp: str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Internal routing tag
    _record_type: str = "alert"

    def to_dict(self):
        return asdict(self)


@dataclass
class SystemMetric:
    id: str          = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str   = AGENT_CLIENT_ID
    timestamp: str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    cpu_percent: float  = 0.0
    ram_percent: float  = 0.0
    disk_percent: float = 0.0

    # Internal routing tag
    _record_type: str = "metric"

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# Log Writer
# ---------------------------------------------------------------------------
class LocalLogWriter:
    def __init__(
        self,
        sqlite_log_file: Path = LOCAL_SQLITE_LOG_FILE,
        supabase_log_file: Path = SUPABASE_LOG_FILE,
    ):
        self._sqlite_log   = sqlite_log_file
        self._supabase_log = supabase_log_file
        self._lock         = threading.Lock()

    def write_record(self, record: dict) -> None:
        with self._lock:
            record_str = json.dumps(record) + "\n"
            # Write for local SQLite sync
            with open(self._sqlite_log, "a", encoding="utf-8") as f:
                f.write(record_str)
            # Write for Supabase sync
            with open(self._supabase_log, "a", encoding="utf-8") as f:
                f.write(record_str)

    def _read_and_clear_file(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        with open(path, "w", encoding="utf-8") as f:
            pass  # truncate
        records = []
        for line in lines:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def read_and_clear(self) -> list[dict]:
        with self._lock:
            return self._read_and_clear_file(self._sqlite_log)

    def read_and_clear_supabase(self) -> list[dict]:
        with self._lock:
            return self._read_and_clear_file(self._supabase_log)


# ---------------------------------------------------------------------------
# System Monitor
# ---------------------------------------------------------------------------
class SystemMonitor:
    def __init__(
        self,
        log_writer: LocalLogWriter,
        emit_alert: Callable,
        poll_interval: float = SYSTEM_POLL_INTERVAL_SECONDS,
    ):
        self._writer   = log_writer
        self._emit_alert = emit_alert
        self._interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        self._cpu_history  = []
        self._ram_history  = []
        self._disk_history = []
        self._alerted_pids = set()

        # Alert states
        self._cpu_state = "NORMAL"
        self._cpu_alert_count = 0
        self._ram_alerted = False
        self._disk_alerted = False

        # Prime psutil baseline
        psutil.cpu_percent(interval=None)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()

    def _poll_loop(self):
        while not self._stop_event.is_set():
            try:
                self._collect_and_evaluate()
            except Exception as e:
                logging.getLogger("agent").error(f"System monitor error: {e}")
            self._stop_event.wait(timeout=self._interval)

    def _collect_and_evaluate(self):
        # 1-second metric
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        
        disk_path = os.path.abspath(os.sep)
        disk = shutil.disk_usage(disk_path)
        disk_pct = round((disk.used / disk.total) * 100, 1) if disk.total > 0 else 0.0

        self._cpu_history.append(cpu)
        self._ram_history.append(mem)
        self._disk_history.append(disk_pct)

        # Monitor restricted processes
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = proc.info['name'].lower()
                pid = proc.info['pid']
                if name in RESTRICTED_PROCESSES and pid not in self._alerted_pids:
                    self._emit_alert("RESTRICTED_PROCESS_LAUNCH", "CRITICAL", f"Restricted CLI tool execution detected: {name} (PID: {pid})")
                    self._alerted_pids.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        # Average and emit every 30 ticks
        if len(self._cpu_history) >= METRIC_AVERAGE_WINDOW_TICKS:
            avg_cpu = sum(self._cpu_history) / len(self._cpu_history)
            avg_ram = sum(self._ram_history) / len(self._ram_history)
            avg_disk = sum(self._disk_history) / len(self._disk_history)
            
            metric = SystemMetric(
                cpu_percent=round(avg_cpu, 1),
                ram_percent=round(avg_ram, 1),
                disk_percent=round(avg_disk, 1)
            )
            self._writer.write_record(metric.to_dict())
            
            self._cpu_history.clear()
            self._ram_history.clear()
            self._disk_history.clear()

        # Evaluate instantaneous metrics for immediate alerts
        self._check_cpu(cpu)
        self._check_ram(mem)
        self._check_disk(disk_pct)

    def _check_cpu(self, cpu: float):
        if cpu >= CPU_CRITICAL_THRESHOLD_PCT:
            # Continuous alerts
            self._emit_alert("CPU_HIGH_USAGE", "CRITICAL", f"CPU usage critically high: {cpu:.1f}%")
            self._cpu_state = "CRITICAL"
            self._cpu_alert_count = 0
        elif cpu >= CPU_HIGH_THRESHOLD_PCT:
            # 3 alerts maximum per high period
            if self._cpu_state != "HIGH":
                self._cpu_alert_count = 0
                self._cpu_state = "HIGH"
            if self._cpu_alert_count < 3:
                self._emit_alert("CPU_HIGH_USAGE", "HIGH", f"CPU usage high: {cpu:.1f}%")
                self._cpu_alert_count += 1
        elif cpu >= CPU_WARNING_THRESHOLD_PCT:
            # 1 alert maximum per medium period
            if self._cpu_state != "WARNING":
                self._emit_alert("CPU_HIGH_USAGE", "MEDIUM", f"CPU usage elevated: {cpu:.1f}%")
                self._cpu_state = "WARNING"
                self._cpu_alert_count = 1
        else:
            self._cpu_state = "NORMAL"
            self._cpu_alert_count = 0

    def _check_ram(self, ram: float):
        if ram >= RAM_CRITICAL_THRESHOLD_PCT:
            severity = "CRITICAL"
        elif ram >= RAM_HIGH_THRESHOLD_PCT:
            severity = "HIGH"
        else:
            self._ram_alerted = False
            return

        if not self._ram_alerted:
            self._emit_alert("RAM_HIGH_USAGE", severity, f"RAM usage high: {ram:.1f}%")
            self._ram_alerted = True

    def _check_disk(self, disk: float):
        if disk >= DISK_CRITICAL_THRESHOLD_PCT:
            severity = "CRITICAL"
        elif disk >= DISK_HIGH_THRESHOLD_PCT:
            severity = "HIGH"
        else:
            self._disk_alerted = False
            return

        if not self._disk_alerted:
            self._emit_alert("DISK_HIGH_USAGE", severity, f"Disk usage high: {disk:.1f}%")
            self._disk_alerted = True


# ---------------------------------------------------------------------------
# Threat Engine
# ---------------------------------------------------------------------------
class QVPNThreatEngine:
    def __init__(self, log_writer: LocalLogWriter, enable_sysmon: bool = True, flush_callback: Callable = None):
        self._writer = log_writer
        self._flush_callback = flush_callback

        self._failed_logins       = {}
        self._connection_attempts = {}
        self._last_threat_time    = 0.0

        self._sysmon = None
        if enable_sysmon:
            self._sysmon = SystemMonitor(log_writer=self._writer, emit_alert=self.emit_alert)
            self._sysmon.start()

    def shutdown(self):
        if self._sysmon:
            self._sysmon.stop()

    def has_active_threats(self) -> bool:
        """Returns True if a threat was detected within the last 5 minutes."""
        return (time.time() - self._last_threat_time) < THREAT_RESOLVE_SECONDS

    def emit_alert(self, alert_type: str, severity: str, description: str, visibility: str = "backend"):
        tag = "[USER]" if visibility == "user" else "[BACKEND]"
        alert = SecurityAlert(
            severity=severity,
            description=f"{tag} {description}",
        )
        self._writer.write_record(alert.to_dict())
        logging.getLogger("agent").info(f"Generated Alert: [{severity}] {alert.description}")
        
        # Track active threat timing (ignore informational/heartbeat alerts)
        if severity != "INFO":
            self._last_threat_time = time.time()
            if self._flush_callback:
                self._flush_callback()

    def process_monitoring_agent_event(self, event: dict):
        event_type = event.get("type")
        details    = event.get("details", {})

        if event_type == "USB_INSERTION":
            hw_id = details.get("hardware_id", "unknown")
            self.emit_alert("USB_INSERTION", "HIGH", f"Unauthorised USB insertion detected: {hw_id}", visibility="user")

        elif event_type == "UNKNOWN_PROCESS_LAUNCH":
            pname = details.get("process_name", "unknown")
            self.emit_alert("SUSPICIOUS_EXECUTABLE", "CRITICAL", f"Suspicious non-system executable launched: {pname}", visibility="user")

        elif event_type == "PORT_SCAN_DETECTED":
            self.emit_alert("PORT_SCAN_DETECTED", "HIGH", f"Local port scanning or flooding detected", visibility="user")

    def process_qvpn_client_event(self, event: dict):
        event_type = event.get("type")
        client_id  = event.get("client_id", "unknown")
        details    = event.get("details", {})

        if event_type == "TUNNEL_FAILURE":
            reason = details.get("reason", "unknown")
            self.emit_alert("TUNNEL_FAILURE", "HIGH", f"Tunnel failure for Client {client_id}. Reason: {reason}")

        elif event_type == "HEARTBEAT_LOSS":
            self.emit_alert("HEARTBEAT_LOSS", "MEDIUM", f"Heartbeat lost for Client {client_id}. Tunnel may be unresponsive.")

        elif event_type == "IP_CHANGE":
            old_ip = details.get("old_ip", "?")
            new_ip = details.get("new_ip", "?")
            self.emit_alert("IP_CHANGE", "MEDIUM", f"IP address change detected for Client {client_id}: {old_ip} -> {new_ip}")

    def process_gateway_event(self, event: dict):
        event_type = event.get("type")
        src_ip     = event.get("source_ip")
        if not src_ip:
            return

        now = time.time()

        if event_type == "FAILED_LOGIN":
            attempts = self._failed_logins.get(src_ip, [])
            attempts = [t for t in attempts if now - t <= BRUTE_FORCE_WINDOW_SECONDS]
            attempts.append(now)
            self._failed_logins[src_ip] = attempts

            if len(attempts) >= BRUTE_FORCE_THRESHOLD:
                self.emit_alert(
                    "BRUTE_FORCE_DETECTED",
                    "CRITICAL",
                    f"Brute-force login attempt detected: {len(attempts)} failed logins within {BRUTE_FORCE_WINDOW_SECONDS}s from {src_ip}",
                )
                self._failed_logins[src_ip] = []

        elif event_type == "CONNECTION_ATTEMPT":
            attempts = self._connection_attempts.get(src_ip, [])
            attempts = [t for t in attempts if now - t <= DOS_WINDOW_SECONDS]
            attempts.append(now)
            self._connection_attempts[src_ip] = attempts

            if len(attempts) >= DOS_THRESHOLD:
                self.emit_alert(
                    "DOS_DETECTED",
                    "HIGH",
                    f"Potential DoS / port-scan detected: {len(attempts)} connection attempts within {DOS_WINDOW_SECONDS}s from {src_ip}",
                )
                self._connection_attempts[src_ip] = []


# ---------------------------------------------------------------------------
# Hardware & External Integrations
# ---------------------------------------------------------------------------
class USBMonitor:
    def __init__(self, engine: QVPNThreatEngine):
        self._engine = engine
        self._stop_event = threading.Event()
        self._thread = None
        
    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        
    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()
            
    def _monitor_loop(self):
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            # Capture baseline drives
            existing_drives = {d.DeviceID for d in c.Win32_LogicalDisk(DriveType=2)}
            
            while not self._stop_event.is_set():
                try:
                    current_drives = {d.DeviceID for d in c.Win32_LogicalDisk(DriveType=2)}
                    new_drives = current_drives - existing_drives
                    for d in new_drives:
                        self._engine.process_monitoring_agent_event({
                            "type": "USB_INSERTION",
                            "details": {"hardware_id": f"Drive Letter {d}"}
                        })
                    existing_drives = current_drives
                except Exception as e:
                    logging.getLogger("agent").error(f"USB monitor error: {e}")
                self._stop_event.wait(2.0)
        except Exception as e:
            logging.getLogger("agent").error(f"Failed to initialize USB Monitor: {e}")
        finally:
            pythoncom.CoUninitialize()


class AgentWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            payload = json.loads(post_data)
            engine = self.server.engine
            
            if self.path == '/gateway':
                engine.process_gateway_event(payload)
            elif self.path == '/client':
                engine.process_qvpn_client_event(payload)
            elif self.path == '/agent':
                engine.process_monitoring_agent_event(payload)
                
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        except Exception as e:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(f'{{"error": "{str(e)}" }}'.encode())

    def log_message(self, format, *args):
        pass # Suppress standard HTTP logs


class MockGatewayServer:
    def __init__(self, engine: QVPNThreatEngine, port: int = 9000):
        self._engine = engine
        self._port = port
        self._server = None
        self._thread = None
        
    def start(self):
        self._server = HTTPServer(('localhost', self._port), AgentWebhookHandler)
        self._server.engine = self._engine
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        
    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join()


import win32evtlog

class WindowsLogMonitor:
    def __init__(self, engine: QVPNThreatEngine):
        self._engine = engine
        self._stop_event = threading.Event()
        self._thread = None
        self._last_records = {"Security": 0}
        self._port_block_count = 0
        self._last_port_block_reset = time.time()
        
    def start(self):
        # Automatically enable required Windows Auditing
        try:
            subprocess.run(['auditpol', '/set', '/subcategory:Process Creation', '/success:enable', '/failure:enable'], capture_output=True, check=True)
            subprocess.run(['auditpol', '/set', '/subcategory:Filtering Platform Packet Drop', '/success:enable', '/failure:enable'], capture_output=True, check=True)
            logging.getLogger("agent").info("Enabled Windows Auditing for Process Creation and Packet Drops.")
        except Exception as e:
            logging.getLogger("agent").warning(f"Could not enable Windows Auditing automatically. Run agent as Admin. Error: {e}")

        # Initialize last_records to current oldest + total
        for log_type in ["Security"]:
            try:
                hand = win32evtlog.OpenEventLog(None, log_type)
                total = win32evtlog.GetNumberOfEventLogRecords(hand)
                oldest = win32evtlog.GetOldestEventLogRecord(hand)
                self._last_records[log_type] = oldest + total - 1
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                logging.getLogger("agent").warning(f"Could not open {log_type} log (Run as Admin?): {e}")

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        
    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join()
            
    def _monitor_loop(self):
        while not self._stop_event.is_set():
            self._poll_log("Security")
            
            # Reset port block count every 10 seconds
            if time.time() - self._last_port_block_reset > 10:
                self._port_block_count = 0
                self._last_port_block_reset = time.time()
                
            self._stop_event.wait(2.0)
            
    def _poll_log(self, log_type):
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events_to_process = []
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            while events:
                for event in events:
                    if event.RecordNumber <= self._last_records[log_type]:
                        break
                    events_to_process.append(event)
                else:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    continue
                break
                
            win32evtlog.CloseEventLog(hand)
            
            if events_to_process:
                self._last_records[log_type] = max(e.RecordNumber for e in events_to_process)
                for event in reversed(events_to_process):
                    self._process_event(log_type, event)
                    
        except Exception as e:
            pass # Ignore read errors (e.g., Access Denied if not admin)
            
    def _process_event(self, log_type, event):
        event_id = event.EventID & 0xFFFF
        
        if log_type == "Security" and event_id == 4688:
            # Process Creation
            if event.StringInserts and len(event.StringInserts) > 5:
                process_path = event.StringInserts[5].lower()
                # If process is not inside standard system folders
                if "c:\\windows\\" not in process_path and "c:\\program files" not in process_path:
                    self._engine.process_monitoring_agent_event({
                        "type": "UNKNOWN_PROCESS_LAUNCH",
                        "details": {"process_name": process_path}
                    })

        elif log_type == "Security" and event_id == 5152:
            # Firewall Dropped Packet (Port Scan indicator)
            self._port_block_count += 1
            if self._port_block_count > 50: # 50 drops in 10s is a scan
                self._engine.process_monitoring_agent_event({
                    "type": "PORT_SCAN_DETECTED"
                })
                self._port_block_count = 0

# ---------------------------------------------------------------------------
# Local SQLite Synchronisation
# ---------------------------------------------------------------------------
class SQLiteSync:
    def __init__(self, log_writer: LocalLogWriter, db_path: Path = SQLITE_DB_FILE):
        self._writer  = log_writer
        self._db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id    TEXT PRIMARY KEY,
                    client_id   TEXT NOT NULL,
                    timestamp   TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status      TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_metrics (
                    alert_id     TEXT PRIMARY KEY,
                    client_id    TEXT NOT NULL,
                    timestamp    TEXT NOT NULL,
                    cpu_percent  REAL NOT NULL,
                    ram_percent  REAL NOT NULL,
                    disk_percent REAL NOT NULL
                )
            """)

    def push_pending(self) -> dict:
        records = self._writer.read_and_clear()
        if not records:
            return {"alerts": 0, "metrics": 0}

        alerts  = [r for r in records if r.get("_record_type") == "alert"]
        metrics = [r for r in records if r.get("_record_type") == "metric"]

        with sqlite3.connect(self._db_path) as conn:
            if alerts:
                conn.executemany(
                    """INSERT OR IGNORE INTO security_alerts
                       (alert_id, client_id, timestamp, severity, description, status)
                       VALUES (:id, :client_id, :timestamp, :severity, :description, :status)""",
                    alerts,
                )
            if metrics:
                conn.executemany(
                    """INSERT OR IGNORE INTO system_metrics
                       (id, client_id, timestamp, cpu_percent, ram_percent, disk_percent)
                       VALUES (:id, :client_id, :timestamp, :cpu_percent, :ram_percent, :disk_percent)""",
                    metrics,
                )

        logging.getLogger("agent").info(
            f"[SQLite] Pushed {len(alerts)} alerts and {len(metrics)} metrics."
        )
        return {"alerts": len(alerts), "metrics": len(metrics)}

    def query_alerts(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT * FROM security_alerts ORDER BY timestamp DESC").fetchall()]

    def query_metrics(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute("SELECT * FROM system_metrics ORDER BY timestamp DESC").fetchall()]


# ---------------------------------------------------------------------------
# Supabase PostgreSQL Synchronisation
# ---------------------------------------------------------------------------
class SupabaseSync:
    def __init__(self, log_writer: LocalLogWriter, database_url: str = DATABASE_URL):
        self._writer       = log_writer
        self._database_url = database_url
        self._log          = logging.getLogger("agent")

    def _get_connection(self):
        return psycopg2.connect(self._database_url)

    def push_pending(self) -> dict:
        if not self._database_url:
            return {"alerts": 0, "metrics": 0}

        records = self._writer.read_and_clear_supabase()
        if not records:
            return {"alerts": 0, "metrics": 0}

        alerts  = [r for r in records if r.get("_record_type") == "alert"]
        metrics = [r for r in records if r.get("_record_type") == "metric"]

        inserted_alerts  = 0
        inserted_metrics = 0

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    if alerts:
                        alert_rows = [
                            (
                                r["id"], r.get("client_id", AGENT_CLIENT_ID), r["timestamp"],
                                r["severity"], r["description"], r["status"]
                            ) for r in alerts
                        ]
                        psycopg2.extras.execute_values(
                            cur,
                            """
                            INSERT INTO qvpn_alerts
                                (alert_id, client_id, timestamp, severity, description, status)
                            VALUES %s
                            ON CONFLICT (alert_id) DO NOTHING
                            """,
                            alert_rows,
                        )
                        inserted_alerts = len(alert_rows)

                    if metrics:
                        metric_rows = [
                            (
                                r["id"], r.get("client_id", AGENT_CLIENT_ID), r["timestamp"],
                                r["cpu_percent"], r["ram_percent"], r["disk_percent"]
                            ) for r in metrics
                        ]
                        psycopg2.extras.execute_values(
                            cur,
                            """
                            INSERT INTO system_metrics
                                (id, client_id, timestamp, cpu_percent, ram_percent, disk_percent)
                            VALUES %s
                            ON CONFLICT (id) DO NOTHING
                            """,
                            metric_rows,
                        )
                        inserted_metrics = len(metric_rows)
                conn.commit()
        except Exception as exc:
            self._log.error(f"[Supabase] Push failed: {exc}. Records remain in log for retry.")
            for r in records:
                with open(self._writer._supabase_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(r) + "\n")
            return {"alerts": 0, "metrics": 0}

        self._log.info(f"[Supabase] Pushed {inserted_alerts} alerts and {inserted_metrics} metrics.")
        return {"alerts": inserted_alerts, "metrics": inserted_metrics}


# ---------------------------------------------------------------------------
# Continuous Agent Runner
# ---------------------------------------------------------------------------
def _flush_once(sqlite_sync: SQLiteSync, supabase_sync: SupabaseSync, logger: logging.Logger) -> None:
    """Push all buffered records to SQLite and Supabase in one shot."""
    sq = sqlite_sync.push_pending()
    sb = supabase_sync.push_pending()
    if sq["alerts"] or sq["metrics"]:
        logger.info(f"[SQLite]   flushed {sq['alerts']} alerts, {sq['metrics']} metrics")
    if sb["alerts"] or sb["metrics"]:
        logger.info(f"[Supabase] flushed {sb['alerts']} alerts, {sb['metrics']} metrics")


def run_agent(sync_interval: float = SYNC_INTERVAL_SECONDS) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    logger = logging.getLogger("agent")

    logger.info("═" * 60)
    logger.info("  QVPN Monitoring Agent (Background Mode) — starting up")
    logger.info(f"  System poll : 1.0s (average pushed every 30s)")
    logger.info(f"  DB heartbeat: every {sync_interval}s")
    logger.info("═" * 60)

    writer = LocalLogWriter()
    
    immediate_flush_event = threading.Event()
    def trigger_flush():
        immediate_flush_event.set()

    engine = QVPNThreatEngine(log_writer=writer, enable_sysmon=True, flush_callback=trigger_flush)

    # Start integrations
    usb_monitor = USBMonitor(engine)
    usb_monitor.start()
    
    http_server = MockGatewayServer(engine, port=9000)
    http_server.start()
    
    win_log_monitor = WindowsLogMonitor(engine)
    win_log_monitor.start()

    logger.info("  [+] USB hardware listener active")
    logger.info("  [+] HTTP Webhook active on localhost:9000")
    logger.info("  [+] Windows Event Log monitor active (Security: Executables & Firewall Drops)")

    sqlite_sync   = SQLiteSync(log_writer=writer)
    supabase_sync = SupabaseSync(log_writer=writer)

    stop_event = threading.Event()

    try:
        last_sync_time = time.time()
        while not stop_event.is_set():
            now = time.time()
            
            # Normal 60-second interval (Heartbeat + Flush)
            if now - last_sync_time >= sync_interval:
                if not engine.has_active_threats():
                    engine.emit_alert("HEARTBEAT", "INFO", "System OK - No active threats")
                _flush_once(sqlite_sync, supabase_sync, logger)
                last_sync_time = now

            # Immediate flush triggered by a threat/alert
            if immediate_flush_event.is_set():
                immediate_flush_event.clear()
                logger.info("--- Immediate Flush (Alert detected) ---")
                _flush_once(sqlite_sync, supabase_sync, logger)

            time.sleep(1)

    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutdown requested — stopping threads...")
        usb_monitor.stop()
        http_server.stop()
        win_log_monitor.stop()
        engine.shutdown()
        logger.info("Performing final flush...")
        _flush_once(sqlite_sync, supabase_sync, logger)
        logger.info("QVPN Monitoring Agent stopped cleanly.")


def run_demo():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    logger = logging.getLogger("agent")
    writer = LocalLogWriter()
    engine = QVPNThreatEngine(log_writer=writer, enable_sysmon=True)

    engine.process_monitoring_agent_event({"type": "UNKNOWN_PROCESS_LAUNCH", "details": {"process_name": "evil.exe"}})
    engine.process_qvpn_client_event({"type": "TUNNEL_FAILURE", "client_id": "CLI-001", "details": {"reason": "Timeout"}})
    for _ in range(5):
        engine.process_gateway_event({"type": "FAILED_LOGIN", "source_ip": "10.0.0.99"})

    engine.shutdown()

    sqlite_sync   = SQLiteSync(log_writer=writer)
    supabase_sync = SupabaseSync(log_writer=writer)
    _flush_once(sqlite_sync, supabase_sync, logger)


if __name__ == "__main__":
    run_agent()
