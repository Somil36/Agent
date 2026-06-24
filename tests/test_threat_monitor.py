"""
tests/test_threat_monitor.py
----------------------------
Tests for the unified QVPN Threat Monitor agent.
"""
import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from Security.agent import (
    AGENT_CLIENT_ID,
    SecurityAlert,
    SystemMetric,
    LocalLogWriter,
    QVPNThreatEngine,
    SQLiteSync,
    SupabaseSync,
    SystemMonitor,
    CPU_HIGH_THRESHOLD_PCT,
    RAM_HIGH_THRESHOLD_PCT,
    DISK_HIGH_THRESHOLD_PCT,
)

@pytest.fixture
def tmp_log_dir(tmp_path):
    d = tmp_path / "logs"
    d.mkdir()
    return d

@pytest.fixture
def writer(tmp_log_dir):
    sqlite_log = tmp_log_dir / "sqlite_logs.json"
    supabase_log = tmp_log_dir / "supabase_logs.jsonb"
    return LocalLogWriter(sqlite_log_file=sqlite_log, supabase_log_file=supabase_log)

@pytest.fixture
def engine(writer):
    # Disable sysmon to prevent background threads during pure engine tests
    eng = QVPNThreatEngine(log_writer=writer, enable_sysmon=False)
    yield eng
    eng.shutdown()

@pytest.fixture
def sqlite_sync(writer, tmp_log_dir):
    db_path = tmp_log_dir / "test.db"
    sync = SQLiteSync(log_writer=writer, db_path=db_path)
    return sync

class TestModels:
    def test_security_alert_defaults(self):
        alert = SecurityAlert()
        assert alert.severity == "LOW"
        assert alert.status == "open"
        assert alert.client_id == AGENT_CLIENT_ID
        assert alert._record_type == "alert"

    def test_system_metric_defaults(self):
        metric = SystemMetric()
        assert metric.cpu_percent == 0.0
        assert metric.client_id == AGENT_CLIENT_ID
        assert metric._record_type == "metric"

class TestLocalLogWriter:
    def test_write_and_read_clear(self, writer):
        writer.write_record({"test": 1})
        writer.write_record({"test": 2})
        records = writer.read_and_clear()
        assert len(records) == 2
        assert len(writer.read_and_clear()) == 0

class TestQVPNThreatEngine:
    def test_usb_insertion(self, engine, writer):
        engine.process_monitoring_agent_event({
            "type": "USB_INSERTION",
            "details": {"hardware_id": "USB-TEST-001"},
        })
        records = writer.read_and_clear()
        assert len(records) == 1
        assert records[0]["severity"] == "HIGH"
        assert "USB-TEST-001" in records[0]["description"]

class TestSQLiteSync:
    def test_push_pending_inserts_records(self, sqlite_sync, writer):
        writer.write_record(SecurityAlert(alert_types="USB", severity="HIGH").to_dict())
        writer.write_record(SystemMetric(cpu_percent=50.0).to_dict())

        pushed = sqlite_sync.push_pending()
        assert pushed["alerts"] == 1
        assert pushed["metrics"] == 1

        alerts = sqlite_sync.query_alerts()
        metrics = sqlite_sync.query_metrics()
        
        assert len(alerts) == 1
        assert len(metrics) == 1
        assert alerts[0]["alert_types"] == "USB"
        assert metrics[0]["cpu_percent"] == 50.0

class TestSystemMonitor:
    def test_collect_and_evaluate(self, writer):
        mock_emit = MagicMock()
        mon = SystemMonitor(log_writer=writer, emit_alert=mock_emit, poll_interval=0.1)
        for _ in range(30):
            mon._collect_and_evaluate()
        records = writer.read_and_clear()
        assert len(records) == 1
        assert records[0]["_record_type"] == "metric"
        assert "cpu_percent" in records[0]

    def test_cpu_alert(self, writer):
        mock_emit = MagicMock()
        mon = SystemMonitor(log_writer=writer, emit_alert=mock_emit, poll_interval=0.1)
        # simulate sustained high cpu (should emit exactly 3 times for HIGH)
        for _ in range(4):
            mon._check_cpu(CPU_HIGH_THRESHOLD_PCT + 1)
        assert mock_emit.call_count == 3
        args, kwargs = mock_emit.call_args
        assert args[1] == "HIGH"


class TestSupabaseSync:
    def test_push_pending_calls_postgres(self, writer, tmp_log_dir):
        """SupabaseSync should call execute_values for alerts and metrics."""
        writer.write_record(SecurityAlert(alert_types="USB", severity="HIGH").to_dict())
        writer.write_record(SystemMetric(cpu_percent=75.0).to_dict())

        # Drain the sqlite log so read_and_clear_supabase has the records
        # (both logs were written simultaneously by write_record)
        mock_cur   = MagicMock()
        mock_conn  = MagicMock()
        mock_conn.__enter__ = lambda s: s
        mock_conn.__exit__  = MagicMock(return_value=False)
        mock_conn.cursor.return_value.__enter__ = lambda s: mock_cur
        mock_conn.cursor.return_value.__exit__  = MagicMock(return_value=False)

        with patch("Security.agent.psycopg2.connect", return_value=mock_conn), \
             patch("Security.agent.psycopg2.extras.execute_values") as mock_ev:
            sync   = SupabaseSync(log_writer=writer, database_url="postgresql://fake")
            result = sync.push_pending()

        assert result["alerts"]  == 1
        assert result["metrics"] == 1
        assert mock_ev.call_count == 2  # once for alerts, once for metrics
