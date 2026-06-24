"""
QVPN Threat Monitor
===================
Industry-level threat detection engine for the QVPN security platform.

Architecture
------------
All threat detection and log building is performed locally on the device.
Logs are written to two local files:
  - supabase_logs.jsonb  → staged records to be pushed to Supabase (PostgreSQL JSONB)
  - sqlite_logs.json     → records for local SQLite testing / offline inspection

Only the final, fully-formed log records are pushed to the remote database.
No intermediate processing state is ever sent upstream.
"""

__version__ = "1.0.0"
__author__  = "QVPN Security Team"
