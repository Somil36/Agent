# QVPN Monitoring Agent

This directory contains the QVPN monitoring agent, which handles local threat detection, system resource polling, and database synchronization.

## Prerequisites

Before you begin, ensure your system meets the following requirements:

* **Operating System**: Windows (The agent uses `pywin32` and `wmi` libraries which are Windows-specific).
* **Python**: Python 3.8 or higher installed and added to your system PATH.
* **Database**: Access to a PostgreSQL database (e.g., Supabase) for remote synchronization.

---

## Step-by-Step Installation

### 1. Navigate to the Agent Directory

Assuming you have cloned the repository, navigate into the `agent` directory where the monitoring application resides:

```cmd
cd path\to\QVPN_START\agent
```


### 2. Install Dependencies

With the virtual environment active, install the required packages using the `requirements.txt` file:

```cmd
pip install -r requirements.txt
```

This will install the following essential packages:
- `psutil` (System and process utilities)
- `psycopg2-binary` (PostgreSQL adapter)
- `pywin32` (Windows API integration)
- `WMI` (Windows Management Instrumentation)
- `python-dotenv` (Environment variable loading)

### 3. Configuration

The agent requires environment variables to connect to your PostgreSQL database. 

1. Create a file named `.env` in the root of the `agent` directory.
2. Add your database connection string to this file as follows:

```env
DATABASE_URL="postgresql://<user>:<password>@<host>:<port>/<dbname>"
```
> **Note:** The agent expects `DATABASE_URL` to be present to sync `qvpn_alerts` and `system_metrics` to your Supabase/PostgreSQL instance.

---

## Running the Agent

To start the unified monitoring agent, run the main Python script from the root of the `agent` directory:

```cmd
python Security/agent.py
```

### What happens when you run the agent?
- **Logging**: A `logs/` directory is automatically created inside the `Security` folder to store local JSONL logs.
- **Local Database**: A local SQLite database (`Security/local_test.db`) will be used or initialized to store local logs and metrics.
- **Remote Sync**: The agent will begin pushing alerts and system resource metrics to your remote PostgreSQL database configured in the `.env` file.
