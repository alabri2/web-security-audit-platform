import sqlite3
from typing import Optional, Dict, Any, List
from app.config import DB_PATH

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _add_column_if_missing(cur, table: str, column: str, ddl: str):
    cols = {row[1] for row in cur.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")

def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript('''
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        mode TEXT,
        status TEXT,
        target_type TEXT,
        score INTEGER,
        start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        end_time DATETIME
    );
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        type TEXT,
        value TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    );
    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER,
        port INTEGER,
        protocol TEXT,
        service_name TEXT,
        service_version TEXT,
        state TEXT,
        FOREIGN KEY(asset_id) REFERENCES assets(id)
    );
    CREATE TABLE IF NOT EXISTS technologies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER,
        technology TEXT,
        version TEXT,
        FOREIGN KEY(asset_id) REFERENCES assets(id)
    );
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        asset TEXT,
        tool TEXT,
        severity TEXT,
        title TEXT,
        description TEXT,
        evidence TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    );
    CREATE TABLE IF NOT EXISTS scan_tools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        tool_name TEXT,
        status TEXT,
        start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        end_time DATETIME,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    );
    ''')
    _add_column_if_missing(cur, "scans", "authorization_confirmed", "authorization_confirmed INTEGER DEFAULT 0")
    _add_column_if_missing(cur, "scans", "selection_mode", "selection_mode TEXT DEFAULT 'auto'")
    _add_column_if_missing(cur, "scans", "requested_target_type", "requested_target_type TEXT")
    conn.commit()
    conn.close()

def create_scan(scan_id, target, mode, authorization_confirmed=0, selection_mode="auto", requested_target_type=None):
    conn = get_conn()
    conn.execute(
        "INSERT INTO scans(id,target,mode,status,authorization_confirmed,selection_mode,requested_target_type) VALUES (?,?,?,?,?,?,?)",
        (scan_id, target, mode, "running", int(bool(authorization_confirmed)), selection_mode, requested_target_type)
    )
    conn.commit()
    conn.close()

def update_target_type(scan_id, target_type):
    conn = get_conn()
    conn.execute("UPDATE scans SET target_type=? WHERE id=?", (target_type, scan_id))
    conn.commit()
    conn.close()

def finish_scan(scan_id, score):
    conn = get_conn()
    conn.execute("UPDATE scans SET status=?, score=?, end_time=CURRENT_TIMESTAMP WHERE id=?", ("finished", score, scan_id))
    conn.commit()
    conn.close()

def fail_scan(scan_id):
    conn = get_conn()
    conn.execute("UPDATE scans SET status=?, end_time=CURRENT_TIMESTAMP WHERE id=?", ("failed", scan_id))
    conn.commit()
    conn.close()

def add_scan_tool(scan_id, tool_name, status):
    conn = get_conn()
    conn.execute("INSERT INTO scan_tools(scan_id, tool_name, status) VALUES (?,?,?)", (scan_id, tool_name, status))
    conn.commit()
    conn.close()

def finish_scan_tool(scan_id, tool_name, status):
    conn = get_conn()
    conn.execute("UPDATE scan_tools SET status=?, end_time=CURRENT_TIMESTAMP WHERE scan_id=? AND tool_name=? AND end_time IS NULL", (status, scan_id, tool_name))
    conn.commit()
    conn.close()

def add_asset(scan_id, asset_type, value):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO assets(scan_id, type, value) VALUES (?,?,?)", (scan_id, asset_type, value))
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    return rid

def add_service(asset_id, port, protocol, service_name, service_version, state):
    conn = get_conn()
    conn.execute("INSERT INTO services(asset_id, port, protocol, service_name, service_version, state) VALUES (?,?,?,?,?,?)", (asset_id, port, protocol, service_name, service_version, state))
    conn.commit()
    conn.close()

def add_technology(asset_id, technology, version=""):
    conn = get_conn()
    conn.execute("INSERT INTO technologies(asset_id, technology, version) VALUES (?,?,?)", (asset_id, technology, version))
    conn.commit()
    conn.close()

def add_finding(scan_id, asset, tool, severity, title, description, evidence=""):
    conn = get_conn()
    conn.execute("INSERT INTO findings(scan_id, asset, tool, severity, title, description, evidence) VALUES (?,?,?,?,?,?,?)", (scan_id, asset, tool, severity, title, description, evidence))
    conn.commit()
    conn.close()

def get_findings(scan_id) -> List[Dict[str, Any]]:
    conn = get_conn()
    rows = conn.execute("SELECT id, asset, tool, severity, title, description, evidence FROM findings WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan(scan_id) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None
