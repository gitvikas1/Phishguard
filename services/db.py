import sqlite3
from datetime import datetime
from typing import Optional

DB_FILE = "history.db"  # single database file

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    verdict TEXT NOT NULL,             -- 'phishing' or 'safe'
    reason TEXT NOT NULL,              -- 'ml', 'phishtank', 'rules'
    score REAL,                        -- ML probability or heuristic score
    created_at TEXT NOT NULL
);
"""

def get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_conn()
    with conn:
        conn.executescript(SCHEMA)
    conn.close()

def log_detection(url: str, verdict: str, reason: str, score: Optional[float]) -> None:
    conn = get_conn()
    with conn:
        conn.execute(
            "INSERT INTO detections (url, verdict, reason, score, created_at) VALUES (?, ?, ?, ?, ?)",
            (url, verdict, reason, score if score is not None else None, datetime.utcnow().isoformat())
        )
    conn.close()

def get_history(limit=500):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, url, verdict, reason, score, created_at FROM detections ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    return rows