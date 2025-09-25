from services.db import get_conn
from datetime import datetime
from typing import Optional

def log_detection(url: str, verdict: str, reason: str, score: Optional[float]) -> None:
    """Log detections into the SQLite database instead of CSV"""
    conn = get_conn()
    with conn:
        conn.execute(
            """
            INSERT INTO detections (url, verdict, reason, score, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (url, verdict, reason, score if score is not None else 0, datetime.utcnow().isoformat())
        )
    conn.close()
