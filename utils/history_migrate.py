import csv
import os
import sqlite3

DB_FILE = "history.db"
CSV_FILE = "history.csv"

def migrate_csv_to_db():
    """Migrate old history.csv entries into SQLite (history.db) if they exist"""
    if not os.path.exists(CSV_FILE):
        print("[Migration] No history.csv found, skipping migration.")
        return

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Ensure detections table exists
    c.execute("""
    CREATE TABLE IF NOT EXISTS detections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        verdict TEXT NOT NULL,
        reason TEXT NOT NULL,
        score REAL,
        created_at TEXT NOT NULL
    );
    """)

    # Read CSV and insert into DB
    with open(CSV_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            url = row["url"]
            verdict = row["verdict"]
            reason = row["reason"]
            score = float(row["score"]) if row["score"] else None
            created_at = row["created_at"]

            # Insert only if URL+created_at not already in DB
            c.execute("""
                SELECT COUNT(*) FROM detections WHERE url=? AND created_at=?
            """, (url, created_at))
            exists = c.fetchone()[0]

            if exists == 0:
                c.execute("""
                    INSERT INTO detections (url, verdict, reason, score, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (url, verdict, reason, score, created_at))
                count += 1

    conn.commit()
    conn.close()

    print(f"[Migration] ✅ Migrated {count} entries from history.csv into history.db")
