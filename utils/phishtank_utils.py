import requests
import csv
import os
from datetime import datetime

HISTORY_CSV = "history.csv"

def log_detection(url, verdict, reason, score):
    """Log both phishing and non-phishing URLs into history.csv"""
    file_exists = os.path.exists(HISTORY_CSV)

    with open(HISTORY_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Time", "URL", "Verdict", "Reason", "Score"])
        writer.writerow([datetime.now(), url, verdict, reason, score])

PHISHTANK_CSV = "phishtank.csv"

def update_phishtank():
    """Download latest PhishTank feed and save locally"""
    url = "http://data.phishtank.com/data/online-valid.csv"
    response = requests.get(url, timeout=30)

    if response.status_code == 200:
        with open(PHISHTANK_CSV, "wb") as f:
            f.write(response.content)
        print("✅ PhishTank feed updated successfully.")
    else:
        print("⚠️ Failed to update PhishTank feed, status:", response.status_code)


def load_phishtank():
    """Load URLs from local CSV into memory (as a set)"""
    urls = set()
    if os.path.exists(PHISHTANK_CSV):
        with open(PHISHTANK_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                urls.add(row["url"])
    return urls
