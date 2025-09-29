import csv
from typing import Tuple, Optional

# Path to your local CSV file
PHISHTANK_CSV_PATH = "phishtank.csv"

# ------------------ Preload CSV URLs ------------------
PHISH_TANK_SET = set()

try:
    with open(PHISHTANK_CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "").strip().lower()
            # Remove scheme for uniform comparison
            if url.startswith("http://"):
                url = url[7:]
            elif url.startswith("https://"):
                url = url[8:]
            PHISH_TANK_SET.add(url)
except Exception as e:
    print(f"[PhishTank] Failed to load CSV: {e}")

# ------------------ Offline URL Check ------------------
def check_url(url: str) -> Tuple[bool, str]:
    """
    Offline-only check for phishing using preloaded PhishTank CSV.
    Returns (True, "phishtank_offline") if found, else (False, "")
    """
    url = url.strip().lower()
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    
    if url in PHISH_TANK_SET:
        return True, "phishtank_offline"
    
    return False, ""
