import csv
import os
from typing import Tuple, Optional
import requests

from config import PHISHTANK_API_KEY, PHISHTANK_OFFLINE_CSV

API_URL = "https://checkurl.phishtank.com/checkurl/"
# PhishTank API returns XML/CSV/JSON depending on parameters; we use JSON.

def check_api(url: str) -> Tuple[bool, Optional[dict]]:
    if not PHISHTANK_API_KEY:
        return False, None
    payload = {
        "format": "json",
        "app_key": PHISHTANK_API_KEY,
        "url": url,
    }
    try:
        resp = requests.post(API_URL, data=payload, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            verified = data.get("results", {}).get("valid", False)
            return bool(verified), data
    except Exception:
        pass
    return False, None

def check_offline(url: str) -> Tuple[bool, Optional[dict]]:
    path = PHISHTANK_OFFLINE_CSV
    if not path or not os.path.exists(path):
        return False, None
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("url") == url:
                    return True, row
    except Exception:
        pass
    return False, None

def check_url(url: str) -> Tuple[bool, str]:
    # Try API first if key provided
    found, details = check_api(url)
    if found:
        return True, "phishtank"
    # Fallback to offline CSV
    found, details = check_offline(url)
    if found:
        return True, "phishtank_offline"
    return False, ""
