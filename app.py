import os
import re
import difflib
import csv
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify

from config import SECRET_KEY
from services.features import extract_features
from services.ml import predict_url
from services.db import init_db, get_history
from utils.history_utils import log_detection
from utils.history_migrate import migrate_csv_to_db
from services.whitelist import SAFE_WHITELIST

# ------------------ Initialize Flask ------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ------------------ Initialize DB ------------------
init_db()
migrate_csv_to_db()

# ------------------ Load PhishTank CSV at startup ------------------
PHISHTANK_FILE = "phishtank.csv"  
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"  # Replace with the correct public CSV link
PHISHTANK_URLS = set()

if not os.path.exists(PHISHTANK_FILE):
    print("[Startup] PhishTank CSV not found locally. Downloading...")
    try:
        r = requests.get(PHISHTANK_URL, timeout=30)
        r.raise_for_status()
        with open(PHISHTANK_FILE, "wb") as f:
            f.write(r.content)
        print(f"[Startup] Downloaded PhishTank CSV successfully ({len(r.content)} bytes).")
    except Exception as e:
        print(f"[Startup] ERROR: Failed to download PhishTank CSV: {e}")

# Load CSV if exists
if os.path.exists(PHISHTANK_FILE):
    with open(PHISHTANK_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url")
            if url:
                url = url.lower().strip()
                if url.endswith("/"):
                    url = url[:-1]
                if url.startswith("http://"):
                    url = url[7:]
                elif url.startswith("https://"):
                    url = url[8:]
                PHISHTANK_URLS.add(url)
    print(f"[Startup] Loaded {len(PHISHTANK_URLS)} URLs from PhishTank CSV.")
else:
    print(f"[Startup] WARNING: PhishTank CSV still not found!")

# ------------------ URL Validation ------------------
def normalize_url(url: str) -> str:
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url

def normalize_phishtank_url(url: str) -> str:
    url = url.lower().strip()
    if url.endswith("/"):
        url = url[:-1]
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    return url

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if parsed.scheme not in ["https"]:
            return False
        if not hostname:
            return False
        if re.search(r"[ <>\"']", url):
            return False
        private_ips = re.compile(
            r"^(127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)$"
        )
        if private_ips.match(hostname):
            return False
        if url.count("@") > 1:
            return False
        if len(hostname) > 253 or not re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", hostname):
            return False
        return True
    except Exception:
        return False

# ------------------ Enhanced Heuristics ------------------
SUSPICIOUS_TLDS = [
    "zip","review","country","stream","gq","ml","tk","cf","work","fit","xyz",
    "men","date","click","party","cam","rest","top","win","loan","vip","trade",
    "account","download","support","security","online","center","web","shop",
    "gift","bonus","free","offer"
]

SUSPICIOUS_KEYWORDS = [
    "login","secure","verify","update","account","bank","paypal","ebay",
    "apple","confirm","signin","wp-admin","password","reset"
]

def enhanced_heuristic(url: str, feats: dict) -> float:
    score = 0.0
    hostname = urlparse(url).hostname or ""
    tld = hostname.split('.')[-1].lower() if hostname else ""

    if tld in SUSPICIOUS_TLDS:
        score += 0.2
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in hostname.lower():
            score += 0.15
    if urlparse(url).scheme == "http":
        score += 0.1
    if hostname.count("-") >= 2:
        score += 0.1
    if re.search(r"\d", hostname):
        score += 0.05
    sld = hostname.split(".")[0]
    if len(sld) >= 15 and re.fullmatch(r"[a-z0-9]+", sld):
        score += 0.15
    subdomains = hostname.split(".")[:-2]
    if len(subdomains) >= 3:
        score += 0.05
    score += (
        feats.get("tld_suspicious", 0) +
        feats.get("ip_in_domain", 0) +
        feats.get("has_at", 0) +
        feats.get("has_hyphen", 0) +
        feats.get("double_slash", 0) +
        (feats.get("keyword_hits", 0) > 0) * 0.05
    )

    return min(score, 1.0)

# ------------------ Routes ------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/learn")
def learn():
    return render_template("learn.html")

@app.route("/history")
def history():
    rows = get_history(limit=500)
    return render_template("history.html", rows=rows)

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url", "").strip()
    if not url:
        return jsonify({"ok": False, "message": "Please enter a URL."}), 400

    url = normalize_url(url)
    if not is_valid_url(url):
        return jsonify({"ok": False, "message": "Invalid URL."}), 400

    url_lower = normalize_phishtank_url(url)
    hostname = urlparse(url).hostname or ""

    # ------------------ 1️⃣ Check PhishTank CSV ------------------
    if url_lower in PHISHTANK_URLS:
        verdict = "phishing"
        reason = "phishtank csv"
        score = 1.0
        log_detection(url, verdict, reason, score)
        return jsonify({
            "ok": True,
            "verdict": verdict,
            "reason": reason,
            "score": score,
            "features": {},
            "message": "Phishing URL Detected [found in PhishTank CSV:-(Phishing.csv is a structured file of known phishing URLs that can be used to train or test phishing detection systems.)]"
        })

    # ------------------ 2️⃣ Whitelist + Typosquat ------------------
    labels = hostname.split(".")
    sld = labels[-2] if len(labels) >= 2 else ""
    for base_domain, allowed_subs in SAFE_WHITELIST.items():
        base_sld = base_domain.split(".")[0]
        if hostname in allowed_subs:
            verdict = "safe"
            reason = "whitelist"
            score = 0.0
            log_detection(url, verdict, reason, score)
            return jsonify({"ok": True,"verdict": verdict,"reason": reason,"score": score,"features": {}, "message": "Safe URL (whitelisted)"})
        similarity = difflib.SequenceMatcher(None, sld, base_sld).ratio()
        if similarity > 0.8:
            verdict = "phishing"
            reason = "typosquat"
            score = 1.0
            log_detection(url, verdict, reason, score)
            return jsonify({"ok": True,"verdict": verdict,"reason": reason,"score": score,"features": {}, "message": f"Phishing URL Detected [typosquat of trusted domain {base_domain}:-A typosquat of a trusted domain is a malicious website that uses a URL with a common misspelling or variation of a well-known, trusted domain name (like gogle.com instead of google.com) to trick users.]"})

    # ------------------ 3️⃣ Feature extraction + enhanced heuristic ------------------
    feats = extract_features(url)
    h_score = enhanced_heuristic(url, feats)

    # ------------------ 4️⃣ ML Prediction ------------------
    proba, label = predict_url(url)
    combined_score = (proba + h_score) / 2.0

    verdict = "safe"
    reason = "ml"

    if combined_score >= 0.65:
        verdict = "phishing"
        reason = "ml+heuristic"
        score = combined_score
    elif label == 1 and proba >= 0.7:
        verdict = "phishing"
        reason = "ml"
        score = proba
    elif h_score >= 0.5:
        verdict = "phishing"
        reason = "heuristic:-(A heuristic is a rule-of-thumb or a set of features used to predict if a URL is malicious.)"
        score = h_score
    else:
        score = proba

    log_detection(url, verdict, reason, score)
    return jsonify({"ok": True,"verdict": verdict,"reason": reason,"score": round(score,4),"features": feats,"message": "No Phishing Detected" if verdict=="safe" else "Phishing URL Detected"})

# ------------------ Run Flask ------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
