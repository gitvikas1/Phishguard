
from flask import Flask, render_template, request, jsonify, redirect, url_for
from services.features import extract_features, vectorize
from services.ml import predict_url
from services.phishtank import check_url as phishtank_check
from services.db import init_db, get_history   
from config import SECRET_KEY
import threading
import time
import schedule
from utils.phishtank_utils import update_phishtank
from utils.history_utils import log_detection
import os

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Initialize DB
init_db()

# Run one-time migration from CSV to DB
from utils.history_migrate import migrate_csv_to_db
migrate_csv_to_db()


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form.get("url", "").strip()
    if not url:
        return jsonify({"ok": False, "message": "Please enter a URL."}), 400

    # Rule-based quick checks
    feats = extract_features(url)
    heuristic_score = (feats["tld_suspicious"] + feats["ip_in_domain"] + feats["has_at"] + feats["has_hyphen"] + (feats["keyword_hits"] > 0)) / 5.0
    rule_flag = heuristic_score >= 0.6

    # ML prediction
    proba, label = predict_url(url)

    # PhishTank
    pt_found, pt_reason = phishtank_check(url)

    verdict = "safe"
    reason = "ml"
    score = proba

    if pt_found:
        verdict = "phishing"
        reason = pt_reason or "phishtank"
    elif label == 1 or rule_flag:
        verdict = "phishing"
        reason = "ml" if label == 1 else "rules"

    # Always log the URL
    log_detection(url, verdict, reason, score)

    # Then return the result
    return jsonify({
        "ok": True,
        "verdict": verdict,
        "reason": reason,
        "score": round(score, 4) if score is not None else None,
        "features": feats,
        "message": "No Phishing Detected" if verdict == "safe" else "Phishing URL Detected"
    })

@app.route("/history")
def history():
    rows = get_history(limit=500)
    return render_template("history.html", rows=rows)

@app.route("/learn")
def learn():
    return render_template("learn.html")

def run_scheduler():
    # Run once at startup
    print("[Scheduler] Updating PhishTank database now...")
    update_phishtank()

    # Schedule it to run every 24 hours
    schedule.every(24).hours.do(update_phishtank)

    # Keep checking every minute
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    # Start scheduler in background
    threading.Thread(target=run_scheduler, daemon=True).start()

    # Start Flask app
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)