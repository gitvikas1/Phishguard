import os

# Flask
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")

# Database
DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "detections.sqlite3"))

# PhishTank
# Set PHISHTANK_API_KEY in environment to enable real-time API lookups.
PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY", None)

# Offline dataset path (optional)
PHISHTANK_OFFLINE_CSV = os.environ.get("PHISHTANK_OFFLINE_CSV", os.path.join(os.path.dirname(__file__), "data", "phishtank_sample.csv"))

# Model path
MODEL_PATH = os.environ.get("MODEL_PATH", os.path.join(os.path.dirname(__file__), "model", "model.pkl"))
