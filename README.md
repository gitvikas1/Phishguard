# Phishing URL Detector (Flask + ML + PhishTank)

A ready-to-run web app that flags suspicious URLs using:
- Heuristic rules
- A Logistic Regression ML model (pre-trained on a small bootstrap dataset)
- PhishTank (online API or offline CSV fallback)

## Quick Start (Windows / VS Code)

1. **Unzip** this folder.
2. Open the folder in **VS Code**.
3. Create and activate a virtual environment (recommended):
   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\activate
   ```
4. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
5. Run the app:
   ```powershell
   python app.py
   ```
6. Visit http://127.0.0.1:5000 in your browser.

## PhishTank Integration
- To enable real-time checks, set your API key:
  ```powershell
  set PHISHTANK_API_KEY=your_key_here
  ```
- Offline fallback uses `data/phishtank_sample.csv`. Replace with a full CSV from PhishTank if desired and set the env var if you put it elsewhere:
  ```powershell
  set PHISHTANK_OFFLINE_CSV=full\path\to\phishtank.csv
  ```

## Project Structure
```
phishguard/
├─ app.py
├─ config.py
├─ requirements.txt
├─ services/
│  ├─ db.py
│  ├─ features.py
│  ├─ ml.py
│  └─ phishtank.py
├─ model/
│  ├─ model.pkl
│  └─ train_model.py
├─ templates/
│  ├─ base.html
│  ├─ index.html
│  ├─ history.html
│  └─ learn.html
├─ static/
│  ├─ styles.css
│  └─ script.js
└─ data/
   └─ phishtank_sample.csv
```

## Notes
- Only **phishing** results are saved to history, per requirement.
- The provided model is for demo only; improve by retraining on a larger dataset via `model/train_model.py`.
- Set `SECRET_KEY` and other settings via environment variables in production.
