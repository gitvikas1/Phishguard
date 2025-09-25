import pandas as pd
import numpy as np
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from pathlib import Path

from services.features import extract_features, vectorize, FEATURE_ORDER
from config import MODEL_PATH

def make_synthetic_dataset():
    # A tiny synthetic dataset to bootstrap the model
    samples = [
        # url, label
        ("https://www.google.com", 0),
        ("http://example.com/login", 1),
        ("https://secure-paypal.com.verify-account.example.co", 1),
        ("http://192.168.1.10/confirm", 1),
        ( "https://mybank.com", 0),
        ("http://free-gift.click/claim", 1),
        ("https://github.com", 0),
        ("http://update-account.xyz/secure", 1),
        ("https://university.edu/verify", 0),
        ("http://amazon.com", 0),
        ("http://amaz0n-verify.com", 1),
        ("https://decathlon.in", 0),
        ("http://malad-decathlon.win/bonus", 1),
        ("https://login.microsoftonline.com", 0),
        ("http://paypall.com.verify-account.info", 1)
    ]
    rows = []
    for url, label in samples:
        feats = extract_features(url)
        feats["label"] = label
        rows.append(feats)
    df = pd.DataFrame(rows)
    return df

def train_and_save():
    df = make_synthetic_dataset()
    X = df[[col for col in df.columns if col != "label"]]
    y = df["label"]
    model = LogisticRegression(max_iter=200)
    model.fit(X.values, y.values)
    Path(MODEL_PATH).parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print("Model trained and saved to", MODEL_PATH)

if __name__ == "__main__":
    train_and_save()
