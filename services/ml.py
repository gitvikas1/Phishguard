import os
import pickle
from typing import Tuple
import numpy as np
from .features import extract_features, vectorize
from config import MODEL_PATH

_model = None

def load_model():
    global _model
    if _model is None:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
    return _model

def predict_url(url: str) -> Tuple[float, int]:
    model = load_model()
    feats = vectorize(extract_features(url))
    proba = float(model.predict_proba([feats])[0][1])  # probability of phishing class=1
    label = int(proba >= 0.5)
    return proba, label
