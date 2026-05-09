# ai/anomaly.py
# Scikit-learn Isolation Forest anomaly detector for NETAD Security System
# Detects suspicious login patterns based on behavioral features.

import os
import time
import joblib
import numpy as np
from datetime import datetime

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'anomaly_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'anomaly_scaler.pkl')

# In-memory rolling window: tracks recent attempts per IP
# { ip: [timestamp, timestamp, ...] }
_ip_attempts: dict = {}

SUSPICIOUS_THRESHOLD = -0.15  # Isolation Forest decision score below this = anomaly


def _get_features(ip: str, username: str) -> list:
    """
    Build a feature vector for a login attempt.
    Features:
      0 - hour of day (0-23)
      1 - attempts in last 60 seconds from this IP
      2 - attempts in last 10 minutes from this IP
      3 - is_weekend (0 or 1)
      4 - username length (proxy for bot-like usernames)
      5 - ip last octet (rough locality signal)
    """
    now = time.time()
    dt = datetime.fromtimestamp(now)

    # Track this attempt
    if ip not in _ip_attempts:
        _ip_attempts[ip] = []
    _ip_attempts[ip].append(now)

    # Prune old entries beyond 10 minutes
    _ip_attempts[ip] = [t for t in _ip_attempts[ip] if now - t < 600]

    attempts_60s  = sum(1 for t in _ip_attempts[ip] if now - t < 60)
    attempts_10m  = len(_ip_attempts[ip])
    hour          = dt.hour
    is_weekend    = 1 if dt.weekday() >= 5 else 0
    uname_len     = len(username)

    try:
        last_octet = int(ip.split('.')[-1])
    except Exception:
        last_octet = 0

    return [hour, attempts_60s, attempts_10m, is_weekend, uname_len, last_octet]


def _build_default_model():
    """
    Train a fresh Isolation Forest on synthetic normal + attack data
    so the model works immediately without needing real login history.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    rng = np.random.default_rng(42)

    # Normal logins: business hours, 1-2 attempts, weekdays
    normal = np.column_stack([
        rng.integers(8, 18, 800),        # hour: 8am-6pm
        rng.integers(1, 2, 800),          # attempts_60s: 1
        rng.integers(1, 3, 800),          # attempts_10m: 1-2
        rng.integers(0, 1, 800),          # is_weekend: mostly 0
        rng.integers(4, 10, 800),         # uname_len: normal names
        rng.integers(1, 20, 800),         # last_octet: local subnet
    ])

    # Attack patterns: off-hours, high frequency, weird usernames
    attack = np.column_stack([
        rng.integers(0, 6, 200),          # hour: midnight-6am
        rng.integers(5, 30, 200),         # attempts_60s: high
        rng.integers(10, 50, 200),        # attempts_10m: high
        rng.integers(0, 2, 200),          # is_weekend: any
        rng.integers(1, 30, 200),         # uname_len: varied
        rng.integers(50, 255, 200),       # last_octet: external IPs
    ])

    X = np.vstack([normal, attack])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.18,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print("[anomaly] Model trained and saved.")
    return model, scaler


def _load_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        model  = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler
    return _build_default_model()


# Load once at import time
_model, _scaler = _load_model()


def is_suspicious(ip: str, username: str) -> tuple[bool, float]:
    """
    Returns (is_suspicious: bool, anomaly_score: float).
    Score < SUSPICIOUS_THRESHOLD means anomalous.
    """
    features = _get_features(ip, username)
    X = np.array([features])
    X_scaled = _scaler.transform(X)
    score = float(_model.decision_function(X_scaled)[0])
    suspicious = score < SUSPICIOUS_THRESHOLD
    return suspicious, score


def retrain(new_samples: list[list]) -> None:
    """
    Online retraining: append new labeled samples and retrain.
    Each sample is a feature vector [hour, attempts_60s, ...].
    Call this periodically from a background job as real login data accumulates.
    """
    global _model, _scaler
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    X_new = np.array(new_samples)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_new)
    model = IsolationForest(n_estimators=200, contamination=0.15, random_state=42, n_jobs=-1)
    model.fit(X_scaled)
    _model  = model
    _scaler = scaler
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print("[anomaly] Model retrained with new data.")
