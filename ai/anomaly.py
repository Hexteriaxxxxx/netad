# ai/anomaly.py
# Scikit-learn Isolation Forest anomaly detector for NETAD Security System
# Detects suspicious login patterns based on behavioral features.
# PH timezone aware — all hours converted to UTC+8 before feature extraction.

import os
import time
import joblib
import numpy as np
from datetime import datetime, timezone, timedelta

MODEL_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'anomaly_model.pkl')
SCALER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'anomaly_scaler.pkl')

# In-memory rolling window: tracks recent attempts per IP
_ip_attempts: dict = {}

# PH timezone offset
_PH = timedelta(hours=8)

# Isolation Forest decision score below this = anomaly
# Loosened slightly from -0.15 to -0.20 to reduce false positives
# on legitimate late-night team members while still catching real attacks
SUSPICIOUS_THRESHOLD = -0.20


def _ph_hour() -> int:
    """Return current hour in PH time (UTC+8), 0-23."""
    return datetime.now(timezone.utc).astimezone(timezone(_PH)).hour


def _get_features(ip: str, username: str) -> list:
    """
    Build a feature vector for a login attempt.

    Features:
      0 - hour of day in PH time (0-23)  ← was UTC before, now correct
      1 - attempts in last 60 seconds from this IP
      2 - attempts in last 10 minutes from this IP
      3 - is_weekend in PH time (0 or 1)
      4 - username length (proxy for bot-like usernames)
      5 - ip last octet (rough locality signal)
    """
    now = time.time()
    ph_now = datetime.now(timezone.utc).astimezone(timezone(_PH))

    # Track this attempt
    if ip not in _ip_attempts:
        _ip_attempts[ip] = []
    _ip_attempts[ip].append(now)
    # Prune entries older than 10 minutes
    _ip_attempts[ip] = [t for t in _ip_attempts[ip] if now - t < 600]

    attempts_60s = sum(1 for t in _ip_attempts[ip] if now - t < 60)
    attempts_10m = len(_ip_attempts[ip])
    hour         = ph_now.hour                          # PH hour ✅
    is_weekend   = 1 if ph_now.weekday() >= 5 else 0   # PH weekend ✅
    uname_len    = len(username)

    try:
        last_octet = int(ip.split('.')[-1])
    except Exception:
        last_octet = 0

    return [hour, attempts_60s, attempts_10m, is_weekend, uname_len, last_octet]


def _build_default_model():
    """
    Train Isolation Forest on synthetic data that reflects real PH team patterns.

    Normal: logins from 5AM-10PM PH, 1-2 attempts, weekdays + weekends,
            short usernames (2-8 chars), local subnet last octets.
    Attack: midnight-4AM PH, high frequency, long/weird usernames, external IPs.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    rng = np.random.default_rng(42)
    N_NORMAL = 1200
    N_ATTACK = 200

    # Normal PH logins: 5AM (hour=5) to 10PM (hour=22)
    normal_hours = np.concatenate([
        rng.integers(5, 10, N_NORMAL // 3),    # early morning 5-9AM
        rng.integers(10, 18, N_NORMAL // 3),   # daytime 10AM-5PM
        rng.integers(18, 23, N_NORMAL // 3),   # evening 6PM-10PM
    ])
    np.random.shuffle(normal_hours)

    normal = np.column_stack([
        normal_hours,
        rng.integers(1, 2, N_NORMAL),           # attempts_60s: 1
        rng.integers(1, 3, N_NORMAL),           # attempts_10m: 1-2
        rng.integers(0, 2, N_NORMAL),           # is_weekend: 0 or 1 (team works weekends)
        rng.integers(2, 8, N_NORMAL),           # uname_len: short real names
        rng.integers(1, 30, N_NORMAL),          # last_octet: local-ish subnet
    ])

    # Attack patterns
    attack = np.column_stack([
        rng.integers(0, 5, N_ATTACK),           # hour: midnight-4AM PH
        rng.integers(5, 40, N_ATTACK),          # attempts_60s: high burst
        rng.integers(10, 60, N_ATTACK),         # attempts_10m: sustained high
        rng.integers(0, 2, N_ATTACK),           # is_weekend: any
        rng.integers(10, 32, N_ATTACK),         # uname_len: long/weird usernames
        rng.integers(60, 255, N_ATTACK),        # last_octet: external IPs
    ])

    X = np.vstack([normal, attack])

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=300,
        contamination=0.14,   # ~14% expected attacks in training set
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print("[anomaly] Default model built with PH-corrected training data.")
    return model, scaler


def _load_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            model  = joblib.load(MODEL_PATH)
            scaler = joblib.load(SCALER_PATH)
            print("[anomaly] Loaded existing model from disk.")
            return model, scaler
        except Exception as e:
            print(f"[anomaly] Failed to load saved model ({e}), rebuilding...")
    return _build_default_model()


# Load once at import time
_model, _scaler = _load_model()


def is_suspicious(ip: str, username: str) -> tuple[bool, float]:
    """
    Returns (is_suspicious: bool, anomaly_score: float).
    Score < SUSPICIOUS_THRESHOLD means anomalous.
    Whitelisted IPs are NOT checked here — caller is responsible for that gate.
    """
    features  = _get_features(ip, username)
    X         = np.array([features])
    X_scaled  = _scaler.transform(X)
    score     = float(_model.decision_function(X_scaled)[0])
    suspicious = score < SUSPICIOUS_THRESHOLD
    if suspicious:
        print(f"[anomaly] SUSPICIOUS ip={ip} user={username} score={score:.3f} features={features}")
    return suspicious, score


def retrain(new_samples: list) -> None:
    """
    Retrain model on new real-world samples.
    Each sample: [hour_ph, attempts_60s, attempts_10m, is_weekend, uname_len, last_octet]
    Merges with synthetic baseline so model never forgets normal patterns
    even if all recent real logins happened to be attacks.
    """
    global _model, _scaler
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    if len(new_samples) < 50:
        print(f"[anomaly] Retrain skipped — only {len(new_samples)} samples (need ≥50)")
        return

    # Rebuild synthetic baseline and merge with real data
    # This prevents catastrophic forgetting when real data is sparse
    rng = np.random.default_rng(int(time.time()) % (2**32))
    N = min(len(new_samples), 500)  # cap synthetic at same size as real data

    baseline_hours = np.concatenate([
        rng.integers(5, 10, N // 3),
        rng.integers(10, 18, N // 3),
        rng.integers(18, 23, N // 3),
    ])
    np.random.shuffle(baseline_hours)

    synthetic = np.column_stack([
        baseline_hours,
        rng.integers(1, 2, N),
        rng.integers(1, 3, N),
        rng.integers(0, 2, N),
        rng.integers(2, 8, N),
        rng.integers(1, 30, N),
    ])

    X_real    = np.array(new_samples)
    X_merged  = np.vstack([synthetic, X_real])

    scaler    = StandardScaler()
    X_scaled  = scaler.fit_transform(X_merged)

    model = IsolationForest(
        n_estimators=300,
        contamination=0.12,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_scaled)

    _model  = model
    _scaler = scaler
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"[anomaly] Model retrained: {len(new_samples)} real + {N} synthetic = {len(X_merged)} total samples.")
