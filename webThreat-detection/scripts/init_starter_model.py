"""
Generate and save a starter Random Forest model artifact (model.pkl).
This allows the API and Chrome extension to work out-of-the-box immediately
before the user downloads the full Kaggle dataset.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

FEATURE_COLUMNS = [
    "url_length",
    "num_dots",
    "has_at_symbol",
    "is_ip_address",
    "use_https",
    "ssl_valid",
    "domain_age_days",
    "num_redirects",
]

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_PATH = os.path.join(BASE_DIR, "app", "model", "model.pkl")


def generate_starter_model():
    rng = np.random.default_rng(42)
    n_samples = 2000

    # 1. Generate safe samples (label = 0)
    n_safe = n_samples // 2
    safe_data = {
        "url_length": rng.integers(15, 45, size=n_safe),
        "num_dots": rng.integers(1, 3, size=n_safe),
        "has_at_symbol": np.zeros(n_safe, dtype=int),
        "is_ip_address": np.zeros(n_safe, dtype=int),
        "use_https": rng.choice([1, 0], p=[0.95, 0.05], size=n_safe),
        "ssl_valid": rng.choice([1, 0], p=[0.94, 0.06], size=n_safe),
        "domain_age_days": rng.integers(365, 3650, size=n_safe),
        "num_redirects": rng.choice([0, 1, 2], p=[0.8, 0.15, 0.05], size=n_safe),
        "label": np.zeros(n_safe, dtype=int),
    }

    # 2. Generate phishing samples (label = 1)
    n_phish = n_samples - n_safe
    phish_data = {
        "url_length": rng.integers(50, 150, size=n_phish),
        "num_dots": rng.integers(3, 7, size=n_phish),
        "has_at_symbol": rng.choice([1, 0], p=[0.4, 0.6], size=n_phish),
        "is_ip_address": rng.choice([1, 0], p=[0.3, 0.7], size=n_phish),
        "use_https": rng.choice([1, 0], p=[0.35, 0.65], size=n_phish),
        "ssl_valid": rng.choice([1, 0], p=[0.2, 0.8], size=n_phish),
        "domain_age_days": rng.choice([rng.integers(1, 45), -1], size=n_phish),
        "num_redirects": rng.choice([0, 1, 2, 3, 4], p=[0.2, 0.2, 0.3, 0.2, 0.1], size=n_phish),
        "label": np.ones(n_phish, dtype=int),
    }

    df_safe = pd.DataFrame(safe_data)
    df_phish = pd.DataFrame(phish_data)
    df = pd.concat([df_safe, df_phish], ignore_index=True)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X, y)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    print(f"Starter model trained and saved successfully to: {MODEL_PATH}")


if __name__ == "__main__":
    generate_starter_model()
