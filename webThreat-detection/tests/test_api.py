"""
API integration tests for the Phishing Detection backend using FastAPI TestClient.
"""

from unittest.mock import MagicMock
import numpy as np
import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.main import app


@pytest.fixture
def client():
    """
    Standard TestClient with lifespan context enabled.
    """
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def client_with_model(monkeypatch):
    """
    TestClient with a simulated RandomForestClassifier loaded into app.main.model.
    Inspects extracted features to realistically classify safe vs phishing URLs.
    """
    mock_rf = MagicMock()

    def mock_predict(df):
        # A URL with IP address, @ symbol, or non-HTTPS is treated as phishing (1), else safe (0)
        row = df.iloc[0]
        if row.get("is_ip_address", 0) == 1 or row.get("has_at_symbol", 0) == 1 or row.get("use_https", 1) == 0:
            return np.array([1])
        return np.array([0])

    def mock_predict_proba(df):
        pred = mock_predict(df)[0]
        if pred == 1:
            return np.array([[0.08, 0.92]])  # High probability for Phishing (class 1)
        return np.array([[0.96, 0.04]])      # High probability for Safe (class 0)

    mock_rf.predict.side_effect = mock_predict
    mock_rf.predict_proba.side_effect = mock_predict_proba
    mock_rf.classes_ = np.array([0, 1])

    monkeypatch.setattr(main_module, "model", mock_rf)

    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client):
    """Test the GET / health check endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_predict_safe_url(client_with_model):
    """
    Test /predict endpoint with a known-safe HTTPS domain.
    """
    safe_url = "https://example.com"
    payload = {"url": safe_url}

    response = client_with_model.post("/predict", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["url"] == safe_url
    assert data["prediction"] == "Safe"
    assert isinstance(data["confidence"], float)
    assert 0.5 <= data["confidence"] <= 1.0


def test_predict_phishing_url(client_with_model):
    """
    Test /predict endpoint with a known phishing-style URL structure:
    - Uses raw IP address instead of domain
    - Contains '@' symbol for credential deception
    - Uses unencrypted HTTP
    """
    phishing_url = "http://192.168.1.100/verify-login.php?user=account@paypal-update.net"
    payload = {"url": phishing_url}

    response = client_with_model.post("/predict", json=payload)
    assert response.status_code == 200

    data = response.json()
    assert data["url"] == phishing_url
    assert data["prediction"] == "Phishing"
    assert isinstance(data["confidence"], float)
    assert 0.5 <= data["confidence"] <= 1.0


def test_predict_without_model(monkeypatch, client):
    """
    Test /predict endpoint fallback heuristic when model is not loaded.
    """
    monkeypatch.setattr(main_module, "MODEL_PATH", "non_existent_model.pkl")
    monkeypatch.setattr(main_module, "model", None)
    response = client.post("/predict", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "Safe"
    assert data["confidence"] == 0.95


def test_predict_vit_bhopal_college_sites(client):
    """
    Test that VIT Bhopal portals (vtop, snm, root domain) are recognized as Safe
    with low risk score (e.g. 2%).
    """
    college_urls = [
        "https://vtop.vitbhopal.ac.in/",
        "https://snm.vitbhopal.ac.in/",
        "https://vitbhopal.ac.in/",
    ]
    for url in college_urls:
        response = client.post("/predict", json={"url": url})
        assert response.status_code == 200
        data = response.json()
        assert data["prediction"] == "Safe"
        assert data["risk_level"] == "Safe"
        assert data["risk_score"] <= 5
        assert "VIT Bhopal" in data["description"]
