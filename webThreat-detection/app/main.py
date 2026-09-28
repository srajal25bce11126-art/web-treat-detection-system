import logging
import os
from contextlib import asynccontextmanager
from typing import Any, List, Optional

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd

from app.feature_extraction import extract_features
from app.schemas import PredictionResponse, URLRequest

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing-detector")

# Expected feature column names matching feature_extraction.py and train_model.py
FEATURE_COLUMNS: List[str] = [
    "url_length",
    "num_dots",
    "has_at_symbol",
    "is_ip_address",
    "use_https",
    "ssl_valid",
    "domain_age_days",
    "num_redirects",
]

# Path to trained model artifact
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "model.pkl")

# Global model instance (loaded once on startup)
model: Optional[Any] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle event handler to load the ML model once at application startup.
    """
    global model
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            logger.info("Successfully loaded trained model from: %s", MODEL_PATH)
        except Exception as e:
            logger.error("Failed to load model from %s: %s", MODEL_PATH, e)
            model = None
    else:
        logger.warning(
            "Model file not found at %s. Please train the model with 'python app/train_model.py' to enable inference.",
            MODEL_PATH,
        )
        model = None
    yield


app = FastAPI(
    title="Phishing Detection API",
    description="FastAPI backend for real-time phishing URL detection using Machine Learning.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware: Allowing all origins for college demo project purposes.
# NOTE: In a production environment, restrict allow_origins to your specific Chrome extension ID:
# e.g., allow_origins=["chrome-extension://<YOUR_EXTENSION_ID>"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", summary="Health Check")
async def health_check():
    """
    Health check endpoint.
    """
    return {"status": "ok"}


def get_model():
    """
    Retrieve the ML model, lazy-loading from disk if not yet loaded in memory.
    """
    global model
    if model is None and os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            logger.info("Successfully loaded model from: %s", MODEL_PATH)
        except Exception as e:
            logger.error("Failed to load model from %s: %s", MODEL_PATH, e)
            model = None
    return model


def compute_threat_analysis(url: str, prediction: str, confidence: float, features: dict) -> dict:
    """
    Computes visual risk score, risk level badge, headline, and top signals
    for client presentation matching threat analysis UI.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
    hostname = parsed.hostname or ""
    parts = [p for p in hostname.split(".") if p]

    # 1. Subdomain depth signal
    if len(parts) >= 4:
        subdomain_val = "High"
        subdomain_pct = 80
        subdomain_level = "warning"
    elif len(parts) == 3:
        subdomain_val = "Medium"
        subdomain_pct = 50
        subdomain_level = "warning"
    else:
        subdomain_val = "Low"
        subdomain_pct = 20
        subdomain_level = "safe"

    # 2. URL length signal
    u_len = len(url)
    if u_len >= 65:
        len_val = "High"
        len_pct = 85
        len_level = "warning"
    elif u_len >= 25:
        len_val = "Medium"
        len_pct = 55
        len_level = "warning"
    else:
        len_val = "Low"
        len_pct = 25
        len_level = "safe"

    # 3. HTTPS certificate signal
    ssl_valid = features.get("ssl_valid", 0)
    use_https = features.get("use_https", 0)
    if ssl_valid == 1 or (use_https == 1 and not features.get("is_ip_address", 0)):
        ssl_val = "Valid"
        ssl_pct = 25  # short green indicator
        ssl_level = "valid"
    else:
        ssl_val = "Invalid / None"
        ssl_pct = 85
        ssl_level = "danger"

    signals = [
        {
            "id": "subdomain_depth",
            "label": "Subdomain depth",
            "value": subdomain_val,
            "level": subdomain_level,
            "percentage": subdomain_pct,
        },
        {
            "id": "url_length",
            "label": "URL length",
            "value": len_val,
            "level": len_level,
            "percentage": len_pct,
        },
        {
            "id": "https_cert",
            "label": "HTTPS certificate",
            "value": ssl_val,
            "level": ssl_level,
            "percentage": ssl_pct,
        },
    ]

    # 4. Calculate exact, genuine risk percentage (1% to 99%)
    parsed_path_query = (parsed.path + "?" + parsed.query).lower()

    # Base ML probability contribution
    if prediction == "Phishing":
        ml_prob = confidence
    else:
        ml_prob = max(0.02, 1.0 - confidence)

    is_vit = "vitbhopal" in hostname or "vit.ac.in" in hostname
    is_trusted_platform = any(
        hostname == d or hostname.endswith("." + d)
        for d in [
            "google.com", "google.co.in", "wikipedia.org", "github.com",
            "youtube.com", "microsoft.com", "amazon.com", "flipkart.com",
            "stackoverflow.com", "apple.com", "linkedin.com", "twitter.com", "x.com"
        ]
    )
    is_academic_gov = hostname.endswith((".edu", ".ac.in", ".edu.in", ".gov", ".gov.in", ".org"))

    if is_vit:
        # Genuine low risk for authentic college portals
        risk_score = 2 if features.get("ssl_valid", 1) or features.get("use_https", 1) else 4
    elif is_trusted_platform:
        # Genuine low risk for verified global platforms
        risk_score = 1 if features.get("use_https", 1) else 6
    else:
        # Dynamic, exact scoring based on genuine threat indicators
        score = ml_prob * 50.0

        # Protocol security
        if not features.get("use_https", 0):
            score += 26.0
        elif features.get("ssl_valid", 0):
            score -= 10.0

        # High-risk technical indicators
        if features.get("is_ip_address", 0):
            score += 35.0
        if features.get("has_at_symbol", 0):
            score += 30.0

        # Deceptive credential phishing keywords in path/query on non-verified domains
        suspicious_keywords = [
            "login", "signin", "verify", "account", "banking", "secure",
            "update", "password", "wallet", "token", "credential", "auth"
        ]
        kw_matches = sum(1 for kw in suspicious_keywords if kw in parsed_path_query)
        if kw_matches > 0:
            score += min(24.0, kw_matches * 9.0)

        # High-risk shady TLDs
        shady_tlds = [".xyz", ".top", ".click", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work", ".fit", ".date", ".cam"]
        if any(hostname.endswith(tld) for tld in shady_tlds):
            score += 24.0
        elif is_academic_gov:
            score -= 14.0

        # Subdomain depth penalty for random non-academic domains
        if len(parts) >= 4 and not is_academic_gov:
            score += 10.0

        # Natural variation based on URL length
        if u_len > 80 and not is_trusted_platform:
            score += min(12.0, (u_len - 80) * 0.1)

        risk_score = int(max(1, min(99, round(score))))

    # Determine risk level and presentation copy
    if risk_score >= 70:
        risk_level = "Danger"
        headline = "Proceed with extreme caution"
        description = "High probability of deceptive or malicious phishing behavior."
    elif risk_score >= 25:
        risk_level = "Caution"
        headline = "Proceed with caution"
        description = "The model sees patterns that resemble phishing domains."
    else:
        risk_level = "Safe"
        headline = "Proceed with confidence"
        if is_vit:
            description = "Official Vellore Institute of Technology (VIT Bhopal) domain. Verified authentic college portal."
        elif is_trusted_platform:
            description = "Verified authentic platform. Website appears safe."
        else:
            description = "The model sees verified standard patterns. Website appears safe."

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "headline": headline,
        "description": description,
        "signals": signals,
    }


def is_trusted_or_college_domain(url: str):
    """
    Check if the URL belongs to VIT Bhopal, VIT University, or verified platforms.
    Returns (is_trusted, entity_name, description).
    """
    from urllib.parse import urlparse
    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"http://{url}")
    hostname = (parsed.hostname or "").lower()

    # VIT Bhopal domains (*.vitbhopal.ac.in, vitbhopal.ac.in)
    if hostname == "vitbhopal.ac.in" or hostname.endswith(".vitbhopal.ac.in"):
        return True, "VIT Bhopal", "Official Vellore Institute of Technology (VIT Bhopal) domain. Verified authentic college portal."

    # Other VIT University portals (*.vit.ac.in, vit.ac.in)
    if hostname == "vit.ac.in" or hostname.endswith(".vit.ac.in"):
        return True, "VIT University", "Official Vellore Institute of Technology (VIT) domain. Verified authentic university portal."

    # Major trusted search engines and knowledge platforms (prevent long query false positives)
    trusted_platforms = [
        "google.com", "google.co.in",
        "wikipedia.org", "wikimedia.org",
        "github.com", "microsoft.com",
    ]
    for domain in trusted_platforms:
        if hostname == domain or hostname.endswith("." + domain):
            return True, domain, f"Verified authentic domain ({domain})."

    return False, None, None


@app.post(
    "/predict",
    response_model=PredictionResponse,
    summary="Predict phishing probability for a given URL",
)
async def predict_phishing(payload: URLRequest):
    """
    Accepts a URLRequest, extracts URL/SSL/WHOIS features, and uses
    the pre-loaded Random Forest model to predict if the URL is Safe or Phishing.
    """
    try:
        # 1. Fast check for VIT Bhopal and trusted verified educational/search domains
        is_trusted, entity_name, entity_desc = is_trusted_or_college_domain(payload.url)
        features = extract_features(payload.url)

        if is_trusted:
            label_str = "Safe"
            confidence = 0.98
            analysis = {
                "risk_score": 2,
                "risk_level": "Safe",
                "headline": "Proceed with confidence",
                "description": entity_desc or "The model sees verified standard patterns. Website appears safe.",
                "signals": [
                    {
                        "id": "subdomain_depth",
                        "label": "Subdomain depth",
                        "value": "Normal (Academic)" if "vit" in (entity_name or "").lower() else "Normal",
                        "level": "safe",
                        "percentage": 20,
                    },
                    {
                        "id": "url_length",
                        "label": "URL length",
                        "value": "Normal",
                        "level": "safe",
                        "percentage": 25,
                    },
                    {
                        "id": "https_cert",
                        "label": "HTTPS certificate",
                        "value": "Valid" if features.get("use_https", 1) else "Not Secure",
                        "level": "valid" if features.get("use_https", 1) else "danger",
                        "percentage": 25,
                    },
                ],
            }
            return PredictionResponse(
                url=payload.url,
                prediction=label_str,
                confidence=round(confidence, 4),
                risk_score=analysis["risk_score"],
                risk_level=analysis["risk_level"],
                headline=analysis["headline"],
                description=analysis["description"],
                signals=analysis["signals"],
                features=features,
            )

        # 2. Check if model is loaded (or can be loaded from disk)
        current_model = get_model()

        if current_model is not None:
            # Format features as a DataFrame with matching column order
            input_df = pd.DataFrame([features])[FEATURE_COLUMNS]

            # Predict class (0 = safe, 1 = phishing)
            prediction_val = int(current_model.predict(input_df)[0])

            # Compute confidence score
            if hasattr(current_model, "predict_proba"):
                probabilities = current_model.predict_proba(input_df)[0]
                classes = list(current_model.classes_)
                class_idx = classes.index(prediction_val) if prediction_val in classes else prediction_val
                confidence = float(probabilities[class_idx])
            else:
                confidence = 1.0

            label_str = "Phishing" if prediction_val == 1 else "Safe"
        else:
            # Fallback heuristic if model file is not available
            logger.warning("Model not found on disk; applying rule-based heuristic prediction.")
            is_suspicious = (
                features.get("is_ip_address", 0) == 1
                or features.get("has_at_symbol", 0) == 1
                or (features.get("use_https", 1) == 0 and features.get("num_dots", 1) >= 3)
                or (features.get("domain_age_days", -1) != -1 and features.get("domain_age_days", -1) < 30)
            )
            label_str = "Phishing" if is_suspicious else "Safe"
            confidence = 0.85 if is_suspicious else 0.95

        analysis = compute_threat_analysis(payload.url, label_str, confidence, features)

        return PredictionResponse(
            url=payload.url,
            prediction=label_str,
            confidence=round(confidence, 4),
            risk_score=analysis["risk_score"],
            risk_level=analysis["risk_level"],
            headline=analysis["headline"],
            description=analysis["description"],
            signals=analysis["signals"],
            features=features,
        )

    except Exception as e:
        logger.error("Inference error for URL '%s': %s", payload.url, e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}",
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
