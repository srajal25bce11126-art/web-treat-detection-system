from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class URLRequest(BaseModel):
    """Request payload containing the target URL to analyze."""
    url: str


# Backwards compatibility alias
URLCheckRequest = URLRequest


class PredictionResponse(BaseModel):
    """Prediction output schema for phishing detection."""
    url: str
    prediction: str  # "Safe" or "Phishing"
    confidence: float
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None  # "Caution", "Danger", "Safe"
    headline: Optional[str] = None
    description: Optional[str] = None
    signals: Optional[List[Dict[str, Any]]] = None
    features: Optional[Dict[str, Any]] = None


class FeatureExtractionResponse(BaseModel):
    """Extracted URL, SSL, and WHOIS features."""
    url: str
    features: Dict[str, Any] = Field(default_factory=dict, description="Extracted feature key-value pairs")


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str = "ok"
    model_loaded: bool = False
