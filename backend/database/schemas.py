"""
Pydantic Schemas
================
Request and response schemas for the PhishGuard API.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


# --- Request schemas --------------------------------------------------------


class AnalyzeRequest(BaseModel):
    """JSON body expected by POST /analyze."""
    # min_length=0 (not 1) so that empty/whitespace-only URLs reach the route's
    # own validation, which returns a clean 400 "URL must not be empty." rather
    # than a Pydantic 422. Maximum length is still enforced here.
    url: str = Field(
        ...,
        min_length=0,
        max_length=2048,
        description="The URL to analyze",
    )


# --- Feature schemas --------------------------------------------------------


class UrlFeatures(BaseModel):
    """Structured features extracted from a URL string."""
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    fragment_length: int
    number_of_dots: int
    number_of_hyphens: int
    number_of_underscores: int
    number_of_digits: int
    number_of_special_characters: int
    number_of_subdomains: int
    has_at_symbol: bool
    has_ip_address: bool
    uses_https: bool
    suspicious_keyword_count: int
    url_entropy: float
    hostname: str
    path: str
    query_present: bool


# --- Security indicator schemas ---------------------------------------------


class SecurityIndicator(BaseModel):
    """A single security rule result."""
    rule: str
    description: str
    severity: str = Field(
        ...,
        pattern="^(low|medium|high)$",
    )
    detected: bool
    value: Optional[str] = None
    status: Optional[str] = None
    message: Optional[str] = None
    evidence: Optional[str] = None


# --- ML analysis schemas ----------------------------------------------------


class MlAnalysis(BaseModel):
    """ML model prediction result."""
    available: bool
    prediction: Optional[str] = None
    phishing_probability: Optional[float] = None
    safe_probability: Optional[float] = None
    model_name: Optional[str] = None
    error: Optional[str] = None
    predicted_label: Optional[str] = None
    model_status: Optional[str] = None


# --- Response schemas -------------------------------------------------------


class AnalyzeResponse(BaseModel):
    """JSON body returned by POST /analyze."""
    url: str
    classification: str
    risk_score: int = Field(..., ge=0, le=100)
    confidence: int = Field(..., ge=0, le=100)
    ml_phishing_probability_pct: Optional[int] = Field(None, ge=0, le=100)
    model_rule_status: Optional[str] = None
    message: str
    detected_indicators: List[SecurityIndicator] = []
    summary: str = ""
    features: UrlFeatures
    ml_analysis: MlAnalysis
    rules: List[SecurityIndicator] = []
    tls_analysis: dict = {}
    header_analysis: dict = {}
    risk_breakdown: dict = {}
    top_factors: List[str] = []
    why_flagged: Optional[dict] = None
    rule_analysis: dict = {}
    connection_security: dict = {}
    model_info: dict = {}
    phishing_analysis: dict = {}
    http_security: dict = {}
    final_assessment: dict = {}


class ScanRecordResponse(BaseModel):
    """A single scan record returned by GET /history."""
    id: int
    url: str
    classification: str
    risk_score: int
    confidence: int
    message: Optional[str] = None
    detected_indicators: Optional[str] = None
    summary: Optional[str] = None
    scanned_at: Optional[str] = None
    security_analysis: Optional[str] = None


class HistoryResponse(BaseModel):
    """Paginated scan history response."""
    records: List[ScanRecordResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class DashboardResponse(BaseModel):
    """Dashboard summary statistics."""
    total_scans: int
    safe_count: int
    suspicious_count: int
    phishing_count: int
    average_risk_score: float
    recent_scans: List[ScanRecordResponse]


class ScanRecordDetailResponse(BaseModel):
    """Full stored scan record returned by GET /history/{id}.

    Unlike ScanRecordResponse this includes the original scanned_at and the
    full JSON indicators so the History "View" action can display the exact
    stored result without re-running the analysis.
    """
    id: int
    url: str
    classification: str
    risk_score: int
    confidence: int
    message: Optional[str] = None
    detected_indicators: Optional[str] = None
    summary: Optional[str] = None
    scanned_at: Optional[str] = None
    security_analysis: Optional[str] = None


class TrendResponse(BaseModel):
    """Daily average risk scores for the last 7 days (Mon..Sun).

    Each day's value is the average risk_score of all scans stored for that
    calendar day. Days with no scans are represented as null so the chart can
    distinguish "no data" from "risk score 0".
    """
    labels: List[str]
    average_risk_scores: List[Optional[float]]
    total_scans: int
