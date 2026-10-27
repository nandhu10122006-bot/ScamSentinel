from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


class RiskClassification(str, Enum):
    KNOWN_THREAT = "KNOWN THREAT DETECTED"
    SUSPICIOUS = "SUSPICIOUS"
    NO_KNOWN_THREAT = "NO KNOWN THREAT DETECTED"
    UNABLE_TO_VERIFY = "UNABLE TO VERIFY"


class IndicatorSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectedIndicator(BaseModel):
    id: str
    category: str
    indicator: str
    severity: IndicatorSeverity
    score_impact: int
    description: str


class ThreatIntelResult(BaseModel):
    provider: str
    configured: bool
    checked: bool
    status: str  # e.g., "confirmed_threat", "no_threat_found", "not_configured", "unavailable"
    threat_types: List[str] = Field(default_factory=list)
    summary: str


class UrlBreakdown(BaseModel):
    scheme: str
    domain: str
    subdomain: str
    tld: str
    port: Optional[int] = None
    path: str
    query_params_count: int = 0
    is_ip_address: bool = False
    has_punycode: bool = False
    entropy: float = 0.0


class UrlScanRequest(BaseModel):
    url: str = Field(..., description="The URL to scan for potential threats and phishing indicators", min_length=1)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("URL cannot be empty or whitespace.")
        if len(trimmed) > 4096:
            raise ValueError("URL exceeds maximum length of 4096 characters.")
        return trimmed


class QrScanRequest(BaseModel):
    qr_content: str = Field(..., description="The decoded content or destination string extracted from a QR code", min_length=1)

    @field_validator("qr_content")
    @classmethod
    def validate_qr_content(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("QR code content cannot be empty.")
        if len(trimmed) > 8192:
            raise ValueError("QR code content exceeds maximum length of 8192 characters.")
        return trimmed


class ScanResponse(BaseModel):
    target: str
    normalized_url: str
    hostname: str = ""
    is_url: bool
    classification: RiskClassification
    risk_score: int = Field(..., ge=0, le=100, description="Local heuristic risk score estimate from 0 to 100 (not a probability)")
    detected_indicators: List[DetectedIndicator]
    explanation: str
    scan_method: str
    threat_intelligence: ThreatIntelResult
    breakdown: Optional[UrlBreakdown] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    status: str
    version: str
    threat_intelligence_configured: bool
    configured_providers: List[str]
