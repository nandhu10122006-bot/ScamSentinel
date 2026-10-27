import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.scan import ThreatIntelResult

client = TestClient(app)


def test_health_endpoint():
    """Verify backend health endpoint structure and provider reporting."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "1.0.0"
    assert "threat_intelligence_configured" in data
    assert isinstance(data["configured_providers"], list)


def test_scan_normal_url():
    """A standard legitimate URL should return NO KNOWN THREAT DETECTED."""
    response = client.post("/api/scan/url", json={"url": "https://www.wikipedia.org"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "NO KNOWN THREAT DETECTED"
    assert data["risk_score"] <= 25
    assert data["is_url"] is True
    assert data["hostname"] == "www.wikipedia.org"
    assert "wikipedia.org" in data["normalized_url"]
    assert "does not guarantee" in data["explanation"].lower()


def test_scan_suspicious_phishing_url():
    """An intentionally suspicious URL with brand spoofing and risky TLD should return SUSPICIOUS."""
    response = client.post(
        "/api/scan/url",
        json={"url": "http://paypal.com.account-verify.suspicious-phish.top/login.php"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "SUSPICIOUS"
    assert data["risk_score"] >= 50
    indicator_ids = [ind["id"] for ind in data["detected_indicators"]]
    assert any("brand-spoof" in i for i in indicator_ids)
    assert any("high-risk-tld" in i for i in indicator_ids)
    assert any("unencrypted-http" in i for i in indicator_ids)


def test_scan_suspicious_ip_and_executable():
    """A direct IP host distributing an executable on a non-standard port."""
    response = client.post(
        "/api/scan/url",
        json={"url": "http://192.168.1.50:8888/system-update.exe"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "SUSPICIOUS"
    assert data["risk_score"] >= 65
    indicator_ids = [ind["id"] for ind in data["detected_indicators"]]
    assert "ip-address-host" in indicator_ids
    assert "dangerous-executable-extension" in indicator_ids
    assert "non-standard-port" in indicator_ids


def test_scan_suspicious_dangerous_scheme():
    """Dangerous URI scheme (javascript:) should trigger critical heuristic indicators."""
    response = client.post(
        "/api/scan/url",
        json={"url": "javascript:alert(document.cookie)"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "SUSPICIOUS"
    assert data["risk_score"] >= 70
    assert any(ind["id"] == "dangerous-scheme" for ind in data["detected_indicators"])


def test_scan_url_shortener():
    """URL shortener should be detected as an obfuscation indicator."""
    response = client.post(
        "/api/scan/url",
        json={"url": "https://bit.ly/secure-login-381"}
    )
    assert response.status_code == 200
    data = response.json()
    assert any(ind["id"] == "url-shortener" for ind in data["detected_indicators"])


def test_scan_qr_endpoint_with_url():
    """QR endpoint with a decoded URL should execute the shared URL analysis engine."""
    response = client.post(
        "/api/scan/qr",
        json={"qr_content": "https://suspicious-bank-login.xyz/verify"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_url"] is True
    assert data["classification"] in ["SUSPICIOUS", "NO KNOWN THREAT DETECTED"]
    assert "suspicious-bank-login.xyz" in data["normalized_url"]


def test_scan_qr_endpoint_with_plain_text():
    """QR endpoint with plain text should return UNABLE TO VERIFY with clear explanation."""
    response = client.post(
        "/api/scan/qr",
        json={"qr_content": "WiFi:S:OfficeNetwork;T:WPA;P:SecretPassword123;;"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_url"] is False
    assert data["classification"] == "UNABLE TO VERIFY"
    assert "cannot be applied to non-url payloads" in data["explanation"].lower()


def test_scan_invalid_empty_url():
    """Empty or whitespace URL must fail validation with HTTP 422."""
    response = client.post("/api/scan/url", json={"url": "   "})
    assert response.status_code == 422


def test_scan_missing_field():
    """Missing URL payload must fail validation with HTTP 422."""
    response = client.post("/api/scan/url", json={})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_threat_intelligence_confirmed_threat():
    """When threat intelligence confirms a match, classification must be KNOWN THREAT DETECTED."""
    mock_result = ThreatIntelResult(
        provider="Google Web Risk Lookup API",
        configured=True,
        checked=True,
        status="confirmed_threat",
        threat_types=["MALWARE"],
        summary="Confirmed threat match detected by Google Web Risk: MALWARE."
    )
    
    with patch("app.services.url_analyzer.threat_intel_service.check_url", new=AsyncMock(return_value=mock_result)):
        response = client.post(
            "/api/scan/url",
            json={"url": "http://testsafebrowsing.appspot.com/s/malware.html"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "KNOWN THREAT DETECTED"
        assert data["risk_score"] >= 95
        assert "Confirmed threat match detected by Google Web Risk" in data["explanation"]


@pytest.mark.asyncio
async def test_threat_intelligence_unavailable_fallback():
    """When threat intelligence is unavailable, report it honestly without claiming live verification."""
    mock_result = ThreatIntelResult(
        provider="Google Web Risk Lookup API",
        configured=True,
        checked=False,
        status="unavailable",
        threat_types=[],
        summary="Google Web Risk service returned HTTP 500. Live verification unavailable."
    )
    
    with patch("app.services.url_analyzer.threat_intel_service.check_url", new=AsyncMock(return_value=mock_result)):
        response = client.post(
            "/api/scan/url",
            json={"url": "https://www.example.com"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["classification"] == "NO KNOWN THREAT DETECTED"
        assert data["threat_intelligence"]["status"] == "unavailable"
        assert "Live verification unavailable" in data["threat_intelligence"]["summary"]
