import os
import base64
import logging
from typing import Optional, Dict, Any, List
import httpx
from ..schemas.scan import ThreatIntelResult

logger = logging.getLogger(__name__)


class ThreatIntelligenceService:
    """
    Threat Intelligence integration service.
    Implements Google's Web Risk Lookup API as primary provider.
    Supports Google Safe Browsing and VirusTotal v3 as secondary integrations.
    Never fabricates responses or claims live lookups occurred when keys are missing.
    """

    def __init__(self):
        self.google_web_risk_api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
        self.google_sb_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.google_web_risk_api_key or self.google_sb_api_key or self.virustotal_api_key)

    @property
    def configured_providers(self) -> List[str]:
        providers = []
        if self.google_web_risk_api_key:
            providers.append("Google Web Risk Lookup API")
        if self.google_sb_api_key:
            providers.append("Google Safe Browsing v4")
        if self.virustotal_api_key:
            providers.append("VirusTotal v3")
        return providers

    async def check_url(self, url: str) -> ThreatIntelResult:
        """
        Check URL against configured threat intelligence providers.
        Does NOT execute or open the URL. Only queries reputation lookup endpoints.
        """
        # 1. Primary: Google Web Risk Lookup API
        if self.google_web_risk_api_key:
            return await self._check_google_web_risk(url)

        # 2. Fallback: Google Safe Browsing v4
        if self.google_sb_api_key:
            return await self._check_google_safe_browsing(url)

        # 3. Fallback: VirusTotal v3
        if self.virustotal_api_key:
            return await self._check_virustotal(url)

        # Unconfigured state
        return ThreatIntelResult(
            provider="Google Web Risk Lookup API",
            configured=False,
            checked=False,
            status="not_configured",
            threat_types=[],
            summary="Live threat intelligence verification unavailable. GOOGLE_WEB_RISK_API_KEY is not configured in backend environment."
        )

    async def _check_google_web_risk(self, url: str) -> ThreatIntelResult:
        """
        Queries Google Web Risk Lookup API (v1 uris:search).
        Official documentation: https://docs.cloud.google.com/web-risk/docs/lookup-api
        """
        endpoint = "https://webrisk.googleapis.com/v1/uris:search"
        params = [
            ("key", self.google_web_risk_api_key),
            ("uri", url),
            ("threatTypes", "MALWARE"),
            ("threatTypes", "SOCIAL_ENGINEERING"),
            ("threatTypes", "UNWANTED_SOFTWARE"),
            ("threatTypes", "SOCIAL_ENGINEERING_EXTENDED_COVERAGE"),
        ]

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                response = await client.get(endpoint, params=params)

                if response.status_code == 200:
                    data = response.json()
                    # Google Web Risk returns an empty object {} if no threats match
                    threat_data = data.get("threat")
                    if threat_data and threat_data.get("threatTypes"):
                        threat_types = list(threat_data.get("threatTypes", []))
                        return ThreatIntelResult(
                            provider="Google Web Risk Lookup API",
                            configured=True,
                            checked=True,
                            status="confirmed_threat",
                            threat_types=threat_types,
                            summary=f"Confirmed threat match detected by Google Web Risk: {', '.join(threat_types)}."
                        )
                    else:
                        return ThreatIntelResult(
                            provider="Google Web Risk Lookup API",
                            configured=True,
                            checked=True,
                            status="no_threat_found",
                            threat_types=[],
                            summary="Live verification complete. No matching threat found in Google Web Risk database."
                        )
                else:
                    logger.warning(f"Google Web Risk returned HTTP status {response.status_code}")
                    return ThreatIntelResult(
                        provider="Google Web Risk Lookup API",
                        configured=True,
                        checked=False,
                        status="unavailable",
                        threat_types=[],
                        summary=f"Google Web Risk service returned HTTP {response.status_code}. Live verification unavailable."
                    )
        except httpx.TimeoutException:
            logger.warning("Google Web Risk API request timed out.")
            return ThreatIntelResult(
                provider="Google Web Risk Lookup API",
                configured=True,
                checked=False,
                status="unavailable",
                threat_types=[],
                summary="Google Web Risk API request timed out. Live verification unavailable."
            )
        except Exception as e:
            logger.error(f"Error querying Google Web Risk API: {e}")
            return ThreatIntelResult(
                provider="Google Web Risk Lookup API",
                configured=True,
                checked=False,
                status="unavailable",
                threat_types=[],
                summary=f"Google Web Risk connection error ({type(e).__name__}). Live verification unavailable."
            )

    async def _check_google_safe_browsing(self, url: str) -> ThreatIntelResult:
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_sb_api_key}"
            payload = {
                "client": {
                    "clientId": "TrustLens-AI",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }

            async with httpx.AsyncClient(timeout=6.0) as client:
                response = await client.post(endpoint, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    matches = data.get("matches", [])
                    if matches:
                        threat_types = list({m.get("threatType") for m in matches if m.get("threatType")})
                        return ThreatIntelResult(
                            provider="Google Safe Browsing v4",
                            configured=True,
                            checked=True,
                            status="confirmed_threat",
                            threat_types=threat_types,
                            summary=f"Confirmed threat match detected by Google Safe Browsing: {', '.join(threat_types)}"
                        )
                    else:
                        return ThreatIntelResult(
                            provider="Google Safe Browsing v4",
                            configured=True,
                            checked=True,
                            status="no_threat_found",
                            threat_types=[],
                            summary="Live verification complete. No threats detected by Google Safe Browsing."
                        )
                else:
                    return ThreatIntelResult(
                        provider="Google Safe Browsing v4",
                        configured=True,
                        checked=False,
                        status="unavailable",
                        threat_types=[],
                        summary=f"Google Safe Browsing returned status {response.status_code}."
                    )
        except Exception as e:
            logger.error(f"Error querying Google Safe Browsing: {e}")
            return ThreatIntelResult(
                provider="Google Safe Browsing v4",
                configured=True,
                checked=False,
                status="unavailable",
                threat_types=[],
                summary=f"Google Safe Browsing check failed: {str(e)[:80]}."
            )

    async def _check_virustotal(self, url: str) -> ThreatIntelResult:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {
                "x-apikey": self.virustotal_api_key,
                "Accept": "application/json"
            }

            async with httpx.AsyncClient(timeout=6.0) as client:
                response = await client.get(endpoint, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0)

                    if malicious > 0:
                        return ThreatIntelResult(
                            provider="VirusTotal v3",
                            configured=True,
                            checked=True,
                            status="confirmed_threat",
                            threat_types=["MALICIOUS"],
                            summary=f"Flagged as malicious by {malicious}/{total} security engines on VirusTotal."
                        )
                    elif suspicious > 0:
                        return ThreatIntelResult(
                            provider="VirusTotal v3",
                            configured=True,
                            checked=True,
                            status="suspicious_threat",
                            threat_types=["SUSPICIOUS"],
                            summary=f"Flagged as suspicious by {suspicious}/{total} security engines on VirusTotal."
                        )
                    else:
                        return ThreatIntelResult(
                            provider="VirusTotal v3",
                            configured=True,
                            checked=True,
                            status="no_threat_found",
                            threat_types=[],
                            summary="Live verification complete. No vendor flags on VirusTotal."
                        )
                else:
                    return ThreatIntelResult(
                        provider="VirusTotal v3",
                        configured=True,
                        checked=False,
                        status="unavailable",
                        threat_types=[],
                        summary=f"VirusTotal lookup returned HTTP {response.status_code}."
                    )
        except Exception as e:
            logger.error(f"Error querying VirusTotal: {e}")
            return ThreatIntelResult(
                provider="VirusTotal v3",
                configured=True,
                checked=False,
                status="unavailable",
                threat_types=[],
                summary=f"VirusTotal check failed: {str(e)[:80]}."
            )


# Singleton instance
threat_intel_service = ThreatIntelligenceService()
