
import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Tuple, Optional, Dict, Any

import tldextract

from ..schemas.scan import (
    RiskClassification,
    IndicatorSeverity,
    DetectedIndicator,
    ThreatIntelResult,
    UrlBreakdown,
    ScanResponse
)
from .threat_intelligence import threat_intel_service

# High-risk TLDs commonly abused by automated spam/phishing campaigns
HIGH_RISK_TLDS = {
    "xyz", "top", "click", "buzz", "club", "work", "rest", "country", 
    "tk", "ml", "ga", "cf", "gq", "zip", "mov", "fit", "surf", "casa",
    "cam", "monster", "cfd", "sbs", "icu", "fun", "uno"
}

# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", 
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "rb.gy",
    "tiny.cc", "lnkd.in", "rebrand.ly", "v.gd"
}

# High-value brand names frequently spoofed in phishing
TARGET_BRANDS = {
    "paypal", "apple", "netflix", "google", "microsoft", "chase", 
    "wellsfargo", "bankofamerica", "amazon", "binance", "coinbase", 
    "metamask", "ledger", "steam", "discord", "facebook", "instagram", 
    "whatsapp", "telegram", "citibank", "usps", "fedex", "dhl", "ups"
}

# Suspicious keywords in subdomains or paths
PHISHING_KEYWORDS = {
    "verify", "verification", "secure", "security", "update-billing", 
    "billing", "account-update", "confirm-identity", "signin", "login", 
    "auth", "authentication", "wallet-connect", "claim", "airdrop", 
    "reward", "suspended", "reactivate", "restore-access", "banking",
    "passcode", "password-reset", "kyc-verify"
}

# Suspicious file extensions indicative of direct payload delivery
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".iso", ".apk", ".dmg", 
    ".jar", ".msi", ".ps1", ".dll", ".hta", ".wsf", ".cpl"
}

# Standard web ports
STANDARD_PORTS = {80, 443, 8080, 8443, 3000, 5173}


def calculate_entropy(text: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 2)


def is_ip_address(host: str) -> bool:
    """Check if host is a valid IPv4 or IPv6 address or decimal/hex representation."""
    if not host:
        return False
    clean_host = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # Check for decimal/hex obfuscated IP (e.g. 2130706433 or 0x7f000001)
    if re.fullmatch(r"^\d{8,11}$", clean_host):
        return True
    if re.fullmatch(r"^0x[0-9a-fA-F]{8}$", clean_host):
        return True
    return False


def is_homoglyph_or_punycode(domain: str) -> Tuple[bool, str]:
    """Detect punycode (xn--) or homoglyph characters mimicking Latin script."""
    if "xn--" in domain.lower():
        return True, "Domain uses Punycode (IDN) representation which can obscure the real destination."
    
    non_ascii = [char for char in domain if ord(char) > 127]
    if non_ascii:
        return True, f"Domain contains {len(non_ascii)} non-ASCII character(s) susceptible to homograph attack."

    return False, ""


class UrlAnalyzerService:
    """
    Unified URL and QR analysis service.
    Combines local heuristic telemetry with Google Web Risk threat intelligence.
    Enforces honest security classifications and avoids unrestricted server-side fetches.
    """

    def __init__(self):
        # Configure tldextract completely offline with built-in snapshot to avoid remote fetches
        self.extractor = tldextract.TLDExtract(suffix_list_urls=None)

    def normalize_target(self, raw_target: str) -> Tuple[str, str, bool]:
        """
        Normalizes target input safely.
        Returns (normalized_url, hostname, is_url).
        """
        trimmed = raw_target.strip()
        
        # Dangerous URI schemes
        dangerous_schemes = ("javascript:", "data:", "vbscript:", "file:")
        if any(trimmed.lower().startswith(s) for s in dangerous_schemes):
            return trimmed, "inline-script", True

        # Standard schemes
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", trimmed):
            parsed = urlparse(trimmed)
            host = (parsed.hostname or "").lower()
            return trimmed, host, True

        # Domain or path without scheme
        domain_pattern = r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$"
        if re.match(domain_pattern, trimmed):
            normalized = f"https://{trimmed}"
            parsed = urlparse(normalized)
            host = (parsed.hostname or "").lower()
            return normalized, host, True

        # IP address without scheme
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$"
        if re.match(ip_pattern, trimmed):
            normalized = f"http://{trimmed}"
            parsed = urlparse(normalized)
            host = (parsed.hostname or "").lower()
            return normalized, host, True

        # Non-URL plain text or unknown format
        return trimmed, "", False

    def _extract_indicators(self, url: str) -> Tuple[List[DetectedIndicator], UrlBreakdown, int]:
        """
        Executes local heuristic checks against the URL without opening or downloading it.
        Returns (indicators_list, breakdown, raw_risk_score).
        """
        indicators: List[DetectedIndicator] = []
        raw_score = 0

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        port = parsed.port

        host_no_port = netloc.split(":")[0].strip("[]")

        # TLD Extraction
        extracted = self.extractor(netloc)
        registered_domain = (
            extracted.top_domain_under_public_suffix 
            if hasattr(extracted, "top_domain_under_public_suffix") 
            else f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        ).lower()
        domain = extracted.domain.lower()
        subdomain = extracted.subdomain.lower()
        suffix = extracted.suffix.lower()

        entropy = calculate_entropy(domain)
        has_ip = is_ip_address(host_no_port)
        has_punycode, punycode_desc = is_homoglyph_or_punycode(netloc)

        breakdown = UrlBreakdown(
            scheme=scheme,
            domain=registered_domain if registered_domain else host_no_port,
            subdomain=subdomain,
            tld=suffix,
            port=port,
            path=path,
            query_params_count=len(parse_qs(query)),
            is_ip_address=has_ip,
            has_punycode=has_punycode,
            entropy=entropy
        )

        # 1. Dangerous Scheme Analysis
        if scheme in ["javascript", "data", "vbscript", "file"]:
            indicators.append(DetectedIndicator(
                id="dangerous-scheme",
                category="protocol",
                indicator=f"Dangerous URI Scheme ({scheme}:)",
                severity=IndicatorSeverity.CRITICAL,
                score_impact=75,
                description=f"The URI scheme '{scheme}:' allows direct script execution or payload injection."
            ))
            raw_score += 75
        elif scheme == "http":
            indicators.append(DetectedIndicator(
                id="unencrypted-http",
                category="protocol",
                indicator="Unencrypted HTTP Connection",
                severity=IndicatorSeverity.LOW,
                score_impact=15,
                description="The URL uses unencrypted HTTP. Data sent over this link is vulnerable to interception."
            ))
            raw_score += 15

        # 2. Direct IP Address in Host
        if has_ip:
            indicators.append(DetectedIndicator(
                id="ip-address-host",
                category="host",
                indicator="Direct IP Address Host",
                severity=IndicatorSeverity.HIGH,
                score_impact=40,
                description="Uses a numerical IP address instead of a domain name, commonly used to evade domain blocklists."
            ))
            raw_score += 40

        # 3. Punycode or Homoglyph Spoofing
        if has_punycode:
            indicators.append(DetectedIndicator(
                id="homoglyph-punycode",
                category="domain",
                indicator="Punycode / Homoglyph Encoding",
                severity=IndicatorSeverity.HIGH,
                score_impact=35,
                description=punycode_desc
            ))
            raw_score += 35

        # 4. High-risk TLD
        if suffix in HIGH_RISK_TLDS:
            indicators.append(DetectedIndicator(
                id="high-risk-tld",
                category="domain",
                indicator=f"High-Risk Top-Level Domain (.{suffix})",
                severity=IndicatorSeverity.MEDIUM,
                score_impact=25,
                description=f"The top-level domain '.{suffix}' is statistically correlated with elevated phishing and scam activity."
            ))
            raw_score += 25

        # 5. URL Shortener Service
        if registered_domain in SHORTENER_DOMAINS:
            indicators.append(DetectedIndicator(
                id="url-shortener",
                category="obfuscation",
                indicator=f"URL Shortener Detected ({registered_domain})",
                severity=IndicatorSeverity.MEDIUM,
                score_impact=20,
                description="URL shorteners obscure the ultimate destination, preventing immediate visual verification."
            ))
            raw_score += 20

        # 6. Embedded Credentials / '@' Symbol
        if "@" in netloc or "@" in url.split("?")[0]:
            indicators.append(DetectedIndicator(
                id="embedded-credentials-at",
                category="obfuscation",
                indicator="Embedded '@' Symbol in URL",
                severity=IndicatorSeverity.CRITICAL,
                score_impact=45,
                description="Contains '@' character before host. Browsers treat text before '@' as credentials, masking the real host."
            ))
            raw_score += 45

        # 7. Brand Impersonation in Subdomain or Path
        for brand in TARGET_BRANDS:
            if brand in subdomain or (brand in path.lower() and registered_domain != f"{brand}.com"):
                if brand not in registered_domain:
                    indicators.append(DetectedIndicator(
                        id=f"brand-spoof-{brand}",
                        category="reputation",
                        indicator=f"Brand Mention in Subdomain/Path ({brand.capitalize()})",
                        severity=IndicatorSeverity.CRITICAL,
                        score_impact=45,
                        description=f"Mentions '{brand.capitalize()}' in subdomain or path, but registered domain is '{registered_domain}'."
                    ))
                    raw_score += 45
                    break

        # 8. Phishing Keywords in Host/Path
        matched_keywords = []
        combined_path_query = (path + "?" + query).lower()
        for kw in PHISHING_KEYWORDS:
            if kw in subdomain or kw in combined_path_query:
                matched_keywords.append(kw)
        
        if matched_keywords:
            severity = IndicatorSeverity.HIGH if len(matched_keywords) >= 2 else IndicatorSeverity.MEDIUM
            impact = min(len(matched_keywords) * 15, 35)
            indicators.append(DetectedIndicator(
                id="phishing-keywords",
                category="path",
                indicator=f"Phishing Keywords Detected ({', '.join(matched_keywords[:3])})",
                severity=severity,
                score_impact=impact,
                description=f"Contains urgency or sensitive credential keywords: {', '.join(matched_keywords[:4])}."
            ))
            raw_score += impact

        # 9. Excessive Subdomains
        subdomain_parts = [part for part in subdomain.split(".") if part]
        if len(subdomain_parts) >= 3:
            indicators.append(DetectedIndicator(
                id="excessive-subdomains",
                category="domain",
                indicator=f"Excessive Subdomain Depth ({len(subdomain_parts)} levels)",
                severity=IndicatorSeverity.MEDIUM,
                score_impact=20,
                description="Deep subdomain hierarchy frequently used to craft deceptive phishing URLs."
            ))
            raw_score += 20

        # 10. High Entropy Hostname
        if entropy > 3.9 and len(domain) > 7:
            indicators.append(DetectedIndicator(
                id="high-entropy-domain",
                category="domain",
                indicator=f"High Shannon Entropy in Domain ({entropy})",
                severity=IndicatorSeverity.MEDIUM,
                score_impact=20,
                description="Domain name exhibits high randomness, characteristic of algorithmically generated domain (DGA) names."
            ))
            raw_score += 20

        # 11. Dangerous Executable File Extension
        lower_path = path.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if lower_path.endswith(ext) or f"{ext}?" in lower_path:
                indicators.append(DetectedIndicator(
                    id="dangerous-executable-extension",
                    category="content_type",
                    indicator=f"Executable File Download Detected ({ext})",
                    severity=IndicatorSeverity.CRITICAL,
                    score_impact=50,
                    description=f"Points directly to a downloadable executable or script package ({ext})."
                ))
                raw_score += 50
                break

        # 12. Non-Standard Port
        if port and port not in STANDARD_PORTS:
            indicators.append(DetectedIndicator(
                id="non-standard-port",
                category="protocol",
                indicator=f"Non-Standard Port ({port})",
                severity=IndicatorSeverity.MEDIUM,
                score_impact=20,
                description=f"Connects to non-standard port {port}, commonly observed in rogue servers or command-and-control panels."
            ))
            raw_score += 20

        # 13. URL Length Anomaly
        if len(url) > 120:
            indicators.append(DetectedIndicator(
                id="excessive-url-length",
                category="obfuscation",
                indicator=f"Excessive URL Length ({len(url)} chars)",
                severity=IndicatorSeverity.LOW,
                score_impact=10,
                description="Abnormally long URL, often used to push malicious domains out of view in mobile browsers."
            ))
            raw_score += 10

        # 14. Double Slash in Path
        if "//" in path:
            indicators.append(DetectedIndicator(
                id="double-slash-path",
                category="obfuscation",
                indicator="Double Slash in URL Path",
                severity=IndicatorSeverity.LOW,
                score_impact=10,
                description="Contains double slashes ('//') inside path component, potentially used in open redirect tricks."
            ))
            raw_score += 10

        # 15. Hyphen Stuffing
        if domain.count("-") >= 3:
            indicators.append(DetectedIndicator(
                id="hyphen-stuffing",
                category="domain",
                indicator=f"Hyphen Stuffing ({domain.count('-')} hyphens)",
                severity=IndicatorSeverity.MEDIUM,
                score_impact=15,
                description="Contains multiple hyphens in the domain name, a typical tactic to craft spoofed brand domains."
            ))
            raw_score += 15

        return indicators, breakdown, raw_score

    async def analyze(self, raw_input: str) -> ScanResponse:
        """
        Main analysis method handling URL and QR code string destinations.
        Applies honest security classifications:
          - KNOWN THREAT DETECTED: confirmed by external threat intelligence
          - SUSPICIOUS: local heuristic warning signs present
          - NO KNOWN THREAT DETECTED: checks found no known threats (does not guarantee safety)
          - UNABLE TO VERIFY: non-URL payloads or unparseable input
        """
        normalized_url, hostname, is_url = self.normalize_target(raw_input)

        if not is_url:
            # Handle plain text QR codes or non-URL strings safely
            threat_intel_result = ThreatIntelResult(
                provider="Google Web Risk Lookup API",
                configured=threat_intel_service.is_configured,
                checked=False,
                status="not_applicable",
                threat_types=[],
                summary="Threat intelligence lookup skipped because input is not a URL."
            )

            return ScanResponse(
                target=raw_input,
                normalized_url=normalized_url,
                hostname="",
                is_url=False,
                classification=RiskClassification.UNABLE_TO_VERIFY,
                risk_score=0,
                detected_indicators=[],
                explanation="Decoded content is plain text or an unsupported format, not a web URL. URL reputation checking cannot be applied to non-URL payloads.",
                scan_method="none",
                threat_intelligence=threat_intel_result,
                breakdown=None
            )

        # 1. Execute local heuristic checks
        indicators, breakdown, raw_score = self._extract_indicators(normalized_url)
        heuristic_score = min(max(raw_score, 0), 100)

        # 2. Query threat intelligence service
        threat_intel = await threat_intel_service.check_url(normalized_url)

        # Determine method string
        if threat_intel.checked:
            scan_method = "heuristics_and_threat_intel"
        else:
            scan_method = "heuristics_only"

        # 3. Determine honest security classification
        # Rule 1: Confirmed threat from trusted threat intelligence service
        if threat_intel.status == "confirmed_threat":
            classification = RiskClassification.KNOWN_THREAT
            final_risk_score = max(heuristic_score, 95)
            explanation = (
                f"Confirmed threat match detected by {threat_intel.provider}: "
                f"{', '.join(threat_intel.threat_types)}. "
                "Do not navigate to this destination or enter sensitive credentials."
            )

        # Rule 2: Warning signs identified by local heuristic checks
        elif heuristic_score > 25 or any(ind.severity in [IndicatorSeverity.HIGH, IndicatorSeverity.CRITICAL] for ind in indicators):
            classification = RiskClassification.SUSPICIOUS
            final_risk_score = heuristic_score
            explanation_parts = [
                f"Local checks identified {len(indicators)} warning sign(s) for {breakdown.domain} "
                f"(including {indicators[0].indicator}). A confirmed threat has not been established by external threat intelligence, "
                "but the URL exhibits suspicious characteristics."
            ]
            if not threat_intel.configured:
                explanation_parts.append("Live threat intelligence verification was unavailable (GOOGLE_WEB_RISK_API_KEY not configured).")
            elif threat_intel.checked:
                explanation_parts.append("Threat intelligence database lookup found no known matching threat.")
            explanation = " ".join(explanation_parts)

        # Rule 3: No known threats detected
        else:
            classification = RiskClassification.NO_KNOWN_THREAT
            final_risk_score = heuristic_score
            if threat_intel.checked and threat_intel.status == "no_threat_found":
                explanation = (
                    f"No known threat detected for {breakdown.domain}. "
                    "Live Google Web Risk verification and local heuristic checks found no known threats. "
                    "Note: This reflects the absence of known threats in checked sources and does not guarantee that the URL is safe."
                )
            else:
                explanation = (
                    f"No known threat detected by local heuristic checks for {breakdown.domain}. "
                    "Note: Live threat intelligence verification was unavailable (GOOGLE_WEB_RISK_API_KEY not configured). "
                    "This does not guarantee that the URL is safe."
                )

        # Final response
        return ScanResponse(
            target=raw_input,
            normalized_url=normalized_url,
            hostname=hostname or breakdown.domain,
            is_url=True,
            classification=classification,
            risk_score=final_risk_score,
            detected_indicators=indicators,
            explanation=explanation,
            scan_method=scan_method,
            threat_intelligence=threat_intel,
            breakdown=breakdown
        )


# Singleton instance
url_analyzer_service = UrlAnalyzerService()

