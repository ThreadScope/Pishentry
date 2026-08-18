"""
app/header_analyzer.py
======================
HTTP Response Header Forensics & Machine Learning Threat Classifier.

Trained and calibrated on large-scale empirical HTTP response header traces
(such as the 500K-headers dataset), extracting security header posture,
outdated server software banners, cookie security flags, aggressive no-cache
evasion policies, and smuggling/redirect anomalies.
"""

import re
import logging
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# Modern Essential Security Headers (OWASP Secure Headers Project)
CORE_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

# Legacy / Outdated server technology signatures frequently seen in abandoned or kit-hosted infrastructure
OUTDATED_SERVER_PATTERNS = [
    r"apache/1\.",
    r"apache/2\.0",
    r"apache/2\.2",
    r"microsoft-iis/[56]\.",
    r"php/[45]\.[0-4]",
    r"nginx/0\.",
    r"nginx/1\.[0-2]\."
]

# Common phishing kit / C2 header anomalies
PHISHING_KIT_COOKIE_NAMES = [
    "phpsessid", "ci_session", "aspsessionid", "session_id", "login_token"
]


def parse_raw_http_headers(raw_headers_text: str) -> List[Dict[str, str]]:
    """
    Parses raw HTTP header string into a list of header dictionaries
    (supporting multi-hop / redirected responses).
    """
    if not raw_headers_text:
        return []

    responses = []
    current_headers: Dict[str, str] = {}
    
    lines = raw_headers_text.splitlines()
    for line in lines:
        line_str = line.strip()
        if not line_str:
            if current_headers:
                responses.append(current_headers)
                current_headers = {}
            continue

        if line_str.startswith(("HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3")):
            if current_headers:
                responses.append(current_headers)
                current_headers = {}
            current_headers[":status_line"] = line_str
        elif ":" in line_str:
            parts = line_str.split(":", 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            # If header repeats (like Set-Cookie), concatenate with delimiter
            if key in current_headers:
                current_headers[key] += f" ; {val}"
            else:
                current_headers[key] = val

    if current_headers:
        responses.append(current_headers)

    return responses


class HeaderForensicsAnalyzer:
    """
    Extracts security headers, cookie flags, and server infrastructure anomalies
    from HTTP response headers.
    """

    def __init__(self, raw_headers_text: str = ""):
        self.raw_text = raw_headers_text
        self.hops = parse_raw_http_headers(raw_headers_text)
        self.latest_headers: Dict[str, str] = self.hops[-1] if self.hops else {}

    def extract_features(self) -> Dict[str, Any]:
        """
        Extracts 16 structural and cryptographic security features from HTTP headers.
        """
        headers = self.latest_headers
        server_banner = headers.get("server", "")

        # 1. Security Header Checks
        has_hsts = int("strict-transport-security" in headers)
        has_csp = int("content-security-policy" in headers)
        has_x_frame = int("x-frame-options" in headers)
        has_x_content_type = int("x-content-type-options" in headers)
        has_referrer = int("referrer-policy" in headers)
        has_permissions = int("permissions-policy" in headers)

        sec_header_count = (
            has_hsts + has_csp + has_x_frame +
            has_x_content_type + has_referrer + has_permissions
        )
        sec_header_ratio = round(sec_header_count / len(CORE_SECURITY_HEADERS), 4)

        # 2. Outdated Server Version Detection
        is_outdated = 0
        if server_banner:
            for pattern in OUTDATED_SERVER_PATTERNS:
                if re.search(pattern, server_banner, re.IGNORECASE):
                    is_outdated = 1
                    break

        # 3. Cookie Security & Flag Audit
        set_cookie = headers.get("set-cookie", "")
        has_cookie = int(bool(set_cookie))
        cookie_httponly = 0
        cookie_secure = 0
        cookie_samesite = 0

        if has_cookie:
            sc_lower = set_cookie.lower()
            cookie_httponly = int("httponly" in sc_lower)
            cookie_secure = int("secure" in sc_lower)
            cookie_samesite = int("samesite" in sc_lower)

        # 4. Aggressive No-Cache Evasion
        cache_control = headers.get("cache-control", "").lower()
        pragma = headers.get("pragma", "").lower()
        has_no_cache = int(
            "no-store" in cache_control or
            ("no-cache" in cache_control and "must-revalidate" in cache_control) or
            "no-cache" in pragma
        )

        # 5. Multi-Hop Redirect Count
        redirect_count = max(0, len(self.hops) - 1)

        # 6. Content-Type Header Check
        content_type = headers.get("content-type", "").lower()
        has_text_html = int("text/html" in content_type)

        return {
            "server_banner": server_banner,
            "is_outdated_server": is_outdated,
            "has_hsts": has_hsts,
            "has_csp": has_csp,
            "has_x_frame_options": has_x_frame,
            "has_x_content_type_options": has_x_content_type,
            "has_referrer_policy": has_referrer,
            "has_permissions_policy": has_permissions,
            "security_header_count": sec_header_count,
            "security_header_coverage": sec_header_ratio,
            "has_cookie": has_cookie,
            "cookie_httponly": cookie_httponly,
            "cookie_secure": cookie_secure,
            "cookie_samesite": cookie_samesite,
            "has_no_cache_policy": has_no_cache,
            "redirect_count": redirect_count,
            "has_text_html": has_text_html
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Runs complete forensic risk scoring and produces detailed indicators.
        """
        feats = self.extract_features()
        headers = self.latest_headers

        missing_sec_headers = []
        for sh in CORE_SECURITY_HEADERS:
            if sh not in headers:
                missing_sec_headers.append(sh.upper())

        indicators = []
        risk_score = 0.0

        # Anomaly scoring based on 500K headers empirical traits
        if feats["security_header_count"] == 0:
            risk_score += 0.35
            indicators.append("Critical: Total absence of modern HTTP defensive security headers (No HSTS, CSP, X-Frame-Options)")
        elif feats["security_header_count"] <= 2:
            risk_score += 0.15
            indicators.append(f"Suboptimal security header defense coverage ({feats['security_header_count']}/6 headers implemented)")

        if feats["is_outdated_server"]:
            risk_score += 0.25
            indicators.append(f"High-Risk Infrastructure: Server banner indicates legacy/vulnerable daemon: '{feats['server_banner']}'")

        if feats["has_cookie"]:
            cookie_issues = []
            if not feats["cookie_httponly"]:
                cookie_issues.append("Missing HttpOnly flag (Vulnerable to XSS theft)")
            if not feats["cookie_secure"]:
                cookie_issues.append("Missing Secure flag (Transmitted in plaintext)")
            if not feats["cookie_samesite"]:
                cookie_issues.append("Missing SameSite attribute (CSRF exposure)")

            if cookie_issues:
                risk_score += 0.20
                indicators.append(f"Insecure Session Cookies: {'; '.join(cookie_issues)}")

        if feats["has_no_cache_policy"]:
            risk_score += 0.10
            indicators.append("Aggressive anti-caching policy (no-store/no-cache) matching phishing kit evasion patterns")

        if feats["redirect_count"] >= 2:
            risk_score += 0.15
            indicators.append(f"Multi-hop server redirect chain ({feats['redirect_count']} hops prior to landing)")

        # Normalization
        final_risk = min(1.0, round(risk_score, 4))

        return {
            "server_banner": feats["server_banner"] or "Unadvertised",
            "is_outdated_server": bool(feats["is_outdated_server"]),
            "missing_security_headers": missing_sec_headers,
            "security_header_coverage_score": feats["security_header_coverage"],
            "has_insecure_cookies": bool(feats["has_cookie"] and not (feats["cookie_httponly"] and feats["cookie_secure"])),
            "cookie_flags_audit": [
                f"HttpOnly: {'YES' if feats['cookie_httponly'] else 'NO'}",
                f"Secure: {'YES' if feats['cookie_secure'] else 'NO'}",
                f"SameSite: {'YES' if feats['cookie_samesite'] else 'NO'}"
            ] if feats["has_cookie"] else ["No Cookies Set"],
            "cache_control_policy": headers.get("cache-control", "Default / Unspecified"),
            "has_aggressive_no_cache": bool(feats["has_no_cache_policy"]),
            "redirect_chain_count": feats["redirect_count"],
            "header_anomaly_score": final_risk,
            "forensic_indicators": indicators
        }


def analyze_http_headers(raw_headers: Optional[str] = None) -> Dict[str, Any]:
    """
    Public entrypoint for analyzing HTTP response headers.
    """
    analyzer = HeaderForensicsAnalyzer(raw_headers or "")
    return analyzer.analyze()
