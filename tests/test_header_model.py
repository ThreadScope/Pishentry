"""
tests/test_header_model.py
==========================
Comprehensive test suite for HTTP Header Forensics & Machine Learning Model
calibrated on empirical header dataset traces (500K-headers dataset).
"""

import pytest
from app.header_analyzer import (
    HeaderForensicsAnalyzer, parse_raw_http_headers, analyze_http_headers
)
from app.schemas import HeaderForensicsTelemetry, ScanResult


class TestHeaderForensics:
    """Tests for HTTP response header parsing and threat classification."""

    SAMPLE_PHISHING_HEADER = """
HTTP/1.1 301 Moved Permanently
Date: Tue, 15 Apr 2014 01:15:06 GMT
Server: Apache/1.3.41 (Unix) mod_ssl/2.8.31 OpenSSL/0.9.8e-fips-rhel5 PHP/4.4.9
Location: /WpjkZ/login.php
Content-Length: 0

HTTP/1.1 200 OK
Date: Tue, 15 Apr 2014 01:15:07 GMT
Server: Apache/1.3.41 (Unix) mod_ssl/2.8.31 OpenSSL/0.9.8e-fips-rhel5 PHP/4.4.9
X-Powered-By: PHP/4.4.9
Set-Cookie: PHPSESSID=291r1qhi683037stim3upp4fc7; path=/
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=iso-8859-1
    """

    SAMPLE_SECURE_HEADER = """
HTTP/1.1 200 OK
Date: Mon, 18 Aug 2026 12:00:00 GMT
Server: cloudflare
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=()
Set-Cookie: __Host-auth=secure_token_123; Secure; HttpOnly; SameSite=Strict; Path=/
Cache-Control: public, max-age=3600
    """

    def test_parse_multi_hop_headers(self):
        hops = parse_raw_http_headers(self.SAMPLE_PHISHING_HEADER)
        assert len(hops) == 2
        assert hops[0][":status_line"].startswith("HTTP/1.1 301")
        assert hops[1][":status_line"].startswith("HTTP/1.1 200")

    def test_outdated_server_detection(self):
        analyzer = HeaderForensicsAnalyzer(self.SAMPLE_PHISHING_HEADER)
        feats = analyzer.extract_features()
        assert feats["is_outdated_server"] == 1
        assert "Apache/1.3" in feats["server_banner"]

    def test_missing_security_headers(self):
        analyzer = HeaderForensicsAnalyzer(self.SAMPLE_PHISHING_HEADER)
        result = analyzer.analyze()
        assert "STRICT-TRANSPORT-SECURITY" in result["missing_security_headers"]
        assert "CONTENT-SECURITY-POLICY" in result["missing_security_headers"]
        assert result["security_header_coverage_score"] == 0.0

    def test_insecure_cookies_detection(self):
        analyzer = HeaderForensicsAnalyzer(self.SAMPLE_PHISHING_HEADER)
        result = analyzer.analyze()
        assert result["has_insecure_cookies"] is True
        assert any("HttpOnly" in ind for ind in result["forensic_indicators"])

    def test_aggressive_no_cache_detection(self):
        analyzer = HeaderForensicsAnalyzer(self.SAMPLE_PHISHING_HEADER)
        result = analyzer.analyze()
        assert result["has_aggressive_no_cache"] is True

    def test_secure_headers_low_risk(self):
        analyzer = HeaderForensicsAnalyzer(self.SAMPLE_SECURE_HEADER)
        result = analyzer.analyze()
        assert result["is_outdated_server"] is False
        assert result["security_header_coverage_score"] == 1.0
        assert result["has_insecure_cookies"] is False
        assert result["header_anomaly_score"] == 0.0

    def test_empty_headers_fallback(self):
        result = analyze_http_headers("")
        assert result["server_banner"] == "Unadvertised"
        assert result["header_anomaly_score"] >= 0.0

    def test_schema_telemetry_integration(self):
        t = HeaderForensicsTelemetry(
            server_banner="nginx/1.24",
            is_outdated_server=False,
            security_header_coverage_score=0.83,
            header_anomaly_score=0.15
        )
        assert t.server_banner == "nginx/1.24"
        assert t.security_header_coverage_score == 0.83

    def test_scan_result_with_header_telemetry(self):
        res = ScanResult(
            url="https://test.com",
            s_lex=0.2,
            s_phish=0.3,
            shap_contributions={"s_lex": 1.0, "s_dom": 0.0, "s_vis": 0.0},
            confidence="full",
            latency_ms=45.0,
            header_forensics=HeaderForensicsTelemetry(
                server_banner="Apache/2.4",
                security_header_coverage_score=0.5
            )
        )
        assert res.header_forensics is not None
        assert res.header_forensics.server_banner == "Apache/2.4"
