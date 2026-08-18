"""
tests/test_web_intrusion_analyzer.py
====================================
Unit and integration tests for Web Server Intrusion Detection Engine
(MITRE ATT&CK T1190, T1110, T1595.002, T1505.003, T1059.007).
"""

import pytest
from app.web_intrusion_analyzer import (
    parse_log_entry, WebServerIntrusionAnalyzer, analyze_web_access_logs
)
from app.schemas import WebIntrusionRequest, WebIntrusionResponse


SAMPLE_LOG_MIXED = """
192.168.1.50 - - [18/Aug/2026:10:00:00 +0000] "GET /index.php HTTP/1.1" 200 4500 "-" "Mozilla/5.0"
192.168.1.100 - - [18/Aug/2026:10:01:00 +0000] "GET /search?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 1200 "-" "Mozilla/5.0"
10.0.0.15 - - [18/Aug/2026:10:02:00 +0000] "GET /view?page=../../../../etc/passwd HTTP/1.1" 200 950 "-" "sqlmap/1.7"
172.16.0.4 - - [18/Aug/2026:10:03:00 +0000] "GET /comment?msg=<script>alert(document.cookie)</script> HTTP/1.1" 200 800 "-" "Mozilla/5.0"
198.51.100.99 - - [18/Aug/2026:10:04:00 +0000] "GET /shell.php?cmd=cmd.exe%20/c%20whoami HTTP/1.1" 200 350 "-" "Nikto/2.1.6"
"""

SAMPLE_BRUTE_FORCE_LOG = "\n".join([
    f'10.20.30.40 - - [18/Aug/2026:10:10:{i:02d} +0000] "POST /api/auth/login HTTP/1.1" 401 128 "-" "python-requests/2.28.1"'
    for i in range(25)
])


class TestWebIntrusionAnalyzer:
    """Test suite for web access log forensic parser and intrusion detection."""

    def test_parse_valid_log_entry(self):
        line = '192.168.1.100 - - [18/Aug/2026:10:01:00 +0000] "GET /products?id=1 HTTP/1.1" 200 4532 "https://ref.com" "CustomUA/1.0"'
        entry = parse_log_entry(line)
        assert entry is not None
        assert entry["ip"] == "192.168.1.100"
        assert entry["method"] == "GET"
        assert entry["uri"] == "/products?id=1"
        assert entry["status"] == 200
        assert entry["size"] == 4532
        assert entry["ua"] == "CustomUA/1.0"

    def test_detect_sqli_attack(self):
        analyzer = WebServerIntrusionAnalyzer(SAMPLE_LOG_MIXED)
        findings = analyzer.detect_attacks()
        sqli_findings = [f for f in findings if any(a["category"] == "SQL Injection" for a in f["attacks"])]
        assert len(sqli_findings) >= 1
        assert sqli_findings[0]["ip"] == "192.168.1.100"
        assert any(a["mitre_technique"] == "T1190" for a in sqli_findings[0]["attacks"])

    def test_detect_lfi_attack(self):
        analyzer = WebServerIntrusionAnalyzer(SAMPLE_LOG_MIXED)
        findings = analyzer.detect_attacks()
        lfi_findings = [f for f in findings if any(a["category"] == "LFI / Path Traversal" for a in f["attacks"])]
        assert len(lfi_findings) >= 1
        assert lfi_findings[0]["ip"] == "10.0.0.15"

    def test_detect_xss_attack(self):
        analyzer = WebServerIntrusionAnalyzer(SAMPLE_LOG_MIXED)
        findings = analyzer.detect_attacks()
        xss_findings = [f for f in findings if any(a["category"] == "Cross-Site Scripting" for a in f["attacks"])]
        assert len(xss_findings) >= 1
        assert xss_findings[0]["ip"] == "172.16.0.4"

    def test_detect_scanner_and_webshell(self):
        analyzer = WebServerIntrusionAnalyzer(SAMPLE_LOG_MIXED)
        findings = analyzer.detect_attacks()
        webshell_findings = [f for f in findings if any(a["category"] == "Command Injection / Webshell" for a in f["attacks"])]
        assert len(webshell_findings) >= 1
        assert webshell_findings[0]["ip"] == "198.51.100.99"

    def test_detect_brute_force_logins(self):
        analyzer = WebServerIntrusionAnalyzer(SAMPLE_BRUTE_FORCE_LOG)
        bf = analyzer.detect_brute_force(threshold=15)
        assert len(bf) == 1
        assert bf[0]["ip"] == "10.20.30.40"
        assert bf[0]["post_count"] == 25
        assert bf[0]["mitre_technique"] == "T1110"

    def test_generate_complete_report(self):
        full_log = SAMPLE_LOG_MIXED + "\n" + SAMPLE_BRUTE_FORCE_LOG
        report = analyze_web_access_logs(full_log)
        assert report["total_requests_parsed"] > 20
        assert report["unique_ip_addresses"] >= 5
        assert report["total_suspicious_events"] >= 4
        assert len(report["soc_remediation_commands"]["iptables"]) >= 1
        assert len(report["soc_remediation_commands"]["nginx_deny"]) >= 1

    def test_schema_serialization(self):
        req = WebIntrusionRequest(log_content=SAMPLE_LOG_MIXED)
        report = analyze_web_access_logs(req.log_content)
        resp = WebIntrusionResponse(**report)
        assert resp.total_requests_parsed > 0
        assert "critical" in resp.severity_breakdown
