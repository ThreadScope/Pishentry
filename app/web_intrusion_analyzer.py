"""
app/web_intrusion_analyzer.py
=============================
Web Server Access Log Intrusion Detection & Threat Hunting Engine.

Implements deep forensic log inspection based on OWASP Top 10 attack signatures,
MITRE ATT&CK matrix mappings, and statistical frequency anomaly detection.
Parses Apache Combined Log Format and Nginx access logs to detect:
- SQL Injection (T1190)
- Local File Inclusion & Path Traversal (T1190)
- Cross-Site Scripting (XSS)
- Web Application Vulnerability Scanners (T1595.002)
- Credential Brute-Forcing & Password Spraying (T1110)
- Webshell Upload & Remote Command Execution (T1505.003, T1059.007)
"""

import re
import urllib.parse
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d+) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# OWASP & MITRE Attack Signature Rules
SQLI_PATTERNS = [
    (r"(?i)(union\s+(all\s+)?select)", "UNION SELECT injection", "critical", "T1190"),
    (r"(?i)(or\s+1\s*=\s*1|or\s+'1'\s*=\s*'1')", "OR 1=1 tautology injection", "critical", "T1190"),
    (r"(?i)('\s*or\s*')", "String-based OR injection", "high", "T1190"),
    (r"(?i)(;\s*drop\s+table)", "DROP TABLE destructive injection", "critical", "T1190"),
    (r"(?i)(sleep\s*\(\d+\)|benchmark\s*\(\d+)", "Time-based blind SQLi", "high", "T1190"),
    (r"(?i)(0x[0-9a-f]{8,})", "Hex-encoded payload injection", "medium", "T1190"),
    (r"(?i)(concat\s*\(|group_concat|load_file\s*\(|into\s+outfile)", "Data extraction SQL function", "high", "T1190"),
    (r"(?i)(information_schema)", "Database schema enumeration", "high", "T1595.002"),
]

LFI_PATTERNS = [
    (r"(\.\./){2,}|(\.\.\\){2,}", "Directory traversal (../)", "high", "T1190"),
    (r"(?i)(/etc/passwd|/etc/shadow|/etc/hosts)", "Sensitive Linux system file access", "critical", "T1190"),
    (r"(?i)(/proc/self|/proc/version)", "Proc filesystem inspection", "high", "T1190"),
    (r"(?i)(php://filter|php://input|data://|zip://)", "PHP stream wrapper inclusion", "critical", "T1190"),
    (r"(?i)(c:\\windows|c:/windows|win\.ini|boot\.ini)", "Windows system path traversal", "high", "T1190"),
    (r"(%00|%2500)", "Null byte injection bypass", "high", "T1190"),
]

XSS_PATTERNS = [
    (r"(?i)(<script[^>]*>|%3Cscript)", "Script tag injection", "high", "T1059.007"),
    (r"(?i)(javascript\s*:|vbscript\s*:)", "Script pseudo-protocol URI", "high", "T1059.007"),
    (r"(?i)(onerror\s*=|onload\s*=|onmouseover\s*=|onclick\s*=)", "DOM event handler injection", "medium", "T1059.007"),
    (r"(?i)(document\.cookie|window\.location|eval\s*\()", "DOM hijacking / Cookie theft payload", "high", "T1059.007"),
]

SCANNER_UA_PATTERNS = [
    (r"(?i)nikto", "Nikto Web Vulnerability Scanner", "medium", "T1595.002"),
    (r"(?i)sqlmap", "sqlmap Automated SQL Injection Tool", "high", "T1595.002"),
    (r"(?i)dirbuster", "DirBuster Directory Enumerator", "medium", "T1595.002"),
    (r"(?i)gobuster", "Gobuster URI/DNS Fuzzer", "medium", "T1595.002"),
    (r"(?i)wfuzz", "Wfuzz Web Application Fuzzer", "medium", "T1595.002"),
    (r"(?i)nmap", "Nmap Scripting Engine Probe", "low", "T1595.002"),
    (r"(?i)masscan", "Masscan Port/Service Scanner", "low", "T1595.002"),
    (r"(?i)zgrab", "ZGrab Banner Scanner", "low", "T1595.002"),
    (r"(?i)(python-requests|python-urllib|go-http-client|curl/\d)", "Scripted HTTP automation client", "low", "T1595.002"),
]

COMMAND_INJECTION_PATTERNS = [
    (r"(?i)(cmd\.exe|/bin/sh|/bin/bash|/bin/zsh)", "OS Shell execution attempt", "critical", "T1059.007"),
    (r"(?i)(powershell(\.exe)?\s+(-enc|-e|iex|invoke-expression))", "Encoded PowerShell execution", "critical", "T1059.007"),
    (r"(?i)(wget\s+http|curl\s+http|nc\s+-e|bash\s+-i)", "Remote binary downloader / Reverse shell", "critical", "T1059.007"),
    (r"(?i)(base64_decode|gzinflate|passthru|shell_exec|system\s*\()", "Webshell payload function", "critical", "T1505.003"),
]


def parse_log_entry(line: str) -> Optional[Dict[str, Any]]:
    """Parses a single Combined Log Format line into structured fields with robust URL unquoting."""
    if not line or not line.strip():
        return None
    match = COMBINED_LOG_PATTERN.match(line.strip())
    if not match:
        return None
    d = match.groupdict()
    d["size"] = int(d["size"]) if d["size"] != "-" else 0
    d["status"] = int(d["status"])

    req = d.pop("request", "").strip()
    if req:
        req_parts = req.split()
        if len(req_parts) >= 3 and req_parts[-1].startswith("HTTP/"):
            d["method"] = req_parts[0]
            d["proto"] = req_parts[-1]
            d["uri"] = " ".join(req_parts[1:-1])
        elif len(req_parts) >= 2:
            d["method"] = req_parts[0]
            d["proto"] = "HTTP/1.1"
            d["uri"] = " ".join(req_parts[1:])
        else:
            d["method"] = "GET"
            d["proto"] = "HTTP/1.1"
            d["uri"] = req
    else:
        d["method"] = "GET"
        d["proto"] = "HTTP/1.1"
        d["uri"] = "/"

    # Decoded URI for comprehensive signature matching
    d["decoded_uri"] = urllib.parse.unquote_plus(d["uri"])
    return d


class WebServerIntrusionAnalyzer:
    """
    Parses web server access logs, correlates attack vectors, detects brute force,
    and produces actionable incident response and firewall blocklists.
    """

    def __init__(self, log_content: str):
        self.raw_log = log_content
        self.entries: List[Dict[str, Any]] = []
        self._parse_all()

    def _parse_all(self):
        lines = self.raw_log.splitlines()
        for line in lines:
            entry = parse_log_entry(line)
            if entry:
                self.entries.append(entry)

    def detect_attacks(self) -> List[Dict[str, Any]]:
        """Inspects all parsed log entries for attack signatures across URI, Headers, and UAs."""
        findings = []
        for entry in self.entries:
            uri = entry["uri"]
            decoded_uri = entry.get("decoded_uri", uri)
            target_uri_str = f"{uri} {decoded_uri}"
            ua = entry["ua"]
            entry_findings = []

            # 1. SQL Injection
            for pattern, desc, sev, mitre in SQLI_PATTERNS:
                if re.search(pattern, target_uri_str):
                    entry_findings.append({
                        "category": "SQL Injection",
                        "description": desc,
                        "severity": sev,
                        "mitre_technique": mitre
                    })

            # 2. Local File Inclusion & Traversal
            for pattern, desc, sev, mitre in LFI_PATTERNS:
                if re.search(pattern, target_uri_str):
                    entry_findings.append({
                        "category": "LFI / Path Traversal",
                        "description": desc,
                        "severity": sev,
                        "mitre_technique": mitre
                    })

            # 3. Cross-Site Scripting
            for pattern, desc, sev, mitre in XSS_PATTERNS:
                if re.search(pattern, target_uri_str):
                    entry_findings.append({
                        "category": "Cross-Site Scripting",
                        "description": desc,
                        "severity": sev,
                        "mitre_technique": mitre
                    })

            # 4. Scanner Signatures
            for pattern, desc, sev, mitre in SCANNER_UA_PATTERNS:
                if re.search(pattern, ua):
                    entry_findings.append({
                        "category": "Automated Scanner",
                        "description": desc,
                        "severity": sev,
                        "mitre_technique": mitre
                    })

            # 5. Command Injection & Webshells
            for pattern, desc, sev, mitre in COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, target_uri_str) or re.search(pattern, ua):
                    entry_findings.append({
                        "category": "Command Injection / Webshell",
                        "description": desc,
                        "severity": sev,
                        "mitre_technique": mitre
                    })

            if entry_findings:
                findings.append({
                    "ip": entry["ip"],
                    "timestamp": entry["time"],
                    "method": entry["method"],
                    "uri": entry["uri"][:250],
                    "status": entry["status"],
                    "user_agent": entry["ua"][:150],
                    "size": entry["size"],
                    "attacks": entry_findings
                })

        return findings

    def detect_brute_force(self, threshold: int = 15) -> List[Dict[str, Any]]:
        """Detects brute force authentication attacks against login/admin endpoints."""
        endpoint_patterns = ["/login", "/wp-login", "/admin", "/signin", "/auth", "/session"]
        ip_post_counts = defaultdict(int)
        ip_endpoints = defaultdict(set)

        for entry in self.entries:
            if entry["method"] == "POST":
                uri_lower = entry["uri"].lower()
                if any(ep in uri_lower for ep in endpoint_patterns):
                    ip_post_counts[entry["ip"]] += 1
                    ip_endpoints[entry["ip"]].add(entry["uri"][:80])

        brute_force = []
        for ip, count in ip_post_counts.items():
            if count >= threshold:
                brute_force.append({
                    "ip": ip,
                    "post_count": count,
                    "target_endpoints": list(ip_endpoints[ip]),
                    "severity": "critical" if count > 50 else "high",
                    "mitre_technique": "T1110",
                    "description": f"High-velocity login brute force: {count} POST requests"
                })
        return brute_force

    def generate_report(self) -> Dict[str, Any]:
        """Compiles a complete structured threat report with SOC statistics and firewall block rules."""
        attack_findings = self.detect_attacks()
        brute_force_findings = self.detect_brute_force()

        # Aggregations
        unique_ips = len(set(e["ip"] for e in self.entries))
        ip_attack_counts = defaultdict(int)
        category_counts = defaultdict(int)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for finding in attack_findings:
            ip = finding["ip"]
            ip_attack_counts[ip] += len(finding["attacks"])
            for att in finding["attacks"]:
                category_counts[att["category"]] += 1
                sev = att.get("severity", "medium").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

        for bf in brute_force_findings:
            ip_attack_counts[bf["ip"]] += bf["post_count"]
            category_counts["Brute Force (T1110)"] += 1
            severity_counts["high"] += 1

        top_attacker_ips = sorted(ip_attack_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Generate IPTables and Nginx Deny Rules
        malicious_ips = [ip for ip, _ in top_attacker_ips if ip_attack_counts[ip] >= 3]
        iptables_rules = [f"iptables -A INPUT -s {ip} -j DROP" for ip in malicious_ips]
        nginx_deny_rules = [f"deny {ip};" for ip in malicious_ips]

        return {
            "total_requests_parsed": len(self.entries),
            "unique_ip_addresses": unique_ips,
            "total_suspicious_events": len(attack_findings) + len(brute_force_findings),
            "severity_breakdown": severity_counts,
            "category_breakdown": dict(category_counts),
            "top_attacker_ips": [{"ip": ip, "threat_events": count} for ip, count in top_attacker_ips],
            "brute_force_detections": brute_force_findings,
            "detailed_findings": attack_findings[:50],  # Return top 50 detailed findings
            "recommended_blocklist_ips": malicious_ips,
            "soc_remediation_commands": {
                "iptables": iptables_rules,
                "nginx_deny": nginx_deny_rules
            }
        }


def analyze_web_access_logs(log_content: Optional[str] = None) -> Dict[str, Any]:
    """Public helper function to analyze web access logs."""
    analyzer = WebServerIntrusionAnalyzer(log_content or "")
    return analyzer.generate_report()
