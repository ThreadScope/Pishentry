"""
app/takedown_generator.py
==========================
Autonomous Phishing Takedown & Cryptographic Evidence Package Generator.

Features:
- Generates standardized RFC-compliant abuse notification emails for domain registrars, DNS providers, and web hosts
- Builds cryptographic SHA-256 evidence digests including scan timestamps, IP addresses, form exfiltration targets, and MITRE ATT&CK techniques
- Produces automated SOC abuse reports for 1-click takedown dispatch
"""

import time
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import tldextract


@dataclass
class TakedownPackageLegacy:
    target_url: str
    target_domain: str
    registrar_abuse_email: str
    hosting_abuse_email: str
    subject_line: str
    body_text: str
    rfc2142_notice: str
    evidence_summary: Dict[str, Any]
    recommended_actions: List[str]
    evidence_digest_sha256: str


@dataclass
class TakedownPackage:
    report_id: str
    target_url: str
    impersonated_brand: str
    risk_score: float
    detection_timestamp: str
    registrar_abuse_email: str
    hosting_provider_abuse_email: str
    mitre_attack_techniques: List[Dict[str, str]]
    evidence_digest_sha256: str
    abuse_email_subject: str
    abuse_email_body: str
    recommended_actions: List[str]


def resolve_mock_abuse_contacts(domain: str) -> Dict[str, str]:
    """Resolves registrar and hosting abuse contact emails for a given domain."""
    ext = tldextract.extract(domain)
    tld = ext.suffix.lower()
    
    if tld in ["xyz", "top", "buzz", "site", "online"]:
        reg_email = "abuse@namecheap.com, abuse@nic.xyz"
    elif tld in ["tk", "ml", "ga", "cf", "gq"]:
        reg_email = "abuse@freenom.com"
    else:
        reg_email = "abuse@registrar-servers.com"

    return {
        "registrar_abuse_email": reg_email,
        "hosting_abuse_email": "abuse-team@hosting-provider.net"
    }


def generate_abuse_takedown_package(scan_data: Any) -> TakedownPackageLegacy:
    """
    Generates legacy TakedownPackage format for dictionary or ScanResult input.
    """
    if hasattr(scan_data, "model_dump"):
        data = scan_data.model_dump()
    elif isinstance(scan_data, dict):
        data = scan_data
    else:
        data = getattr(scan_data, "__dict__", {})

    url = data.get("url", "")
    ext = tldextract.extract(url)
    target_domain = ext.top_domain_under_public_suffix or url.replace("https://", "").replace("http://", "").split("/")[0]
    
    matched_brand = data.get("matched_brand") or "Protected Entity"
    phishpedia = data.get("phishpedia_consistency") or {}
    brand_name = phishpedia.get("brand_display_name") or matched_brand.capitalize()
    canonical_domains = phishpedia.get("canonical_domains") or [f"{matched_brand.lower()}.com"]
    canonical_str = ", ".join(canonical_domains)

    tls = data.get("tls_telemetry") or {}
    resolved_ip = tls.get("resolved_ip", "Pending DNS Resolution")

    contacts = resolve_mock_abuse_contacts(target_domain)
    
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    raw_evidence = f"{url}|{target_domain}|{resolved_ip}|{timestamp}"
    evidence_hash = hashlib.sha256(raw_evidence.encode("utf-8")).hexdigest()

    subject_line = f"[URGENT ABUSE TAKEDOWN] Malicious Phishing Attack Impersonating {brand_name} on {target_domain}"

    body_text = f"""Dear Abuse Team,

CloneCatcher AI has detected active credential phishing hosted on your network infrastructure.

Incident Telemetry:
- Target Domain: {target_domain}
- Full URL: {url}
- Host IP: {resolved_ip}
- Impersonated Brand: {brand_name} (Official Domain: {canonical_str})
- Detection Timestamp: {timestamp}
- Cryptographic Checksum: {evidence_hash}

Pursuant to your Acceptable Use Policy, please terminate hosting and suspend domain resolution immediately to prevent victim credential theft.

Sincerely,
CloneCatcher AI Cyber Defense Team
"""

    rfc2142 = f"abuse@{target_domain}, security@{target_domain}, postmaster@{target_domain}"
    evidence_summary = {
        "url": url,
        "domain": target_domain,
        "resolved_ip": resolved_ip,
        "matched_brand": matched_brand,
        "sha256": evidence_hash
    }

    return TakedownPackageLegacy(
        target_url=url,
        target_domain=target_domain,
        registrar_abuse_email=contacts["registrar_abuse_email"],
        hosting_abuse_email=contacts["hosting_abuse_email"],
        subject_line=subject_line,
        body_text=body_text,
        rfc2142_notice=rfc2142,
        evidence_summary=evidence_summary,
        recommended_actions=[
            "Send takedown request to registrar abuse desk",
            "Submit URL to global threat intelligence feeds (Google Safe Browsing, PhishTank)",
            "Deploy DNS sinkhole policy across corporate gateway"
        ],
        evidence_digest_sha256=evidence_hash
    )


def generate_takedown_package(
    url: str,
    brand_id: str,
    risk_score: float = 0.95,
    s_lex: float = 0.0,
    s_dom: float = 0.0,
    s_vis: float = 0.0,
    ip_address: Optional[str] = None,
    form_action: Optional[str] = None
) -> Dict[str, Any]:
    """
    Assembles a complete cryptographic takedown evidence package and abuse report.
    """
    clean_brand = (brand_id or "Enterprise Brand").capitalize()
    timestamp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    raw_evidence = f"{url}|{brand_id}|{risk_score}|{s_lex}|{s_dom}|{s_vis}|{timestamp_str}"
    evidence_hash = hashlib.sha256(raw_evidence.encode("utf-8")).hexdigest()
    report_id = f"PS-TKD-{evidence_hash[:12].upper()}"

    ext = tldextract.extract(url)
    domain = ext.top_domain_under_public_suffix or url
    contacts = resolve_mock_abuse_contacts(domain)

    mitre_techniques = [
        {"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access"},
        {"id": "T1656", "name": "Impersonation", "tactic": "Defense Evasion"},
        {"id": "T1056.001", "name": "Input Capture: Keylogging / Credential Theft", "tactic": "Collection"}
    ]

    abuse_subject = f"[URGENT ABUSE REPORT] Phishing Website Impersonating {clean_brand} ({url})"
    
    abuse_body = f"""Dear Abuse Team,

This is an automated high-priority abuse notification from Pishentry Multi-Modal AI Threat Intelligence.

We have detected an active credential phishing attack hosted on your infrastructure that illicitly impersonates {clean_brand}.

=== ATTACK TELEMETRY & EVIDENCE ===
Report ID: {report_id}
Malicious URL: {url}
Targeted Brand: {clean_brand}
Composite AI Phishing Confidence: {risk_score * 100:.1f}%
- Lexical Risk (S_lex): {s_lex:.2f}
- DOM Structural Similarity (S_dom): {s_dom:.2f}
- Visual Perceptual Similarity (S_vis): {s_vis:.2f}
Timestamp (UTC): {timestamp_str}
Host IP: {ip_address or 'Pending DNS Resolution'}
Exfiltration Form Target: {form_action or 'Direct In-Line Capture'}
Cryptographic Evidence Digest (SHA-256): {evidence_hash}

=== MITRE ATT&CK MAPPINGS ===
- T1566.002: Phishing: Spearphishing Link
- T1656: Impersonation of {clean_brand}
- T1056.001: Credential Form Theft

=== REQUESTED ACTION ===
Pursuant to your Acceptable Use Policy and international anti-phishing guidelines, we urgently request that you:
1. Immediately suspend DNS resolution / hosting for this malicious resource.
2. Preserve server access logs for law enforcement forensic coordination.
3. Block subsequent lookalike registrations under this domain cluster.

Thank you for your prompt cooperation in protecting internet users from credential theft.

Sincerely,
Pishentry Cyber Threat Intelligence Unit
https://pishentry.security
"""

    package = TakedownPackage(
        report_id=report_id,
        target_url=url,
        impersonated_brand=clean_brand,
        risk_score=round(risk_score, 4),
        detection_timestamp=timestamp_str,
        registrar_abuse_email=contacts["registrar_abuse_email"],
        hosting_provider_abuse_email=contacts["hosting_abuse_email"],
        mitre_attack_techniques=mitre_techniques,
        evidence_digest_sha256=evidence_hash,
        abuse_email_subject=abuse_subject,
        abuse_email_body=abuse_body,
        recommended_actions=[
            "Submit abuse notification email to registrar and hosting provider",
            "Report malicious URL to Google Safe Browsing and Microsoft SmartScreen",
            "Deploy local firewall and DNS sinkhole rules to protect corporate endpoints",
            "Preserve cryptographic evidence package for incident response documentation"
        ]
    )
    return asdict(package)
