"""
app/threat_narrative.py
========================
Autonomous AI Cyber Threat Narrative & Executive Incident Briefing Generator.

Synthesizes multi-modal signals (XGBoost SHAP weights, TLS certificates,
AiTM reverse proxy traces, honeytoken exfil drops, and brand attribution)
into an executive-ready plain-English cyber threat intelligence briefing.
"""

from typing import Dict, Any, List
from pydantic import BaseModel, Field

class ThreatNarrativeReport(BaseModel):
    incident_title: str = Field(..., description="High-level incident title")
    severity_level: str = Field("CRITICAL", description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    threat_actor_tradecraft: str = Field(..., description="Summary of attacker techniques and mechanics")
    executive_summary: str = Field(..., description="Clear executive-level non-technical summary")
    forensic_indicators_of_compromise: List[str] = Field(default_factory=list, description="Extracted IOCs")
    recommended_soc_actions: List[str] = Field(default_factory=list, description="Prescriptive remediation checklist")

def generate_threat_narrative(scan_data: Dict[str, Any]) -> ThreatNarrativeReport:
    """
    Generates a structured executive threat briefing from deep scan telemetry.
    """
    url = scan_data.get("url", "")
    s_phish = scan_data.get("s_phish", 0.0)
    target_attr = scan_data.get("target_attribution") or {}
    entity_name = target_attr.get("identity_display_name") or (scan_data.get("matched_brand") or "Protected Enterprise").upper()
    archetype = target_attr.get("campaign_archetype", "Brand Impersonation & Credential Theft")
    
    aitm = scan_data.get("aitm_telemetry") or {}
    quishing = scan_data.get("quishing_telemetry") or {}
    honeytoken = scan_data.get("honeytoken_telemetry") or {}
    dom_f = scan_data.get("dom_forensics") or {}
    tls_data = scan_data.get("tls_telemetry") or {}

    import urllib.parse
    domain = urllib.parse.urlparse(url).netloc or url

    # Determine Severity
    if s_phish >= 0.70 or aitm.get("is_aitm_suspect") or honeytoken.get("is_trapped"):
        severity = "CRITICAL"
    elif s_phish >= 0.35:
        severity = "HIGH"
    elif s_phish >= 0.15:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Build Tradecraft Narrative
    tradecraft_parts = []
    if aitm.get("is_aitm_suspect"):
        tradecraft_parts.append("The adversary is operating an Adversary-in-the-Middle (AiTM) reverse proxy (Evilginx3/Modlishka pattern) to intercept real-time session cookies and bypass multi-factor authentication (MFA).")
    
    if quishing.get("is_quishing_suspect"):
        tradecraft_parts.append("The attack utilizes out-of-band Optical QR Code Phishing (Quishing) to circumvent email link scanners and coerce mobile device scanning.")

    if honeytoken.get("is_trapped"):
        proto = honeytoken.get("exfiltration_protocol", "HTTP POST")
        dest = honeytoken.get("exfiltration_host", "external drop")
        tradecraft_parts.append(f"Autonomous honeytoken validation trapped active credential exfiltration routing over {proto} to `{dest}`.")

    if dom_f.get("has_form_action_mismatch"):
        tradecraft_parts.append("Authentication form contains a cross-origin form action mismatch submitting harvested credentials to an unauthorized server.")

    if dom_f.get("is_formless_harvesting"):
        tradecraft_parts.append("Credential inputs are injected outside standard HTML `<form>` tags to evade automated form inspectors.")

    if not tradecraft_parts:
        if s_phish >= 0.50:
            tradecraft_parts.append(f"Adversary deployed a deceptive clone replicating the visual brand identity of {entity_name} hosted on an untrusted non-canonical domain.")
        else:
            tradecraft_parts.append("No hostile offensive tradecraft or credential harvesting mechanisms were verified.")

    tradecraft = " ".join(tradecraft_parts)

    # Executive Summary
    if severity in ["CRITICAL", "HIGH"]:
        exec_summary = (
            f"PhishSentry AI identified an active high-confidence cyber threat targeting {entity_name} at domain `{domain}` "
            f"with a {s_phish*100:.1f}% calculated phishing probability. The candidate infrastructure exhibits {archetype} characteristics."
        )
    else:
        exec_summary = (
            f"Target `{domain}` was evaluated as low risk ({s_phish*100:.1f}% risk score). "
            f"No evidence of credential interception or brand spoofing was detected."
        )

    # IOCs
    iocs = [f"Target URL: {url}", f"Primary Hostname: {domain}"]
    if tls_data.get("resolved_ip"):
        iocs.append(f"Resolved IP: {tls_data.get('resolved_ip')}")
    if tls_data.get("issuer"):
        iocs.append(f"TLS Issuer: {tls_data.get('issuer')}")
    if honeytoken.get("exfiltration_destination"):
        iocs.append(f"C2 Exfil Endpoint: {honeytoken.get('exfiltration_destination')}")

    # Recommended Actions
    actions = []
    if severity in ["CRITICAL", "HIGH"]:
        actions.append(f"Add `{domain}` to perimeter firewall and WAF domain blocklists.")
        if tls_data.get("resolved_ip"):
            actions.append(f"Blackhole traffic to hosting IP `{tls_data.get('resolved_ip')}` on edge routers.")
        if aitm.get("is_aitm_suspect"):
            actions.append("Force immediate password resets and revoke active OAuth/SAML session tokens for any users who visited this domain.")
            actions.append("Enforce FIDO2 / WebAuthn hardware security keys to immunize against AiTM reverse proxies.")
        actions.append(f"Submit legal RFC 2142 / DMCA abuse takedown notice to hosting ASN.")
    else:
        actions.append("No blocking action required. Retain telemetry logs for behavioral baseline tracking.")

    return ThreatNarrativeReport(
        incident_title=f"Security Incident Briefing: {entity_name} Threat Attribution ({domain})",
        severity_level=severity,
        threat_actor_tradecraft=tradecraft,
        executive_summary=exec_summary,
        forensic_indicators_of_compromise=iocs,
        recommended_soc_actions=actions
    )
