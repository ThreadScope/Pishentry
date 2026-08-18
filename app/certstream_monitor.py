"""
app/certstream_monitor.py
=========================
Real-Time Certificate Transparency (CertStream) Phishing Discovery Stream.

Inspired by Phishpedia's zero-day discovery methodology:
Monitors live or queried Certificate Transparency logs for newly-issued SSL/TLS certificates
targeting protected enterprise brands.
"""

import time
import random
from typing import List, Dict, Optional
from pydantic import BaseModel, Field

class CertStreamEvent(BaseModel):
    domain: str = Field(..., description="Newly issued domain name extracted from Certificate Transparency log.")
    san_list: List[str] = Field(default_factory=list, description="Subject Alternative Names in certificate.")
    issuer: str = Field(..., description="Certificate Authority (e.g. Let's Encrypt, ZeroSSL, Cloudflare).")
    timestamp: float = Field(default_factory=time.time, description="Unix timestamp of certificate issuance.")
    matched_target_brand: Optional[str] = Field(None, description="Protected brand suspected of being targeted.")
    risk_level: str = Field("HIGH", description="Assessed risk (CRITICAL, HIGH, SUSPICIOUS, BENIGN).")
    is_zero_day: bool = Field(True, description="True if detected prior to reputation blocklist indexing.")
    heuristic_triggers: List[str] = Field(default_factory=list, description="Detection reasons (e.g. Brand in subdomain, Abuse TLD).")

def evaluate_certstream_domain(
    domain: str,
    san_list: List[str],
    issuer: str,
    protected_brands: List[str]
) -> Optional[CertStreamEvent]:
    """
    Analyzes a domain from a CT-log event against protected brand signatures.
    """
    clean_domain = domain.lower().strip()
    triggers = []
    matched_brand = None
    
    ABUSE_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".work", ".live", ".icu", ".site", ".online", ".ru", ".cn"}
    
    # Check if domain uses an abuse TLD
    has_abuse_tld = any(clean_domain.endswith(tld) for tld in ABUSE_TLDS)
    if has_abuse_tld:
        triggers.append("High-Abuse Threat TLD")

    # Homoglyph translation for advanced lookalike matching
    HOMOGLYPH_MAP = str.maketrans({"1": "l", "0": "o", "5": "s", "3": "e", "@": "a", "8": "b"})
    normalized_domain = clean_domain.translate(HOMOGLYPH_MAP)

    # Check for brand lookalike keywords
    for b in protected_brands:
        b_clean = b.lower()
        if b_clean in clean_domain or b_clean in normalized_domain:
            matched_brand = b_clean
            
            # Check if domain is legitimate official brand domain
            if clean_domain == f"{b_clean}.com" or clean_domain == f"www.{b_clean}.com" or clean_domain.endswith(f".{b_clean}.com"):
                return None  # Legitimate official brand certificate
                
            # Suspicious permutations
            if b_clean in normalized_domain and b_clean not in clean_domain:
                triggers.append(f"Homoglyph brand spoofing ('{b_clean}')")
            if "-" in clean_domain:
                triggers.append(f"Hyphenated brand spoofing ('{b_clean}')")
            if any(kw in clean_domain for kw in ["login", "signin", "verify", "secure", "auth", "update", "account"]):
                triggers.append("Authentication lure keyword")
            if clean_domain.count(".") > 2:
                triggers.append("Subdomain masquerading depth")
            break


    if not matched_brand and not triggers:
        return None

    risk = "CRITICAL" if len(triggers) >= 2 else ("HIGH" if matched_brand else "SUSPICIOUS")

    return CertStreamEvent(
        domain=clean_domain,
        san_list=san_list,
        issuer=issuer,
        timestamp=time.time(),
        matched_target_brand=matched_brand,
        risk_level=risk,
        is_zero_day=True,
        heuristic_triggers=triggers or ["Lookalike Brand Pattern"]
    )

def generate_sample_certstream_feed(protected_brands: List[str]) -> List[CertStreamEvent]:
    """
    Generates a realistic stream of live zero-day Certificate Transparency events for demonstration.
    """
    sample_candidates = [
        ("paypa1-security-verification.xyz", ["paypa1-security-verification.xyz", "www.paypa1-security-verification.xyz"], "Let's Encrypt"),
        ("accounts-google-portal-auth.live", ["accounts-google-portal-auth.live"], "ZeroSSL"),
        ("microsoft-office365-session-update.top", ["microsoft-office365-session-update.top"], "Cloudflare Inc ECC CA-3"),
        ("dhl-express-tracking-delivery-confirm.site", ["dhl-express-tracking-delivery-confirm.site"], "Let's Encrypt"),
        ("bankofamerica-secure-signon.icu", ["bankofamerica-secure-signon.icu"], "cAutoSSL"),
        ("github-recovery-tokens-review.work", ["github-recovery-tokens-review.work"], "Let's Encrypt")
    ]
    
    events = []
    for d, sans, iss in sample_candidates:
        ev = evaluate_certstream_domain(d, sans, iss, protected_brands)
        if ev:
            events.append(ev)
    return events
