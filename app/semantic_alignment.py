import re
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class SemanticAlignmentResult:
    is_discrepancy_detected: bool
    domain_intent_brand: Optional[str]
    rendered_content_brand: Optional[str]
    discrepancy_type: str  # "MATCH", "CLOAKING_CONTENT_SWAP", "SPOOFED_PORTAL", "BENIGN_MISMATCH"
    alignment_score: float  # 1.0 = perfect alignment, 0.0 = total discrepancy / cloaking
    mitre_attack_id: str
    reasons: List[str]
    forensic_summary: str

KNOWN_BENIGN_CLOAK_TARGETS = {
    "google": ["google search", "i'm feeling lucky", "google.com", "about store gmail"],
    "bing": ["bing search", "microsoft bing"],
    "wikipedia": ["wikipedia", "the free encyclopedia"],
    "cloudflare": ["just a moment", "checking your browser", "cf-turnstile"],
    "default_parked": ["domain for sale", "buy this domain", "parked free", "cpanel", "apache2 ubuntu default"]
}

def analyze_domain_purpose_alignment(
    url: str,
    dom_html: Optional[str],
    s_lex_brand: Optional[str],
    s_vis_brand: Optional[str],
    is_canonical: bool
) -> SemanticAlignmentResult:
    """
    Analyzes whether the rendered visible DOM and visual brand logically align with the
    domain's lexical reputation and registered intent. Detects reverse-proxy content swapping,
    crawler cloaking, and benign bait-and-switch evasion tactics.
    """
    if not url:
        return SemanticAlignmentResult(
            is_discrepancy_detected=False,
            domain_intent_brand=None,
            rendered_content_brand=None,
            discrepancy_type="MATCH",
            alignment_score=1.0,
            mitre_attack_id="N/A",
            reasons=[],
            forensic_summary="No URL provided for analysis."
        )

    clean_dom = (dom_html or "").lower()
    url_lower = url.lower()
    
    # 1. Identify if rendered content is masquerading or proxying a known benign portal (e.g. Google Search)
    rendered_benign_proxy = None
    for brand, markers in KNOWN_BENIGN_CLOAK_TARGETS.items():
        if any(marker in clean_dom for marker in markers):
            rendered_benign_proxy = brand
            break

    # 2. Check for Domain vs. Render Discrepancies
    reasons = []
    discrepancy_detected = False
    discrepancy_type = "MATCH"
    alignment_score = 1.0
    mitre_id = "N/A"

    # SCENARIO 1: Reverse-Proxy Content Swapping / Benign Bait Evasion
    # Domain claims to be Brand A (e.g. DHL/PayPal in URL), but renders Brand B (e.g. Google Search or Wikipedia) to trick crawlers
    if s_lex_brand and rendered_benign_proxy and (s_lex_brand != rendered_benign_proxy) and not is_canonical:
        discrepancy_detected = True
        discrepancy_type = "CLOAKING_CONTENT_SWAP"
        alignment_score = 0.15
        mitre_id = "MITRE ATT&CK T1027.006 (Indicator Blocking / Crawler Cloaking) / T1556"
        reasons.append(f"Domain lexical structure targets '{s_lex_brand.upper()}', but rendered DOM displays '{rendered_benign_proxy.upper()}' content.")
        reasons.append("High-confidence Cloaking / Reverse-Proxy Swapping detected: Attacker server serves benign bait page to security crawlers.")

    # SCENARIO 2: Phishing Impersonation (Domain is third-party, but visual content renders protected brand login)
    elif s_vis_brand and not is_canonical and (s_vis_brand not in url_lower):
        discrepancy_detected = True
        discrepancy_type = "SPOOFED_PORTAL"
        alignment_score = 0.20
        mitre_id = "MITRE ATT&CK T1566.002 (Spearphishing Link) / T1556"
        reasons.append(f"Domain origin is untrusted third-party, but rendered page visually displays '{s_vis_brand.upper()}' corporate portal.")

    # SCENARIO 3: Canonical Baseline Alignment
    elif is_canonical:
        discrepancy_detected = False
        discrepancy_type = "MATCH"
        alignment_score = 1.0
        reasons.append("Rendered page content and domain authority align with verified canonical registry.")

    # Build forensic summary
    if discrepancy_type == "CLOAKING_CONTENT_SWAP":
        summary = f"🚨 REVERSE-PROXY CLOAKING DETECTED: Tested domain implies '{s_lex_brand}', but the rendered viewport displays '{rendered_benign_proxy}' bait content to evade automated detection."
    elif discrepancy_type == "SPOOFED_PORTAL":
        summary = f"⚠️ BRAND IMPERSONATION DISCREPANCY: Non-canonical domain rendering '{s_vis_brand}' authentication interface."
    else:
        summary = "Verified domain purpose matches visible rendered page structure."

    return SemanticAlignmentResult(
        is_discrepancy_detected=discrepancy_detected,
        domain_intent_brand=s_lex_brand,
        rendered_content_brand=rendered_benign_proxy or s_vis_brand,
        discrepancy_type=discrepancy_type,
        alignment_score=alignment_score,
        mitre_attack_id=mitre_id,
        reasons=reasons,
        forensic_summary=summary
    )
