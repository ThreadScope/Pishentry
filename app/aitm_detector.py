import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass
from app.schemas import TLSTelemetry

logger = logging.getLogger(__name__)

@dataclass
class AiTMDetectionResult:
    is_aitm_suspect: bool
    confidence_level: str  # "CRITICAL", "HIGH", "MEDIUM", "NONE"
    mitre_attack_id: str   # e.g., "T1556 / T1539 (Steal Web Session Cookie)"
    target_brand: Optional[str]
    reasons: list
    risk_score_boost: float

def detect_aitm_proxy(
    url: str,
    s_vis: Optional[float],
    s_dom: Optional[float],
    matched_brand: Optional[str],
    is_canonical: bool,
    tls_telemetry: Optional[TLSTelemetry],
    dom_html: Optional[str] = None
) -> AiTMDetectionResult:
    """
    Detects Adversary-in-the-Middle (AiTM) Reverse Proxy kits (Evilginx, Modlishka, Muraena)
    that proxy authentic login workflows to steal session tokens & 2FA session cookies.
    """
    reasons = []
    is_suspect = False
    confidence = "NONE"
    score_boost = 0.0
    mitre_id = "T1556 / T1539"

    if is_canonical:
        return AiTMDetectionResult(
            is_aitm_suspect=False,
            confidence_level="NONE",
            mitre_attack_id="N/A",
            target_brand=matched_brand,
            reasons=["Verified canonical domain."],
            risk_score_boost=0.0
        )

    vis_score = s_vis or 0.0
    dom_score = s_dom or 0.0
    max_similarity = max(vis_score, dom_score)

    # Condition 1: High visual or DOM impersonation of protected enterprise brand
    if max_similarity >= 0.60 and matched_brand:
        # Check Condition 2: TLS Infrastructure Mismatch
        if tls_telemetry and tls_telemetry.has_tls:
            if tls_telemetry.is_free_ca:
                reasons.append(
                    f"AiTM Signature: High visual resemblance to {matched_brand.upper()} ({max_similarity*100:.1f}%) "
                    f"hosted under an automated/free TLS Certificate ({tls_telemetry.issuer or 'Let\'s Encrypt'})."
                )
                is_suspect = True
                confidence = "HIGH"
                score_boost += 0.35
            elif tls_telemetry.is_self_signed:
                reasons.append(
                    f"AiTM Signature: Self-signed certificate deployed on brand impersonation portal."
                )
                is_suspect = True
                confidence = "CRITICAL"
                score_boost += 0.40

        # Check Condition 3: Subdomain Stacking / Reverse Proxy Pattern
        url_lower = url.lower()
        if any(b_name in url_lower for b_name in ["login.", "signin.", "auth.", "sso.", "portal.", "account."]):
            if not is_suspect:
                is_suspect = True
                confidence = "MEDIUM"
                score_boost += 0.20
            reasons.append("Contains enterprise SSO/login sub-patterns proxied on a non-canonical hostname.")

        # Check Condition 4: DOM Input Form Reverse-Proxy Attributes
        if dom_html:
            dom_l = dom_html.lower()
            if 'type="password"' in dom_l and ('evilginx' in dom_l or 'proxy' in dom_l or 'xhr' in dom_l):
                reasons.append("DOM contains active credential forwarding or reverse proxy artifact.")
                is_suspect = True
                confidence = "CRITICAL"
                score_boost += 0.30

    if is_suspect and confidence in ["HIGH", "CRITICAL"]:
        mitre_id = "MITRE ATT&CK T1556 (Modify Authentication Process) / T1539 (Steal Web Session Cookie)"

    return AiTMDetectionResult(
        is_aitm_suspect=is_suspect,
        confidence_level=confidence,
        mitre_attack_id=mitre_id,
        target_brand=matched_brand,
        reasons=reasons,
        risk_score_boost=min(0.40, score_boost)
    )
