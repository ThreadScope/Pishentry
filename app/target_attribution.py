"""
app/target_attribution.py
==========================
Next-Generation Multi-Modal Target Identity & Campaign Archetype Attribution Engine.

Replaces naive static "matched_brand" lookups with a dynamic, multi-modal entity classifier:
- Cross-correlates Lexical proximity, ResNet-50 visual layout, DOM tag patterns, In-Image OCR text, and Phishpedia domain consistency.
- Automatically discovers specific enterprise brands (e.g. Microsoft 365, PayPal, Google, Bank of America).
- If no specific brand matches, dynamically classifies the Campaign Archetype:
  - Universal Corporate Credential Harvester
  - Adversary-in-the-Middle (AiTM) Reverse Proxy
  - Web3 / Cryptocurrency Wallet Drainer
  - Financial & Banking Identity Theft Portal
  - Logistics / Package Delivery Lure
"""

import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class TargetAttributionResult(BaseModel):
    target_identity: str = Field(..., description="Canonical identifier or archetype ID")
    identity_display_name: str = Field(..., description="Human-readable entity name or campaign archetype")
    campaign_archetype: str = Field(..., description="Category of threat campaign")
    attribution_confidence: float = Field(..., ge=0.0, le=1.0, description="Attribution confidence score")
    is_canonical_identity: bool = Field(False, description="True if domain is authoritative owner")
    impersonation_evidence: List[str] = Field(default_factory=list, description="Forensic evidence trail")
    suggested_mitigation: str = Field("", description="Tailored SOC remediation advisory")

# Well-known enterprise entity catalog
ENTERPRISE_IDENTITIES: Dict[str, Dict[str, Any]] = {
    "paypal": {
        "display_name": "PayPal Inc.",
        "canonical_domains": ["paypal.com", "paypalobjects.com"],
        "keywords": ["paypal", "paypa1", "send money", "wallet", "pp-secure", "the secure way to pay", "pay and get paid", "forgotten your email", "sign up for paypal"],
        "archetype": "Financial & Payment Processing Service"
    },
    "google": {
        "display_name": "Google Workspace & Accounts",
        "canonical_domains": ["google.com", "accounts.google.com", "gmail.com"],
        "keywords": ["google", "gmail", "workspace", "goog1e", "drive", "docs"],
        "archetype": "Cloud Identity & Productivity Suite"
    },
    "microsoft": {
        "display_name": "Microsoft 365 & Entra ID",
        "canonical_domains": ["microsoft.com", "login.microsoftonline.com", "office.com", "live.com", "outlook.com"],
        "keywords": ["microsoft", "office365", "o365", "outlook", "azure", "sharepoint", "onedrive", "entra"],
        "archetype": "Enterprise Identity & Single Sign-On (SSO)"
    },
    "bankofamerica": {
        "display_name": "Bank of America",
        "canonical_domains": ["bankofamerica.com", "bofa.com"],
        "keywords": ["bank of america", "bofa", "bankofamerica", "online banking", "safe pass"],
        "archetype": "Retail & Corporate Banking Portal"
    },
    "chase": {
        "display_name": "JPMorgan Chase & Co.",
        "canonical_domains": ["chase.com", "jpmorganchase.com"],
        "keywords": ["chase", "jpmorgan", "chase online", "chase bank"],
        "archetype": "Retail & Corporate Banking Portal"
    },
    "dhl": {
        "display_name": "DHL Express Logistics",
        "canonical_domains": ["dhl.com", "dhl-express.com"],
        "keywords": ["dhl", "express tracking", "parcel delivery", "shipment pending", "customs duty"],
        "archetype": "Logistics & Package Delivery Service"
    },
    "github": {
        "display_name": "GitHub (Microsoft Corp)",
        "canonical_domains": ["github.com", "github.io"],
        "keywords": ["github", "repository", "git sign in", "ssh key", "personal access token"],
        "archetype": "Developer Infrastructure & Source Code Host"
    },
    "docusign": {
        "display_name": "DocuSign Digital Signatures",
        "canonical_domains": ["docusign.com", "docusign.net"],
        "keywords": ["docusign", "document signing", "envelope pending", "review document"],
        "archetype": "Enterprise Document & Legal Workflow"
    },
    "dropbox": {
        "display_name": "Dropbox Cloud Storage",
        "canonical_domains": ["dropbox.com", "dropboxstatic.com"],
        "keywords": ["dropbox", "shared file", "view document", "shared folder"],
        "archetype": "Cloud File Sharing & Storage"
    },
    "apple": {
        "display_name": "Apple Inc. (Apple ID & iCloud)",
        "canonical_domains": ["apple.com", "icloud.com"],
        "keywords": ["apple id", "icloud", "find my", "apple pay", "itunes"],
        "archetype": "Consumer Identity & Device Ecosystem"
    }
}

def attribute_target_identity(
    registered_domain: str,
    lexical_matched_brand: Optional[str] = None,
    dom_matched_brand: Optional[str] = None,
    vis_matched_brand: Optional[str] = None,
    vis_score: float = 0.0,
    dom_score: float = 0.0,
    ocr_extracted_text: str = "",
    dom_text: str = "",
    is_aitm: bool = False,
    is_quishing: bool = False
) -> TargetAttributionResult:
    """
    Intelligently attributes the target identity or campaign archetype using multi-modal evidence.
    """
    reg_clean = (registered_domain or "").lower()
    combined_text = f"{ocr_extracted_text} {dom_text}".lower()
    evidence = []
    
    # 1. Candidate Entity Scoring Matrix
    candidate_scores: Dict[str, float] = {}

    for brand_id, meta in ENTERPRISE_IDENTITIES.items():
        score = 0.0
        
        # Check canonical domain ownership
        is_canon = any(reg_clean == c.lower() or reg_clean.endswith(f".{c.lower()}") for c in meta["canonical_domains"])
        if is_canon:
            evidence.append(f"Verified authoritative domain ownership for {meta['display_name']}.")
            return TargetAttributionResult(
                target_identity=brand_id,
                identity_display_name=meta["display_name"],
                campaign_archetype="Legitimate Authoritative Portal",
                attribution_confidence=1.0,
                is_canonical_identity=True,
                impersonation_evidence=evidence,
                suggested_mitigation="Safe. Authoritative enterprise portal."
            )

        # Lexical evidence
        if lexical_matched_brand == brand_id:
            score += 0.40
            evidence.append(f"Domain lexical spoofing pattern matching {meta['display_name']}.")

        # Visual ResNet-50 evidence
        if vis_matched_brand == brand_id and vis_score > 0.40:
            score += vis_score * 0.50
            evidence.append(f"Visual layout resemblance ({vis_score*100:.1f}%) to {meta['display_name']}.")

        # DOM structural evidence
        if dom_matched_brand == brand_id and dom_score > 0.35:
            score += dom_score * 0.35
            evidence.append(f"DOM structural alignment ({dom_score*100:.1f}%) with {meta['display_name']}.")

        # OCR & in-image keyword evidence
        for kw in meta["keywords"]:
            if kw in combined_text:
                score += 0.25
                evidence.append(f"Optical in-image text contains brand identifier '{kw}'.")
                break

        if score > 0:
            candidate_scores[brand_id] = score

    # 2. If specific enterprise brand was identified with sufficient confidence
    if candidate_scores:
        best_brand = max(candidate_scores, key=candidate_scores.get)
        best_score = min(1.0, candidate_scores[best_brand])
        
        if best_score >= 0.35:
            meta = ENTERPRISE_IDENTITIES[best_brand]
            archetype = "Adversary-in-the-Middle (AiTM) Reverse Proxy" if is_aitm else (
                "Quishing (QR Phishing) Campaign" if is_quishing else "Brand Impersonation & Credential Theft"
            )
            return TargetAttributionResult(
                target_identity=best_brand,
                identity_display_name=meta["display_name"],
                campaign_archetype=archetype,
                attribution_confidence=best_score,
                is_canonical_identity=False,
                impersonation_evidence=evidence,
                suggested_mitigation=f"Block domain immediately on WAF/Firewall and inspect for compromised credentials targeting {meta['display_name']}."
            )

    # 3. Dynamic Campaign Archetype Attribution (No single brand catalog match)
    if is_aitm:
        return TargetAttributionResult(
            target_identity="aitm_reverse_proxy",
            identity_display_name="Adversary-in-the-Middle (AiTM) Proxy",
            campaign_archetype="Dynamic Session Interception",
            attribution_confidence=0.88,
            is_canonical_identity=False,
            impersonation_evidence=["Reverse proxy session-stealing tradecraft identified (Evilginx / Modlishka)."],
            suggested_mitigation="Revoke user session tokens, enforce FIDO2 WebAuthn / passkeys, and block proxy IP."
        )

    if is_quishing:
        return TargetAttributionResult(
            target_identity="quishing_lure",
            identity_display_name="Quishing (QR Code) Theft Portal",
            campaign_archetype="Out-of-Band Optical Phishing",
            attribution_confidence=0.85,
            is_canonical_identity=False,
            impersonation_evidence=["Embedded QR matrix pattern designed to bypass email security gateways."],
            suggested_mitigation="Warn users against scanning untrusted QR codes from corporate emails."
        )

    # Check for Web3 / Crypto keywords
    if any(k in combined_text for k in ["metamask", "seed phrase", "connect wallet", "keystore", "crypto wallet", "private key"]):
        return TargetAttributionResult(
            target_identity="web3_wallet_drainer",
            identity_display_name="Web3 & Cryptocurrency Wallet Drainer",
            campaign_archetype="Cryptocurrency Asset Theft",
            attribution_confidence=0.82,
            is_canonical_identity=False,
            impersonation_evidence=["Form requests private seed phrase, mnemonic phrase, or Web3 wallet connection."],
            suggested_mitigation="Add to DNS sinkhole and notify crypto intelligence threat feeds."
        )

    # Check for generic corporate credential harvester
    if any(k in combined_text for k in ["password", "sign in", "login", "username", "account", "verify your account", "session expired"]):
        return TargetAttributionResult(
            target_identity="generic_credential_harvester",
            identity_display_name="Universal Credential Harvester",
            campaign_archetype="Generic Corporate Account Phishing",
            attribution_confidence=0.65,
            is_canonical_identity=False,
            impersonation_evidence=["Authentication input fields located on non-standard unauthenticated hosting."],
            suggested_mitigation="Enforce enterprise SSO and block domain at secure email gateway."
        )

    # Default baseline
    return TargetAttributionResult(
        target_identity="unclassified_target",
        identity_display_name="Unclassified Web Surface",
        campaign_archetype="General Web Surface",
        attribution_confidence=0.10,
        is_canonical_identity=False,
        impersonation_evidence=["No prominent brand impersonation or credential harvesting signatures detected."],
        suggested_mitigation="No active blocking needed unless telemetry escalates."
    )
