"""
app/phishpedia_engine.py
========================
Implementation of the Phishpedia (USENIX Security '21) Consistency-Based Phishing Identification Model.

Core Concepts:
1. Visual & Structural Brand Intention Resolution (Identifying target brand B from logos/visuals).
2. Domain-Brand Consistency Verification (Comparing registered domain d against canonical domain set C(B)).
3. Inherently Interpretable Visual Attribution (No black-box bias, robust to test-time distribution shift).
"""

import urllib.parse
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

class PhishpediaConsistencyResult(BaseModel):
  brand_intention: Optional[str] = Field(None, description="Target brand identity detected from visual/DOM features.")
  brand_display_name: Optional[str] = Field(None, description="Human-readable brand name (e.g. PayPal, Microsoft).")
  brand_confidence: float = Field(0.0, description="Confidence score in brand intention detection (0.0 to 1.0).")
  registered_domain: str = Field(..., description="Actual registered domain of candidate URL.")
  canonical_domains: List[str] = Field(default_factory=list, description="Official canonical domain set for detected brand.")
  is_consistent: bool = Field(True, description="True if domain matches canonical brand set, False if inconsistent (Phishing).")
  phishing_decision: bool = Field(False, description="True if Phishpedia flags webpage as Phishing.")
  visual_explanation: str = Field(..., description="Human-interpretable visual and domain consistency explanation.")
  mitre_attack_id: str = Field("T1566.002", description="Associated MITRE ATT&CK technique.")

def evaluate_phishpedia_consistency(
  url: str,
  matched_brand: Optional[str],
  visual_similarity: float,
  dom_similarity: float,
  brand_metadata: Dict[str, dict]
) -> PhishpediaConsistencyResult:
  """
  Evaluates Phishpedia domain-brand consistency.
  
  Phishpedia Rule:
  If Brand Intention B is identified (visual_similarity > threshold or matched_brand known),
  and candidate registered domain d is NOT in canonical_domains(B),
  then Page is an INCONSISTENT BRAND IMPERSONATION -> PHISHING.
  """
  parsed = urllib.parse.urlparse(url)
  hostname = (parsed.netloc or parsed.path).split(":")[0].lower()
  
  # Extract registered domain (simple suffix extractor)
  parts = hostname.split(".")
  if len(parts) >= 2:
    reg_domain = ".".join(parts[-2:])
  else:
    reg_domain = hostname

  # If no brand detected or low confidence
  if not matched_brand or visual_similarity < 0.25:
    return PhishpediaConsistencyResult(
      brand_intention=None,
      brand_display_name=None,
      brand_confidence=0.0,
      registered_domain=hostname,
      canonical_domains=[],
      is_consistent=True,
      phishing_decision=False,
      visual_explanation=f"No protected brand intention detected for domain '{hostname}'. Layout appears generic or benign.",
      mitre_attack_id="None"
    )

  clean_brand = matched_brand.lower().strip()
  brand_info = brand_metadata.get(clean_brand, {})
  canonical_list = [c.lower() for c in brand_info.get("canonical_domains", [clean_brand + ".com"])]
  brand_name = brand_info.get("display_name", clean_brand.capitalize())
  
  # Consistency check: Is candidate hostname a subdomain of or equal to any canonical domain?
  is_domain_match = any(
    hostname == c or hostname.endswith("." + c)
    for c in canonical_list
  )
  
  # Combined confidence in brand intention (fusing visual & structural signals)
  intention_confidence = round(min(1.0, (visual_similarity * 0.7) + (dom_similarity * 0.3)), 4)

  if is_domain_match:
    return PhishpediaConsistencyResult(
      brand_intention=clean_brand,
      brand_display_name=brand_name,
      brand_confidence=intention_confidence,
      registered_domain=hostname,
      canonical_domains=canonical_list,
      is_consistent=True,
      phishing_decision=False,
      visual_explanation=f" CONSISTENT: Visual presentation matches '{brand_name}', and hostname '{hostname}' is an authentic canonical domain.",
      mitre_attack_id="None"
    )
  else:
    return PhishpediaConsistencyResult(
      brand_intention=clean_brand,
      brand_display_name=brand_name,
      brand_confidence=intention_confidence,
      registered_domain=hostname,
      canonical_domains=canonical_list,
      is_consistent=False,
      phishing_decision=True,
      visual_explanation=(
        f" INCONSISTENT (Phishpedia Rule): Webpage visually presents '{brand_name}' identity "
        f"(visual match {visual_similarity*100:.1f}%), but host domain '{hostname}' does NOT match "
        f"the authentic canonical domain set ({', '.join(canonical_list)}). "
        f"Definitive brand impersonation."
      ),
      mitre_attack_id="T1566.002"
    )
