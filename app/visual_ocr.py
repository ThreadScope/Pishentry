"""
app/visual_ocr.py
==================
In-Image Visual Text & Canvas Optical Character Recognition (OCR) Engine.

Implements textual logo & adversarial case/font manipulation recovery per arXiv:2405.19598v2:
- Detects uppercase/lowercase transformations (e.g., 'facebook' -> 'FACEBOOK')
- Detects font substitutions and character-spaced brand masquerades ('P A Y P A L')
- Recovers brand intention when attackers eliminate graphical logos from DOM/screenshots
"""

import re
import logging
from typing import Optional, List, Dict, Any, Tuple
from pydantic import BaseModel, Field
from PIL import Image, ImageOps, ImageFilter
import io

logger = logging.getLogger(__name__)

class VisualOCRResult(BaseModel):
    has_in_image_text: bool = Field(False, description="True if text was detected inside viewport graphics")
    extracted_text_snippet: str = Field("", description="Optical text extracted from viewport")
    detected_brand_keywords: List[str] = Field(default_factory=list, description="Brand identifiers found in image")
    detected_security_keywords: List[str] = Field(default_factory=list, description="Security/auth keywords found in image")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="OCR extraction confidence")
    evidence: List[str] = Field(default_factory=list, description="Forensic audit trail")

# Expanded 35+ Enterprise Brand Lexicon (including case & token permutations)
BRAND_LEXICON = [
    "paypal", "microsoft", "office 365", "office365", "outlook", "azure",
    "google", "gmail", "gsuite", "workspace", "facebook", "meta", "instagram",
    "apple", "apple id", "icloud", "amazon", "amazon prime", "aws",
    "netflix", "chase", "bank of america", "bofa", "wells fargo", "citibank",
    "hsbc", "barclays", "dhl express", "dhl", "fedex", "ups", "usps",
    "docusign", "dropbox", "github", "gitlab", "okta", "metamask", "binance",
    "coinbase", "steam", "spotify", "ebay", "adobe"
]

SECURITY_PROMPT_LEXICON = [
    "sign in", "log in", "enter password", "verify account", "session expired",
    "update security", "confirm identity", "account suspended", "2-step verification",
    "one-time password", "security alert", "billing issue", "unusual activity",
    "passcode", "security code", "authenticate", "unlock account", "keep me signed in"
]

def preprocess_for_ocr(image: Image.Image) -> Image.Image:
    """Enhances image contrast and binarizes for robust optical character extraction."""
    try:
        gray = image.convert("L")
        gray = ImageOps.autocontrast(gray, cutoff=2)
        # Median filter to remove salt-and-pepper noise
        denoised = gray.filter(ImageFilter.MedianFilter(size=3))
        return denoised
    except Exception:
        return image

def extract_visual_text_from_screenshot(
    image_bytes: Optional[bytes]
) -> VisualOCRResult:
    """
    Performs visual character and keyword extraction from screenshot bytes.
    Uses robust optical image preprocessing and optical pattern recognition.
    """
    if not image_bytes or len(image_bytes) < 100:
        return VisualOCRResult()

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        w, h = img.size
        
        # Crop header/center auth box region where phish logos and prompts appear
        auth_box = img.crop((int(w * 0.10), int(h * 0.04), int(w * 0.90), int(h * 0.80)))
        processed_box = preprocess_for_ocr(auth_box)
        
        extracted_text = ""
        try:
            import pytesseract
            extracted_text = pytesseract.image_to_string(processed_box, timeout=2)
        except Exception:
            extracted_text = ""

        # Normalize text and strip extraneous spaced characters (e.g. 'F A C E B O O K' -> 'facebook')
        norm_text = re.sub(r"\s+", " ", extracted_text.lower()).strip()
        de_spaced_text = re.sub(r"(?<=\b\w)\s+(?=\w\b)", "", norm_text)

        found_brands = []
        for b in BRAND_LEXICON:
            if b in norm_text or b in de_spaced_text or b.replace(" ", "") in de_spaced_text:
                if b not in found_brands:
                    found_brands.append(b)

        found_sec = []
        for s in SECURITY_PROMPT_LEXICON:
            if s in norm_text or s in de_spaced_text:
                if s not in found_sec:
                    found_sec.append(s)

        evidence = []
        if found_brands:
            evidence.append(f"In-Image OCR: Detected graphical brand identifiers (Case/Font invariant): {', '.join(found_brands)}")
        if found_sec:
            evidence.append(f"In-Image OCR: Detected graphical authentication prompts: {', '.join(found_sec)}")

        has_text = bool(found_brands or found_sec or len(extracted_text.strip()) > 15)
        conf = 0.95 if found_brands and found_sec else (0.80 if (found_brands or found_sec) else (0.35 if has_text else 0.0))

        return VisualOCRResult(
            has_in_image_text=has_text,
            extracted_text_snippet=extracted_text[:300].strip(),
            detected_brand_keywords=found_brands,
            detected_security_keywords=found_sec,
            confidence_score=conf,
            evidence=evidence
        )

    except Exception as e:
        logger.debug(f"Visual OCR extraction skipped: {e}")
        return VisualOCRResult()

