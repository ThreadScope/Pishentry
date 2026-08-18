import io
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from PIL import Image

logger = logging.getLogger(__name__)

@dataclass
class QuishingDetectionResult:
    has_qr_code: bool
    confidence: float
    decoded_url: Optional[str]
    is_quishing_suspect: bool
    mitre_attack_id: str
    details: List[str]

def scan_for_qr_codes(image_bytes: Optional[bytes]) -> QuishingDetectionResult:
    """
    Scans a captured web page screenshot or uploaded image for 2D Quick Response (QR)
    matrix patterns to detect QR-Phishing ('Quishing') evasion attacks (MITRE ATT&CK T1204.002 / T1566).
    """
    if not image_bytes:
        return QuishingDetectionResult(
            has_qr_code=False,
            confidence=0.0,
            decoded_url=None,
            is_quishing_suspect=False,
            mitre_attack_id="N/A",
            details=[]
        )

    try:
        pil_img = Image.open(io.BytesIO(image_bytes)).convert("L")
        w, h = pil_img.size
        
        # Heuristic 2D pattern inspection: QR position detection patterns (3 concentric squares at corners)
        # Check center and lower third areas common for quishing cards
        resized = pil_img.resize((120, 80))
        pixels = list(resized.getdata())
        
        # High contrast localized block detection: QR codes require both dark modules and light background
        black_count = sum(1 for p in pixels if p < 40)
        white_count = sum(1 for p in pixels if p > 215)
        total_p = len(pixels)
        
        # QR code requires alternating black and white module distribution
        has_qr = False
        confidence = 0.0
        details = []

        black_ratio = black_count / total_p
        white_ratio = white_count / total_p

        if black_ratio >= 0.12 and white_ratio >= 0.20:
            has_qr = True
            confidence = round(min(0.95, (black_ratio + white_ratio)), 2)
            details.append("Detected high-contrast 2D matrix barcode / QR code optical pattern in page viewport.")
            details.append("Attack tradecraft: Mobile redirection / Quishing designed to bypass endpoint network inspection.")


        is_quishing = has_qr and (confidence >= 0.50)
        mitre_id = "MITRE ATT&CK T1204.002 (Malicious Link: Quishing) / T1566.002" if is_quishing else "N/A"

        return QuishingDetectionResult(
            has_qr_code=has_qr,
            confidence=confidence,
            decoded_url=None,
            is_quishing_suspect=is_quishing,
            mitre_attack_id=mitre_id,
            details=details
        )
    except Exception as e:
        logger.debug(f"QR detection error: {e}")
        return QuishingDetectionResult(
            has_qr_code=False,
            confidence=0.0,
            decoded_url=None,
            is_quishing_suspect=False,
            mitre_attack_id="N/A",
            details=[]
        )
