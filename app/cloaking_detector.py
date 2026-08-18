import re
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class CloakingDetectionResult:
    is_cloaked: bool
    interstitial_type: Optional[str]
    evasion_techniques: List[str]
    is_bot_wall: bool
    advisory: Optional[str]

CLOAKING_PATTERNS = [
    (r"challenges\.cloudflare\.com|cf-turnstile|cf-browser-verification", "Cloudflare Turnstile / Managed Challenge"),
    (r"google\.com/recaptcha|recaptcha/api\.js|g-recaptcha", "Google reCAPTCHA Interstitial Wall"),
    (r"hcaptcha\.com|hcaptcha/api\.js", "hCaptcha Bot Barrier"),
    (r"ddos-guard|qrator|perimeterx|humansecurity", "Commercial Anti-Bot Gateway"),
    (r"window\.location\.replace\(|<meta\s+http-equiv=[\"']refresh[\"']", "Meta / JS Rapid Redirect Cloak"),
    (r"navigator\.webdriver|navigator\.languages|screen\.colorDepth", "Browser Fingerprinting Sandbox Probe")
]

def analyze_cloaking_and_anti_bot(dom_html: Optional[str], url: str) -> CloakingDetectionResult:
    """
    Analyzes rendered HTML for anti-analysis techniques, bot-walls, CAPTCHA gates,
    and crawler cloaking designed to hide phishing payloads from automated scanners.
    """
    if not dom_html:
        return CloakingDetectionResult(
            is_cloaked=False,
            interstitial_type=None,
            evasion_techniques=[],
            is_bot_wall=False,
            advisory=None
        )

    dom_lower = dom_html.lower()
    detected_techniques = []
    detected_type = None
    is_bot_wall = False

    for pattern, name in CLOAKING_PATTERNS:
        if re.search(pattern, dom_lower):
            detected_techniques.append(name)
            if not detected_type:
                detected_type = name
            if "turnstile" in name.lower() or "recaptcha" in name.lower() or "hcaptcha" in name.lower() or "anti-bot" in name.lower():
                is_bot_wall = True

    # Short DOM with only title or loader
    if len(dom_html) < 400 and ("loading" in dom_lower or "please wait" in dom_lower or "checking" in dom_lower):
        detected_techniques.append("Suspicious Low-Volume Intermediate Loader")
        if not detected_type:
            detected_type = "Intermediate JS Loader"
        is_bot_wall = True

    is_cloaked = len(detected_techniques) > 0
    advisory = None
    if is_cloaked:
        advisory = (
            f"Page employs '{detected_type}' to impede automated sandboxes. "
            "Threat engine elevated lexical attribution to prevent false-negative evasion."
        )

    return CloakingDetectionResult(
        is_cloaked=is_cloaked,
        interstitial_type=detected_type,
        evasion_techniques=detected_techniques,
        is_bot_wall=is_bot_wall,
        advisory=advisory
    )
