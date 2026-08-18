"""
app/kit_fingerprinter.py
========================
Phishing Kit Fingerprinting & C2 Telegram Exfiltration Drop Detector.

Identifies known commercial and underground phishing kits (EvilProxy, Modlishka, 16Shop, W3LL Store, Kr3pto)
and detects direct Telegram Bot API credential exfiltration webhooks (MITRE ATT&CK T1020).
"""

import re
from typing import List, Dict, Optional
from pydantic import BaseModel, Field

class PhishingKitSignature(BaseModel):
    is_kit_detected: bool = False
    kit_name: Optional[str] = None
    kit_family: Optional[str] = None
    confidence: float = 0.0
    detected_indicators: List[str] = []
    is_telegram_exfiltration: bool = False
    telegram_bot_endpoints: List[str] = []
    mitre_attack_id: str = "T1020"

KNOWN_KIT_PATTERNS = {
    "EvilProxy": [r"evilproxy", r"reverse_proxy_token", r"/proxy/auth/v1", r"ep_session"],
    "Modlishka": [r"modlishka", r"m_auth_cookie", r"modlishka_token"],
    "16Shop": [r"16shop", r"16_framework", r"/assets/includes/killbot", r"antibot_16"],
    "W3LL Store": [r"w3ll", r"w3ll_store", r"/w3ll/", r"w3ll_guard"],
    "Kr3pto": [r"kr3pto", r"sms_otp_trap", r"krypto_theme"],
    "Caffeine": [r"caffeine_core", r"caffeine_portal", r"/caffeine/api"]
}

def fingerprint_phishing_kit(html_content: str, raw_scripts: List[str]) -> PhishingKitSignature:
    """
    Scans rendered HTML and scripts for phishing kit signatures and Telegram exfiltration webhooks.
    """
    text_to_scan = (html_content + "\n" + "\n".join(raw_scripts)).lower()
    
    indicators = []
    matched_kit = None
    highest_matches = 0

    # 1. Match known kit signatures
    for kit, patterns in KNOWN_KIT_PATTERNS.items():
        matches = [p for p in patterns if re.search(p, text_to_scan)]
        if len(matches) > highest_matches:
            highest_matches = len(matches)
            matched_kit = kit
            indicators.extend([f"Pattern '{m}' matched {kit} kit signature" for m in matches])

    # 2. Check for Telegram Bot API Credential Exfiltration (MITRE T1020)
    tg_pattern = r"https?://api\.telegram\.org/bot[0-9]+:[a-za-z0-9_-]+/sendmessage"
    tg_matches = re.findall(tg_pattern, text_to_scan)
    is_tg = len(tg_matches) > 0
    if is_tg:
        indicators.append("Direct Telegram Bot API credential exfiltration drop detected (MITRE T1020)")

    is_detected = (matched_kit is not None) or is_tg

    return PhishingKitSignature(
        is_kit_detected=is_detected,
        kit_name=matched_kit or ("Custom Telegram Harvester" if is_tg else None),
        kit_family="Reverse-Proxy AiTM" if matched_kit in ["EvilProxy", "Modlishka"] else ("Commodity Phishing Kit" if matched_kit else None),
        confidence=0.95 if matched_kit else (0.90 if is_tg else 0.0),
        detected_indicators=indicators,
        is_telegram_exfiltration=is_tg,
        telegram_bot_endpoints=[m[:45] + "..." for m in tg_matches],
        mitre_attack_id="T1020" if is_tg else "T1566.002"
    )
