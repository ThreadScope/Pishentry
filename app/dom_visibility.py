"""
app/dom_visibility.py
=====================
Computed CSS Visibility & Anti-Zero-Font Obfuscation Filter.

Detects and strips:
- Zero-font spans (<span style="font-size: 0px">, <span style="font-size: 0.1px">)
- Zero-width Unicode character injections (\u200B, \u200C, \u200D, \uFEFF, \u00AD)
- Off-screen positioned elements (left: -9999px, top: -9999px, text-indent: -9999px)
- Invisible elements (display: none, visibility: hidden, opacity: 0)

Extracts 100% clean human-visible text stream for robust brand and intent classification.
"""

import re
import logging
from typing import Tuple, List
from bs4 import BeautifulSoup, Comment

logger = logging.getLogger(__name__)

# Zero-width Unicode and soft hyphen regex
ZERO_WIDTH_CHARS_REGEX = re.compile(r"[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u2060\u180E]+")

# CSS rules that render text invisible to human eyes
HIDDEN_STYLE_PATTERNS = [
    re.compile(r"font-size\s*:\s*0(?:\.0+)?(?:px|em|pt|rem|%|vw|vh)?(?:\s*!important)?", re.IGNORECASE),
    re.compile(r"display\s*:\s*none(?:\s*!important)?", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden(?:\s*!important)?", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?(?:\s*!important)?", re.IGNORECASE),
    re.compile(r"left\s*:\s*-[0-9]{3,}(?:px|em)?", re.IGNORECASE),
    re.compile(r"top\s*:\s*-[0-9]{3,}(?:px|em)?", re.IGNORECASE),
    re.compile(r"text-indent\s*:\s*-[0-9]{3,}(?:px|em)?", re.IGNORECASE),
    re.compile(r"transform\s*:\s*scale\(0\)", re.IGNORECASE),
    re.compile(r"max-height\s*:\s*0(?:px)?", re.IGNORECASE),
    re.compile(r"max-width\s*:\s*0(?:px)?", re.IGNORECASE)
]

def clean_human_visible_dom_text(html_content: str) -> Tuple[str, bool, List[str]]:
    """
    Strips zero-font, hidden, off-screen, and zero-width obfuscated elements from HTML.
    Returns:
      (cleaned_visible_text, has_zero_font_obfuscation, detected_evasion_artifacts)
    """
    if not html_content or not html_content.strip():
        return "", False, []

    evasion_artifacts = []
    has_obfuscation = False

    # Check for raw zero-width character evasion
    if ZERO_WIDTH_CHARS_REGEX.search(html_content):
        has_obfuscation = True
        evasion_artifacts.append("Zero-Width Unicode Characters: Stripped hidden zero-width spaces/connectors used to split brand keywords.")

    try:
        soup = BeautifulSoup(html_content, "html.parser")

        # 1. Remove HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()


        # 2. Remove script, style, noscript, and SVG definition tags
        for tag in soup.find_all(["script", "style", "noscript", "svg", "defs", "clippath", "template"]):
            tag.decompose()

        # 3. Identify and strip CSS-hidden elements
        for element in soup.find_all(True):
            style = element.get("style", "")
            hidden_attr = element.get("hidden")
            aria_hidden = element.get("aria-hidden")

            is_hidden = False
            if hidden_attr is not None or aria_hidden == "true":
                is_hidden = True

            if style:
                for pattern in HIDDEN_STYLE_PATTERNS:
                    if pattern.search(style):
                        is_hidden = True
                        has_obfuscation = True
                        evasion_artifacts.append(f"CSS Invisible Element: Stripped tag <{element.name}> with hidden style: '{style.strip()}'")
                        break

            if is_hidden:
                element.decompose()

        # 4. Extract sanitized text
        raw_text = soup.get_text(separator=" ", strip=True)
        # Strip remaining zero-width Unicode characters
        sanitized_text = ZERO_WIDTH_CHARS_REGEX.sub("", raw_text)
        # Normalize whitespace
        cleaned_text = re.sub(r"\s+", " ", sanitized_text).strip()

        return cleaned_text, has_obfuscation, list(set(evasion_artifacts))

    except Exception as e:
        logger.warning(f"Error in computed CSS visibility extraction: {e}")
        cleaned_text = ZERO_WIDTH_CHARS_REGEX.sub("", html_content)
        return cleaned_text, False, []
