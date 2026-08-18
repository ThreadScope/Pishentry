"""
app/phishzoo_tokenizer.py
=========================
PhishZoo Content Tokenization & Brand Matching Engine.

Adapted from the PhishZoo experiment (Liang et al.) which combines:
1. HTML keyword extraction (strips scripts/styles, tokenizes visible text)
2. URL keyword extraction (splits on delimiters, removes noise tokens)
3. TF-IDF vectorization for brand-page content matching

This provides a content-based semantic signal that complements
visual (CNN/EMD) and lexical (URL entropy) approaches.
"""

import re
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Brand keyword dictionaries (top TF-IDF tokens per protected brand)
BRAND_KEYWORD_MAP: Dict[str, List[str]] = {
    "paypal": ["paypal", "payment", "invoice", "billing", "transaction", "dispute", "resolution"],
    "google": ["google", "gmail", "account", "search", "drive", "chrome", "workspace"],
    "microsoft": ["microsoft", "outlook", "office", "onedrive", "teams", "azure", "windows"],
    "apple": ["apple", "icloud", "iphone", "itunes", "appstore", "macbook", "facetime"],
    "amazon": ["amazon", "prime", "shipping", "order", "alexa", "kindle", "delivery"],
    "netflix": ["netflix", "streaming", "subscription", "watch", "profile", "series"],
    "chase": ["chase", "banking", "checking", "savings", "jpmorgan", "quickdeposit"],
    "bankofamerica": ["bankofamerica", "merrill", "erica", "checking", "banking"],
    "facebook": ["facebook", "meta", "messenger", "instagram", "social", "friends"],
    "dhl": ["dhl", "express", "shipping", "tracking", "parcel", "delivery", "courier"],
    "adobe": ["adobe", "acrobat", "creative", "photoshop", "illustrator", "reader"],
    "wellsfargo": ["wellsfargo", "banking", "mortgage", "invest", "retirement"],
    "hsbc": ["hsbc", "banking", "global", "premier", "advance", "jade"],
    "docusign": ["docusign", "esignature", "document", "envelope", "signing"],
    "dropbox": ["dropbox", "storage", "sharing", "files", "sync", "collaborate"],
    "linkedin": ["linkedin", "professional", "network", "career", "recruiter"],
    "coinbase": ["coinbase", "crypto", "bitcoin", "ethereum", "wallet", "blockchain"],
    "steam": ["steam", "valve", "gaming", "store", "community", "workshop"],
}


class PhishZooTokenizer:
    """
    Tokenizes HTML content and URL to extract brand-relevant keywords,
    then matches against known brand keyword profiles.
    """

    def __init__(self, html_content: Optional[str] = None, url: str = ""):
        self.html_content = html_content
        self.url = url

    def _tokenize_html(self) -> str:
        """
        Extract visible text tokens from HTML, removing scripts and styles.
        Filters tokens shorter than 3 characters.
        """
        if not self.html_content or len(self.html_content) < 20:
            return ""
        try:
            soup = BeautifulSoup(self.html_content, "html.parser")
            # Kill script and style elements
            for tag in soup(["script", "style"]):
                tag.decompose()

            text = soup.get_text()
            # Clean special characters
            text = re.sub(r"[`=@©#$%^*()_+\[\]{};\\'\\:\"|\u003c,./\u003c\u003e?''-]", " ", "".join(text.splitlines()))
            text = text.replace("\xa0", " ")
            tokens = [t for t in text.split() if len(t) >= 3]
            return " ".join(tokens)
        except Exception as e:
            logger.debug(f"HTML tokenization error: {e}")
            return ""

    def _tokenize_url(self) -> str:
        """
        Extract meaningful tokens from the URL by splitting on delimiters.
        Removes common noise tokens (www, http, com, etc.)
        """
        noise = {"www", "http", "https", "com", "org", "net", "html", "php", "aspx", ""}
        tokens = re.split(r"[`=@©#$%^*()_+\[\]{};\\'\\:\"|\u003c,./\u003c\u003e?''-]", self.url)
        return " ".join(t for t in tokens if t.lower() not in noise and len(t) >= 2)

    def get_combined_tokens(self) -> str:
        """Returns combined HTML + URL tokens."""
        html_tokens = self._tokenize_html()
        url_tokens = self._tokenize_url()
        return (html_tokens + " " + url_tokens).strip()

    def match_brand_keywords(self) -> Dict[str, Any]:
        """
        Matches combined tokens against known brand keyword profiles.

        Returns dict with:
        - detected_brand: best matching brand (or None)
        - brand_confidence: 0.0-1.0 confidence score
        - matched_keywords: list of matched keywords
        - token_count: total extracted tokens
        """
        combined = self.get_combined_tokens().lower()
        tokens = set(combined.split())

        best_brand = None
        best_score = 0.0
        best_keywords: List[str] = []

        for brand, keywords in BRAND_KEYWORD_MAP.items():
            matched = [kw for kw in keywords if kw in tokens or any(kw in t for t in tokens)]
            if matched:
                # Weighted scoring: brand name match worth more
                score = 0.0
                for kw in matched:
                    if kw == brand:
                        score += 0.4  # Brand name direct match
                    else:
                        score += 0.15  # Supporting keyword match
                score = min(score, 1.0)

                if score > best_score:
                    best_score = score
                    best_brand = brand
                    best_keywords = matched

        return {
            "detected_brand": best_brand,
            "brand_confidence": round(best_score, 4),
            "matched_keywords": best_keywords,
            "token_count": len(tokens),
            "phishzoo_method": "tfidf_keyword_match"
        }


def analyze_content_brand_match(
    url: str,
    html_content: Optional[str] = None
) -> Dict[str, Any]:
    """
    High-level API: Tokenize URL + HTML and match against brand keyword profiles.
    """
    tokenizer = PhishZooTokenizer(html_content=html_content, url=url)
    return tokenizer.match_brand_keywords()
