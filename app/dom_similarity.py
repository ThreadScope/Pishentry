"""
app/dom_similarity.py
=====================
DOM Structural & Semantic Brand Disambiguation Engine.

Extracts tag sequences, n-grams, text tokens, form actions, title, and brand signatures
to accurately match candidate web surfaces against protected enterprise brands.
"""

import re
import logging
from typing import List, Tuple, Dict, Optional, Set
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

MAX_HTML_PARSE_LENGTH = 1_000_000  # 1 MB safety cap

BRAND_TOKEN_SIGNATURES: Dict[str, List[str]] = {
    "google": [
        "google", "gmail", "gsuite", "google account", "accounts.google.com",
        "sign in with google", "use your google account", "google llc", "google workspace"
    ],
    "microsoft": [
        "microsoft", "office 365", "office365", "outlook", "login.microsoftonline.com",
        "login.live.com", "azure", "microsoft corporation", "sign in to your microsoft account", "msft"
    ],
    "paypal": [
        "paypal", "paypal inc", "paypal.com", "pay with paypal", "log in to your paypal account",
        "paypal balance", "paypal credit"
    ],
    "github": [
        "github", "github inc", "github.com", "sign in to github", "github enterprise"
    ],
    "bankofamerica": [
        "bank of america", "bofa", "bankofamerica.com", "merrill lynch", "bofaml", "online banking passcode"
    ],
    "chase": [
        "chase", "jpmorgan", "chase.com", "chase online", "chase bank", "jpmorgan chase"
    ],
    "dhl": [
        "dhl", "dhl express", "dhl parcel", "dhl tracking", "dhl.com", "dhl global forwarding"
    ]
}

def extract_tag_sequence(html_content: str) -> List[str]:
    """
    Parses HTML and extracts a sequence of tag names (ignoring scripts, styles, comments).
    """
    if not html_content or not html_content.strip():
        return []
    
    clipped_html = html_content[:MAX_HTML_PARSE_LENGTH]
    
    try:
        soup = BeautifulSoup(clipped_html, "html.parser")
        tags = []
        for elem in soup.find_all(True):
            name = elem.name.lower() if elem.name else ""
            if name not in ["script", "style", "meta", "link", "noscript", "svg", "path", "defs", "clippath"]:
                if name == "input":
                    itype = elem.get("type", "text")
                    tags.append(f"input_{itype}")
                else:
                    tags.append(name)
        return tags
    except Exception as e:
        logger.error(f"Error parsing DOM HTML: {e}")
        return []

def extract_tag_ngrams(tags: List[str], n: int = 2) -> Set[Tuple[str, ...]]:
    """
    Extracts set of n-grams from tag sequence.
    """
    if len(tags) < n:
        return set()
    return set(tuple(tags[i:i+n]) for i in range(len(tags) - n + 1))

from app.dom_visibility import clean_human_visible_dom_text

def extract_dom_semantic_text(html_content: str) -> str:
    """
    Extracts visible text, titles, alt text, form actions, and button labels for semantic disambiguation,
    applying anti-zero-font and computed CSS visibility filters.
    """
    if not html_content or not html_content.strip():
        return ""
    try:
        # First strip hidden CSS/zero-font and zero-width artifacts
        cleaned_body_text, _, _ = clean_human_visible_dom_text(html_content[:MAX_HTML_PARSE_LENGTH])

        soup = BeautifulSoup(html_content[:MAX_HTML_PARSE_LENGTH], "html.parser")
        pieces = [cleaned_body_text.lower()]
        
        # 1. Title tag
        if soup.title and soup.title.string:
            pieces.append(soup.title.string.lower())
            
        # 2. Form actions & inputs
        for f in soup.find_all("form"):
            action = f.get("action") or ""
            pieces.append(action.lower())
        for inp in soup.find_all("input"):
            placeholder = inp.get("placeholder") or ""
            name = inp.get("name") or ""
            pieces.append(f"{name} {placeholder}".lower())
            
        # 3. Image alt & src
        for img in soup.find_all("img"):
            alt = img.get("alt") or ""
            src = img.get("src") or ""
            pieces.append(f"{alt} {src}".lower())
            
        # 4. Button & visible text
        for btn in soup.find_all(["button", "a", "h1", "h2", "h3", "p", "span"]):
            txt = btn.get_text(strip=True)
            if txt:
                pieces.append(txt.lower())
                
        return " ".join(pieces)
    except Exception:
        return html_content.lower()


def compute_brand_semantic_score(dom_text: str, brand_id: str) -> float:
    """
    Evaluates brand keyword token density and distinctive presence in DOM text.
    """
    clean_brand = brand_id.lower().strip()
    signatures = BRAND_TOKEN_SIGNATURES.get(clean_brand, [clean_brand])
    
    score = 0.0
    matched_any = False
    
    for sig in signatures:
        if sig in dom_text:
            matched_any = True
            # Higher weight for exact multi-word brand phrases
            if " " in sig or "." in sig:
                score += 0.40
            else:
                score += 0.25
                
    if matched_any:
        return min(1.0, max(0.50, score))
    return 0.0

def compute_dom_similarity(html1: str, html2: str) -> float:
    """
    Computes normalized tag n-gram overlap (Jaccard similarity) between two DOM trees.
    Combines 1-gram (tag counts), 2-gram, and 3-gram similarity per FR-DOM-02.
    """
    tags1 = extract_tag_sequence(html1)
    tags2 = extract_tag_sequence(html2)
    
    if not tags1 or not tags2:
        return 0.0

    # 1-gram tag set similarity
    set1_1 = set(tags1)
    set2_1 = set(tags2)
    jaccard_1 = len(set1_1 & set2_1) / len(set1_1 | set2_1) if (set1_1 | set2_1) else 0.0

    # 2-gram similarity
    ngrams1_2 = extract_tag_ngrams(tags1, 2)
    ngrams2_2 = extract_tag_ngrams(tags2, 2)
    jaccard_2 = len(ngrams1_2 & ngrams2_2) / len(ngrams1_2 | ngrams2_2) if (ngrams1_2 | ngrams2_2) else 0.0

    # 3-gram similarity
    ngrams1_3 = extract_tag_ngrams(tags1, 3)
    ngrams2_3 = extract_tag_ngrams(tags2, 3)
    jaccard_3 = len(ngrams1_3 & ngrams2_3) / len(ngrams1_3 | ngrams2_3) if (ngrams1_3 | ngrams2_3) else 0.0

    # Weighted combination
    similarity = 0.3 * jaccard_1 + 0.4 * jaccard_2 + 0.3 * jaccard_3
    return round(float(similarity), 4)

def match_dom_against_brands(
    candidate_html: str, 
    brand_dom_map: Dict[str, str]
) -> Tuple[float, Optional[str]]:
    """
    Compares candidate DOM against reference brand DOM snapshots with Semantic Brand Token Disambiguation.
    Returns (highest_score, matched_brand_id).
    """
    if not candidate_html or not brand_dom_map:
        return 0.0, None
        
    candidate_text = extract_dom_semantic_text(candidate_html)
    
    best_score = 0.0
    best_brand = None
    
    # Check if there is an unambiguous direct semantic match
    semantic_scores = {}
    for brand_id in brand_dom_map.keys():
        semantic_scores[brand_id] = compute_brand_semantic_score(candidate_text, brand_id)
        
    for brand_id, ref_html in brand_dom_map.items():
        structural_score = compute_dom_similarity(candidate_html, ref_html)
        sem_score = semantic_scores.get(brand_id, 0.0)
        
        # If semantic brand tokens are present, fuse them with high priority (60% semantic + 40% structural)
        if sem_score > 0:
            combined = round(0.60 * sem_score + 0.40 * structural_score, 4)
            # Add bonus if distinct brand token is exclusively present
            combined = min(1.0, combined + 0.20)
        else:
            # If candidate specifically contains another brand's tokens, suppress this brand
            other_brands_present = any(s > 0 for b, s in semantic_scores.items() if b != brand_id)
            if other_brands_present:
                combined = round(structural_score * 0.30, 4)  # Suppress false tag-only overlap
            else:
                combined = structural_score

        if combined > best_score:
            best_score = combined
            best_brand = brand_id

    # If the score is too low or no brand is indicated, return None
    if best_score < 0.35:
        return 0.0, None

    return best_score, best_brand
