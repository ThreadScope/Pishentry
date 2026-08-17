import os
import json
import logging
from typing import List, Tuple, Dict, Optional, Set
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def extract_tag_sequence(html_content: str) -> List[str]:
    """
    Parses HTML and extracts a sequence of tag names (ignoring scripts, styles, comments).
    """
    if not html_content or not html_content.strip():
        return []
    
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        tags = []
        for elem in soup.find_all(True):
            if elem.name not in ["script", "style", "meta", "link", "noscript", "svg", "path"]:
                tags.append(elem.name.lower())
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
    Compares candidate DOM against reference brand DOM snapshots per FR-DOM-03.
    Returns (highest_score, matched_brand_id).
    """
    if not candidate_html or not brand_dom_map:
        return 0.0, None
        
    best_score = 0.0
    best_brand = None

    for brand_id, ref_html in brand_dom_map.items():
        score = compute_dom_similarity(candidate_html, ref_html)
        if score > best_score:
            best_score = score
            best_brand = brand_id

    return best_score, best_brand
