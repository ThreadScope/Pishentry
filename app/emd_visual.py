"""
app/emd_visual.py
=================
Earth Mover's Distance (EMD) Visual Signature Comparison Engine.

Adapted from the EMD experiment (Liang et al.) for lightweight,
feature-based visual similarity comparison using color cluster
centroids and spatial distribution analysis.

Unlike deep CNN approaches, EMD compares color histogram signatures
and spatial centroids — effective for detecting visual clones
that reuse the same color palette even if layout shifts.
"""

import logging
import io
from collections import Counter
from math import sqrt
from typing import Optional, Tuple, Dict, Any

import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)

# EMD Configuration (from experiment defaults)
EMD_IMG_W = 100
EMD_IMG_H = 100
EMD_NUM_CLUSTERS = 20  # Top-s dominant color clusters
EMD_CDF_QUANT = 32     # Color quantization depth
EMD_P = 0.5            # Color distance weight
EMD_Q = 0.5            # Centroid spatial distance weight


def _get_color_signature(img: Image.Image) -> Tuple[list, float]:
    """
    Computes the EMD color signature from an image.
    Returns list of ((color_tuple, centroid_xy), frequency) and max color magnitude.
    """
    img = img.resize((EMD_IMG_W, EMD_IMG_H)).convert("RGBA")
    r, g, b, a = img.split()

    rgba_list = []
    pixel_coords = []
    for i in range(img.size[0]):
        for j in range(img.size[1]):
            pixel_coords.append((i, j))
            rgba_list.append((
                r.getpixel((i, j)) % EMD_CDF_QUANT,
                g.getpixel((i, j)) % EMD_CDF_QUANT,
                b.getpixel((i, j)) % EMD_CDF_QUANT,
                a.getpixel((i, j)) % EMD_CDF_QUANT
            ))

    # Get top-s dominant colors
    top_colors = Counter(rgba_list).most_common(EMD_NUM_CLUSTERS)

    signature = []
    r_vals, g_vals, b_vals, a_vals = [], [], [], []

    for color_tuple, freq in top_colors:
        # Compute centroid for this color cluster
        cx, cy = 0.0, 0.0
        for idx, rgba in enumerate(rgba_list):
            if rgba == color_tuple:
                cx += pixel_coords[idx][0]
                cy += pixel_coords[idx][1]
        centroid = (cx / freq, cy / freq)
        signature.append(((color_tuple, centroid), freq))
        r_vals.append(color_tuple[0])
        g_vals.append(color_tuple[1])
        b_vals.append(color_tuple[2])
        a_vals.append(color_tuple[3])

    md_color = sqrt(max(r_vals, default=0)**2 + max(g_vals, default=0)**2 +
                    max(b_vals, default=0)**2 + max(a_vals, default=0)**2)

    return signature, max(md_color, 1e-6)


def compute_emd_similarity(sig_a: list, sig_b: list,
                           md_color_a: float, md_color_b: float) -> float:
    """
    Computes the Earth Mover's Distance based visual similarity between two signatures.
    Returns similarity score in [0.0, 1.0] where higher = more similar.
    """
    md_color = max(md_color_a, md_color_b)
    md_centroid = sqrt(EMD_IMG_W * EMD_IMG_H)

    s = min(len(sig_a), len(sig_b), EMD_NUM_CLUSTERS)
    if s == 0:
        return 0.0

    # Build distance matrices
    dis_color = np.zeros((s, s), dtype=np.float64)
    dis_centroid = np.zeros((s, s), dtype=np.float64)

    for i in range(s):
        color_a = sig_a[i][0][0]
        centroid_a = sig_a[i][0][1]
        for j in range(s):
            color_b = sig_b[j][0][0]
            centroid_b = sig_b[j][0][1]

            c_diff = tuple(a - b for a, b in zip(color_a, color_b))
            s_diff = (centroid_a[0] - centroid_b[0], centroid_a[1] - centroid_b[1])

            dis_color[i][j] = sqrt(sum(x * x for x in c_diff))
            dis_centroid[i][j] = sqrt(sum(x * x for x in s_diff))

    # Normalize
    dis_color /= max(md_color, 1e-6)
    dis_centroid /= max(md_centroid, 1e-6)

    # Weighted combined distance
    dis = EMD_P * dis_color + EMD_Q * dis_centroid

    # Greedy minimum cost matching
    emd = 0.0
    remaining = dis.copy()
    for i in range(min(s, remaining.shape[0])):
        if remaining.shape[1] == 0:
            break
        min_d = np.min(remaining[0])
        min_idx = np.argmin(remaining[0])
        emd += min_d
        remaining = np.delete(remaining, 0, axis=0)
        remaining = np.delete(remaining, min_idx, axis=1)

    emd /= max(s, 1)

    # Non-linear scaling (from original experiment)
    if emd > 0.3:
        emd *= 2
    elif emd < 0.3:
        emd /= 2

    similarity = max(0.0, 1.0 - emd)
    return round(similarity, 4)


def compare_screenshots_emd(
    candidate_bytes: bytes,
    reference_path_or_bytes: Any
) -> Dict[str, Any]:
    """
    Compares a candidate screenshot against a reference using EMD visual signatures.

    Args:
        candidate_bytes: PNG/JPEG bytes of the candidate screenshot
        reference_path_or_bytes: Either a file path (str) or bytes of the reference image

    Returns:
        Dict with emd_similarity, color_distance, and is_visual_clone flag.
    """
    result = {
        "emd_similarity": 0.0,
        "is_visual_clone": False,
        "emd_threshold": 0.955
    }

    try:
        cand_img = Image.open(io.BytesIO(candidate_bytes))
        if isinstance(reference_path_or_bytes, str):
            ref_img = Image.open(reference_path_or_bytes)
        elif isinstance(reference_path_or_bytes, bytes):
            ref_img = Image.open(io.BytesIO(reference_path_or_bytes))
        else:
            return result

        sig_a, md_a = _get_color_signature(cand_img)
        sig_b, md_b = _get_color_signature(ref_img)

        sim = compute_emd_similarity(sig_a, sig_b, md_a, md_b)
        result["emd_similarity"] = sim
        result["is_visual_clone"] = bool(sim >= 0.955)

    except Exception as e:
        logger.debug(f"EMD comparison error: {e}")

    return result
