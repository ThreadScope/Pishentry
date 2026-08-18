import io
import logging
from typing import Dict, Tuple, Optional
import numpy as np
from PIL import Image

try:
    import torch
    import torchvision.transforms as T
    from torchvision.models import resnet50, ResNet50_Weights
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

logger = logging.getLogger(__name__)

def compute_image_dhash(image: Image.Image, hash_size: int = 8) -> int:
    """Computes 64-bit difference hash (dHash) of an image for perceptual layout comparison."""
    try:
        resized = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.BILINEAR)
        pixels = np.array(resized, dtype=np.uint8).flatten()
        diff = []
        for row in range(hash_size):
            for col in range(hash_size):
                p_left = int(pixels[row * (hash_size + 1) + col])
                p_right = int(pixels[row * (hash_size + 1) + col + 1])
                diff.append(p_left > p_right)
        
        decimal_val = 0
        for idx, val in enumerate(diff):
            if val:
                decimal_val += 1 << idx
        return decimal_val
    except Exception as e:
        logger.debug(f"dHash error: {e}")
        return 0

def compute_dhash_similarity(hash1: Optional[int], hash2: Optional[int], bits: int = 64) -> float:
    """Calculates normalized similarity [0.0, 1.0] from Hamming distance."""
    if hash1 is None or hash2 is None:
        return 0.0
    if hash1 == hash2:
        return 1.0
    xor_val = hash1 ^ hash2
    dist = bin(xor_val).count("1")
    return round(max(0.0, 1.0 - (dist / bits)), 4)


class VisualEmbedder:
    def __init__(self):
        self.device = "cuda" if (HAS_TORCH and torch.cuda.is_available()) else "cpu"
        self.model = None
        self.transform = None
        self._init_model()

    def _init_model(self):
        if not HAS_TORCH:
            logger.warning("PyTorch/torchvision not available. Visual similarity will use fallback histogram matching.")
            return

        try:
            weights = ResNet50_Weights.DEFAULT
            model = resnet50(weights=weights)
            model.fc = torch.nn.Identity()
            model.eval()
            model.to(self.device)
            self.model = model
            self.transform = weights.transforms()
            logger.info("ResNet-50 visual feature extractor loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load ResNet-50 model: {e}")
            self.model = None

    def get_image_embedding(self, image_bytes_or_pil) -> np.ndarray:
        """
        Generates 2048-dim normalized embedding vector from image bytes or PIL Image.
        Safely handles corrupt or unreadable image data.
        """
        try:
            if isinstance(image_bytes_or_pil, bytes):
                if not image_bytes_or_pil:
                    return np.zeros(2048 if (self.model is not None) else 768, dtype=np.float32)
                image = Image.open(io.BytesIO(image_bytes_or_pil)).convert("RGB")
            elif isinstance(image_bytes_or_pil, Image.Image):
                image = image_bytes_or_pil.convert("RGB")
            else:
                return np.zeros(2048 if (self.model is not None) else 768, dtype=np.float32)
        except Exception as e:
            logger.warning(f"Error decoding image for visual embedding: {e}")
            return np.zeros(2048 if (self.model is not None) else 768, dtype=np.float32)

        if self.model is not None and self.transform is not None:
            try:
                tensor = self.transform(image).unsqueeze(0).to(self.device)
                with torch.no_grad():
                    feat = self.model(tensor).squeeze(0).cpu().numpy()
                norm = np.linalg.norm(feat)
                if norm > 0:
                    feat = feat / norm
                return feat.astype(np.float32)
            except Exception as e:
                logger.error(f"Error during ResNet inference: {e}")
                return np.zeros(2048, dtype=np.float32)
        else:
            try:
                image_resized = image.resize((128, 128))
                hist = image_resized.histogram()
                arr = np.array(hist, dtype=np.float32)
                norm = np.linalg.norm(arr)
                return (arr / norm) if norm > 0 else arr
            except Exception as e:
                logger.error(f"Error generating fallback histogram embedding: {e}")
                return np.zeros(768, dtype=np.float32)

def compute_cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
    """
    Computes cosine similarity between two normalized vectors per FR-VIS-03.
    """
    if vec1 is None or vec2 is None:
        return 0.0
    try:
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        if norm1 == 0 or norm2 == 0:
            return 0.0
        dot = np.dot(vec1, vec2)
        sim = dot / (norm1 * norm2)
        if np.isnan(sim) or np.isinf(sim):
            return 0.0
        return round(float(np.clip(sim, 0.0, 1.0)), 4)
    except Exception as e:
        logger.warning(f"Cosine similarity error: {e}")
        return 0.0

class ReferenceBrandVisualStore:
    """
    Precomputes and caches dual-engine visual representations:
    1. 2048-dim ResNet-50 deep semantic embeddings
    2. 64-bit perceptual difference hashes (dHash)
    """
    def __init__(self, embedder: VisualEmbedder):
        self.embedder = embedder
        self.brand_embeddings: Dict[str, np.ndarray] = {}
        self.brand_hashes: Dict[str, int] = {}

    def load_reference_brand(self, brand_id: str, image_path: str):
        try:
            with open(image_path, "rb") as f:
                img_bytes = f.read()
            emb = self.embedder.get_image_embedding(img_bytes)
            self.brand_embeddings[brand_id] = emb
            
            # Compute dHash
            pil_img = Image.open(io.BytesIO(img_bytes))
            self.brand_hashes[brand_id] = compute_image_dhash(pil_img)
            logger.info(f"Loaded and cached dual-engine visual embeddings for brand: {brand_id}")
        except Exception as e:
            logger.error(f"Failed to load reference image for {brand_id} from {image_path}: {e}")

    def find_best_match(self, candidate_image_bytes: bytes) -> Tuple[float, Optional[str]]:
        """
        Computes dual-engine similarity (ResNet cosine + perceptual dHash)
        Returns (highest_similarity_score, matched_brand_id).
        """
        if not candidate_image_bytes or not self.brand_embeddings:
            return 0.0, None

        candidate_emb = self.embedder.get_image_embedding(candidate_image_bytes)
        if np.linalg.norm(candidate_emb) == 0:
            return 0.0, None

        cand_hash = 0
        try:
            cand_img = Image.open(io.BytesIO(candidate_image_bytes))
            cand_hash = compute_image_dhash(cand_img)
        except Exception:
            pass

        best_score = 0.0
        best_brand = None

        for brand_id, ref_emb in self.brand_embeddings.items():
            cos_score = compute_cosine_similarity(candidate_emb, ref_emb)
            ref_hash = self.brand_hashes.get(brand_id, 0)
            
            if cand_hash and ref_hash:
                dhash_score = compute_dhash_similarity(cand_hash, ref_hash)
                # If layout hash is low (< 0.45), heavily penalize to prevent false white-page matches
                if dhash_score < 0.45:
                    combined_score = round(0.30 * cos_score + 0.70 * dhash_score, 4)
                else:
                    combined_score = round(0.60 * cos_score + 0.40 * dhash_score, 4)
            else:
                combined_score = cos_score


            if combined_score > best_score:
                best_score = combined_score
                best_brand = brand_id

        # Require minimum confidence threshold to prevent false brand attribution on generic pages
        if best_score < 0.60:
            return best_score, None

        return best_score, best_brand




