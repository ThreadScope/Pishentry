import io
import logging
from typing import Dict, Tuple, Optional, List
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
            # Remove classification head to get 2048-dim embedding
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
        Generates 2048-dim normalized embedding vector from image bytes or PIL Image per FR-VIS-02.
        """
        if isinstance(image_bytes_or_pil, bytes):
            image = Image.open(io.BytesIO(image_bytes_or_pil)).convert("RGB")
        elif isinstance(image_bytes_or_pil, Image.Image):
            image = image_bytes_or_pil.convert("RGB")
        else:
            raise ValueError("Input must be image bytes or PIL Image")

        if self.model is not None and self.transform is not None:
            tensor = self.transform(image).unsqueeze(0).to(self.device)
            with torch.no_grad():
                feat = self.model(tensor).squeeze(0).cpu().numpy()
            norm = np.linalg.norm(feat)
            if norm > 0:
                feat = feat / norm
            return feat.astype(np.float32)
        else:
            # Fallback color histogram embedding if torch unavailable
            image_resized = image.resize((128, 128))
            hist = image_resized.histogram()
            arr = np.array(hist, dtype=np.float32)
            norm = np.linalg.norm(arr)
            return (arr / norm) if norm > 0 else arr

def compute_cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
    """
    Computes cosine similarity between two normalized vectors per FR-VIS-03.
    """
    if vec1 is None or vec2 is None:
        return 0.0
    dot = np.dot(vec1, vec2)
    norm1 = np.linalg.norm(vec1)
    norm2 = np.linalg.norm(vec2)
    if norm1 == 0 or norm2 == 0:
        return 0.0
    sim = dot / (norm1 * norm2)
    return round(float(sim), 4)

class ReferenceBrandVisualStore:
    """
    Precomputes and caches reference brand visual embeddings per FR-VIS-05.
    """
    def __init__(self, embedder: VisualEmbedder):
        self.embedder = embedder
        self.brand_embeddings: Dict[str, np.ndarray] = {}

    def load_reference_brand(self, brand_id: str, image_path: str):
        try:
            with open(image_path, "rb") as f:
                img_bytes = f.read()
            emb = self.embedder.get_image_embedding(img_bytes)
            self.brand_embeddings[brand_id] = emb
            logger.info(f"Loaded and cached visual embedding for brand: {brand_id}")
        except Exception as e:
            logger.error(f"Failed to load reference image for {brand_id} from {image_path}: {e}")

    def find_best_match(self, candidate_image_bytes: bytes) -> Tuple[float, Optional[str]]:
        """
        Computes cosine similarity against stored brand embeddings per FR-VIS-03 and FR-VIS-04.
        Returns (highest_similarity_score, matched_brand_id).
        """
        if not candidate_image_bytes or not self.brand_embeddings:
            return 0.0, None

        candidate_emb = self.embedder.get_image_embedding(candidate_image_bytes)
        best_score = 0.0
        best_brand = None

        for brand_id, ref_emb in self.brand_embeddings.items():
            score = compute_cosine_similarity(candidate_emb, ref_emb)
            if score > best_score:
                best_score = score
                best_brand = brand_id

        return best_score, best_brand
