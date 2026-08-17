import io
import pytest
import numpy as np
from PIL import Image
from app.visual_similarity import VisualEmbedder, compute_cosine_similarity, ReferenceBrandVisualStore

def create_dummy_image(color=(255, 0, 0), text="Brand A") -> bytes:
    img = Image.new("RGB", (400, 300), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def test_visual_embedding_self_similarity():
    embedder = VisualEmbedder()
    img_a = create_dummy_image(color=(0, 50, 200))
    
    emb1 = embedder.get_image_embedding(img_a)
    emb2 = embedder.get_image_embedding(img_a)
    
    sim = compute_cosine_similarity(emb1, emb2)
    assert pytest.approx(sim, 0.01) == 1.0

def test_visual_embedding_unrelated_images():
    embedder = VisualEmbedder()
    img_blue = create_dummy_image(color=(0, 0, 255))
    img_white = create_dummy_image(color=(255, 255, 255))
    
    emb_blue = embedder.get_image_embedding(img_blue)
    emb_white = embedder.get_image_embedding(img_white)
    
    sim = compute_cosine_similarity(emb_blue, emb_white)
    # Cosine similarity between blue and white images should be less than self-similarity
    assert sim < 0.95

def test_visual_store_matching():
    embedder = VisualEmbedder()
    store = ReferenceBrandVisualStore(embedder)
    
    img_paypal = create_dummy_image(color=(0, 48, 135))
    emb_paypal = embedder.get_image_embedding(img_paypal)
    store.brand_embeddings["paypal"] = emb_paypal
    
    score, matched = store.find_best_match(img_paypal)
    assert matched == "paypal"
    assert pytest.approx(score, 0.01) == 1.0
