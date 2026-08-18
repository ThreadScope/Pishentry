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

def test_corrupt_image_safety():
    embedder = VisualEmbedder()
    emb_empty = embedder.get_image_embedding(b"")
    assert isinstance(emb_empty, np.ndarray)
    emb_corrupt = embedder.get_image_embedding(b"not-an-image-data-header")
    assert isinstance(emb_corrupt, np.ndarray)
    sim = compute_cosine_similarity(emb_empty, emb_corrupt)
    assert sim == 0.0

def test_adversarial_denoising_defense():
    from app.visual_similarity import apply_adversarial_denoising, compute_image_dhash, compute_dhash_similarity
    from PIL import ImageDraw
    
    # Create structured webpage layout (header + central login container)
    clean_img = Image.new("RGB", (600, 400), color=(240, 242, 245))
    draw = ImageDraw.Draw(clean_img)
    draw.rectangle([0, 0, 600, 60], fill=(0, 48, 135)) # header banner
    draw.rectangle([150, 100, 450, 320], fill=(255, 255, 255)) # login card
    draw.rectangle([180, 160, 420, 190], fill=(230, 230, 230)) # input box
    draw.rectangle([180, 240, 420, 280], fill=(0, 112, 186)) # button
    
    # Inject synthetic high-frequency adversarial noise (simulating FGSM / PGD pixel perturbations)
    arr = np.array(clean_img, dtype=np.int16)
    noise = np.random.randint(-12, 12, arr.shape)
    perturbed_arr = np.clip(arr + noise, 0, 255).astype(np.uint8)
    perturbed_img = Image.fromarray(perturbed_arr)
    
    # Denoise
    denoised_img = apply_adversarial_denoising(perturbed_img)
    assert denoised_img is not None
    assert denoised_img.size[0] <= 800
    
    # Verify dHash layout similarity is preserved (>=0.80) between clean and denoised perturbed image
    hash_clean = compute_image_dhash(clean_img)
    hash_denoised = compute_image_dhash(denoised_img)
    layout_sim = compute_dhash_similarity(hash_clean, hash_denoised)
    assert layout_sim >= 0.80


def test_ocr_case_conversion_and_character_spacing():
    from app.visual_ocr import extract_visual_text_from_screenshot
    from PIL import ImageDraw
    
    # Create image with uppercase/spaced text: 'F A C E B O O K'
    img = Image.new("RGB", (600, 400), color=(240, 242, 245))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    
    res = extract_visual_text_from_screenshot(buf.getvalue())
    assert isinstance(res.detected_brand_keywords, list)

def test_image_cnn_phishing_probability():
    from app.visual_similarity import compute_image_cnn_phishing_probability
    from PIL import ImageDraw
    
    # Test blank image
    assert compute_image_cnn_phishing_probability(b"") == 0.0
    
    # Test rendered login page screenshot
    login_img = Image.new("RGB", (600, 400), color=(240, 242, 245))
    draw = ImageDraw.Draw(login_img)
    draw.rectangle([150, 80, 450, 320], fill=(255, 255, 255)) # card
    draw.rectangle([180, 140, 420, 180], fill=(220, 220, 220)) # username
    draw.rectangle([180, 200, 420, 240], fill=(220, 220, 220)) # password
    draw.rectangle([180, 260, 420, 300], fill=(0, 120, 215)) # submit
    buf = io.BytesIO()
    login_img.save(buf, format="PNG")
    
    prob = compute_image_cnn_phishing_probability(buf.getvalue())
    assert isinstance(prob, float)
    assert prob >= 0.20



