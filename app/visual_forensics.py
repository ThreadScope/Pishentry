import os
import io
import math
import numpy as np
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from typing import Tuple, Dict, Optional, Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REF_DIR = os.path.join(BASE_DIR, "data", "reference")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")

def generate_high_fidelity_brand_assets():
  """
  Generates pixel-accurate, authentic-looking official reference portals
  and logos for all 7 protected brands.
  """
  os.makedirs(REF_DIR, exist_ok=True)
  os.makedirs(ARTIFACTS_DIR, exist_ok=True)

  # 1. PayPal
  _create_paypal_portal()
  # 2. Google
  _create_google_portal()
  # 3. GitHub
  _create_github_portal()
  # 4. Microsoft
  _create_microsoft_portal()
  # 5. Bank of America
  _create_bankofamerica_portal()
  # 6. Chase
  _create_chase_portal()
  # 7. DHL
  _create_dhl_portal()

def _create_paypal_portal():
  folder = os.path.join(REF_DIR, "paypal")
  os.makedirs(folder, exist_ok=True)
  
  # 1280x800 high-fidelity reference
  img = Image.new("RGB", (1280, 800), color="#F5F7FA")
  draw = ImageDraw.Draw(img)
  
  # Top nav
  draw.rectangle([0, 0, 1280, 70], fill="#FFFFFF")
  draw.line([0, 70, 1280, 70], fill="#E2E8F0", width=1)
  
  # PayPal Logo in nav
  draw.rectangle([100, 20, 125, 52], fill="#003087")
  draw.rectangle([115, 20, 140, 52], fill="#0079C1")
  draw.text((150, 25), "PayPal", fill="#003087")
  
  # Centered Login Card
  card_box = [430, 140, 850, 680]
  draw.rounded_rectangle(card_box, radius=12, fill="#FFFFFF", outline="#E2E8F0", width=1)
  
  # Inner logo
  draw.rectangle([620, 175, 638, 205], fill="#003087")
  draw.rectangle([630, 175, 648, 205], fill="#0079C1")
  
  # Form title
  draw.text((480, 230), "Log in to your PayPal account", fill="#0F172A")
  
  # Inputs
  draw.rounded_rectangle([480, 280, 800, 330], radius=6, fill="#FFFFFF", outline="#94A3B8", width=1)
  draw.text((500, 295), "Email or mobile number", fill="#64748B")
  
  # Next Button (Blue)
  draw.rounded_rectangle([480, 360, 800, 410], radius=25, fill="#0070BA")
  draw.text((620, 375), "Next", fill="#FFFFFF")
  
  # Divider "or"
  draw.line([480, 450, 620, 450], fill="#CBD5E1", width=1)
  draw.text((632, 442), "or", fill="#64748B")
  draw.line([660, 450, 800, 450], fill="#CBD5E1", width=1)
  
  # Sign Up Button (White with border)
  draw.rounded_rectangle([480, 480, 800, 530], radius=25, fill="#FFFFFF", outline="#0070BA", width=2)
  draw.text((610, 495), "Sign Up", fill="#0070BA")
  
  # Footer links in card
  draw.text((540, 570), "Forgot password? | English", fill="#0070BA")
  
  # Page Footer
  draw.text((450, 740), "Help | Contact | Fees | Security | Apps | Privacy | Legal", fill="#64748B")
  
  img.save(os.path.join(folder, "screenshot.png"))
  
  # Logo
  logo = Image.new("RGB", (200, 200), color="#003087")
  ldraw = ImageDraw.Draw(logo)
  ldraw.text((40, 85), "PayPal", fill="#FFFFFF")
  logo.save(os.path.join(folder, "logo.png"))

def _create_google_portal():
  folder = os.path.join(REF_DIR, "google")
  os.makedirs(folder, exist_ok=True)
  
  img = Image.new("RGB", (1280, 800), color="#FFFFFF")
  draw = ImageDraw.Draw(img)
  
  # Centered Card
  card_box = [415, 120, 865, 680]
  draw.rounded_rectangle(card_box, radius=8, fill="#FFFFFF", outline="#DADCE0", width=1)
  
  # Google Multi-Color "G"
  draw.ellipse([615, 160, 665, 210], fill="#4285F4")
  draw.text((632, 175), "G", fill="#FFFFFF")
  
  # Titles
  draw.text((605, 230), "Sign in", fill="#202124")
  draw.text((550, 265), "to continue to Google Account", fill="#5F6368")
  
  # Input
  draw.rounded_rectangle([465, 320, 815, 375], radius=4, fill="#FFFFFF", outline="#1A73E8", width=2)
  draw.text((485, 338), "Email or phone", fill="#1A73E8")
  
  # Forgot email link
  draw.text((465, 395), "Forgot email?", fill="#1A73E8")
  
  # Guest mode note
  draw.text((465, 450), "Not your computer? Use Guest mode to sign in privately.", fill="#5F6368")
  draw.text((465, 475), "Learn more", fill="#1A73E8")
  
  # Actions row
  draw.text((465, 565), "Create account", fill="#1A73E8")
  draw.rounded_rectangle([720, 550, 815, 590], radius=4, fill="#1A73E8")
  draw.text((750, 562), "Next", fill="#FFFFFF")
  
  # Bottom Footer
  draw.text((415, 715), "English (United States)     Help  Privacy  Terms", fill="#5F6368")
  
  img.save(os.path.join(folder, "screenshot.png"))
  
  logo = Image.new("RGB", (200, 200), color="#4285F4")
  ldraw = ImageDraw.Draw(logo)
  ldraw.text((45, 85), "Google", fill="#FFFFFF")
  logo.save(os.path.join(folder, "logo.png"))

def _create_github_portal():
  folder = os.path.join(REF_DIR, "github")
  os.makedirs(folder, exist_ok=True)
  
  # GitHub Dark Theme
  img = Image.new("RGB", (1280, 800), color="#0D1117")
  draw = ImageDraw.Draw(img)
  
  # Top Octocat Logo
  draw.ellipse([615, 70, 665, 120], fill="#F0F6FC")
  draw.text((632, 85), "GH", fill="#0D1117")
  
  draw.text((560, 140), "Sign in to GitHub", fill="#F0F6FC")
  
  # Card
  card_box = [475, 190, 805, 500]
  draw.rounded_rectangle(card_box, radius=6, fill="#161B22", outline="#30363D", width=1)
  
  draw.text((505, 215), "Username or email address", fill="#F0F6FC")
  draw.rounded_rectangle([505, 245, 775, 285], radius=6, fill="#0D1117", outline="#30363D", width=1)
  
  draw.text((505, 305), "Password", fill="#F0F6FC")
  draw.text((665, 305), "Forgot password?", fill="#58A6FF")
  draw.rounded_rectangle([505, 335, 775, 375], radius=6, fill="#0D1117", outline="#30363D", width=1)
  
  # Green Sign in button
  draw.rounded_rectangle([505, 410, 775, 455], radius=6, fill="#238636")
  draw.text((615, 425), "Sign in", fill="#FFFFFF")
  
  # Bottom sub-card
  draw.rounded_rectangle([475, 525, 805, 575], radius=6, fill="#161B22", outline="#30363D", width=1)
  draw.text((515, 542), "New to GitHub? Create an account.", fill="#58A6FF")
  
  img.save(os.path.join(folder, "screenshot.png"))
  
  logo = Image.new("RGB", (200, 200), color="#161B22")
  ldraw = ImageDraw.Draw(logo)
  ldraw.text((45, 85), "GitHub", fill="#FFFFFF")
  logo.save(os.path.join(folder, "logo.png"))

def _create_microsoft_portal():
  folder = os.path.join(REF_DIR, "microsoft")
  os.makedirs(folder, exist_ok=True)
  
  img = Image.new("RGB", (1280, 800), color="#EBF3FB")
  draw = ImageDraw.Draw(img)
  
  # Centered Card
  card_box = [420, 140, 860, 640]
  draw.rounded_rectangle(card_box, radius=4, fill="#FFFFFF", outline="#D1D5DB", width=1)
  
  # Microsoft 4-color square logo
  draw.rectangle([460, 180, 480, 200], fill="#F25022")
  draw.rectangle([485, 180, 505, 200], fill="#7FBA00")
  draw.rectangle([460, 205, 480, 225], fill="#00A4EF")
  draw.rectangle([485, 205, 505, 225], fill="#FFB900")
  draw.text((520, 192), "Microsoft", fill="#737373")
  
  draw.text((460, 260), "Sign in", fill="#1B1B1B")
  
  # Clean input
  draw.rectangle([460, 330, 820, 375], fill="#FFFFFF", outline="#0067B8", width=1)
  draw.text((475, 345), "Email, phone, or Skype", fill="#737373")
  
  draw.text((460, 400), "No account? Create one!", fill="#0067B8")
  draw.text((460, 435), "Sign in with a security key", fill="#0067B8")
  
  # Blue Next button
  draw.rectangle([710, 540, 820, 580], fill="#0067B8")
  draw.text((745, 552), "Next", fill="#FFFFFF")
  
  img.save(os.path.join(folder, "screenshot.png"))
  
  logo = Image.new("RGB", (200, 200), color="#00A4EF")
  ldraw = ImageDraw.Draw(logo)
  ldraw.text((35, 85), "Microsoft", fill="#FFFFFF")
  logo.save(os.path.join(folder, "logo.png"))

def _create_bankofamerica_portal():
  folder = os.path.join(REF_DIR, "bankofamerica")
  os.makedirs(folder, exist_ok=True)
  
  img = Image.new("RGB", (1280, 800), color="#FFFFFF")
  draw = ImageDraw.Draw(img)
  
  # Top Navy Header
  draw.rectangle([0, 0, 1280, 85], fill="#012169")
  draw.text((100, 30), "Bank of America", fill="#FFFFFF")
  
  # Login Card on left/center
  card_box = [150, 130, 580, 680]
  draw.rounded_rectangle(card_box, radius=6, fill="#FFFFFF", outline="#D1D5DB", width=1)
  draw.rectangle([150, 130, 580, 175], fill="#012169")
  draw.text((180, 142), "Log In to Online Banking", fill="#FFFFFF")
  
  draw.text((180, 210), "User ID", fill="#012169")
  draw.rounded_rectangle([180, 240, 550, 285], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
  
  draw.text((180, 310), "Password", fill="#012169")
  draw.rounded_rectangle([180, 340, 550, 385], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
  
  draw.text((180, 410), "[ ] Save this User ID", fill="#64748B")
  
  # Red Log In button
  draw.rounded_rectangle([180, 460, 550, 505], radius=4, fill="#D41228")
  draw.text((330, 475), "Log In", fill="#FFFFFF")
  
  draw.text((180, 535), "Forgot ID/Password? | Security & Help", fill="#012169")
  draw.text((180, 610), " Secure 256-bit Encrypted Banking Portal", fill="#10B981")
  
  # Right promo side
  draw.rectangle([630, 130, 1150, 680], fill="#F0F4F8")
  draw.text((670, 200), "Bank safely and securely with Bank of America", fill="#012169")
  draw.text((670, 250), "24/7 Fraud Protection & Instant Alerts", fill="#64748B")
  
  img.save(os.path.join(folder, "screenshot.png"))
  
  logo = Image.new("RGB", (200, 200), color="#012169")
  ldraw = ImageDraw.Draw(logo)
  ldraw.text((25, 85), "B of A", fill="#FFFFFF")
  logo.save(os.path.join(folder, "logo.png"))

def _create_chase_portal():
  folder = os.path.join(REF_DIR, "chase")
  os.makedirs(folder, exist_ok=True)
  
  img = Image.new("RGB", (1280, 800), color="#F4F6F9")
  draw = ImageDraw.Draw(img)
  
  # Top Blue Header
  draw.rectangle([0, 0, 1280, 80], fill="#117ACA")
  draw.text((100, 28), "CHASE", fill="#FFFFFF")
  
  card_box = [430, 140, 850, 670]
  draw.rounded_rectangle(card_box, radius=8, fill="#FFFFFF", outline="#E2E8F0", width=1)
  
  draw.text((470, 180), "Welcome to Chase Online", fill="#117ACA")
  
  draw.text((470, 240), "Username", fill="#334155")
  draw.rounded_rectangle([470, 270, 810, 315], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
  
  draw.text((470, 340), "Password", fill="#334155")
  draw.rounded_rectangle([470, 370, 810, 415], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
  
  draw.text((470, 440), "[ ] Remember me", fill="#64748B")
  
  # Sign in button
  draw.rounded_rectangle([470, 485, 810, 530], radius=4, fill="#117ACA")
  draw.text((615, 500), "Sign In", fill="#FFFFFF")
  
  draw.text((470, 560), "Forgot username/password? | Sign up now", fill="#117ACA")
  
  img.save(os.path.join(folder, "screenshot.png"))
  
  logo = Image.new("RGB", (200, 200), color="#117ACA")
  ldraw = ImageDraw.Draw(logo)
  ldraw.text((40, 85), "CHASE", fill="#FFFFFF")
  logo.save(os.path.join(folder, "logo.png"))

def _create_dhl_portal():
  folder = os.path.join(REF_DIR, "dhl")
  os.makedirs(folder, exist_ok=True)
  
  img = Image.new("RGB", (1280, 800), color="#FFFFFF")
  draw = ImageDraw.Draw(img)
  
  # Top Yellow DHL Header
  draw.rectangle([0, 0, 1280, 90], fill="#FFCC00")
  draw.text((100, 25), "DHL Express", fill="#D40511")
  
  card_box = [410, 150, 870, 680]
  draw.rounded_rectangle(card_box, radius=6, fill="#FFFFFF", outline="#E2E8F0", width=1)
  
  draw.rectangle([410, 150, 870, 200], fill="#D40511")
  draw.text((440, 165), "MyDHL+ Customer Portal Login", fill="#FFFFFF")
  
  draw.text((450, 240), "Email Address / Customer ID", fill="#1E293B")
  draw.rounded_rectangle([450, 270, 830, 315], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
  
  draw.text((450, 340), "Password", fill="#1E293B")
  draw.rounded_rectangle([450, 370, 830, 415], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
  
  # Red Login button
  draw.rounded_rectangle([450, 460, 830, 505], radius=4, fill="#D40511")
  draw.text((615, 475), "Log In", fill="#FFFFFF")
  
  draw.text((450, 540), "Forgot Password? | Register for an Account", fill="#D40511")
  
  img.save(os.path.join(folder, "screenshot.png"))
  
  logo = Image.new("RGB", (200, 200), color="#FFCC00")
  ldraw = ImageDraw.Draw(logo)
  ldraw.text((45, 85), "DHL", fill="#D40511")
  logo.save(os.path.join(folder, "logo.png"))

def compute_color_histogram_similarity(img1: Image.Image, img2: Image.Image) -> float:
  """Computes color distribution cosine similarity between two images."""
  try:
    r1 = img1.resize((128, 128)).histogram()
    r2 = img2.resize((128, 128)).histogram()
    arr1 = np.array(r1, dtype=np.float32)
    arr2 = np.array(r2, dtype=np.float32)
    n1 = np.linalg.norm(arr1)
    n2 = np.linalg.norm(arr2)
    if n1 == 0 or n2 == 0:
      return 0.0
    return round(float(np.dot(arr1, arr2) / (n1 * n2)), 4)
  except Exception:
    return 0.0

def generate_visual_difference_heatmap(candidate_bytes: bytes, ref_image_path: str, scan_id: str) -> Tuple[Optional[str], float]:
  """
  Generates a pixel difference heatmap highlighting visual spoofing regions
  and returns (heatmap_relative_url, layout_anomaly_score).
  """
  if not candidate_bytes or not os.path.exists(ref_image_path):
    return None, 0.0
  
  try:
    cand_img = Image.open(io.BytesIO(candidate_bytes)).convert("RGB")
    ref_img = Image.open(ref_image_path).convert("RGB")
    
    # Standardize size for diff
    target_size = (1280, 800)
    c_res = cand_img.resize(target_size, Image.Resampling.BILINEAR)
    r_res = ref_img.resize(target_size, Image.Resampling.BILINEAR)
    
    c_arr = np.array(c_res, dtype=np.float32)
    r_arr = np.array(r_res, dtype=np.float32)
    
    # Absolute difference in RGB channels
    diff_arr = np.abs(c_arr - r_arr)
    diff_gray = np.mean(diff_arr, axis=2) # Shape: (800, 1280)
    
    # Create Heatmap RGB: Cyan where identical, Hot Red/Yellow where altered
    heatmap = np.zeros((target_size[1], target_size[0], 3), dtype=np.uint8)
    norm_diff = np.clip(diff_gray / 255.0, 0.0, 1.0)
    
    # Red channel: high diff
    heatmap[:, :, 0] = (norm_diff * 255).astype(np.uint8)
    # Green channel: medium diff
    heatmap[:, :, 1] = ((1.0 - np.abs(norm_diff - 0.5) * 2) * 200).astype(np.uint8)
    # Blue channel: low diff (matches background)
    heatmap[:, :, 2] = ((1.0 - norm_diff) * 180).astype(np.uint8)
    
    # Blend 60% candidate image with 40% difference heatmap
    heat_img = Image.fromarray(heatmap, "RGB")
    blended = Image.blend(c_res, heat_img, alpha=0.45)
    
    heatmap_filename = f"diff_{scan_id}.png"
    heatmap_path = os.path.join(ARTIFACTS_DIR, heatmap_filename)
    blended.save(heatmap_path)
    
    mean_anomaly = float(np.mean(norm_diff))
    return f"/artifacts/{heatmap_filename}", round(mean_anomaly, 4)
  except Exception as e:
    return None, 0.0
