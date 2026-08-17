# PhishSentry AI — Multi-Modal Phishing Detector (MVP)

PhishSentry AI is a single-URL phishing detector that fuses **Lexical (URL)**, **DOM Structural**, and **Visual Similarity** signals into a unified XGBoost classifier with SHAP-based explainability.

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Environment Setup
```powershell
# Create & activate Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt

# Install Playwright browser binaries
playwright install chromium
```

### 2. Run Unit Tests (Phases 1–7 Validation)
```powershell
pytest -v
```

### 3. Launch Both Backend & Frontend (Recommended)
```powershell
python start.py
```
This script automatically starts:
- **FastAPI Backend API**: [http://127.0.0.1:8000](http://127.0.0.1:8000) (Docs at `/docs`)
- **Streamlit Demo UI**: [http://localhost:8501](http://localhost:8501)

---

### 4. Build Dataset & Train Fusion Model (Optional Offline Training)
```powershell
python -m training.build_dataset
python -m training.train_fusion_model
```

### 5. Running Services Individually
```powershell
# Start Backend API only
uvicorn app.main:app --reload --port 8000

# Start Streamlit UI only
streamlit run ui/streamlit_app.py
```

---

## 🏗️ Architecture & Signal Pipeline

```
URL Input
   │
   ├─► Lexical features (Entropy, Levenshtein, Punycode, TLD) ──┐
   │                                                            │
   ├─► Playwright Render ─► DOM Tree ─► Tag n-gram similarity   ├─► XGBoost Fusion ─► S_phish + SHAP
   │                                                            │
   └─► Screenshot ─► ResNet-50 Embedding ─► Cosine Similarity  ──┘
       vs. protected_brands.json Reference Set
```

- **Lexical Module (`app/lexical.py`)**: Pure function, zero network calls. Computes Shannon entropy, min Levenshtein distance to protected brands, homoglyph/punycode checks, and suspicious TLD flags.
- **Renderer (`app/renderer.py`)**: Headless Playwright browser wrapper with a 10s hard timeout and graceful fallback on timeout/network block (NFR-04).
- **DOM Similarity (`app/dom_similarity.py`)**: Normalized tag-sequence n-gram overlap (Jaccard similarity) against stored brand snapshots.
- **Visual Similarity (`app/visual_similarity.py`)**: Pretrained ResNet-50 2048-dim feature embedding with cosine similarity against cached reference brand screenshots.
- **Fusion & Explainability (`app/fusion.py`)**: Gradient-boosted tree (XGBoost) combining $S_{lex}$, $S_{dom}$, and $S_{vis}$ into $S_{phish} \in [0, 1]$ with SHAP feature contribution breakdown.

---

## 📁 Repository Structure

```
phishsentry/
├── README.md
├── requirements.txt
├── PhishSentry_AI_BUILD_INSTRUCTIONS.md
├── PhishSentry_AI_MVP_PRD.md
├── PhishSentry_AI_MVP_SRS.md
├── PhishSentry_AI_System_Design.md
├── app/
│   ├── main.py                 # FastAPI application
│   ├── lexical.py              # Phase 1 lexical analyzer
│   ├── renderer.py             # Phase 3 Playwright renderer
│   ├── dom_similarity.py       # Phase 4 DOM n-gram similarity
│   ├── visual_similarity.py    # Phase 5 ResNet visual embedding
│   ├── fusion.py                # Phase 6 XGBoost fusion + SHAP
│   └── schemas.py               # Pydantic data schemas
├── data/
│   ├── protected_brands.json   # Ground-truth reference brand store
│   └── reference/              # Canonical screenshots, logos & DOMs
├── training/
│   ├── build_dataset.py        # Dataset builder
│   ├── train_fusion_model.py   # Training script & held-out eval
│   └── model.pkl               # Saved XGBoost artifact
├── tests/                      # Pytest unit & integration tests
└── ui/
    └── streamlit_app.py        # Streamlit demo dashboard
```
