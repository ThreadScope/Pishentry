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

## 📁 Clean Repository Structure

```text
Pishentry/
├── README.md                           # Enterprise documentation & quickstart
├── requirements.txt                    # Python dependencies
├── start.py                            # Unified FastAPI + Streamlit launcher
├── LICENSE                             # MIT License
├── app/                                # Core Engine Backend (FastAPI)
│   ├── main.py                         # FastAPI orchestration & endpoints
│   ├── lexical.py                      # Lexical entropy & typosquat detection
│   ├── renderer.py                     # Headless Playwright & Shadow DOM unroller
│   ├── dom_visibility.py               # Anti-Zero-Font & CSS visibility filter
│   ├── dom_similarity.py               # DOM semantic brand token engine
│   ├── dom_comparator.py               # Formless theft & webhook drop auditor
│   ├── visual_similarity.py            # ResNet-50 + layout dHash matching
│   ├── visual_forensics.py             # Visual anomaly difference heatmap generator
│   ├── phishpedia_engine.py            # USENIX '21 domain-brand consistency model
│   ├── aitm_detector.py                # Reverse-proxy AiTM cloaking detector
│   ├── cloaking_detector.py            # Cloudflare / Bot-wall bypass analyzer
│   ├── quishing_detector.py            # QR code payload decoder & quishing analyzer
│   ├── redirect_tracer.py              # Recursive multi-hop redirect unmasker
│   ├── kit_fingerprinter.py            # Phishing kit & Telegram drop fingerprinter
│   ├── takedown_generator.py           # RFC 2142 / DMCA legal takedown notice generator
│   ├── fusion.py                       # XGBoost multi-modal fusion & SHAP explainer
│   ├── export_rules.py                 # OASIS STIX 2.1, Sigma, YARA & DNS generators
│   ├── telemetry.py                    # TLS & certificate forensics inspector
│   ├── webhook.py                      # Real-time SIEM/SOAR incident webhook dispatcher
│   └── schemas.py                      # Pydantic data schemas
├── data/                               # Ground-Truth Brand Assets & Metadata
│   ├── protected_brands.json           # Protected enterprise brands catalog
│   └── reference/                      # Canonical screenshots, logos & DOM baselines
├── reports/                            # Technical Audit & SOC Analysis Reports
│   ├── false_positive_analysis_report.md  # False positive RCA & remediation report
│   ├── PhishSentry_10X_Full_System_Performance_Audit.md # 10X system audit
│   ├── PhishSentry_10X_SOC_Testing_Report.html           # Interactive SOC test report
│   ├── PhishSentry_10X_SOC_Testing_Report.pdf            # PDF executive report
│   └── Cybersecurity_Skills_Audit_Report.html            # Skills compliance audit
├── scripts/                            # Utility & Maintenance Scripts
│   ├── generate_10x_pdf_report.py      # Automated PDF report compiler
│   └── add_antigravity_skill.py        # Antigravity skill registrar
├── skills/                             # Antigravity Cybersecurity Skills
├── tests/                              # Pytest Regression & Integration Suite (65/65 Passing)
├── training/                           # Dataset Pipelines & Machine Learning Artifacts
│   ├── build_dataset.py                # Dataset builder
│   ├── train_fusion_model.py           # Training pipeline & evaluation metrics
│   ├── dataset.json                    # Synthetic & real-world training samples
│   └── model.pkl                       # Trained XGBoost model artifact
└── ui/                                 # Streamlit Enterprise SOC Triage Console
    └── streamlit_app.py                # Real-time multi-tab triage dashboard
```


