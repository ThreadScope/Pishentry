# PhishSentry AI — Autonomous Multi-Modal Zero-Hour Phishing Detection & Active Triage Engine

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110.0-009688.svg)](https://fastapi.tiangolo.com/)
[![Playwright](https://img.shields.io/badge/Playwright-1.62.0-green.svg)](https://playwright.dev/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.32.0-FF4B4B.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**PhishSentry AI (`Pishentry`)** is an enterprise-grade, tri-modal artificial intelligence system designed to detect and mitigate zero-hour phishing attacks before traditional threat feeds and blocklists update. 

Unlike legacy signature-based filters, PhishSentry AI executes an active **Multi-Modal Inspection Pipeline** combining **Lexical Analysis**, **Headless DOM Forensics**, and **Deep Visual Perception (ResNet-50 + dHash)** into a calibrated **XGBoost Classifier** with **TreeSHAP Explainability** and **Automated 1-Click Takedown Generation**.

---

## 🔑 Key Capabilities & USPs

- ⚡ **Zero-Hour Tri-Modal Fusion Engine**: Concurrent execution of Lexical ($S_{lex}$), DOM Structural ($S_{dom}$), and Deep Visual ($S_{vis}$) feature extraction.
- 🛡️ **Anti-AiTM & Reverse Proxy Detection**: Identifies session-stealing reverse proxies (Evilginx3, Modlishka) bypassing multi-factor authentication (MFA).
- 🔍 **Formless Theft & Webhook Trap Auditor**: Detects stealthy JavaScript exfiltration targeting Discord webhooks, Telegram bots, or Supabase endpoints without HTML `<form>` tags.
- 👁️ **Optical Quishing Scanner**: Scans viewport screenshots for embedded QR codes and unmasks hidden optical redirect payloads.
- 📜 **Phishpedia (USENIX '21) Consistency Engine**: Enforces canonical domain-brand consistency checks to eliminate false positives on legitimate portals.
- ⚖️ **1-Click RFC 2142 / DMCA Takedown Generator**: Auto-resolves registrar and hosting abuse desks, compiling timestamped evidence into official legal takedown notices.
- 🧱 **Multi-Vendor Firewall Export**: Automatically formats drop rules for Palo Alto Networks (PAN-OS), Cloudflare WAF, Fortinet FortiGate, Cisco ASA, and Suricata IPS.
- 🛰️ **OASIS STIX 2.1 Threat Intel Bundling**: Exports standardized STIX 2.1 JSON bundles for SIEM / SOAR platform ingestion.

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

### 2. Launch Unified Services (Backend + Frontend)
```powershell
python start.py
```
This launcher automatically initializes:
- **FastAPI Backend API**: [http://127.0.0.1:8000](http://127.0.0.1:8000) (Interactive OpenAPI Docs at [/docs](http://127.0.0.1:8000/docs))
- **Streamlit SOC Console UI**: [http://localhost:8501](http://localhost:8501)

### 3. Run Automated Playwright E2E Test Suite
```powershell
.venv\Scripts\python.exe tests/test_playwright_e2e.py
```
*Validates 27/27 API endpoints and UI tab workflows with Playwright trace recording (`tests/playwright_reports/trace.zip`).*

### 4. Running Services Individually
```powershell
# Start Backend API only
uvicorn app.main:app --reload --port 8000

# Start Streamlit UI only
streamlit run ui/streamlit_app.py
```

---

## 🏗️ Technical Architecture & Pipeline Flow

```
                      ┌──────────────────────────────────────┐
                      │         Candidate Target URL         │
                      └──────────────────┬───────────────────┘
                                         │
         ┌───────────────────────────────┼───────────────────────────────┐
         ▼                               ▼                               ▼
┌──────────────────┐           ┌──────────────────┐            ┌──────────────────┐
│ Lexical Engine   │           │ Playwright DOM   │            │ Headless Capture │
│ Shannon Entropy  │           │ Tag N-Grams      │            │ ResNet-50 Vector │
│ Levenshtein Dist │           │ Formless Theft   │            │ Layout dHash     │
│ Punycode Check   │           │ Zero-Font Filter │            │ Anomaly Heatmap  │
└────────┬─────────┘           └────────┬─────────┘            └────────┬─────────┘
         │                              │                               │
         └──────────────────────────────┼───────────────────────────────┘
                                        ▼
                      ┌──────────────────────────────────┐
                      │ XGBoost Multi-Modal Fusion Model │
                      │     (19-Dimensional Space)       │
                      └─────────────────┬────────────────┘
                                        │
                ┌───────────────────────┴───────────────────────┐
                ▼                                               ▼
 ┌─────────────────────────────┐                 ┌─────────────────────────────┐
 │  Phishing Score: 0% – 100%  │                 │  Mathematical SHAP Values   │
 │  Safe | Suspicious | Phish  │                 │  Additive Feature Attribution│
 └─────────────────────────────┘                 └─────────────────────────────┘
```

---

## 📁 Repository Structure

```text
Pishentry/
├── README.md                           # Enterprise documentation & quickstart
├── SIH_PRESENTATION_DECK.md            # Official Smart India Hackathon presentation deck
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
│   ├── target_attribution.py           # Multi-modal entity & campaign archetype attribution
│   ├── fusion.py                       # XGBoost multi-modal fusion & SHAP explainer
│   ├── export_rules.py                 # OASIS STIX 2.1, Sigma, YARA & DNS generators
│   ├── telemetry.py                    # TLS & certificate forensics inspector
│   ├── webhook.py                      # Real-time SIEM/SOAR incident webhook dispatcher
│   └── schemas.py                      # Pydantic data schemas
├── data/                               # Ground-Truth Brand Assets & Metadata
│   ├── protected_brands.json           # Protected enterprise brands catalog
│   └── reference/                      # Canonical screenshots, logos & DOM baselines
├── playwright-skill/                   # Playwright automation guidance & patterns
├── reports/                            # Technical Audit & SOC Analysis Reports
├── scripts/                            # Utility & Maintenance Scripts
├── tests/                              # Pytest Unit & Playwright E2E Test Suite (27/27 Passing)
├── training/                           # Dataset Pipelines & Machine Learning Artifacts
│   ├── build_dataset.py                # Dataset builder
│   ├── train_fusion_model.py           # Training pipeline & evaluation metrics
│   └── model.pkl                       # Trained XGBoost model artifact
└── ui/                                 # Streamlit Enterprise SOC Triage Console
    └── streamlit_app.py                # Real-time multi-tab triage dashboard
```

---

## 📜 License & Security Boundary

This project is licensed under the **MIT License**. Intended for defensive security operations, threat hunting, and testing applications you own or have explicit authorization to test.
