import streamlit as st
import requests
import json
import os
from PIL import Image

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")

st.set_page_config(
    page_title="PhishSentry AI — Security Analyst Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom High-Precision Dark Security Theme CSS
CUSTOM_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    code, pre, [class*="stCode"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stApp {
        background-color: #0b0f19;
        color: #f8fafc;
    }

    /* Header Banner */
    .header-container {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 1.25rem 1.75rem;
        background: linear-gradient(135deg, #151d2a 0%, #0f172a 100%);
        border: 1px solid #1e293b;
        border-radius: 12px;
        margin-bottom: 1.5rem;
    }
    
    .brand-title {
        font-size: 1.35rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        color: #f8fafc;
        margin: 0;
    }

    .brand-subtitle {
        font-size: 0.85rem;
        color: #94a3b8;
        margin-top: 0.2rem;
        font-weight: 500;
    }

    .badge-status-online {
        background: rgba(16, 185, 129, 0.12);
        color: #10b981;
        border: 1px solid rgba(16, 185, 129, 0.3);
        padding: 0.35rem 0.75rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.04em;
    }

    /* Card Panels */
    .metric-card {
        background: #131b29;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 1.25rem;
        height: 100%;
    }

    .metric-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #64748b;
        font-weight: 700;
        margin-bottom: 0.4rem;
    }

    .metric-value {
        font-size: 1.75rem;
        font-weight: 800;
        color: #f8fafc;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Verdict Banners */
    .verdict-critical {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(127, 29, 29, 0.2) 100%);
        border: 1px solid rgba(239, 68, 68, 0.4);
        border-left: 5px solid #ef4444;
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }

    .verdict-suspicious {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.15) 0%, rgba(120, 53, 15, 0.2) 100%);
        border: 1px solid rgba(245, 158, 11, 0.4);
        border-left: 5px solid #f59e0b;
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }

    .verdict-safe {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(6, 78, 59, 0.2) 100%);
        border: 1px solid rgba(16, 185, 129, 0.4);
        border-left: 5px solid #10b981;
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1.5rem;
    }

    .verdict-tag {
        display: inline-block;
        font-size: 0.75rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        padding: 0.25rem 0.6rem;
        border-radius: 4px;
        text-transform: uppercase;
        margin-bottom: 0.5rem;
    }

    .tag-critical { background: #ef4444; color: #ffffff; }
    .tag-suspicious { background: #f59e0b; color: #000000; }
    .tag-safe { background: #10b981; color: #ffffff; }

    /* Custom Input Form styling */
    .stTextInput > div > div > input {
        background-color: #151d2a !important;
        color: #f8fafc !important;
        border: 1px solid #334155 !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 0.95rem !important;
    }

    .stButton > button {
        background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%) !important;
        color: #ffffff !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 0.6rem 1.5rem !important;
        letter-spacing: 0.02em !important;
        transition: all 0.2s ease !important;
    }

    .stButton > button:hover {
        background: linear-gradient(135deg, #0369a1 0%, #075985 100%) !important;
        box-shadow: 0 4px 12px rgba(2, 132, 199, 0.3) !important;
    }

    /* Tabs Override */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #1e293b;
    }

    .stTabs [data-baseweb="tab"] {
        background-color: #131b29;
        border-radius: 6px 6px 0 0;
        color: #94a3b8;
        font-weight: 600;
        font-size: 0.85rem;
        padding: 0.5rem 1.25rem;
    }

    .stTabs [aria-selected="true"] {
        background-color: #1e293b !important;
        color: #38bdf8 !important;
        border-bottom: 2px solid #38bdf8 !important;
    }
</style>
"""

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Top Bar Header
st.markdown("""
<div class="header-container">
    <div>
        <div class="brand-title">PhishSentry AI <span style="color: #38bdf8; font-weight: 400; font-size: 0.9rem;">CONSOLE v1.0</span></div>
        <div class="brand-subtitle">Multi-Modal Phishing Analysis & Forensic Attribution Platform</div>
    </div>
    <div class="badge-status-online">PIPELINE ACTIVE</div>
</div>
""", unsafe_allow_html=True)

# Sidebar System Diagnostics
st.sidebar.markdown("### System Diagnostics")
api_url_input = st.sidebar.text_input("FastAPI Endpoint", value=API_BASE_URL)

try:
    health_resp = requests.get(f"{api_url_input}/health", timeout=3)
    if health_resp.status_code == 200:
        hdata = health_resp.json()
        st.sidebar.markdown(f"""
        <div style="background: #131b29; padding: 0.85rem; border-radius: 8px; border: 1px solid #1e293b; margin-top: 0.5rem;">
            <div style="font-size: 0.8rem; color: #10b981; font-weight: 600; margin-bottom: 0.4rem;">CONNECTED TO BACKEND</div>
            <div style="font-size: 0.75rem; color: #94a3b8;">Protected Brands: <strong style="color: #f8fafc;">{hdata.get('brands_loaded', 0)}</strong></div>
            <div style="font-size: 0.75rem; color: #94a3b8;">Fusion Model: <strong style="color: #f8fafc;">{'XGBoost Active' if hdata.get('model_loaded') else 'Fallback'}</strong></div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.sidebar.error("Backend returned non-200 response")
except Exception:
    st.sidebar.warning(f"Offline at {api_url_input}")
    st.sidebar.info("Run `python start.py` to start both servers.")

# URL Input Scan Form
st.markdown("#### Analyze Suspicious Target URL")

with st.form("scan_form", clear_on_submit=False):
    col_input, col_submit = st.columns([5, 1])
    with col_input:
        url_input = st.text_input(
            "Target URL",
            placeholder="https://paypa1-secure-login.tk/auth",
            label_visibility="collapsed"
        )
    with col_submit:
        submit_btn = st.form_submit_button("Run Analysis", use_container_width=True)

if submit_btn and url_input:
    with st.spinner("Rendering page via Playwright and executing multi-modal fusion..."):
        try:
            resp = requests.post(
                f"{api_url_input}/scan",
                json={"url": url_input},
                timeout=30
            )
            
            if resp.status_code == 400:
                st.error(f"Malformed URL Error: {resp.json().get('detail')}")
            elif resp.status_code != 200:
                st.error(f"API Error ({resp.status_code}): {resp.text}")
            else:
                data = resp.json()
                
                s_phish = data.get("s_phish", 0.0)
                s_lex = data.get("s_lex", 0.0)
                s_dom = data.get("s_dom")
                s_vis = data.get("s_vis")
                matched_brand = data.get("matched_brand")
                confidence = data.get("confidence", "full")
                shap_dict = data.get("shap_contributions", {})
                latency = data.get("latency_ms", 0)

                # Verdict Classification Display
                if s_phish >= 0.70:
                    banner_class = "verdict-critical"
                    tag_class = "tag-critical"
                    verdict_text = "CRITICAL PHISHING THREAT DETECTED"
                    verdict_desc = f"Target page exhibits high visual/structural impersonation alignment with <strong>{matched_brand.upper() if matched_brand else 'PROTECTED BRAND'}</strong>."
                elif s_phish >= 0.40:
                    banner_class = "verdict-suspicious"
                    tag_class = "tag-suspicious"
                    verdict_text = "SUSPICIOUS TARGET — HIGH RISK"
                    verdict_desc = "Target URL shows suspicious lexical anomaly or structural resemblance to known login templates."
                else:
                    banner_class = "verdict-safe"
                    tag_class = "tag-safe"
                    verdict_text = "VERIFIED SAFE / LOW RISK"
                    verdict_desc = "No significant structural, visual, or lexical brand spoofing indicators detected."

                st.markdown(f"""
                <div class="{banner_class}">
                    <div class="verdict-tag {tag_class}">{verdict_text}</div>
                    <div style="display: flex; align-items: baseline; justify-content: space-between;">
                        <div>
                            <div style="font-size: 2.2rem; font-weight: 800; font-family: 'JetBrains Mono', monospace;">
                                {s_phish * 100:.1f}% <span style="font-size: 1rem; color: #94a3b8; font-weight: 500;">Phishing Probability ($S_{{phish}}$)</span>
                            </div>
                            <div style="font-size: 0.9rem; color: #cbd5e1; margin-top: 0.25rem;">{verdict_desc}</div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Matched Target</div>
                            <div style="font-size: 1.25rem; font-weight: 700; color: #38bdf8;">{matched_brand.upper() if matched_brand else 'NONE'}</div>
                            <div style="font-size: 0.75rem; color: #64748b; margin-top: 0.2rem;">Pipeline Latency: {latency / 1000:.2f}s</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                if confidence == "reduced":
                    st.warning("⚠️ **Reduced Confidence Alert**: Headless render timed out or target site blocked browser. Evaluated on lexical pre-filter fallback to ensure no security bypass.")

                # Tabbed Forensic Workspace
                tab1, tab2, tab3 = st.tabs(["Signal Attribution (SHAP)", "Side-by-Side Visual Forensics", "Lexical Technical Details"])

                with tab1:
                    st.markdown("##### Multi-Modal Feature Signal Breakdown")
                    c1, c2, c3 = st.columns(3)
                    
                    with c1:
                        w_lex = shap_dict.get("s_lex", 0.33)
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-label">Lexical Signal ($S_{{lex}}$)</div>
                            <div class="metric-value">{s_lex:.4f}</div>
                            <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.5rem;">SHAP Attribution Weight: <strong style="color: #38bdf8;">{w_lex*100:.1f}%</strong></div>
                        </div>
                        """, unsafe_allow_html=True)
                        st.progress(float(w_lex))

                    with c2:
                        w_dom = shap_dict.get("s_dom", 0.33)
                        dom_str = f"{s_dom:.4f}" if s_dom is not None else "N/A"
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-label">DOM Structural Similarity ($S_{{dom}}$)</div>
                            <div class="metric-value">{dom_str}</div>
                            <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.5rem;">SHAP Attribution Weight: <strong style="color: #38bdf8;">{w_dom*100:.1f}%</strong></div>
                        </div>
                        """, unsafe_allow_html=True)
                        st.progress(float(w_dom))

                    with c3:
                        w_vis = shap_dict.get("s_vis", 0.34)
                        vis_str = f"{s_vis:.4f}" if s_vis is not None else "N/A"
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-label">Visual ResNet Embedding ($S_{{vis}}$)</div>
                            <div class="metric-value">{vis_str}</div>
                            <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.5rem;">SHAP Attribution Weight: <strong style="color: #38bdf8;">{w_vis*100:.1f}%</strong></div>
                        </div>
                        """, unsafe_allow_html=True)
                        st.progress(float(w_vis))

                with tab2:
                    st.markdown("##### Visual Layout Forensics")
                    col_img1, col_img2 = st.columns(2)
                    
                    with col_img1:
                        st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #94a3b8; margin-bottom: 0.5rem;'>CANDIDATE LIVE RENDER</div>", unsafe_allow_html=True)
                        scr_url = data.get("screenshot_url")
                        if scr_url:
                            st.image(f"{api_url_input}{scr_url}", use_container_width=True)
                        else:
                            st.info("No screenshot available for unreachable candidate site.")

                    with col_img2:
                        brand_title = matched_brand.upper() if matched_brand else "CANONICAL REFERENCE"
                        st.markdown(f"<div style='font-size: 0.85rem; font-weight: 700; color: #94a3b8; margin-bottom: 0.5rem;'>CANONICAL REFERENCE ({brand_title})</div>", unsafe_allow_html=True)
                        ref_url = data.get("matched_brand_screenshot_url")
                        if ref_url:
                            st.image(f"{api_url_input}{ref_url}", use_container_width=True)
                        else:
                            st.info("No reference brand screenshot matched.")

                with tab3:
                    st.markdown("##### Lexical & Domain Breakdown")
                    st.json({
                        "target_url": url_input,
                        "lexical_risk_score_s_lex": s_lex,
                        "matched_brand_label": matched_brand,
                        "pipeline_latency_ms": latency,
                        "confidence_mode": confidence
                    })

        except Exception as e:
            st.error(f"Error connecting to backend API: {e}")

else:
    # Idle State Instructions
    st.markdown("""
    <div style="background: #131b29; border: 1px border #1e293b; border-radius: 10px; padding: 2rem; text-align: center; margin-top: 2rem;">
        <div style="font-size: 1.1rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.5rem;">Ready for Threat Triage</div>
        <div style="font-size: 0.85rem; color: #94a3b8; max-width: 600px; margin: 0 auto;">
            Enter any target domain or login URL in the input field above to analyze its lexical features, Playwright DOM structure, and ResNet-50 visual layout against protected brand templates.
        </div>
    </div>
    """, unsafe_allow_html=True)
