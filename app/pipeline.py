"""
app/pipeline.py
===============
High-Performance Multi-Stage Asynchronous Data Flow Engine for CloneCatcher AI.

Coordinates concurrent data ingestion, thread-pooled feature extraction,
hierarchical brand resolution, multi-modal XGBoost/SHAP fusion, Phishpedia
consistency verification, and automated SOC defensive intelligence generation.
"""

import os
import io
import time
import uuid
import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from PIL import Image

from app.schemas import (
    ScanResult, TLSTelemetry, VisualForensicsDetail, OfficialBrandPortal,
    AiTMTelemetry, CloakingTelemetry, QuishingTelemetry, SemanticAlignmentTelemetry,
    DOMDeepForensicsTelemetry, FormActionAuditDetail, PhishpediaTelemetry,
    RedirectTraceTelemetry, PhishingKitTelemetry, TargetAttributionTelemetry,
    HoneytokenExfiltrationTelemetry, VisualOCRTelemetry, RedirectGraphTelemetry,
    ThreatNarrativeResponse, MultiVendorFirewallResponse,
    ISCXEnsembleTelemetry, StackModelTelemetry, PhishZooTelemetry,
    HeaderForensicsTelemetry
)

from app.lexical import analyze_lexical, LexicalFeatures
from app.renderer import render_url
from app.telemetry import extract_tls_telemetry
from app.dom_similarity import match_dom_against_brands
from app.visual_similarity import (
    VisualEmbedder, ReferenceBrandVisualStore, compute_cosine_similarity,
    compute_image_dhash, compute_dhash_similarity, compute_image_cnn_phishing_probability
)
from app.visual_forensics import (
    generate_visual_difference_heatmap, compute_color_histogram_similarity
)
from app.fusion import FusionClassifier
from app.aitm_detector import detect_aitm_proxy
from app.cloaking_detector import analyze_cloaking_and_anti_bot
from app.quishing_detector import scan_for_qr_codes
from app.semantic_alignment import analyze_domain_purpose_alignment
from app.dom_comparator import extract_dom_deep_forensics
from app.phishpedia_engine import evaluate_phishpedia_consistency
from app.kit_fingerprinter import fingerprint_phishing_kit
from app.target_attribution import attribute_target_identity
from app.honeytoken_interactor import analyze_outbound_network_requests, generate_canary_identity
from app.visual_ocr import extract_visual_text_from_screenshot
from app.redirect_graph import trace_redirect_graph
from app.threat_narrative import generate_threat_narrative
from app.firewall_rules import generate_multi_vendor_firewall_rules
from app.iscx_features import ISCXModelEnsemble
from app.stackmodel_features import extract_stackmodel_23_features
from app.phishzoo_tokenizer import analyze_content_brand_match
from app.header_analyzer import analyze_http_headers
from app.fastflux_tracker import evaluate_fastflux_dns_risk

logger = logging.getLogger("phishsentry.pipeline")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")


@dataclass
class PipelineContext:
    """Encapsulates all intermediate and final state flowing through the scan pipeline."""
    url: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    start_time: float = field(default_factory=time.time)
    stage_timings: Dict[str, float] = field(default_factory=dict)
    
    # Ingestion Artifacts
    lex_res: Optional[LexicalFeatures] = None
    screenshot_bytes: Optional[bytes] = None
    dom_html: Optional[str] = None
    screenshot_rel_url: Optional[str] = None
    raw_tls: Optional[Any] = None
    tls_telemetry: Optional[TLSTelemetry] = None
    redirect_graph_telemetry: Optional[RedirectGraphTelemetry] = None
    redirect_telemetry: Optional[RedirectTraceTelemetry] = None

    # Multi-Modal Extracted Features
    dom_score: float = 0.0
    dom_matched_brand: Optional[str] = None
    vis_score: float = 0.0
    vis_matched_brand: Optional[str] = None
    cloaking_telemetry: Optional[CloakingTelemetry] = None
    dom_forensics: Optional[DOMDeepForensicsTelemetry] = None
    kit_telemetry: Optional[PhishingKitTelemetry] = None
    quishing_telemetry: Optional[QuishingTelemetry] = None
    visual_ocr_telemetry: Optional[VisualOCRTelemetry] = None
    semantic_telemetry: Optional[SemanticAlignmentTelemetry] = None
    fastflux_raw: Optional[Dict[str, Any]] = None

    # Decision & Attribution
    matched_brand: Optional[str] = None
    matched_brand_screenshot_rel_url: Optional[str] = None
    visual_forensics: Optional[VisualForensicsDetail] = None
    s_phish: float = 0.0
    shap_contribs: Dict[str, float] = field(default_factory=dict)
    confidence: str = "full"
    phishpedia_telemetry: Optional[PhishpediaTelemetry] = None
    aitm_telemetry: Optional[AiTMTelemetry] = None
    target_attribution_telemetry: Optional[TargetAttributionTelemetry] = None
    honeytoken_telemetry: Optional[HoneytokenExfiltrationTelemetry] = None

    # SOC Defensive Outputs
    threat_narrative_telemetry: Optional[ThreatNarrativeResponse] = None
    firewall_rules_telemetry: Optional[MultiVendorFirewallResponse] = None

    # Experiment-Backed AI Model Telemetry (ISCX + StackModel + PhishZoo)
    iscx_ensemble_telemetry: Optional[ISCXEnsembleTelemetry] = None
    stackmodel_telemetry: Optional[StackModelTelemetry] = None
    phishzoo_telemetry: Optional[PhishZooTelemetry] = None
    header_forensics_telemetry: Optional[HeaderForensicsTelemetry] = None


class ScanPipeline:
    """
    Orchestrates the modular, concurrent CloneCatcher AI data flow:
    Stage 1: Async Ingestion & Network Lineage
    Stage 2: Parallel Multi-Modal Feature Extraction (Thread-pooled CPU/IO)
    Stage 3: Decision, Attribution & Multi-Modal XGBoost/SHAP Fusion
    Stage 4: Automated SOC Defensive Generation
    Stage 5: Result Assembly & Timing Compilation
    """

    def __init__(
        self,
        brands_data: List[dict],
        brand_names: List[str],
        canonical_map: Dict[str, List[str]],
        brand_dom_map: Dict[str, str],
        embedder: Optional[VisualEmbedder],
        visual_store: Optional[ReferenceBrandVisualStore],
        fusion_model: Optional[FusionClassifier]
    ):
        self.brands_data = brands_data
        self.brand_names = brand_names
        self.canonical_map = canonical_map
        self.brand_dom_map = brand_dom_map
        self.embedder = embedder
        self.visual_store = visual_store
        self.fusion_model = fusion_model

    async def execute(self, url: str) -> ScanResult:
        ctx = PipelineContext(url=url.strip())

        # Stage 1: Async Ingestion & Network Lineage
        t0 = time.time()
        await self._stage_1_ingestion(ctx)
        ctx.stage_timings["stage_1_ingestion_ms"] = round((time.time() - t0) * 1000, 2)

        # Stage 2: Parallel Multi-Modal Feature Extraction
        t0 = time.time()
        await self._stage_2_feature_extraction(ctx)
        ctx.stage_timings["stage_2_features_ms"] = round((time.time() - t0) * 1000, 2)

        # Stage 3: Decision, Attribution & Multi-Modal Fusion
        t0 = time.time()
        await self._stage_3_fusion_and_attribution(ctx)
        ctx.stage_timings["stage_3_fusion_ms"] = round((time.time() - t0) * 1000, 2)

        # Stage 4: Automated SOC Defensive Generation
        t0 = time.time()
        await self._stage_4_soc_generation(ctx)
        ctx.stage_timings["stage_4_soc_ms"] = round((time.time() - t0) * 1000, 2)

        # Stage 5: Final Result Assembly
        return self._stage_5_assemble_result(ctx)

    async def _stage_1_ingestion(self, ctx: PipelineContext):
        """
        Stage 1: Normalizes URL and concurrently runs Lexical analysis,
        Playwright stealth rendering, TLS handshake inspection, and async Redirect Graph tracing.
        """
        # Lexical extraction (fast CPU)
        ctx.lex_res = analyze_lexical(
            ctx.url, self.brand_names, canonical_domain_map=self.canonical_map
        )

        # Concurrent Playwright Render + TLS Inspection + Redirect Graph Lineage
        render_task = render_url(ctx.url, timeout_ms=10000)
        tls_task = extract_tls_telemetry(ctx.url, timeout_seconds=3.0)
        redirect_task = trace_redirect_graph(ctx.url, timeout_sec=3.5)

        (screenshot_bytes, dom_html), raw_tls, redirect_graph_res = await asyncio.gather(
            render_task, tls_task, redirect_task, return_exceptions=False
        )

        ctx.screenshot_bytes = screenshot_bytes
        ctx.dom_html = dom_html
        ctx.raw_tls = raw_tls

        # Build TLS Telemetry
        ctx.tls_telemetry = TLSTelemetry(
            has_tls=raw_tls.has_tls,
            issuer=raw_tls.issuer,
            subject=raw_tls.subject,
            san_list=raw_tls.san_list,
            valid_from=raw_tls.valid_from,
            valid_to=raw_tls.valid_to,
            days_to_expiry=raw_tls.days_to_expiry,
            is_self_signed=raw_tls.is_self_signed,
            is_free_ca=raw_tls.is_free_ca,
            resolved_ip=raw_tls.resolved_ip,
            error_detail=raw_tls.error_detail
        )

        # Build Redirect Graph & Trace Telemetry
        ctx.redirect_graph_telemetry = RedirectGraphTelemetry(
            hop_count=redirect_graph_res.hop_count,
            initial_url=redirect_graph_res.initial_url,
            final_destination_url=redirect_graph_res.final_destination_url,
            has_url_shortener=redirect_graph_res.has_url_shortener,
            has_open_redirect=redirect_graph_res.has_open_redirect,
            has_protocol_downgrade=redirect_graph_res.has_protocol_downgrade,
            unique_domains_in_chain=redirect_graph_res.unique_domains_in_chain,
            graph_risk_score=redirect_graph_res.graph_risk_score,
            evidence=redirect_graph_res.evidence
        )

        is_multi = redirect_graph_res.hop_count > 1
        ctx.redirect_telemetry = RedirectTraceTelemetry(
            original_url=redirect_graph_res.initial_url,
            final_url=redirect_graph_res.final_destination_url,
            total_hops=redirect_graph_res.hop_count,
            is_multi_hop=is_multi,
            is_shortened=redirect_graph_res.has_url_shortener,
            evasion_risk_boost=redirect_graph_res.graph_risk_score * 0.30 if is_multi else 0.0
        )

        # Persist screenshot artifact if available
        if ctx.screenshot_bytes:
            artifact_filename = f"scan_{ctx.scan_id}.png"
            artifact_path = os.path.join(ARTIFACTS_DIR, artifact_filename)
            try:
                with open(artifact_path, "wb") as f:
                    f.write(ctx.screenshot_bytes)
                ctx.screenshot_rel_url = f"/artifacts/{artifact_filename}"
            except Exception as e:
                logger.warning(f"Could not persist scan screenshot artifact: {e}")

    async def _stage_2_feature_extraction(self, ctx: PipelineContext):
        """
        Stage 2: Parallel execution of multi-modal feature extractors via asyncio.to_thread
        to avoid blocking the main event loop on CPU-heavy operations.
        """
        # 1. Anti-Bot / Cloaking detection
        def run_cloaking():
            return analyze_cloaking_and_anti_bot(ctx.dom_html, ctx.url)

        # 2. DOM structural & token brand matching
        def run_dom_match():
            if ctx.dom_html:
                return match_dom_against_brands(ctx.dom_html, self.brand_dom_map)
            return 0.0, None

        # 3. Visual embedding & ResNet / dHash + Image CNN matching (Karmakar et al., 2025)
        def run_vis_match():
            if ctx.screenshot_bytes and self.visual_store is not None:
                vis_score, matched_brand = self.visual_store.find_best_match(ctx.screenshot_bytes)
                cnn_prob = compute_image_cnn_phishing_probability(ctx.screenshot_bytes)
                if matched_brand and cnn_prob > 0.50:
                    vis_score = round(min(1.0, max(vis_score, 0.65 * vis_score + 0.35 * cnn_prob)), 4)
                return vis_score, matched_brand
            return 0.0, None

        # 4. Deep DOM node & form action forensics
        def run_dom_forensics():
            return extract_dom_deep_forensics(
                dom_html=ctx.dom_html,
                candidate_url=ctx.url,
                canonical_domains=self.canonical_map.get(ctx.lex_res.matched_brand) if ctx.lex_res and ctx.lex_res.matched_brand else None
            )

        # 5. Phishing Kit / Exfiltration Script Fingerprinting
        def run_kit_fingerprint():
            return fingerprint_phishing_kit(html_content=ctx.dom_html or "", raw_scripts=[])

        # 6. Quishing / QR Code matrix scanning
        def run_quishing():
            return scan_for_qr_codes(ctx.screenshot_bytes)

        # 7. Optical Character Recognition (OCR)
        def run_ocr():
            return extract_visual_text_from_screenshot(ctx.screenshot_bytes)

        # 8. Domain Purpose & Semantic Alignment
        def run_semantic_alignment():
            return analyze_domain_purpose_alignment(
                url=ctx.url,
                dom_html=ctx.dom_html,
                s_lex_brand=ctx.lex_res.matched_brand if ctx.lex_res else None,
                s_vis_brand=None,
                is_canonical=ctx.lex_res.is_canonical_domain if ctx.lex_res else False
            )

        gather_results = await asyncio.gather(
            asyncio.to_thread(run_cloaking),
            asyncio.to_thread(run_dom_match),
            asyncio.to_thread(run_vis_match),
            asyncio.to_thread(run_dom_forensics),
            asyncio.to_thread(run_kit_fingerprint),
            asyncio.to_thread(run_quishing),
            asyncio.to_thread(run_ocr),
            asyncio.to_thread(run_semantic_alignment)
        )

        cloaking_raw = gather_results[0]
        dom_match_res = gather_results[1]
        dom_score = float(dom_match_res[0])
        dom_matched_brand = dom_match_res[1]
        vis_match_res = gather_results[2]
        vis_score = float(vis_match_res[0])
        vis_matched_brand = vis_match_res[1]
        dom_forensics_raw = gather_results[3]
        kit_raw = gather_results[4]
        quishing_raw = gather_results[5]
        ocr_raw = gather_results[6]
        semantic_raw = gather_results[7]

        ctx.dom_score = dom_score
        ctx.dom_matched_brand = dom_matched_brand
        ctx.vis_score = vis_score
        ctx.vis_matched_brand = vis_matched_brand

        ctx.cloaking_telemetry = CloakingTelemetry(
            is_cloaked=cloaking_raw.is_cloaked,
            interstitial_type=cloaking_raw.interstitial_type,
            evasion_techniques=cloaking_raw.evasion_techniques,
            is_bot_wall=cloaking_raw.is_bot_wall,
            advisory=cloaking_raw.advisory
        )

        ctx.dom_forensics = DOMDeepForensicsTelemetry(
            total_dom_nodes=dom_forensics_raw.total_dom_nodes,
            form_count=dom_forensics_raw.form_count,
            password_input_count=dom_forensics_raw.password_input_count,
            form_actions=[
                FormActionAuditDetail(
                    form_id=fa.form_id,
                    form_name=fa.form_name,
                    action_url=fa.action_url,
                    method=fa.method,
                    target_domain=fa.target_domain,
                    is_external_mismatch=fa.is_external_mismatch,
                    input_fields=fa.input_fields,
                    has_password_field=fa.has_password_field
                ) for fa in dom_forensics_raw.form_actions
            ],
            has_form_action_mismatch=dom_forensics_raw.has_form_action_mismatch,
            suspicious_external_scripts=dom_forensics_raw.suspicious_external_scripts,
            has_iframe_overlay=dom_forensics_raw.has_iframe_overlay,
            structural_node_diff_ratio=dom_forensics_raw.structural_node_diff_ratio,
            mitre_attack_id=dom_forensics_raw.mitre_attack_id,
            forensic_highlights=dom_forensics_raw.forensic_highlights,
            is_formless_harvesting=dom_forensics_raw.is_formless_harvesting,
            has_zero_font_obfuscation=dom_forensics_raw.has_zero_font_obfuscation,
            exfiltration_endpoints=dom_forensics_raw.exfiltration_endpoints,
            has_shadow_dom_nodes=dom_forensics_raw.has_shadow_dom_nodes,
            total_hyperlinks_count=dom_forensics_raw.total_hyperlinks_count,
            null_hyperlinks_ratio=dom_forensics_raw.null_hyperlinks_ratio,
            external_hyperlinks_ratio=dom_forensics_raw.external_hyperlinks_ratio,
            internal_hyperlinks_ratio=dom_forensics_raw.internal_hyperlinks_ratio,
            empty_anchor_tags_ratio=dom_forensics_raw.empty_anchor_tags_ratio,
            anchor_text_discrepancy_count=dom_forensics_raw.anchor_text_discrepancy_count,
            external_resources_ratio=dom_forensics_raw.external_resources_ratio,
            favicon_external_mismatch=dom_forensics_raw.favicon_external_mismatch,
            has_server_form_handler_mismatch=dom_forensics_raw.has_server_form_handler_mismatch,
            has_right_click_disabled=dom_forensics_raw.has_right_click_disabled,
            has_text_selection_disabled=dom_forensics_raw.has_text_selection_disabled,
            has_browser_in_the_browser=dom_forensics_raw.has_browser_in_the_browser
        )

        ctx.kit_telemetry = PhishingKitTelemetry(
            is_kit_detected=kit_raw.is_kit_detected,
            kit_name=kit_raw.kit_name,
            kit_family=kit_raw.kit_family,
            confidence=kit_raw.confidence,
            detected_indicators=kit_raw.detected_indicators,
            is_telegram_exfiltration=kit_raw.is_telegram_exfiltration,
            telegram_bot_endpoints=kit_raw.telegram_bot_endpoints,
            mitre_attack_id=kit_raw.mitre_attack_id
        )

        ctx.quishing_telemetry = QuishingTelemetry(
            has_qr_code=quishing_raw.has_qr_code,
            confidence=quishing_raw.confidence,
            decoded_url=quishing_raw.decoded_url,
            is_quishing_suspect=quishing_raw.is_quishing_suspect,
            mitre_attack_id=quishing_raw.mitre_attack_id,
            details=quishing_raw.details
        )

        ctx.visual_ocr_telemetry = VisualOCRTelemetry(
            has_in_image_text=ocr_raw.has_in_image_text,
            extracted_text_snippet=ocr_raw.extracted_text_snippet,
            detected_brand_keywords=ocr_raw.detected_brand_keywords,
            detected_security_keywords=ocr_raw.detected_security_keywords,
            confidence_score=ocr_raw.confidence_score,
            evidence=ocr_raw.evidence
        )

        ctx.semantic_telemetry = SemanticAlignmentTelemetry(
            is_discrepancy_detected=semantic_raw.is_discrepancy_detected,
            domain_intent_brand=semantic_raw.domain_intent_brand,
            rendered_content_brand=semantic_raw.rendered_content_brand,
            discrepancy_type=semantic_raw.discrepancy_type,
            alignment_score=semantic_raw.alignment_score,
            mitre_attack_id=semantic_raw.mitre_attack_id,
            reasons=semantic_raw.reasons,
            forensic_summary=semantic_raw.forensic_summary
        )

        # ── Experiment-Backed AI Model Feature Extraction (ISCX + StackModel + PhishZoo) ──
        def run_iscx_ensemble():
            """ISCX 79-dim feature vector + Logistic/RF/SVM ensemble scoring."""
            try:
                iscx = ISCXModelEnsemble()
                return iscx.predict(ctx.url)
            except Exception as e:
                logger.debug(f"ISCX ensemble extraction error: {e}")
                return {"lr_prob": 0.0, "rf_prob": 0.0, "svm_pred": 0, "ensemble_score": 0.0, "feature_dim": 79}

        def run_stackmodel():
            """StackModel 23-feature content-based extraction."""
            try:
                return extract_stackmodel_23_features(ctx.url, ctx.dom_html)
            except Exception as e:
                logger.debug(f"StackModel extraction error: {e}")
                return {"stackmodel_risk_score": 0.0}

        def run_phishzoo():
            """PhishZoo TF-IDF content tokenization and brand matching."""
            try:
                return analyze_content_brand_match(ctx.url, ctx.dom_html)
            except Exception as e:
                logger.debug(f"PhishZoo tokenization error: {e}")
                return {"detected_brand": None, "brand_confidence": 0.0, "matched_keywords": [], "token_count": 0}

        def run_headers():
            """HTTP Response Header Forensics & Security Posture Analysis."""
            try:
                raw_hdrs = ""
                if ctx.raw_tls and hasattr(ctx.raw_tls, "raw_headers"):
                    raw_hdrs = ctx.raw_tls.raw_headers
                return analyze_http_headers(raw_hdrs)
            except Exception as e:
                logger.debug(f"Header forensics analysis error: {e}")
                return {"server_banner": "Unadvertised", "is_outdated_server": False, "missing_security_headers": [], "security_header_coverage_score": 0.0, "has_insecure_cookies": False, "cookie_flags_audit": [], "cache_control_policy": "Default", "has_aggressive_no_cache": False, "redirect_chain_count": 0, "header_anomaly_score": 0.0, "forensic_indicators": []}

        def run_fastflux():
            """Fast-Flux DNS, TTL Anomaly, and ASN Shannon Entropy."""
            try:
                raw_ip = ctx.raw_tls.resolved_ip if ctx.raw_tls else None
                ips = [raw_ip] if raw_ip and raw_ip != "Pending DNS Resolution" else None
                return evaluate_fastflux_dns_risk(domain=ctx.url, resolved_ips=ips)
            except Exception as e:
                logger.debug(f"Fastflux evaluation error: {e}")
                return {"fast_flux_composite_index": 0.05, "ttl_anomaly_score": 0.0, "asn_diversity_score": 0.0, "max_asn_reputation_risk": 0.05}

        iscx_raw, stackmodel_raw, phishzoo_raw, header_raw, fastflux_raw = await asyncio.gather(
            asyncio.to_thread(run_iscx_ensemble),
            asyncio.to_thread(run_stackmodel),
            asyncio.to_thread(run_phishzoo),
            asyncio.to_thread(run_headers),
            asyncio.to_thread(run_fastflux)
        )
        ctx.fastflux_raw = fastflux_raw

        ctx.iscx_ensemble_telemetry = ISCXEnsembleTelemetry(
            logistic_regression_score=round(float(iscx_raw.get("lr_prob", 0.0)), 4),
            random_forest_score=round(float(iscx_raw.get("rf_prob", 0.0)), 4),
            svm_decision=int(iscx_raw.get("svm_pred", 0)),
            ensemble_phish_score=round(float(iscx_raw.get("ensemble_score", 0.0)), 4),
            feature_vector_dim=int(iscx_raw.get("feature_vector_dim", iscx_raw.get("feature_dim", 79)))
        )

        ctx.stackmodel_telemetry = StackModelTelemetry(
            internal_link=int(stackmodel_raw.get("internal_link", 0)),
            external_link=int(stackmodel_raw.get("external_link", 0)),
            empty_link=int(stackmodel_raw.get("empty_link", 0)),
            login_form=int(stackmodel_raw.get("login_form", 0)),
            html_len=int(stackmodel_raw.get("html_len", 0)),
            hidden=int(stackmodel_raw.get("hidden", 0)),
            alarm_window=int(stackmodel_raw.get("alarm_window", 0)),
            redirection=int(stackmodel_raw.get("redirection", 0)),
            title_domain=int(stackmodel_raw.get("title_domain", 0)),
            brand_domain=int(stackmodel_raw.get("brand_domain", 1)),
            external_resource=int(stackmodel_raw.get("external_resource", 0)),
            domain_is_ip=int(stackmodel_raw.get("domain_is_ip", 0)),
            sensitive_word=int(stackmodel_raw.get("sensitive_word", 0)),
            https=int(stackmodel_raw.get("https", 0)),
            stackmodel_risk_score=round(float(stackmodel_raw.get("stackmodel_risk_score", 0.0)), 4)
        )

        ctx.phishzoo_telemetry = PhishZooTelemetry(
            detected_brand=phishzoo_raw.get("detected_brand"),
            brand_confidence=round(float(phishzoo_raw.get("brand_confidence", 0.0)), 4),
            matched_keywords=phishzoo_raw.get("matched_keywords", []),
            token_count=int(phishzoo_raw.get("token_count", 0))
        )

        ctx.header_forensics_telemetry = HeaderForensicsTelemetry(
            server_banner=header_raw.get("server_banner", "Unadvertised"),
            is_outdated_server=bool(header_raw.get("is_outdated_server", False)),
            missing_security_headers=header_raw.get("missing_security_headers", []),
            security_header_coverage_score=round(float(header_raw.get("security_header_coverage_score", 0.0)), 4),
            has_insecure_cookies=bool(header_raw.get("has_insecure_cookies", False)),
            cookie_flags_audit=header_raw.get("cookie_flags_audit", []),
            cache_control_policy=header_raw.get("cache_control_policy", "Default / Unspecified"),
            has_aggressive_no_cache=bool(header_raw.get("has_aggressive_no_cache", False)),
            redirect_chain_count=int(header_raw.get("redirect_chain_count", 0)),
            header_anomaly_score=round(float(header_raw.get("header_anomaly_score", 0.0)), 4),
            forensic_indicators=header_raw.get("forensic_indicators", [])
        )


    async def _stage_3_fusion_and_attribution(self, ctx: PipelineContext):
        """
        Stage 3: Resolves ground truth brand with P1-P4 priority matrix, computes visual difference
        heatmaps, evaluates XGBoost/SHAP fusion, Phishpedia consistency, AiTM proxies, and target attribution.
        """
        lex_res = ctx.lex_res
        s_dom = ctx.dom_score
        s_vis = ctx.vis_score

        # Hierarchical Multi-Modal Brand Resolution (Incorporating arXiv:2405.19598v2):
        # P1. Lexical / URL ground-truth match (e.g. accounts.google.com, paypa1.xyz)
        # P2. DOM semantic token match (e.g. "Google", "Use your Google Account")
        # P2.5 In-Image OCR Brand Match (Countering Logo Elimination & Font/Case Alterations per arXiv:2405.19598v2)
        # P3. High-confidence Deep visual feature match (if confident >= 0.65 AND supported by DOM/OCR)
        # P4. Stand-Alone Visual Feature match (if >= 0.80)
        # Default: None
        ocr_brands = ctx.visual_ocr_telemetry.detected_brand_keywords if ctx.visual_ocr_telemetry else []
        matched_ocr_brand = None
        for ob in ocr_brands:
            clean_ob = ob.lower().replace(" ", "").replace("_", "")
            if clean_ob in self.brand_names:
                matched_ocr_brand = clean_ob
                break

        # P2.8 PhishZoo TF-IDF Content Brand Match
        phishzoo_brand = ctx.phishzoo_telemetry.detected_brand if ctx.phishzoo_telemetry else None

        if lex_res and lex_res.matched_brand and lex_res.levenshtein_sim >= 0.6:
            matched_brand = lex_res.matched_brand
        elif ctx.dom_matched_brand and ctx.dom_score >= 0.40:
            matched_brand = ctx.dom_matched_brand
        elif matched_ocr_brand and ctx.visual_ocr_telemetry and (ctx.visual_ocr_telemetry.confidence_score >= 0.75 or ctx.dom_score >= 0.25):
            # Recovers target brand when adversary eliminated or recolored the graphical logo
            matched_brand = matched_ocr_brand
        elif phishzoo_brand and ctx.phishzoo_telemetry and ctx.phishzoo_telemetry.brand_confidence >= 0.55 and phishzoo_brand in self.brand_names:
            # PhishZoo TF-IDF content tokens match a protected brand
            matched_brand = phishzoo_brand
        elif ctx.vis_matched_brand and ctx.vis_score >= 0.65 and (ctx.dom_score >= 0.25 or matched_ocr_brand == ctx.vis_matched_brand):
            matched_brand = ctx.vis_matched_brand
        elif ctx.vis_matched_brand and ctx.vis_score >= 0.80:
            matched_brand = ctx.vis_matched_brand
        elif matched_ocr_brand and ctx.visual_ocr_telemetry and ctx.visual_ocr_telemetry.confidence_score >= 0.60:
            matched_brand = matched_ocr_brand
        else:
            matched_brand = None

        # Synchronize signal scores with actual confirmed brand
        if matched_brand is not None:
            s_dom = ctx.dom_score if ctx.dom_matched_brand == matched_brand else (ctx.dom_score if ctx.dom_score > 0 else 0.40)
            s_vis = ctx.vis_score if ctx.vis_matched_brand == matched_brand else (ctx.vis_score if ctx.vis_score > 0 else 0.50)
        else:
            s_dom = 0.0
            s_vis = 0.0

        ctx.matched_brand = matched_brand
        ctx.dom_score = s_dom
        ctx.vis_score = s_vis

        # Look up matched brand reference screenshot
        if matched_brand:
            for b in self.brands_data:
                if b["brand_id"] == matched_brand:
                    rel_path = b["screenshot_path"].replace("\\", "/")
                    ctx.matched_brand_screenshot_rel_url = f"/{rel_path}" if not rel_path.startswith("/") else rel_path
                    break

        # Compute In-Depth Visual Forensics & Difference Heatmap if brand detected
        if matched_brand and ctx.screenshot_bytes and self.visual_store is not None:
            brand_ref_img_path = None
            for b in self.brands_data:
                if b["brand_id"] == matched_brand:
                    brand_ref_img_path = os.path.join(BASE_DIR, b["screenshot_path"].replace("/", os.sep))
                    break

            if brand_ref_img_path and os.path.exists(brand_ref_img_path):
                def run_visual_forensics_computations():
                    heatmap_rel_url, anomaly_score = generate_visual_difference_heatmap(
                        ctx.screenshot_bytes, brand_ref_img_path, ctx.scan_id
                    )
                    cand_emb = self.embedder.get_image_embedding(ctx.screenshot_bytes) if self.embedder else None
                    ref_emb = self.visual_store.brand_embeddings.get(matched_brand) if self.visual_store else None
                    cos_sim = compute_cosine_similarity(cand_emb, ref_emb) if (cand_emb is not None and ref_emb is not None) else 0.0

                    try:
                        c_pil = Image.open(io.BytesIO(ctx.screenshot_bytes))
                        r_pil = Image.open(brand_ref_img_path)
                        c_hash = compute_image_dhash(c_pil)
                        r_hash = compute_image_dhash(r_pil)
                        dhash_sim = compute_dhash_similarity(c_hash, r_hash)
                        color_sim = compute_color_histogram_similarity(c_pil, r_pil)
                    except Exception:
                        dhash_sim = 0.0
                        color_sim = 0.0

                    official_portal = None
                    for b in self.brands_data:
                        if b["brand_id"] == matched_brand:
                            official_portal = OfficialBrandPortal(
                                brand_id=b["brand_id"],
                                display_name=b["display_name"],
                                official_login_url=b.get("official_login_url", f"https://{b['canonical_domains'][0]}"),
                                canonical_domains=b.get("canonical_domains", []),
                                brand_color=b.get("brand_color", "#003087"),
                                official_cert_issuer=b.get("official_cert_issuer", "Verified Official TLS CA"),
                                security_advice=b.get("security_advice", "Verify official domain certificate."),
                                logo_url=f"/{b['logo_path'].replace(os.sep, '/')}",
                                screenshot_url=f"/{b['screenshot_path'].replace(os.sep, '/')}"
                            )
                            break

                    return VisualForensicsDetail(
                        resnet_feature_sim=cos_sim,
                        layout_dhash_sim=dhash_sim,
                        color_histogram_sim=color_sim,
                        diff_heatmap_url=heatmap_rel_url,
                        anomaly_score=anomaly_score,
                        official_portal=official_portal
                    )

                ctx.visual_forensics = await asyncio.to_thread(run_visual_forensics_computations)

        # AiTM Reverse Proxy Analysis
        aitm_raw = detect_aitm_proxy(
            url=ctx.url,
            s_vis=s_vis,
            s_dom=s_dom,
            matched_brand=matched_brand,
            is_canonical=lex_res.is_canonical_domain if lex_res else False,
            tls_telemetry=ctx.tls_telemetry,
            dom_html=ctx.dom_html
        )
        ctx.aitm_telemetry = AiTMTelemetry(
            is_aitm_suspect=aitm_raw.is_aitm_suspect,
            confidence_level=aitm_raw.confidence_level,
            mitre_attack_id=aitm_raw.mitre_attack_id,
            target_brand=aitm_raw.target_brand,
            reasons=aitm_raw.reasons,
            risk_score_boost=aitm_raw.risk_score_boost
        )

        # Multi-Modal XGBoost + TreeSHAP Fusion Classification (23 Dimensions)
        if self.fusion_model is not None:
            ff_data = getattr(ctx, "fastflux_raw", None)
            s_phish, shap_contribs, confidence = self.fusion_model.predict(
                lex_res.s_lex if lex_res else 0.0, s_dom, s_vis,
                url=ctx.url,
                brand_list=self.brand_names,
                canonical_map=self.canonical_map,
                lex_features=lex_res,
                fastflux_data=ff_data
            )
        else:
            s_phish = lex_res.s_lex if lex_res else 0.0
            shap_contribs = {"s_lex": 1.0, "s_dom": 0.0, "s_vis": 0.0, "s_dns": 0.0}
            confidence = "reduced"

        # Phishpedia (USENIX '21) Consistency-Based Model
        brand_meta_dict = {b["brand_id"]: b for b in self.brands_data}
        phishpedia_res = evaluate_phishpedia_consistency(
            url=ctx.url,
            matched_brand=matched_brand,
            visual_similarity=s_vis or 0.0,
            dom_similarity=s_dom or 0.0,
            brand_metadata=brand_meta_dict
        )
        ctx.phishpedia_telemetry = PhishpediaTelemetry(
            brand_intention=phishpedia_res.brand_intention,
            brand_display_name=phishpedia_res.brand_display_name,
            brand_confidence=phishpedia_res.brand_confidence,
            registered_domain=phishpedia_res.registered_domain,
            canonical_domains=phishpedia_res.canonical_domains,
            is_consistent=phishpedia_res.is_consistent,
            phishing_decision=phishpedia_res.phishing_decision,
            visual_explanation=phishpedia_res.visual_explanation,
            mitre_attack_id=phishpedia_res.mitre_attack_id
        )

        # Apply multi-signal threat elevations
        is_canonical = lex_res.is_canonical_domain if lex_res else False
        if phishpedia_res.phishing_decision and not is_canonical:
            s_phish = max(s_phish, 0.85)

        if ctx.kit_telemetry and ctx.kit_telemetry.is_kit_detected and not is_canonical:
            s_phish = max(s_phish, 0.90)

        if ctx.redirect_telemetry and ctx.redirect_telemetry.is_multi_hop and not is_canonical:
            s_phish = min(1.0, max(s_phish, s_phish + ctx.redirect_telemetry.evasion_risk_boost))

        if ctx.aitm_telemetry and ctx.aitm_telemetry.is_aitm_suspect:
            s_phish = min(1.0, max(s_phish, s_phish + ctx.aitm_telemetry.risk_score_boost))

        if ctx.quishing_telemetry and ctx.quishing_telemetry.is_quishing_suspect and not is_canonical:
            s_phish = min(1.0, max(s_phish, s_phish + 0.30))

        if ctx.dom_forensics and ctx.dom_forensics.has_form_action_mismatch and not is_canonical:
            s_phish = min(1.0, max(s_phish, 0.85))

        if ctx.dom_forensics and ctx.dom_forensics.is_formless_harvesting and not is_canonical:
            s_phish = min(1.0, max(s_phish, 0.85))

        if ctx.dom_forensics and ctx.dom_forensics.exfiltration_endpoints and not is_canonical:
            s_phish = min(1.0, max(s_phish, 0.90))

        if ctx.dom_forensics and ctx.dom_forensics.has_browser_in_the_browser and not is_canonical:
            s_phish = min(1.0, max(s_phish, 0.92))

        if ctx.dom_forensics and ctx.dom_forensics.anchor_text_discrepancy_count > 0 and not is_canonical:
            s_phish = min(1.0, max(s_phish, 0.88))

        if ctx.dom_forensics and ctx.dom_forensics.has_server_form_handler_mismatch and not is_canonical:
            s_phish = min(1.0, max(s_phish, 0.82))

        if ctx.dom_forensics and ctx.dom_forensics.null_hyperlinks_ratio >= 0.50 and ctx.dom_forensics.total_hyperlinks_count >= 4 and not is_canonical:
            s_phish = min(1.0, max(s_phish, s_phish + 0.20))

        if ctx.dom_forensics and ctx.dom_forensics.has_zero_font_obfuscation and not is_canonical:
            s_phish = min(1.0, max(s_phish, s_phish + 0.25))

        if ctx.semantic_telemetry and ctx.semantic_telemetry.discrepancy_type == "CLOAKING_CONTENT_SWAP":
            s_phish = min(1.0, max(s_phish, 0.85))

        if ctx.cloaking_telemetry and ctx.cloaking_telemetry.is_cloaked and lex_res and lex_res.s_lex >= 0.35:
            s_phish = max(s_phish, lex_res.s_lex)

        # ── Experiment-Backed AI Model Threat Elevation ──

        # ISCX 79-Feature Ensemble (Logistic + Random Forest + SVM)
        if ctx.iscx_ensemble_telemetry and ctx.iscx_ensemble_telemetry.ensemble_phish_score >= 0.70 and not is_canonical:
            s_phish = min(1.0, max(s_phish, 0.30 * s_phish + 0.70 * ctx.iscx_ensemble_telemetry.ensemble_phish_score))

        # StackModel 23-Feature Content Risk
        if ctx.stackmodel_telemetry and ctx.stackmodel_telemetry.stackmodel_risk_score >= 0.60 and not is_canonical:
            s_phish = min(1.0, max(s_phish, s_phish + 0.15 * ctx.stackmodel_telemetry.stackmodel_risk_score))

        # PhishZoo TF-IDF Brand Content Mismatch
        if ctx.phishzoo_telemetry and ctx.phishzoo_telemetry.detected_brand and not is_canonical:
            phishzoo_brand = ctx.phishzoo_telemetry.detected_brand
            # If content matches a brand but URL is not canonical → risk
            if phishzoo_brand and ctx.phishzoo_telemetry.brand_confidence >= 0.55:
                s_phish = min(1.0, max(s_phish, 0.80))

        # Canonical Domain Safety Guard
        if is_canonical:
            s_phish = min(s_phish, 0.05)

        ctx.s_phish = s_phish
        ctx.shap_contribs = shap_contribs
        ctx.confidence = confidence

        # Next-Gen Target Identity Attribution
        target_attr_raw = attribute_target_identity(
            registered_domain=lex_res.registered_domain if lex_res else "",
            lexical_matched_brand=lex_res.matched_brand if lex_res else None,
            dom_matched_brand=ctx.dom_matched_brand,
            vis_matched_brand=ctx.vis_matched_brand,
            vis_score=s_vis or 0.0,
            dom_score=s_dom or 0.0,
            ocr_extracted_text=ctx.visual_ocr_telemetry.extracted_text_snippet if ctx.visual_ocr_telemetry else "",
            dom_text=ctx.dom_html or "",
            is_aitm=ctx.aitm_telemetry.is_aitm_suspect if ctx.aitm_telemetry else False,
            is_quishing=ctx.quishing_telemetry.is_quishing_suspect if ctx.quishing_telemetry else False
        )
        ctx.target_attribution_telemetry = TargetAttributionTelemetry(
            target_identity=target_attr_raw.target_identity,
            identity_display_name=target_attr_raw.identity_display_name,
            campaign_archetype=target_attr_raw.campaign_archetype,
            attribution_confidence=target_attr_raw.attribution_confidence,
            is_canonical_identity=target_attr_raw.is_canonical_identity,
            impersonation_evidence=target_attr_raw.impersonation_evidence,
            suggested_mitigation=target_attr_raw.suggested_mitigation
        )

        # Synthetic Honeytoken Analysis
        canary_id, _ = generate_canary_identity()
        honeytoken_raw = analyze_outbound_network_requests(
            target_url=ctx.url,
            captured_requests=[],
            decoy_id=canary_id
        )
        ctx.honeytoken_telemetry = HoneytokenExfiltrationTelemetry(
            is_trapped=honeytoken_raw.is_trapped,
            decoy_identifier=honeytoken_raw.decoy_identifier,
            exfiltration_destination=honeytoken_raw.exfiltration_destination,
            exfiltration_protocol=honeytoken_raw.exfiltration_protocol,
            exfiltration_host=honeytoken_raw.exfiltration_host,
            is_external_c2=honeytoken_raw.is_external_c2,
            trapped_payload_preview=honeytoken_raw.trapped_payload_preview,
            mitre_technique=honeytoken_raw.mitre_technique,
            evidence=honeytoken_raw.evidence
        )

    async def _stage_4_soc_generation(self, ctx: PipelineContext):
        """
        Stage 4: Concurrently generates Autonomous Threat Narrative and Multi-Vendor Firewall & WAF Rules.
        """
        interim_scan_dict = {
            "url": ctx.url,
            "s_phish": ctx.s_phish,
            "matched_brand": ctx.matched_brand or (ctx.target_attribution_telemetry.target_identity if ctx.target_attribution_telemetry else None),
            "target_attribution": ctx.target_attribution_telemetry.model_dump() if ctx.target_attribution_telemetry else {},
            "aitm_telemetry": ctx.aitm_telemetry.model_dump() if ctx.aitm_telemetry else {},
            "quishing_telemetry": ctx.quishing_telemetry.model_dump() if ctx.quishing_telemetry else {},
            "honeytoken_telemetry": ctx.honeytoken_telemetry.model_dump() if ctx.honeytoken_telemetry else {},
            "dom_forensics": ctx.dom_forensics.model_dump() if ctx.dom_forensics else {},
            "tls_telemetry": ctx.tls_telemetry.model_dump() if ctx.tls_telemetry else {}
        }

        def run_narrative():
            return generate_threat_narrative(interim_scan_dict)

        def run_firewall():
            return generate_multi_vendor_firewall_rules(interim_scan_dict)

        narrative_raw, firewall_raw = await asyncio.gather(
            asyncio.to_thread(run_narrative),
            asyncio.to_thread(run_firewall)
        )

        ctx.threat_narrative_telemetry = ThreatNarrativeResponse(
            incident_title=narrative_raw.incident_title,
            severity_level=narrative_raw.severity_level,
            threat_actor_tradecraft=narrative_raw.threat_actor_tradecraft,
            executive_summary=narrative_raw.executive_summary,
            forensic_indicators_of_compromise=narrative_raw.forensic_indicators_of_compromise,
            recommended_soc_actions=narrative_raw.recommended_soc_actions
        )

        ctx.firewall_rules_telemetry = MultiVendorFirewallResponse(
            target_domain=firewall_raw.target_domain,
            target_ip=firewall_raw.target_ip,
            palo_alto_cli=firewall_raw.palo_alto_cli,
            cloudflare_waf_json=firewall_raw.cloudflare_waf_json,
            fortigate_cli=firewall_raw.fortigate_cli,
            cisco_asa_acl=firewall_raw.cisco_asa_acl,
            suricata_ips_rule=firewall_raw.suricata_ips_rule
        )

    def _stage_5_assemble_result(self, ctx: PipelineContext) -> ScanResult:
        """
        Stage 5: Assembles and validates final ScanResult schema.
        """
        total_latency_ms = round((time.time() - ctx.start_time) * 1000, 2)
        ctx.stage_timings["total_latency_ms"] = total_latency_ms

        return ScanResult(
            url=ctx.url,
            s_lex=ctx.lex_res.s_lex if ctx.lex_res else 0.0,
            s_dom=ctx.dom_score if ctx.dom_score > 0 else (None if ctx.dom_matched_brand is None else 0.0),
            s_vis=ctx.vis_score if ctx.vis_score > 0 else (None if ctx.vis_matched_brand is None else 0.0),
            matched_brand=ctx.matched_brand,
            s_phish=ctx.s_phish,
            shap_contributions=ctx.shap_contribs,
            confidence=ctx.confidence,
            screenshot_url=ctx.screenshot_rel_url,
            matched_brand_screenshot_url=ctx.matched_brand_screenshot_rel_url,
            tls_telemetry=ctx.tls_telemetry,
            visual_forensics=ctx.visual_forensics,
            aitm_telemetry=ctx.aitm_telemetry,
            cloaking_telemetry=ctx.cloaking_telemetry,
            quishing_telemetry=ctx.quishing_telemetry,
            semantic_alignment=ctx.semantic_telemetry,
            dom_forensics=ctx.dom_forensics,
            phishpedia_consistency=ctx.phishpedia_telemetry,
            redirect_trace=ctx.redirect_telemetry,
            kit_fingerprint=ctx.kit_telemetry,
            target_attribution=ctx.target_attribution_telemetry,
            honeytoken_telemetry=ctx.honeytoken_telemetry,
            visual_ocr=ctx.visual_ocr_telemetry,
            redirect_graph=ctx.redirect_graph_telemetry,
            threat_narrative=ctx.threat_narrative_telemetry,
            firewall_rules=ctx.firewall_rules_telemetry,
            iscx_ensemble=ctx.iscx_ensemble_telemetry,
            stackmodel_features=ctx.stackmodel_telemetry,
            phishzoo_analysis=ctx.phishzoo_telemetry,
            header_forensics=ctx.header_forensics_telemetry,
            latency_ms=total_latency_ms
        )
