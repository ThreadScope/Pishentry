# Pishentry: Next-Generation Enterprise AI Architecture & Mathematical Specification

## 1. Executive Overview
This document specifies the advanced mathematical methods, statistical models, and architectural implementations for 3 enterprise-grade real-time security systems within **Pishentry**:
1. **Active Honeytoken & C2 Exfiltration Tracker** (`app/active_honeytoken_interactor.py`)
2. **Fast-Flux DNS & ASN Bulletproof Hosting Tracker** (`app/fastflux_tracker.py`)
3. **MHTML & Cryptographic Legal Evidence Archiver** (`app/evidence_archiver.py`)

---

## 2. Active Honeytoken & C2 Exfiltration Tracker

### 2.1 Threat Context
Modern adversary-in-the-middle (AiTM) and credential phishing kits (e.g. EvilProxy, Tycoon 2FA, Caffeine) employ multi-stage client-side loaders that only reveal their command-and-control (C2) exfiltration channels when a human submits input credentials.

### 2.2 Mathematical & Cryptographic Formulation

#### A. Deterministic HMAC Canary Token Generation
To ensure canary credentials are mathematically trackable across threat intelligence databases without storing raw plaintext in database tables:
$$\text{Seed} = \text{HMAC-SHA256}(K_{\text{secret}}, \text{TargetURL} \parallel t_{\text{utc}})$$
$$\text{CanaryID} = \text{Hex}(\text{Seed})[:12]$$
$$\text{CanaryEmail} = \text{"sec-canary-" } \parallel \text{CanaryID} \parallel \text{"@corp-canary.internal"}$$
$$\text{CanaryPassword} = \text{"CanaryTok!9#" } \parallel \text{CanaryID}$$

#### B. Active Playwright Form Interaction & Network Interception
- Locates candidate input nodes:
  $$\text{Inputs}_{\text{text}} = \text{Query}(\text{"input[type=text], input[type=email], input[name*=user]"})$$
  $$\text{Inputs}_{\text{pass}} = \textQuery(\text{"input[type=password], input[name*=pass]"})$$
  $$\text{Buttons}_{\text{submit}} = \text{Query}(\text{"button[type=submit], input[type=submit], form button"})$$
- Emulates keystroke timing jitter:
  $$\Delta t_{\text{key}} \sim \mathcal{U}(40\text{ms}, 120\text{ms})$$
- Intercepts all outbound asynchronous network requests ($\text{POST}, \text{GET}, \text{WebSocket}$) during and following form dispatch.

#### C. C2 Destination Classifier
Outbound request URLs $U_{\text{out}}$ are classified into signature families:
- **Telegram Bot API**:
  $$\text{Pattern}_{\text{tg}} = \text{r"https:\/\/api\.telegram\.org\/bot[\w\-:]+\/sendMessage"}$$
- **Discord Webhook**:
  $$\text{Pattern}_{\text{discord}} = \text{r"https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w\-]+"}$$
- **PHP Drop Script**:
  $$\text{Pattern}_{\text{php}} = \text{r"\/[a-zA-Z0-9_\-]+\.(php|asp|aspx|jsp|cgi|pl)"}$$
- **Direct IP / Non-Standard Port Exfiltration**:
  $$\text{Pattern}_{\text{raw\_ip}} = \text{r"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{2,5})?"}$$

#### D. Active Exfiltration Confirmation Score
$$S_{\text{exfil}} = \min\left(1.0, 0.40 \cdot \mathbb{I}(\text{Form Submitted}) + 0.60 \cdot \mathbb{I}(\text{C2 Pattern Matched})\right)$$

---

## 3. Fast-Flux DNS & ASN Bulletproof Hosting Tracker

### 3.1 Threat Context
Bulletproof phishing infrastructure utilizes Fast-Flux DNS, rapidly rotating DNS A/AAAA records across hundreds of compromised hosts with ultra-short Time-to-Live (TTL $\le 60\text{s}$) to evade IP blacklisting and CDN domain takedowns.

### 3.2 Mathematical Formulations

#### A. Multi-Resolver Query Matrix
Queries are dispatched in parallel across 4 geographically diverse Tier-1 recursive DNS resolvers:
$$\mathcal{R} = \{ \text{1.1.1.1 (Cloudflare)}, \text{8.8.8.8 (Google)}, \text{9.9.9.9 (Quad9)}, \text{208.67.222.222 (OpenDNS)} \}$$
Let $\mathcal{A}_{\text{all}} = \bigcup_{r \in \mathcal{R}} \text{Resolve}(D, r)$ be the union of resolved IP addresses.

#### B. TTL Anomaly Scoring Function ($S_{\text{ttl}}$)
$$S_{\text{ttl}} = \begin{cases} 
1.0 & \text{if } \text{TTL}_{\text{min}} \le 60\text{s} \\ 
1.0 - \frac{\text{TTL}_{\text{min}} - 60}{240} & \text{if } 60\text{s} < \text{TTL}_{\text{min}} \le 300\text{s} \\ 
0.0 & \text{if } \text{TTL}_{\text{min}} > 300\text{s} 
\end{cases}$$

#### C. ASN Shannon Diversity Entropy ($H_{\text{asn}}$)
Let $N_{\text{ip}} = |\mathcal{A}_{\text{all}}|$ be the count of unique resolved IP addresses across resolvers. Let $K$ be the number of unique Autonomous System Numbers (ASNs) represented.
For each unique $\text{ASN}_k$, let $p_k = \frac{\text{count}(\text{ASN}_k)}{N_{\text{ip}}}$:
$$H_{\text{asn}} = -\sum_{k=1}^K p_k \log_2(p_k)$$

Normalized ASN Diversity Score ($S_{\text{asn\_div}}$):
$$S_{\text{asn\_div}} = \begin{cases} 
0.0 & \text{if } K \le 1 \\ 
\frac{H_{\text{asn}}}{\log_2(K)} & \text{if } K > 1 
\end{cases}$$

#### D. Bulletproof Hosting ASN Reputation Risk ($S_{\text{asn\_rep}}$)
Identifies presence in known high-abuse / bulletproof network ranges:
$$S_{\text{asn\_rep}} = \max_{k \in 1..K} \text{ReputationRisk}(\text{ASN}_k) \in [0.0, 1.0]$$

#### E. Composite Fast-Flux Index ($I_{\text{ff}}$)
$$I_{\text{ff}} = 0.35 \cdot S_{\text{ttl}} + 0.35 \cdot S_{\text{asn\_div}} + 0.30 \cdot S_{\text{asn\_rep}}$$

---

## 4. MHTML & Cryptographic Legal Evidence Archiver

### 4.1 Threat Context
For computer emergency response teams (CERTs), domain registrars, and legal prosecution, static screenshots alone are insufficient. A legally binding digital evidence chain must preserve raw network transactions, TLS certificates, and exact DOM structures with cryptographic integrity.

### 4.2 Mathematical & Cryptographic Architecture

#### A. Merkle Tree Evidence Digest
Individual component hashes are computed using SHA-256:
$$H_{\text{dom}} = \text{SHA256}(\text{Raw DOM HTML Binary})$$
$$H_{\text{scr}} = \text{SHA256}(\text{Viewport PNG Screenshot})$$
$$H_{\text{har}} = \text{SHA256}(\text{HAR Network Transaction Dump})$$
$$H_{\text{tls}} = \text{SHA256}(\text{DER Certificate Chain})$$

Root Cryptographic Fingerprint ($H_{\text{root}}$):
$$H_{\text{root}} = \text{SHA256}(H_{\text{dom}} \parallel H_{\text{scr}} \parallel H_{\text{har}} \parallel H_{\text{tls}})$$

#### B. RFC 2557 MHTML Packaging
Serializes the live DOM state, inline styles, external stylesheets, scripts, base64-encoded web fonts, and sub-resources into a MIME-encapsulated `.mhtml` document readable by all modern forensic tooling.

#### C. Standalone Forensic ZIP Archive Architecture
```
evidence_<report_id>.zip
├── manifest.json            <- Metadata, MITRE ATT&CK tags, timestamp, SHA-256 tree
├── snapshot.mhtml           <- Complete offline page bundle
├── screenshot.png           <- Full HD viewport capture
├── network_traffic.har      <- Complete request/response trace
└── checksums.sha256         <- Cryptographic verification file
```

---

## 5. Execution Roadmap
1. Build `app/active_honeytoken_interactor.py` (Canary generator + form submitter + C2 sniffer).
2. Build `app/fastflux_tracker.py` (Multi-resolver DNS engine + TTL/ASN entropy math).
3. Build `app/evidence_archiver.py` (MHTML serializer + SHA-256 Merkle root + ZIP builder).
4. Expose FastAPI routes in `app/main.py`.
5. Integrate HUD telemetry into Streamlit UI `ui/streamlit_app.py`.
6. Add unit test suite `tests/test_enterprise_realtime_engines.py` and run full regression suite.
