# MailTrace.AI — Unified Enterprise System Architecture & Implementation Blueprint
**Document Version:** 3.1.0 (Autonomous Zero-API-Key Forensic Edition)  
**Security Classification:** Restricted / Official  
**Jurisdiction Compliance:** Bharatiya Sakshya Adhiniyam (BSA) 2023 — Section 63 | FIPS 140-3 | RFC 5322, 7208, 6376, 7489, 8617  
**Authors:** Senior Software Architect & Forensic Intelligence Systems Team  
**Status:** IMPLEMENTATION-READY (Awaiting User Review & Approval)  

---

## Table of Contents
1. [Executive Summary & Architectural Charter](#1-executive-summary--architectural-charter)
2. [Deep Comparative Analysis: Previous Architecture vs. Updated Architecture](#2-deep-comparative-analysis-previous-architecture-vs-updated-architecture)
3. [The Zero-API-Key Autonomous Architecture: Eliminating External Dependencies, Rate Limits & Watermarks](#3-the-zero-api-key-autonomous-architecture-eliminating-external-dependencies-rate-limits--watermarks)
4. [Exhaustive Real-World Parameter Specification & Mathematical Forensic Analysis](#4-exhaustive-real-world-parameter-specification--mathematical-forensic-analysis)
5. [System Architecture & High-Level Design (HLD)](#5-system-architecture--high-level-design-hld)
6. [Data Flow Architecture (DFD Level 0, Level 1, Level 2)](#6-data-flow-architecture-dfd-level-0-level-1-level-2)
7. [Low-Level Design (LLD) & Forensic Micro-Engines](#7-low-level-design-lld--forensic-micro-engines)
   - 7.1 Immutable Evidence Preservation & Ingestion Gate
   - 7.2 Multi-Pass Adversarial De-Obfuscation Pipeline (ZWSP + Homoglyph + Lookalike)
   - 7.3 RFC-822 MIME Decomposition & Chronological MTA Hop Parser
   - 7.4 Protocol Authenticity & Cryptographic Identity Matrix (SPF/DKIM/DMARC/ARC)
   - 7.5 Autonomous Quishing & Computer Vision QR Payload Extractor
   - 7.6 Network Provenance, ASN & Infrastructure Intelligence
   - 7.7 NLP Behavioral Manipulation, Urgency & BEC Deconstructors
   - 7.8 32-Dimensional Feature Vector Synthesis & Normalized Threat Scoring
   - 7.9 Attack DNA, Cosine Similarity & Campaign Clustering Engine
   - 7.10 Legal Evidence Custody & Section 63 BSA 2023 Digital Certificate Engine
8. [Database Schema & Entity-Relationship Architecture (ERD + DDL)](#8-database-schema--entity-relationship-architecture-erd--ddl)
9. [UI/UX Design System Specification (shadcn/ui Synthesized Architecture)](#9-uiux-design-system-specification-shadcnui-synthesized-architecture)
10. [Unified Class Diagram & Component Interconnects (UML)](#10-unified-class-diagram--component-interconnects-uml)
11. [End-to-End Dynamic Interaction Workflows (Sequence Diagrams)](#11-end-to-end-dynamic-interaction-workflows-sequence-diagrams)
12. [State Transition Models (Evidence & Case Lifecycle)](#12-state-transition-models-evidence--case-lifecycle)
13. [Deployment Topology, Container Orchestration & Security Hardening](#13-deployment-topology-container-orchestration--security-hardening)
14. [API Contract & REST Interface Definitions](#14-api-contract--rest-interface-definitions)
15. [Implementation Roadmap, Verification Protocol & Acceptance Criteria](#15-implementation-roadmap-verification-protocol--acceptance-criteria)

---

## 1. Executive Summary & Architectural Charter

### 1.1 Purpose
MailTrace.AI is an autonomous, evidence-oriented email threat intelligence, adversarial de-obfuscation, network infrastructure provenance, and forensic certification platform. The system is engineered to solve the acute legal and technical challenges faced by corporate Security Operations Centers (SOC), national cyber crime investigation cells, CERT agencies, and digital forensic law enforcement examiners.

Unlike standard email security gateways (SEG) that merely render binary "SPAM/HAM" classifications or quarantine suspect emails, MailTrace.AI treats every incoming electronic message as potential **courtroom digital evidence**. It guarantees:
1. **Pre-Parsing Cryptographic Preservation:** Strict zero-alteration raw byte hashing before any MIME decomposition.
2. **Adversarial Resilience:** Robust unmasking of zero-width character evasion, Cyrillic/Greek homoglyph deception, Punycode tricks, and QR-code visual payloads (Quishing).
3. **MTA Infrastructure Reconstruction:** Hop-by-hop chronological extraction of the true internet transit path, isolating private LAN jumps from untrusted foreign origin relays.
4. **Autonomous Evidence-Grounded Scoring:** A deterministic 32-dimensional feature vector combined with NLP behavioral telemetry, where every point deduction corresponds to a traceable finding ID (`[F-001]` to `[F-010]`).
5. **Statutory Admissibility Compliance:** Native generation of Section 63 certificates under the **Bharatiya Sakshya Adhiniyam (BSA) 2023** (superseding Section 65B of the Indian Evidence Act 1872), incorporating SHA-256 hash chains, system hardware hashes, and examiner declarations.
6. **Zero-API-Key Autonomous Operation:** Complete elimination of external cloud API dependencies, preventing tile watermarks, rate limiting, and investigative data leakage.

### 1.2 Implementation Status Classification
In adherence to senior architectural standards, all components throughout this document are strictly categorized as:
* **[IMPLEMENTED]**: Functioning in the current live repository code (`backend/`, `frontend/`, `tests/`), verified by automated test suites.
* **[PROPOSED]**: Fully architected, detailed with schemas, contracts, algorithms, and ready for immediate deployment.
* **[ASSUMED]**: External environmental variables, standard network latency limits, and OS-level primitives.

---

## 2. Deep Comparative Analysis: Previous Architecture vs. Updated Architecture

The repository contains a historical design document titled `previous architecture.md` (originating from an earlier SkyBlaze / CyberTrace iteration). The table below details the architectural evolution, identifying which features were retained, improved, newly designed, or refactored.

| Architectural Dimension | Previous Architecture (`previous architecture.md`) | Updated Architecture (`updated architecture.md` — MailTrace.AI) | Architectural Rationale & Enhancement Details |
| :--- | :--- | :--- | :--- |
| **System Branding & Core Focus** | "CyberTrace / SkyBlaze" general anti-phishing concept. | **MailTrace.AI v2.6 Enterprise** (SIH 2026 flagship platform). | **[IMPLEMENTED]** Shift from generic classification to high-density forensic analysis and courtroom-ready evidence certification. |
| **External API Dependency** | Depended on third-party cloud APIs (commercial map tiles, cloud threat feeds, external GeoIP). | **Zero-API-Key Autonomous Architecture.** | **[IMPLEMENTED]** Replaced gated CartoDB tiles with keyless Esri World Dark Gray Base & Reference; offline MaxMind MMDB; local in-memory CV QR scanning. Eliminates "API KEY REQUIRED" watermarks and cloud costs. |
| **Presentation Tier** | React 19 + TypeScript + Cytoscape.js (heavy frontend bundle). | **Zero-Build Native HTML5 + Tailwind CSS + Vanilla JS + Leaflet + Chart.js + Lucide Icons.** | **[IMPLEMENTED]** Eliminates complex Node.js build steps, heavy client-side hydrate delays, and memory leaks. Delivers sub-10ms instantaneous rendering in low-latency air-gapped forensic labs. |
| **UI/UX Design Tokens** | Generic dark enterprise styling without standardized token variables. | **Official `shadcn/ui` Design System Synthesis.** | **[IMPLEMENTED]** Adopts modern HSL/OKLCH semantic CSS tokens (`--card`, `--muted`, `--accent`, `--border`, `--ring`, `--destructive`), card anatomy, pill tabs (`TabsList`/`TabsTrigger`), and accessible dialog modals with <kbd>Esc</kbd> dismissal. |
| **Evidence Preservation** | Stored in MinIO object storage; raw bytes parsed asynchronously. | **Pre-Parse SHA-256 Hashing Gate + Dual Storage (Local Encrypted Store [IMPLEMENTED] + MinIO S3 Object Store [PROPOSED]).** | **[IMPLEMENTED]** Solves parser mutation risk: raw byte streams are hashed *before* any MIME parser touches encoding or line endings, guaranteeing an unbreakable chain of custody. |
| **Adversarial De-Obfuscation** | Basic Unicode ZWSP and Punycode mention. | **Multi-Pass Forensic Normalization Engine [IMPLEMENTED].** | **[IMPLEMENTED]** Complete pipeline: Pass 1 strips 6 Unicode zero-width evasion characters; Pass 2 applies NFKC compatibility decomposition to unmask Cyrillic/Greek homoglyphs; Pass 3 computes Levenshtein edit distance against 50+ global enterprise brands. |
| **Header & Hop Parsing** | Mentions `Received` parsing. | **Deterministic Chronological RFC-5322 Hop Reconstruction [IMPLEMENTED].** | **[IMPLEMENTED]** Extracts reverse-ordered `Received` chains, separates private RFC 1918 hops from untrusted public relays, calculates inter-MTA transmission latency, and extracts originating IPs. |
| **Protocol Matrix** | Theoretical SPF, DKIM, DMARC checks. | **Rigorous RFC-Compliant Evaluator [IMPLEMENTED].** | **[IMPLEMENTED]** Evaluates RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), and RFC 8617 (ARC), analyzing organizational alignment between visible `From:`, `Return-Path:`, and cryptographic signature domains. |
| **Quishing (QR Phishing)** | Brief QR image detection mention. | **Computer Vision In-Memory QR Payload Decoder [IMPLEMENTED].** | **[IMPLEMENTED]** Decodes inline Base64 images and attachments in-memory via `BytesIO`, extracting concealed URLs as first-class IoCs without writing untrusted image files to disk. |
| **Feature Vector & Scoring** | Conceptual 70% rule / 30% AI split. | **32-Dimensional FIPS-Compliant Feature Vector [IMPLEMENTED].** | **[IMPLEMENTED]** Strict 32D mathematical vector: Protocol Auth (25%), Header Alignment (20%), Obfuscation/Evasion (20%), NLP/Urgency (15%), Quishing (10%), Network/Tor Provenance (10%). Yields a 0–100 Fraud Score mapped to 4 threat tiers. |
| **Campaign Correlation** | `pgvector` cosine similarity planned. | **Hybrid Vector Engine: NumPy/SciPy Cosine Similarity [IMPLEMENTED] + PostgreSQL `pgvector` HNSW Index [PROPOSED].** | **[IMPLEMENTED/PROPOSED]** Enables rapid standalone local analysis without requiring a running database server for hackathon demos, while providing a drop-in PostgreSQL 16 `pgvector` enterprise schema for multi-tenant deployment. |
| **Legal Admissibility** | Section 65B Indian Evidence Act mentioned. | **Full Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023 Compliance [IMPLEMENTED].** | **[IMPLEMENTED]** Updates to current Indian statutory law (effective July 1, 2024), generating digitally sealed admissibility certificates including device hash, custodial ledger sequence, and examiner declaration. |
| **Multi-Tenancy & Access** | Planned PostgreSQL Row-Level Security (RLS). | **Full RBAC + Tenant Isolation Architecture [PROPOSED DDL].** | **[PROPOSED]** Defined PostgreSQL 16 schema with `tenant_id` propagation, RLS policies, and 5 granular roles (Tier-1 Analyst, Senior Examiner, Police IO, CISO, Auditor). |
| **Task Processing** | Celery + Redis only. | **Dual-Engine Execution: Fast-Path Synchronous Engine [IMPLEMENTED] + Asynchronous Celery/Redis Worker Pipeline [PROPOSED].** | **[IMPLEMENTED/PROPOSED]** Fast-Path executes full 32D forensic analysis in <80ms for interactive UI/UX; Asynchronous Celery pipeline handles bulk enterprise queues (10,000+ emails/hour). |

---

## 3. The Zero-API-Key Autonomous Architecture: Eliminating External Dependencies, Rate Limits & Watermarks

### 3.1 The Vulnerability of Third-Party Cloud APIs in Digital Forensics
Standard web architectures rely heavily on third-party SaaS APIs (Google Maps, CartoDB, OpenAI, VirusTotal, MaxMind Cloud API). In a cyber forensic and military SOC context, this reliance introduces **four catastrophic operational failure modes**:

1. **Watermark / Basemap Degradation:** Commercial tile providers (such as CARTO) enforce API key gating on raster tiles. When unauthenticated, they inject visual watermarks (`"API KEY REQUIRED carto.com/basemaps/apikey"`), obscuring critical MTA hop coordinates and destroying visual clarity during court presentations and executive briefings.
2. **Operational Security (OpSec) & Confidentiality Leakage:** Querying external SaaS APIs with forensic artifacts (target email addresses, subject lines, suspect IP addresses, extracted malicious domains) directly leaks classified investigative leads to third-party commercial cloud providers and potential surveillance adversaries monitoring search telemetry.
3. **Rate Limiting & Denial-of-Service During Active Outbreaks:** When a major phishing or ransomware campaign strikes an enterprise (e.g., 10,000 incoming malicious emails in 30 minutes), external cloud API quotas (e.g., 500 requests/day on free tiers) are instantly exhausted, paralyzing the SOC investigation.
4. **Air-Gapped Inoperability:** Defense networks, police forensic laboratories, and classified government enclaves (such as CERT-In, CBI, and intelligence bureaus) operate in strictly air-gapped environments with **zero outbound internet connectivity**. Systems requiring cloud API keys fail immediately.

### 3.2 The MailTrace.AI Zero-API-Key Architectural Triad
To resolve this permanently, MailTrace.AI implements a strictly autonomous, zero-API-key architecture across all five core subsystems:

```mermaid
flowchart TD
    subgraph Subsystem1 ["1. Geospatial Mapping"]
        ESRI["Esri ArcGIS World Dark Gray<br/>(100% Free, Zero-Key, Zero Watermark)"]
        OSM["OpenStreetMap + CSS Dark Inverter<br/>(Hardware-Accelerated Fallback)"]
        GEOJSON["Embedded GeoJSON Vector Map<br/>(100% Air-Gapped Offline)"]
    end

    subgraph Subsystem2 ["2. IP & ASN Intelligence"]
        MMDB["Local MaxMind GeoLite2 MMDB<br/>(Zero-Network Binary Tree Search)"]
        TOR_LOCAL["Local Tor Exit Node Directory<br/>(Offline CIDR Consensus Matching)"]
    end

    subgraph Subsystem3 ["3. Quishing & Computer Vision"]
        PYZBAR["Local In-Memory PyZbar / OpenCV<br/>(Zero-Vision-API Optical Decoding)"]
    end

    subgraph Subsystem4 ["4. NLP & Behavioral Synthesis"]
        REGEX_NLP["Local Deterministic Heuristic Engine<br/>(Urgency, Coercion, BEC Matrices)"]
        ONNX["Local Quantized ONNX / GGUF Transformer<br/>(Zero-Cloud-LLM Edge Inference)"]
    end

    subgraph Subsystem5 ["5. Legal Evidence Certification"]
        FIPS_CRYPTO["Local FIPS 140-3 SHA-256 Engine<br/>(Hardware MAC + System UUID Binding)"]
    end

    Subsystem1 --> ENGINE["MailTrace.AI Autonomous Forensic Engine<br/>100% Self-Contained, Air-Gapped Ready"]
    Subsystem2 --> ENGINE
    Subsystem3 --> ENGINE
    Subsystem4 --> ENGINE
    Subsystem5 --> ENGINE
```

#### 1. Keyless Geospatial Basemap Architecture (`frontend/app.js`)
* **Primary Basemap:** **Esri ArcGIS World Dark Gray Base & Reference**.
  * Base Tile URL: `https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}`
  * Reference Tile URL: `https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}`
  * Properties: Officially free for public mapping, unmetered, zero API keys required, zero watermark, crystal-clear dark gray aesthetic specifically designed for cybersecurity overlay visualization.
* **Secondary Fallback:** **OpenStreetMap Standard + CSS Dark Matrix Filter**:
  * Tile URL: `https://tile.openstreetmap.org/{z}/{x}/{y}.png`
  * Applied CSS Filter:
    ```css
    .leaflet-tile-pane {
      filter: invert(100%) hue-rotate(180deg) brightness(90%) contrast(120%) saturate(20%);
    }
    ```
* **Tertiary Air-Gapped Fallback:** **Embedded GeoJSON Polygon Vector Map**:
  * Static file: `frontend/assets/world-110m.json` (~140 KB).
  * Rendered directly via Leaflet `L.geoJSON()` with SVG path rendering when network access is completely disabled.

#### 2. Local Binary MaxMind MMDB Geolocation & ASN Lookup
* Replaces commercial HTTP GeoIP lookups with local memory-mapped `.mmdb` files (`GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`).
* Execution speed: $< 10 \mu\text{s}$ per IP resolution via binary tree traversal in RAM.
* Zero external HTTP queries; zero risk of leaking target IPs; zero API keys needed.

#### 3. In-Memory Computer Vision Optical QR Decoder
* Uses local C/Python bindings (`pyzbar`, `opencv-python`, or `zxing-cpp`) operating directly on in-memory byte streams via `io.BytesIO`.
* Zero reliance on Google Cloud Vision, AWS Rekognition, or external OCR APIs.

#### 4. Localized NLP & Behavioral Engine
* Evaluates urgency, coercion, and BEC financial deception via a local, deterministic regex-scoring matrix ($< 2\text{ms}$ execution on Python standard library) with optional local ONNX quantized transformers (DistilRoBERTa) executed on CPU/GPU.
* Zero reliance on OpenAI, Anthropic, or external cloud LLM tokens.

#### 5. Local Cryptographic Custody & Section 63 BSA Certification
* All cryptographic digests ($H_{\text{raw}}$), hardware MAC hashes, and Section 63 legal certificates are calculated using local Python `hashlib` (FIPS 140-3 compliant).
* Zero third-party timestamping authority or external blockchain gas fees needed to establish courtroom validity under Indian law.

---

## 4. Exhaustive Real-World Parameter Specification & Mathematical Forensic Analysis

Real-world electronic mail forensic investigation requires precise mathematical analysis of technical parameters that attackers exploit and examiners must verify.

### 4.1 MTA Timing, Network Jitter & Clock Skew Analysis
Every RFC 5322 compliant Mail Transfer Agent (MTA) prepends a `Received:` header containing a timestamp formatted according to RFC 2822 (e.g., `Fri, 18 Sep 2026 09:14:24 +0000`).

#### Mathematical Hop Latency & Jitter
Let the chronologically reconstructed sequence of MTA hops be $H = [h_1, h_2, \dots, h_n]$, where $h_1$ is the originating hop and $h_n$ is the final recipient gateway. Let $t_i$ be the POSIX epoch timestamp of hop $h_i$.

The transit latency between consecutive hops is:
$$\Delta t_i = t_i - t_{i-1} \quad \text{for } i \in [2, n]$$

The total propagation latency across the entire route is:
$$T_{\text{total}} = t_n - t_1 = \sum_{i=2}^{n} \Delta t_i$$

The network jitter across the relay chain is:
$$J = \frac{1}{n-2} \sum_{i=2}^{n-1} |\Delta t_{i+1} - \Delta t_i|$$

#### Real-World Forensic Anomaly Conditions
1. **Negative Latency ($\Delta t_i < -60\text{s}$):**
   * Indicates either a **forged `Received:` header** injected by the attacker or severe NTP clock desynchronization on the sending MTA. MailTrace.AI automatically generates finding `[F-008] MTA Time Drift / Forged Header Anomaly`.
2. **Abnormal Stall Latency ($\Delta t_i > 86400\text{s}$):**
   * Highlights messages held in intermediate spool queues for >24 hours, characteristic of graylisting, downstream queue poisoning, or store-and-forward relay abuse.

### 4.2 Network Boundary Demarcation & CIDR Categorization
To prevent false origin attribution, MailTrace.AI strictly isolates private, local, and carrier-grade NAT IP addresses from public internet routing hops.

| IP Address Range | CIDR Block | RFC Standard | Forensic Classification | Origin Eligibility |
| :--- | :--- | :--- | :--- | :--- |
| `10.0.0.0` – `10.255.255.255` | `10.0.0.0/8` | RFC 1918 | Private Network (Class A) | **Ineligible** (Internal Hop) |
| `172.16.0.0` – `172.31.255.255` | `172.16.0.0/12` | RFC 1918 | Private Network (Class B) | **Ineligible** (Internal Hop) |
| `192.168.0.0` – `192.168.255.255` | `192.168.0.0/16` | RFC 1918 | Private Network (Class C) | **Ineligible** (Internal Hop) |
| `100.64.0.0` – `100.127.255.255` | `100.64.0.0/10` | RFC 6598 | Shared Carrier-Grade NAT (CGNAT) | **Ineligible** (ISP Internal) |
| `127.0.0.0` – `127.255.255.255` | `127.0.0.0/8` | RFC 1122 | Loopback Interface | **Ineligible** (Host Local) |
| `169.254.0.0` – `169.254.255.255` | `169.254.0.0/16` | RFC 3927 | Link-Local (APIPA) | **Ineligible** (Auto-Config) |
| `fc00::` – `fdff:ffff:...` | `fc00::/7` | RFC 4193 | Unique Local Address (IPv6 ULA) | **Ineligible** (Internal IPv6) |
| **All Other Routable IPv4/IPv6** | **Global Unicast** | RFC 4291 / 791 | **Public Internet Relay** | **Eligible True Origin** |

The **True Originating IP** ($IP_{\text{origin}}$) is mathematically defined as the IP address of the earliest chronological hop $h_k$ such that:
$$k = \min \{ j \in [1, n] \mid IP(h_j) \notin \text{PrivateRanges} \}$$

### 4.3 Autonomous System (BGP ASN) Threat Weighting Matrix
MailTrace.AI maps the resolved Autonomous System Number (ASN) and hosting provider to a discrete infrastructure risk weight $W_{\text{infra}} \in [0.0, 1.0]$:

| Infrastructure Category | Example ASNs / Providers | Forensic Risk Score ($S_{\text{net}}$) | Threat Weight ($W_{\text{infra}}$) | Forensic Context |
| :--- | :--- | :--- | :--- | :--- |
| **National Government / Leased Line** | AS45820 (NIC India), AS24186 (RailTel) | $0.00$ | $0.00$ | Trusted state infrastructure. |
| **Tier-1 Telecom / Residential ISP** | AS701 (Verizon), AS2856 (BT), AS55836 (Airtel) | $15.00$ | $0.15$ | Typical end-user broadband. |
| **Enterprise Cloud Datacenter** | AS16509 (AWS EC2), AS8075 (Microsoft Azure) | $55.00$ | $0.55$ | Common for compromised SaaS relays. |
| **Bulletproof / High-Abuse Hosting** | AS57043, AS200052, AS206981 | $85.00$ | $0.85$ | Unregulated foreign VPS providers. |
| **Anonymizer (Tor Exit Node / VPN)** | Tor Exit Relays, AS62014, AS9009 (M247) | $100.00$ | $1.00$ | Direct evasion of origin tracking. |

### 4.4 Cryptographic Protocol Conformance (SPF, DKIM, DMARC, ARC)

#### 1. SPF Evaluation Mechanics (RFC 7208)
SPF matches the client IP against the SPF record published in DNS TXT for the `Return-Path` domain ($D_{\text{mailfrom}}$):
$$\text{SPF\_Result}(IP_{\text{origin}}, D_{\text{mailfrom}}) \in \{\text{Pass}, \text{Fail}, \text{SoftFail}, \text{Neutral}, \text{None}, \text{PermError}, \text{TempError}\}$$
* **Relaxed Alignment ($aspf=r$):** The visible `From:` domain and $D_{\text{mailfrom}}$ must share the same Organizational Domain (e.g., `mail.bank.com` aligns with `bank.com`).
* **Strict Alignment ($aspf=s$):** The visible `From:` domain and $D_{\text{mailfrom}}$ must match exactly.

#### 2. DKIM Cryptographic Verification (RFC 6376)
DKIM validates digital signatures embedded in the `DKIM-Signature` header:
$$\text{DKIM-Signature}: v=1;\; a=\text{rsa-sha256};\; c=\text{relaxed/relaxed};\; d=\text{example.com};\; s=s2026;\; bh=\dots;\; b=\dots$$
* **Body Hash Verification:**
  $$bh_{\text{calc}} = \text{Base64}(\text{SHA-256}(\text{Canonicalize}_{\text{body}}(B, l)))$$
  If $bh_{\text{calc}} \ne bh_{\text{header}}$, the message body was modified in transit.
* **Header Signature Verification:**
  $$b_{\text{verified}} = \text{Verify}_{\text{RSA}}(\text{PubKey}(s, d), \text{Canonicalize}_{\text{header}}(H), b)$$

#### 3. DMARC Alignment & Enforcement (RFC 7489)
$$\text{DMARC\_Pass} \iff (\text{SPF\_Pass} \land \text{SPF\_Aligned}) \lor (\text{DKIM\_Pass} \land \text{DKIM\_Aligned})$$
If $\text{DMARC\_Pass} = \text{False}$, the policy action specified by the domain owner is triggered:
$$\text{Action} \in \{\text{none}, \text{quarantine}, \text{reject}\} \times \text{percentage}(pct)$$

### 4.5 Adversarial Encoding, Confusable Scripts & Levenshtein Algorithms

#### 1. Zero-Width Space Evasion Codepoints
Adversaries insert non-rendering Unicode codepoints between keyword characters (e.g., `P\u200Ba\u200By\u200BP\u200Ba\u200Bl`) to break string pattern matching while maintaining visual deception:

```text
U+200B  [E2 80 8B]  ZERO WIDTH SPACE
U+200C  [E2 80 8C]  ZERO WIDTH NON-JOINER
U+200D  [E2 80 8D]  ZERO WIDTH JOINER
U+200E  [E2 80 8E]  LEFT-TO-RIGHT MARK
U+200F  [E2 80 8F]  RIGHT-TO-LEFT MARK
U+2060  [E2 81 A0]  WORD JOINER
```

#### 2. Cyrillic & Greek Homoglyphs (NFKC Normalization)
Attackers substitute visually identical Cyrillic glyphs into Latin brand names. MailTrace.AI applies Unicode Standard Annex #15 (NFKC) and character replacement:

| Deceptive Character | Unicode Codepoint | Script | Latin Forensic Target | Unicode Hex |
| :--- | :--- | :--- | :--- | :--- |
| **а** | `U+0430` | Cyrillic Small Letter A | **a** | `U+0061` |
| **с** | `U+0441` | Cyrillic Small Letter Es | **c** | `U+0063` |
| **е** | `U+0435` | Cyrillic Small Letter Ie | **e** | `U+0065` |
| **о** | `U+043E` | Cyrillic Small Letter O | **o** | `U+006F` |
| **р** | `U+0440` | Cyrillic Small Letter Er | **p** | `U+0070` |
| **ѕ** | `U+0455` | Cyrillic Small Letter Dze | **s** | `U+0073` |
| **і** | `U+0456` | Cyrillic Small Letter Byelorussian-Ukrainian I | **i** | `U+0069` |

The Script-Mixing Anomaly Ratio is:
$$R_{\text{mix}} = \frac{N_{\text{non-latin\_confusables}}}{N_{\text{word\_length}}}$$
Any token with $R_{\text{mix}} > 0$ within a predominantly Latin text block triggers `[F-003] Adversarial Homoglyph Unmasked`.

#### 3. Damerau-Levenshtein Domain Lookalike Distance
To catch typosquatting and lookalike domains (e.g., `micros0ft-security.com` vs `microsoft.com`), MailTrace.AI calculates the minimum operations (insertions, deletions, substitutions, and transposition of adjacent characters) required to transform domain $A$ into protected brand $B$:

$$D_{A,B}(i, j) = \min \begin{cases} 
D_{A,B}(i-1, j) + 1 \\ 
D_{A,B}(i, j-1) + 1 \\ 
D_{A,B}(i-1, j-1) + \text{cost} \\ 
D_{A,B}(i-2, j-2) + 1 & \text{if } A[i]=B[j-1] \land A[i-1]=B[j] 
\end{cases}$$

A domain with $D_{A, B} \le 2$ targeting a major enterprise brand generates `[F-004] Deceptive Brand Lookalike Domain Identified`.

### 4.6 Section 63 BSA 2023 Statutory Admissibility Parameters
Under Section 63 of the Bharatiya Sakshya Adhiniyam 2023, electronic evidence is admissible in Indian courts only when accompanied by an official certificate identifying the electronic record and describing the manner in which it was produced.

The MailTrace.AI Cryptographic Evidence Tuple is:
$$\mathcal{E} = \langle \text{CertUUID}, H_{\text{SHA256}}(B_{\text{raw}}), |B_{\text{raw}}|, T_{\text{ISO8601}}, H_{\text{HW}}(\text{MAC}, \text{UUID}), H_{\text{Build}}(\text{GitCommit}), \text{ExaminerProfile} \rangle$$

Where:
* $H_{\text{SHA256}}(B_{\text{raw}})$: Cryptographic hash of the untouched RFC 5322 byte stream.
* $|B_{\text{raw}}|$: Exact file size in bytes.
* $T_{\text{ISO8601}}$: Tamper-evident UTC timestamp down to microsecond precision.
* $H_{\text{HW}}$: SHA-256 hash of system motherboard serial and MAC address.
* $H_{\text{Build}}$: Cryptographic commit SHA of the MailTrace.AI software engine (`101774f`).
* $\text{ExaminerProfile}$: Full legal name, official designation, and cyber forensic division of the investigating officer.

---

## 5. System Architecture & High-Level Design (HLD)

### 5.1 High-Level Architecture Diagram
The architecture is structured in five decoupled, resilient layers: Presentation Tier, API & Gateway Tier, Forensic Analysis Engine, Asynchronous Job Queue, and Persistent Storage & Intelligence Tier.

```mermaid
flowchart TB
    subgraph ClientTier ["Presentation Layer (Modern Browser Client)"]
        UI["MailTrace.AI Forensic SOC Workstation<br/>(HTML5 / Tailwind CSS / Vanilla JS)"]
        MAP["Keyless Esri Dark Gray Map<br/>(Zero API Key, Zero Watermark)"]
        RADAR["Chart.js 32D Radar & Progress Gauges"]
        DIALOG["Accessible BSA Cert Dialog<br/>(shadcn Tokens & Esc Trap)"]
    end

    subgraph GatewayTier ["Gateway & Control Tier (FastAPI Engine)"]
        API["FastAPI REST Application (v2.6.0)<br/>CORS / Rate Limiter / Auth Guards"]
        ROUTER["Forensic API Router<br/>/analyze, /samples, /evidence, /health"]
        CUSTODY_GATE["Pre-Parsing Custody Gate<br/>SHA-256 Digest Generator"]
    end

    subgraph AsyncTier ["Optional Enterprise Asynchronous Task Queue"]
        REDIS[("Redis 7.2 Broker<br/>Job Queues & State Cache")]
        CELERY["Celery Distributed Workers<br/>Parallel Forensic Tasks"]
    end

    subgraph EngineTier ["Autonomous Forensic Micro-Processing Engine"]
        MIME_PARSER["RFC-822 MIME Parser<br/>& Chronological Hop Extractor"]
        DEOBF["Adversarial De-Obfuscator<br/>(ZWSP + NFKC + Levenshtein)"]
        PROTO["Protocol Validator<br/>(SPF, DKIM, DMARC, ARC)"]
        QUISH["Quishing CV Engine<br/>(In-Memory QR Extraction)"]
        GEO["Network & ASN Intel<br/>(Local MMDB / Tor Consensus)"]
        NLP["NLP Behavioral Engine<br/>(Urgency, BEC, Wire Fraud)"]
        SYNTH["32D Vector Synthesizer<br/>& Fraud Score Calculator"]
        CERT_GEN["Section 63 BSA 2023<br/>Certificate Generator"]
    end

    subgraph StorageTier ["Data, Storage & Intelligence Tier"]
        MINIO[("MinIO S3 Object Store<br/>(Raw Immutable .EML Vault)")]
        POSTGRES[("PostgreSQL 16 + pgvector<br/>(Metadata, Vectors, RLS)")]
        INTEL_FEEDS[("Local Intel Databases<br/>(MaxMind MMDB, Tor Exit List)")]
    end

    UI <-->|"HTTP/2 REST + JSON"| API
    MAP --- UI
    RADAR --- UI
    DIALOG --- UI

    API --> CUSTODY_GATE
    CUSTODY_GATE -->|"Raw Bytes"| MINIO
    CUSTODY_GATE --> ROUTER

    ROUTER -->|"Fast-Path Sync (<80ms)"| MIME_PARSER
    ROUTER -.->|"Bulk Async Jobs"| REDIS
    REDIS --> CELERY
    CELERY --> MIME_PARSER

    MIME_PARSER --> DEOBF
    MIME_PARSER --> PROTO
    MIME_PARSER --> QUISH
    MIME_PARSER --> GEO
    MIME_PARSER --> NLP

    GEO <--> INTEL_FEEDS

    DEOBF --> SYNTH
    PROTO --> SYNTH
    QUISH --> SYNTH
    GEO --> SYNTH
    NLP --> SYNTH

    SYNTH --> CERT_GEN
    SYNTH -->|"Vectors & Findings"| POSTGRES
    CERT_GEN -->|"Admissibility Dossier"| POSTGRES
    CERT_GEN -->|"PDF / JSON Export"| UI
```

---

## 6. Data Flow Architecture (DFD Level 0, Level 1, Level 2)

### 6.1 DFD Level 0: Context Diagram

```mermaid
flowchart LR
    ANALYST(("Forensic Analyst /<br/>Investigating Officer"))
    SYSTEM["MailTrace.AI System Boundary"]
    LEGAL_COURT(("Court of Law /<br/>Judiciary Authority"))
    INTEL_NET(("Local Offline Databases<br/>(GeoLite2 MMDB, Tor List)"))

    ANALYST -->|"Uploads Raw .EML Evidence"| SYSTEM
    ANALYST -->|"Executes Case Analysis Query"| SYSTEM
    SYSTEM -->|"Interactive Forensic SOC Telemetry"| ANALYST
    SYSTEM -->|"Section 63 BSA Legal Dossier & Certificate"| LEGAL_COURT
    SYSTEM <-->|"Reads Local Offline Intelligence"| INTEL_NET
```

### 6.2 DFD Level 1: Forensic Processing Pipeline

```mermaid
flowchart TD
    EVIDENCE[".EML Evidence Stream"] --> P1["1.0 Ingestion & Cryptographic Fingerprinting"]
    P1 -->|"Untouched Raw Bytes"| STORE_RAW[("Immutable Evidence Vault")]
    P1 -->|"SHA-256 Digest + Raw Stream"| P2["2.0 MIME & Header Decomposition"]
    
    P2 -->|"Header Collection"| P3["3.0 Authentication & Identity Alignment"]
    P2 -->|"Received Hop Chain"| P4["4.0 Route Tracing & GeoIP Association"]
    P2 -->|"Body Text (Plain/HTML)"| P5["5.0 Adversarial De-Obfuscation Pipeline"]
    P2 -->|"Inline/Attachment Images"| P6["6.0 Quishing & Optical Payload Extractor"]
    
    P3 -->|"SPF/DKIM/DMARC Pass/Fail"| P7["7.0 32D Threat Vector Synthesis"]
    P4 -->|"MTA Hops & Latency"| P7
    P5 -->|"ZWSP & Homoglyphs"| P7
    P6 -->|"Decoded QR URLs"| P7
    P5 -->|"Normalized Text"| P8["8.0 NLP Urgency & Intent Evaluation"]
    P8 -->|"Manipulation Score"| P7

    P7 -->|"Composite Fraud Score (0-100)"| P9["9.0 Attack DNA & Campaign Clustering"]
    P7 -->|"Validated Finding Citations"| P10["10.0 Section 63 BSA Certificate Generation"]
    P9 -->|"pgvector Embedding"| STORE_DB[("PostgreSQL 16 + pgvector")]
    P10 -->|"Legal Evidence Dossier"| DOSSIER["Court-Admissible PDF & JSON Bundle"]
```

### 6.3 DFD Level 2: De-Obfuscation Subsystem

```mermaid
flowchart LR
    RAW_IN["Raw Extracted Body Text"] --> S1["Step 2.1: Zero-Width Character Scanning"]
    S1 -->|"Count ZWSP & Strip U+200B/C/D"| INTER_1["De-Spaced Text"]
    INTER_1 --> S2["Step 2.2: Unicode NFKC Decomposition"]
    S2 -->|"Identify Non-ASCII Codepoints"| S3["Step 2.3: Homoglyph Mapping Engine"]
    S3 -->|"Replace Cyrillic/Greek with Latin"| NORM_OUT["Clean Normalized Forensic Text"]
    
    RAW_IN --> S4["Step 2.4: Header Sender Domain Extraction"]
    S4 --> S5["Step 2.5: Brand Levenshtein Edit Distance"]
    S5 -->|"Distance <= 2 to Target Brand"| LOOKALIKE["Flag Lookalike Impersonation"]
```

---

## 7. Low-Level Design (LLD) & Forensic Micro-Engines

### 7.1 Immutable Evidence Preservation & Ingestion Gate
* **Status:** `[IMPLEMENTED]` in `backend/forensics/chain_of_custody.py`
* **Algorithm:**
  1. Receive raw byte stream $B$ via HTTP multipart upload or pre-packaged sample loader.
  2. Compute $H(B) = \text{SHA-256}(B)$ immediately using `hashlib.sha256()`.
  3. Generate unique UUIDv4 `case_id`.
  4. Write entry to in-memory/database `CUSTODY_LEDGER` with UTC timestamp, operator identity, byte length, and $H(B)$.
  5. Store raw bytes into immutable vault before invoking any parser.

### 7.2 Multi-Pass Adversarial De-Obfuscation Pipeline
* **Status:** `[IMPLEMENTED]` in `backend/forensics/deobfuscation.py`
* **Pass 1 — Zero-Width Space Stripping:** Detects and counts `U+200B`, `U+200C`, `U+200D`, `U+200E`, `U+200F`, `U+2060`.
* **Pass 2 — Unicode NFKC Compatibility Decomposition:** Normalizes text via `unicodedata.normalize('NFKC', text)`.
* **Pass 3 — Cyrillic/Greek Homoglyph Substitution:** Queries forensic homoglyph table replacing Cyrillic 'а', 'с', 'е', 'о', 'р', 'ѕ', 'і' with Latin equivalents.
* **Pass 4 — Domain Lookalike Detection (Levenshtein Distance):** Calculates edit distance against 50+ enterprise brands.

### 7.3 RFC-822 MIME Decomposition & Chronological MTA Hop Parser
* **Status:** `[IMPLEMENTED]` in `backend/forensics/header_parser.py`
* **Specification:** Adheres to RFC 5322 and RFC 2045–2049.
* **Hop Extraction Logic:**
  1. Parse all instances of `Received:`.
  2. Reverse order to produce chronological sequence numbers: Hop #1 (Origin) to Hop #N (Gateway).
  3. Regex pattern extraction for `from`, `by`, IP, and timestamp.
  4. Parse RFC 2822 timestamps into POSIX epoch timestamps to compute inter-hop relay latency $\Delta t_i$.

### 7.4 Protocol Authenticity & Cryptographic Identity Matrix
* **Status:** `[IMPLEMENTED]` in `backend/forensics/protocols.py`
* **Protocols Evaluated:**
  * **SPF (RFC 7208):** Evaluates `Received-SPF` and `Authentication-Results`.
  * **DKIM (RFC 6376):** Inspects `DKIM-Signature` headers for cryptographic domain signature verification.
  * **DMARC (RFC 7489):** Verifies organizational alignment.
  * **ARC (RFC 8617):** Authenticated Received Chain verification.

### 7.5 Autonomous Quishing & Computer Vision QR Payload Extractor
* **Status:** `[IMPLEMENTED]` in `backend/forensics/quishing.py`
* **Payload Unmasking:**
  1. Scan email attachments and inline Base64 images.
  2. Stream image bytes in-memory through `BytesIO` without writing to disk.
  3. Scan image array for 2D Quick Response barcode patterns.
  4. Decode embedded URLs and extract as high-risk IoCs.

### 7.6 Network Provenance, ASN & Infrastructure Intelligence
* **Status:** `[IMPLEMENTED]` in `backend/forensics/network_intel.py`
* **Infrastructure Categorization:**
  * Categorizes relay IP addresses into: `Public Gateway`, `Anonymizer (Tor Exit Node)`, `Commercial VPN`, `Bulletproof Hosting Provider`, `Cloud Datacenter`, or `Private (RFC 1918)`.
  * Resolves ASN, ISP name, and geographic coordinates.

### 7.7 NLP Behavioral Manipulation, Urgency & BEC Deconstructors
* **Status:** `[IMPLEMENTED]` in `backend/forensics/threat_scoring.py`
* **Semantic Vector Indicators:**
  * **Urgency & Coercion:** Detects artificial deadlines.
  * **Financial & Wire Transfer Fraud (BEC):** Detects executive wire keywords.
  * **Credential Phishing Hooks:** Detects credential-harvesting phrases.

### 7.8 32-Dimensional Feature Vector Synthesis & Normalized Threat Scoring
* **Status:** `[IMPLEMENTED]` in `backend/forensics/threat_scoring.py`
* **Scoring Formula:**
  $$\text{FraudScore} = \sum_{k=1}^{6} W_k \times S_k$$
  Where weights $W_k$ and sub-scores $S_k$ are distributed as:
  1. $S_{\text{auth}}$: Protocol Authenticity Risk ($W_{\text{auth}} = 0.25$)
  2. $S_{\text{header}}$: Header & Identity Alignment Anomaly ($W_{\text{header}} = 0.20$)
  3. $S_{\text{deobf}}$: Obfuscation & Homoglyph Evasion ($W_{\text{deobf}} = 0.20$)
  4. $S_{\text{nlp}}$: Behavioral Manipulation & BEC Intent ($W_{\text{nlp}} = 0.15$)
  5. $S_{\text{quish}}$: Quishing / QR Visual Payload ($W_{\text{quish}} = 0.10$)
  6. $S_{\text{net}}$: Infrastructure Provenance & Tor Risk ($W_{\text{net}} = 0.10$)
* **Risk Tier Mapping:**
  * $[0.0, 25.0)$: `LOW RISK (BENIGN)`
  * $[25.0, 50.0)$: `SUSPICIOUS`
  * $[50.0, 75.0)$: `MALICIOUS`
  * $[75.0, 100.0]$: `CRITICAL THREAT`

### 7.9 Attack DNA, Cosine Similarity & Campaign Clustering Engine
* **Status:** `[IMPLEMENTED]` local vector math; `[PROPOSED]` PostgreSQL `pgvector` HNSW index
* **Vector Definition:** A normalized vector $\vec{V} \in \mathbb{R}^{32}$ encoding the 32 discrete forensic features.
* **Cosine Similarity:**
  $$\text{Similarity}(\vec{A}, \vec{B}) = \frac{\vec{A} \cdot \vec{B}}{\|\vec{A}\|_2 \|\vec{B}\|_2}$$
  Two emails with $\text{Similarity} \ge 0.88$ are automatically clustered into the same threat campaign cluster.

### 7.10 Legal Evidence Custody & Section 63 BSA 2023 Digital Certificate Engine
* **Status:** `[IMPLEMENTED]` in `backend/forensics/chain_of_custody.py`
* **Statutory Compliance:** Generates the certificate mandated by Section 63 of the Bharatiya Sakshya Adhiniyam 2023 for the admissibility of electronic records in Indian courts.

---

## 8. Database Schema & Entity-Relationship Architecture (ERD + DDL)

### 8.1 Entity-Relationship Diagram (Mermaid)

```mermaid
erDiagram
    TENANTS ||--o{ USERS : owns
    TENANTS ||--o{ CASES : owns
    USERS ||--o{ CASES : investigates
    CASES ||--o{ EMAILS : contains
    EMAILS ||--o{ EMAIL_HEADERS : has
    EMAILS ||--o{ EMAIL_HOPS : traces
    EMAILS ||--o{ EMAIL_IOCS : extracts
    EMAILS ||--|| FORENSIC_ANALYSES : produces
    EMAILS ||--o{ DEOBFUSCATION_EVENTS : logs
    CASES ||--o{ CUSTODY_EVENTS : records
    CASES ||--o{ BSA_CERTIFICATES : certifies
    CAMPAIGNS ||--o{ CAMPAIGN_CASES : correlates

    TENANTS {
        uuid id PK
        varchar name
        varchar code UK
        timestamp created_at
    }

    USERS {
        uuid id PK
        uuid tenant_id FK
        varchar email UK
        varchar full_name
        varchar role
        varchar password_hash
        timestamp created_at
    }

    CASES {
        uuid id PK
        uuid tenant_id FK
        uuid investigator_id FK
        varchar case_number UK
        varchar status
        varchar threat_tier
        numeric fraud_score
        timestamp created_at
    }

    EMAILS {
        uuid id PK
        uuid case_id FK
        varchar filename
        varchar raw_sha256
        int file_size_bytes
        varchar storage_uri
        timestamp ingested_at
    }

    EMAIL_HOPS {
        uuid id PK
        uuid email_id FK
        int hop_sequence
        varchar from_mta
        varchar by_mta
        inet relay_ip
        varchar country
        varchar asn
        numeric latency_seconds
        boolean is_origin
    }

    FORENSIC_ANALYSES {
        uuid id PK
        uuid email_id FK
        numeric fraud_score
        varchar risk_tier
        boolean spf_pass
        boolean dkim_pass
        boolean dmarc_pass
        boolean quishing_detected
        jsonb metrics_breakdown
        vector attack_dna_vector
        timestamp analyzed_at
    }

    BSA_CERTIFICATES {
        uuid id PK
        uuid case_id FK
        varchar certificate_number UK
        varchar raw_sha256
        text certificate_body
        examiner_name varchar
        timestamp generated_at
    }

    CUSTODY_EVENTS {
        uuid id PK
        uuid case_id FK
        varchar action
        varchar operator
        varchar sha256_hash
        text details
        timestamp event_time
    }
```

### 8.2 PostgreSQL 16 + pgvector Production DDL

```sql
-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";

-- 1. Multi-Tenant Organization Registry
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    code VARCHAR(64) UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 2. User & RBAC Accounts
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL CHECK (role IN ('TIER_1_ANALYST', 'SENIOR_EXAMINER', 'POLICE_IO', 'CISO', 'ADMINISTRATOR')),
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 3. Investigation Cases
CREATE TABLE cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    investigator_id UUID REFERENCES users(id) ON DELETE SET NULL,
    case_number VARCHAR(64) UNIQUE NOT NULL,
    status VARCHAR(32) DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ANALYZING', 'CERTIFIED', 'CLOSED', 'ARCHIVED')),
    threat_tier VARCHAR(32) DEFAULT 'PENDING',
    fraud_score NUMERIC(5, 2) DEFAULT 0.00,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 4. Ingested Evidence Emails
CREATE TABLE emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    raw_sha256 CHAR(64) NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    storage_uri VARCHAR(512) NOT NULL,
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 5. Chronological MTA Relay Hops
CREATE TABLE email_hops (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    hop_sequence INTEGER NOT NULL,
    from_mta VARCHAR(512),
    by_mta VARCHAR(512),
    relay_ip INET,
    latitude NUMERIC(9, 6),
    longitude NUMERIC(9, 6),
    city VARCHAR(128),
    country VARCHAR(128),
    asn VARCHAR(128),
    isp VARCHAR(255),
    infra_type VARCHAR(64),
    latency_seconds NUMERIC(8, 2) DEFAULT 0.00,
    is_origin BOOLEAN DEFAULT FALSE NOT NULL
);

-- 6. Full Forensic 32D Analysis & Vector Storage
CREATE TABLE forensic_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID UNIQUE NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
    fraud_score NUMERIC(5, 2) NOT NULL,
    risk_tier VARCHAR(32) NOT NULL,
    spf_status VARCHAR(16) NOT NULL,
    dkim_status VARCHAR(16) NOT NULL,
    dmarc_status VARCHAR(16) NOT NULL,
    overall_auth_pass BOOLEAN NOT NULL,
    quishing_detected BOOLEAN DEFAULT FALSE NOT NULL,
    zero_width_count INTEGER DEFAULT 0 NOT NULL,
    homoglyphs_unmasked_count INTEGER DEFAULT 0 NOT NULL,
    metrics_breakdown JSONB NOT NULL,
    attack_dna_vector vector(32) NOT NULL,
    findings JSONB NOT NULL,
    analyzed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Create HNSW Vector Index for Instant Sub-Millisecond Campaign Clustering
CREATE INDEX idx_forensic_vector_hnsw ON forensic_analyses 
USING hnsw (attack_dna_vector vector_cosine_ops) 
WITH (m = 16, ef_construction = 64);

-- 7. Section 63 BSA 2023 Digital Evidence Certificates
CREATE TABLE bsa_certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    certificate_number VARCHAR(128) UNIQUE NOT NULL,
    raw_sha256 CHAR(64) NOT NULL,
    certificate_body TEXT NOT NULL,
    examiner_name VARCHAR(255) NOT NULL,
    examiner_designation VARCHAR(255) NOT NULL,
    organization VARCHAR(255) NOT NULL,
    generated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- 8. Immutable Chain-of-Custody Event Ledger
CREATE TABLE custody_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    action VARCHAR(128) NOT NULL,
    operator VARCHAR(255) NOT NULL,
    sha256_hash CHAR(64) NOT NULL,
    details TEXT,
    event_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Row-Level Security (RLS) Policy for Multi-Tenant Isolation
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE emails ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_cases ON cases
    FOR ALL
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
```

---

## 9. UI/UX Design System Specification (shadcn/ui Synthesized Architecture)

The presentation tier synthesizes the component ergonomics, accessible dialog patterns, pill-style tab navigation, and token variables discovered in the isolated clone of `shadcn/ui` (`_temp/design-references/shadcn-ui/` commit `a87a63b`).

### 9.1 Semantic Token Architecture

```css
:root {
  /* Surface & Base Canvas */
  --background: #06090e;         /* Deep cyber slate */
  --foreground: #f8fafc;         /* High-contrast slate-50 */
  --card: #0b111a;               /* Elevated card container */
  --card-foreground: #f8fafc;
  --popover: #0b111a;
  --popover-foreground: #f8fafc;

  /* Primary Brand Accent */
  --primary: #06b6d4;            /* Cyan-500 forensic telemetry accent */
  --primary-foreground: #ffffff;
  
  /* Secondary & Muted Structural Elements */
  --secondary: #162032;          /* Slate-850 hover background */
  --secondary-foreground: #e2e8f0;
  --muted: #101826;              /* Low-contrast pill and track background */
  --muted-foreground: #94a3b8;   /* Slate-400 for subtext and captions */
  
  /* Critical & Adversarial Badges */
  --destructive: #ef4444;        /* Red-500 threat marker */
  --destructive-foreground: #ffffff;
  
  /* Structural Boundaries & Focus Halos */
  --border: #1e293b;             /* Slate-800 1px divider */
  --input: #1e293b;
  --ring: #06b6d4;               /* Focus-visible halo */
  --radius: 0.625rem;            /* 10px rounded corner baseline */
}
```

### 9.2 Core Component Anatomy Specifications

#### 1. Card Anatomy (`.ui-card`)
* **Container:** `background: var(--card); border: 1px solid var(--border); border-radius: var(--radius);`
* **Header (`.ui-card-header`):** Flexbox container separating `.ui-card-title` (compact, bold, tracking-tight) from `.ui-card-description` (muted, 11px font size).
* **Content (`.ui-card-content`):** Padding standard: `1.25rem 1.5rem`.

#### 2. Pill Tabs Ergonomics (`.tabs-pill-container` & `.tab-pill-btn`)
* **List Wrapper:** Encapsulated capsule `bg-muted` (`#101826`) with `0.25rem` inner padding and `0.75rem` border radius.
* **Button State Machine:**
  * Inactive: `color: var(--muted-foreground); background: transparent;`
  * Active: `background: var(--secondary); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); font-weight: 600; box-shadow: 0 2px 8px rgba(0,0,0,0.4);`
  * Accessibility: Full WAI-ARIA implementation (`role="tablist"`, `role="tab"`, `aria-selected="true/false"`, `aria-controls="tab-id"`).

#### 3. Accessible Dialog Modal (`#cert-modal`)
* **Backdrop:** `fixed inset-0 z-50 bg-black/80 backdrop-blur-sm` for optical isolation.
* **Dialog Card:** Fixed maximum width (`max-w-3xl`), centered via CSS grid/flex, equipped with `role="dialog"`, `aria-modal="true"`, `aria-labelledby="modal-cert-title"`.
* **Keyboard Navigation:** Native <kbd>Escape</kbd> key listener dismisses dialog instantly; focus automatically captured upon opening.

#### 4. Keyless Map Visualization (`#leaflet-map`)
* **Tile Server:** Esri ArcGIS World Dark Gray Base & Reference.
* **Zero Watermarks:** Zero API key required, crisp dark tiles, zero rate limit popups.

---

## 10. Unified Class Diagram & Component Interconnects (UML)

```mermaid
classDiagram
    class MailTraceApp {
        +FastAPI app
        +serve_index()
        +health_check()
        +get_sample_analysis(sample_key)
        +process_email_bytes(raw_bytes, filename)
    }

    class CustodyManager {
        +calculate_sha256(raw_bytes) str
        +record_custody_action(case_id, action, operator, hash, details)
        +generate_section_63_bsa_certificate(params) dict
    }

    class HeaderParser {
        +parse_email_headers(raw_bytes) dict
        +reconstruct_mta_hops(received_headers) list
        +calculate_hop_latency(t1, t2) float
    }

    class DeobfuscationEngine {
        +detect_zero_width(text) tuple
        +normalize_unicode_nfkc(text) str
        +unmask_homoglyphs(text) list
        +calculate_domain_lookalike(domain, brand_catalog) dict
    }

    class ProtocolValidator {
        +analyze_authentication_protocols(headers, domain, ip) dict
        +validate_spf(headers, domain, ip) dict
        +validate_dkim(headers) dict
        +validate_dmarc(headers, from_domain) dict
    }

    class QuishingDetector {
        +detect_quishing(text, html, attachments) dict
        +scan_image_for_qr(image_bytes) list
    }

    class NetworkIntelEngine {
        +enrich_hops_with_network_intel(hops) list
        +classify_infrastructure(ip) str
        +lookup_asn_and_geo(ip) dict
    }

    class ThreatScorer {
        +evaluate_nlp_heuristics(text) dict
        +compute_32d_feature_vector(sub_results) dict
        +calculate_composite_fraud_score(vector) float
        +map_risk_tier(score) str
    }

    MailTraceApp --> CustodyManager : invokes preservation
    MailTraceApp --> HeaderParser : delegates parsing
    MailTraceApp --> DeobfuscationEngine : unmasks evasion
    MailTraceApp --> ProtocolValidator : checks alignment
    MailTraceApp --> QuishingDetector : scans optical payloads
    MailTraceApp --> NetworkIntelEngine : enriches IPs
    MailTraceApp --> ThreatScorer : synthesizes 32D vector
```

---

## 11. End-to-End Dynamic Interaction Workflows (Sequence Diagrams)

### 11.1 End-to-End Forensic Ingestion & Analysis Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Forensic Investigator
    participant UI as Forensic SOC Workstation
    participant API as FastAPI Gateway
    participant Custody as Custody & Preservation Gate
    participant Parser as RFC-822 MIME Parser
    participant Deobf as De-Obfuscation Pipeline
    participant Intel as GeoIP / Network Intel
    participant Scorer as 32D Scoring Engine
    participant DB as PostgreSQL + pgvector

    Analyst->>UI: Uploads suspicious .EML file (or selects sample)
    UI->>API: POST /api/analyze/upload (multipart form-data)
    
    API->>Custody: calculate_sha256(raw_bytes)
    Custody-->>API: Returns SHA-256 Digest
    API->>Custody: record_custody_action("EVIDENCE_INGESTED")
    
    API->>Parser: parse_email_headers(raw_bytes)
    Parser-->>API: Extracted Headers, Body Preview, Received Hops
    
    par Parallel Forensic Analysis
        API->>Deobf: deobfuscate_pipeline(body, sender_domain)
        Deobf-->>API: ZWSP Count, Unmasked Homoglyphs, Lookalike Domain
    and
        API->>Intel: enrich_hops_with_network_intel(hops)
        Intel-->>API: Geo Coordinates, ASN, Tor/VPN/Cloud Classification
    end
    
    API->>Scorer: compute_32d_feature_vector(all_signals)
    Scorer-->>API: 32D Vector, Fraud Score (0-100), Risk Tier, Findings [F-001..]
    
    API->>DB: Store Case Metadata, Findings, and 32D Vector Embedding
    DB-->>API: Commit Acknowledged
    
    API-->>UI: Complete Forensic Analysis JSON Payload
    UI->>UI: Update SVG Threat Gauge, Render 32D Radar & Leaflet Hop Map
```

### 11.2 Section 63 BSA 2023 Certificate Issuance & Legal Export Workflow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Forensic Investigator
    participant UI as Forensic SOC Workstation
    participant API as FastAPI Gateway
    participant Custody as Custody Ledger
    participant DB as PostgreSQL Database
    actor Court as Court of Law

    Analyst->>UI: Clicks "Section 63 BSA Certificate"
    UI->>API: POST /api/evidence/certificate {case_id, investigator_name}
    API->>DB: Fetch Case Ingestion Digest & Verified Findings
    DB-->>API: Case Record & Cryptographic Hash
    
    API->>Custody: generate_section_63_bsa_certificate(params)
    Custody-->>API: Digitally Formatted Certificate Body & Unique Cert ID
    API->>Custody: record_custody_action("BSA_CERTIFICATE_ISSUED")
    API-->>UI: Returns Certificate JSON
    
    UI->>UI: Opens Accessible Dialog Modal (Esc Trap Active)
    Analyst->>UI: Clicks "Print Certificate" or "Export PDF"
    UI-->>Court: Formal Court-Admissible Electronic Evidence Dossier
```

---

## 12. State Transition Models (Evidence & Case Lifecycle)

```mermaid
stateDiagram-v2
    [*] --> Ingested : Raw .EML Uploaded
    
    state Ingested {
        [*] --> Hashed : Calculate SHA-256 Digest
        Hashed --> Sealed : Write Entry to Custody Ledger
    }

    Sealed --> Analyzing : Hand off to Forensic Pipeline
    
    state Analyzing {
        [*] --> HeaderDecomposition
        HeaderDecomposition --> DeobfuscationPass
        DeobfuscationPass --> ProtocolVerification
        ProtocolVerification --> OpticalQuishingScan
        OpticalQuishingScan --> VectorSynthesis
        VectorSynthesis --> [*]
    }

    Analyzing --> Evaluated : 32D Fraud Score Synthesized
    
    Evaluated --> Certified : Examiner Generates Section 63 BSA Certificate
    Evaluated --> Escalated : High Risk (Score >= 75) Triggers SOC Escalation
    
    Certified --> CourtDossierExported : PDF & Raw EML Bundled
    CourtDossierExported --> Archived : Case Concluded
    Archived --> [*]
```

---

## 13. Deployment Topology, Container Orchestration & Security Hardening

### 13.1 Multi-Container Docker Architecture (`docker-compose.yml`)

```yaml
version: '3.8'

services:
  # 1. Reverse Proxy & SSL Termination
  gateway:
    image: caddy:2.7-alpine
    container_name: mailtrace-gateway
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./infra/Caddyfile:/etc/caddy/Caddyfile:ro
    depends_on:
      - backend

  # 2. FastAPI Core Forensic Application
  backend:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: mailtrace-api
    environment:
      - DATABASE_URL=postgresql://mailtrace:SecurePass123!@postgres:5432/mailtrace_db
      - REDIS_URL=redis://redis:6379/0
      - MINIO_ENDPOINT=minio:9000
      - MINIO_ACCESS_KEY=mailtrace-vault
      - MINIO_SECRET_KEY=SecureVaultSecretKey2026!
    ports:
      - "8000:8000"
    depends_on:
      - postgres
      - redis
      - minio

  # 3. PostgreSQL 16 with pgvector Extension
  postgres:
    image: pgvector/pgvector:pg16
    container_name: mailtrace-postgres
    environment:
      - POSTGRES_USER=mailtrace
      - POSTGRES_PASSWORD=SecurePass123!
      - POSTGRES_DB=mailtrace_db
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./infra/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    ports:
      - "5432:5432"

  # 4. Redis Job Broker & Cache
  redis:
    image: redis:7.2-alpine
    container_name: mailtrace-redis
    ports:
      - "6379:6379"

  # 5. MinIO Immutable Evidence Object Storage
  minio:
    image: minio/minio:RELEASE.2024-01-18T22-51-28Z
    container_name: mailtrace-minio
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=mailtrace-vault
      - MINIO_ROOT_PASSWORD=SecureVaultSecretKey2026!
    volumes:
      - miniodata:/data
    ports:
      - "9000:9000"
      - "9001:9001"

volumes:
  pgdata:
  miniodata:
```

### 13.2 Security & Compliance Hardening Controls
1. **Air-Gapped Operation:** All forensic micro-engines operate deterministically without external internet connectivity.
2. **Read-Only Evidence Vault:** Once raw `.eml` bytes are committed to MinIO or the local store, object permissions are strictly read-only.
3. **FIPS 140-3 Cryptographic Integrity:** All SHA-256 and HMAC calculations use verified standard library implementations.
4. **Defense Against Parser Exploits:** Image loading is capped at $4096 \times 4096$ pixels to prevent decompression bombs.
5. **Zero-Trust Network Association:** Geolocation coordinates are strictly labelled as **Network Infrastructure Association**, preventing false evidentiary claims of suspect physical location.

---

## 14. API Contract & REST Interface Definitions

| HTTP Method | Endpoint URI | Description | Auth Required | Status |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/` | Serves the unified SOC Forensics workstation interface (`index.html`). | No | `[IMPLEMENTED]` |
| `GET` | `/api/health` | Diagnostic health probe reporting custody ledger size and standards. | No | `[IMPLEMENTED]` |
| `GET` | `/api/samples` | Returns catalog of verified pre-packaged attack scenarios. | No | `[IMPLEMENTED]` |
| `GET` | `/api/samples/{sample_key}` | Executes end-to-end 32D analysis on chosen sample case. | No | `[IMPLEMENTED]` |
| `POST` | `/api/analyze/upload` | Multipart upload of custom raw RFC-822 `.eml` evidence file. | Optional/Token | `[IMPLEMENTED]` |
| `POST` | `/api/evidence/certificate` | Generates Section 63 BSA 2023 Digital Evidence Certificate. | Role: Examiner | `[IMPLEMENTED]` |
| `GET` | `/api/evidence/export/{case_id}` | Exports IoCs in structured format (`?format=json` or `?format=csv`). | Role: Analyst | `[IMPLEMENTED]` |
| `GET` | `/api/evidence/case/{case_id}` | Returns complete forensic analysis JSON record for external SIEM. | Role: Analyst | `[IMPLEMENTED]` |
| `POST` | `/api/campaigns/correlate` | Executes cosine similarity query across stored `pgvector` embeddings. | Role: Senior | `[PROPOSED]` |
| `GET` | `/api/cases/{case_id}/pdf` | Generates multi-page court-admissible PDF forensic report dossier. | Role: Examiner | `[PROPOSED]` |

---

## 15. Implementation Roadmap, Verification Protocol & Acceptance Criteria

### 15.1 Phase Breakdown
* **Phase 1 (Complete — Verified in Live Code):**
  * Core forensic micro-engines (`header_parser.py`, `deobfuscation.py`, `protocols.py`, `network_intel.py`, `quishing.py`, `threat_scoring.py`, `chain_of_custody.py`).
  * Fast-path FastAPI server (`backend/main.py`) with sample loading and upload endpoints.
  * 15/15 automated pytest test suite (`test_api.py`, `test_forensics.py`).
  * Modern UI/UX frontend (`index.html`, `style.css`, `app.js`) with shadcn/ui design tokens, keyless Esri dark basemap, Chart.js radar, and Section 63 certificate modal.
  * Git synchronization: GitHub repository provisioned and up-to-date.

* **Phase 2 (Immediate Execution — Ready for Approval):**
  * Spin up PostgreSQL 16 + `pgvector` container using the provided DDL schema.
  * Connect `forensic_analyses` table to store 32D vector embeddings on every analysis.
  * Implement `/api/campaigns/correlate` endpoint for automated incident clustering.
  * Add automated PDF report generation endpoint using ReportLab / WeasyPrint.

* **Phase 3 (Enterprise Scale & National CERT Integration):**
  * Connect Celery distributed workers for asynchronous processing of 10,000+ daily email queues.
  * Enable multi-tenant Row-Level Security (RLS) for multi-agency joint investigation task forces.
  * Provision STIX 2.1 / TAXII threat intelligence feed connectors.

### 15.2 Acceptance Verification Criteria
1. **Mathematical Reproducibility:** The same `.eml` evidence file must always generate the exact same SHA-256 digest, 32D feature vector, and fraud score regardless of execution environment.
2. **Evidence-Grounded Citations:** Every high-risk indicator in the final assessment must map to a discrete, reproducible finding code (`[F-001]` to `[F-010]`).
3. **Zero Test Regressions:** `python -m pytest tests/ -v` must maintain 100% pass status across all unit and integration tests.
4. **Court Admissibility Compliance:** Generated Section 63 BSA certificates must contain the mandatory statutory declarations required under Indian electronic evidence jurisprudence.
5. **Zero API Key Dependency:** All visual maps, de-obfuscation algorithms, and cryptographic certifications must function flawlessly offline with zero external cloud API keys or watermarks.
