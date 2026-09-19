# MailTrace AI — System Architecture & Forensic Specification
> **AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform**  
> *Official Technical Architecture Package for Smart India Hackathon (SIH 2026)*  
> **Repository**: [https://github.com/rakeshsinghrawat107/MailTrace-AI](https://github.com/rakeshsinghrawat107/MailTrace-AI)  
> **Architecture Status**: Verified & Implemented

---

## 1. Executive Summary & Problem Scope
Traditional email security gateways (SEGs) typically function as binary classifiers ("Phishing: YES/NO" or "Spam score: 8.2"). When high-severity security incidents occur—such as Business Email Compromise (BEC), spear-phishing wire fraud, or advanced quishing (QR-code phishing)—incident responders, SOC analysts, and cyber crime law enforcement agencies lack:
1. **Explainable Multi-pass De-obfuscation**: Attackers insert zero-width characters (`\u200B`, `\u200C`) and Cyrillic/Greek homoglyphs to defeat static keyword filters.
2. **Hop-by-Hop Relay Provenance**: Reconstructing the complete MTA (Mail Transfer Agent) hop chain from `Received:` headers to track true originating infrastructure rather than attacker-controlled spoofed headers.
3. **Multi-Vector Feature Correlation**: Combining domain lookalike distance (Levenshtein/Punycode), protocol alignment (SPF, DKIM, DMARC), and behavioral NLP into a deterministic 32-dimensional feature vector.
4. **Section 63 BSA 2023 Digital Evidence Admissibility**: Indian evidence law under the **Bharatiya Sakshya Adhiniyam (BSA) 2023 (Section 63)** requires cryptographic hash verification (SHA-256), immutable custody logging, and certified audit trails for electronic records to be admissible in court.

**MailTrace AI** closes this gap by transforming raw `.eml` or RFC-822 email evidence into court-ready forensic intelligence, autonomous threat correlation graphs, and visual hop trace maps.

---

## 2. Design Assumptions & Boundary Definitions

### Verified Implementations [IMPLEMENTED]
- Multi-pass adversarial de-obfuscation (Pass 1: Zero-width character stripper; Pass 2: Unicode NFKC homoglyph normalization & Cyrillic lookalike mapping; Pass 3: Punycode domain decoder).
- RFC-822 / MIME header parser extracting sender identities, return paths, reply-to anomalies, and ordered `Received:` hops.
- Protocol validation engine for SPF, DKIM, and DMARC alignment and policy conformance.
- Network intelligence engine resolving hop IP geolocation, Autonomous System Numbers (ASN), ISP, and infrastructure classification (Tor, VPN, Public Cloud, Residential).
- 32-dimensional explainable feature vector extraction and normalized fraud risk index (0–100 scale).
- SHA-256 cryptographic evidence hashing upon ingestion with chain-of-custody logging.
- Section 63 BSA 2023 Digital Evidence Certificate generator with verified finding citations `[F-001]`, `[F-002]`, etc.
- Interactive Cyber SOC Analyst Dashboard with Leaflet geo-routing map, radar vector gauge, and IoC export (CSV/JSON).

### Proposed & Extended Capabilities [PROPOSED]
- Distributed pgvector embeddings for petabyte-scale campaign clustering across enterprise tenants.
- Real-time DNSBL/SURBL live threat feed querying with local Redis cache fallback.
- Hardware Security Module (HSM) / KMS cryptographic signing of Section 63 certificates.

### Foundational Constraints [ASSUMED]
- Email headers may contain fabricated entries; the system treats only headers inserted by verified upstream MTAs as trusted, designating earliest visible hops as *probable origin* rather than physical attacker identity.

---

## 3. High-Level Design (HLD)

### Cloud Architecture Diagram (Generated via Eraser API)
![MailTrace AI Architecture](https://storage.googleapis.com/second-petal-295822.appspot.com/elements/elements%3A6c747efc10b5a7e6110b607a19471691cadd9183dbc7bde643f95a3448563091.png)
> **Open & Edit in Eraser**: [https://app.eraser.io/new?requestId=3d3CcXTU9ERwvDw0g4g2&state=TNltlLesfKL3mcDqgXFgs](https://app.eraser.io/new?requestId=3d3CcXTU9ERwvDw0g4g2&state=TNltlLesfKL3mcDqgXFgs)

### System Architecture Flowchart (Mermaid)

```mermaid
flowchart TB
    subgraph ClientLayer ["Client & Analyst Presentation Layer"]
        UI["SOC Forensic Dashboard (React + Vite + Modern Cyber Dark UI)"]
        TraceMap["Interactive Leaflet Hop Trace Map"]
        VectorRadar["32D Feature Vector Radar"]
        IoCTable["IoC Extraction & Filter Table"]
        CertView["Section 63 BSA 2023 Certificate Viewer"]
    end

    subgraph APILayer ["API & Ingestion Gateway"]
        Gateway["FastAPI REST Gateway (Port 8000)"]
        RateLimiter["Rate Limiting & Input Validation"]
        Hasher["SHA-256 Cryptographic Evidence Ingestion Engine"]
    end

    subgraph ForensicCore ["Forensic & Intelligence Pipeline"]
        Deobf["Adversarial De-Obfuscation (ZWSP Stripper + NFKC Homoglyph)"]
        HeaderParser["RFC-822 MIME & Hop Path Reconstructor"]
        ProtocolEngine["Authentication Validator (SPF / DKIM / DMARC)"]
        NLPHeuristics["Social Engineering & Fraud Classifier (Urgency/BEC)"]
        GeoIntel["IP Geolocation, ASN & Infrastructure Classifier"]
        QuishingEngine["Quishing Detector (QR-Code Image Extraction)"]
        VectorEngine["32-Dimensional Explainable Feature Vector Engine"]
    end

    subgraph StorageLayer ["Evidence Vault & Custody Ledger"]
        EvidenceVault["Immutable Evidence Storage (Original .eml Hash)"]
        AuditLedger["Chain-of-Custody Audit Trail (Append-Only)"]
        IoCStore["IoC Intelligence Index (IPs, Domains, Hashes)"]
    end

    UI -->|Upload .eml / Select Sample| Gateway
    Gateway --> RateLimiter --> Hasher
    Hasher -->|Store Immutable Byte Copy| EvidenceVault
    Hasher -->|Generate Ingestion Receipt| AuditLedger
    Hasher --> Deobf --> HeaderParser

    HeaderParser --> ProtocolEngine
    HeaderParser --> GeoIntel
    HeaderParser --> QuishingEngine
    Deobf --> NLPHeuristics

    ProtocolEngine --> VectorEngine
    GeoIntel --> VectorEngine
    NLPHeuristics --> VectorEngine
    QuishingEngine --> VectorEngine

    VectorEngine --> IoCStore
    VectorEngine --> Gateway
    Gateway --> UI

    UI --> TraceMap
    UI --> VectorRadar
    UI --> IoCTable
    UI --> CertView
```

---

## 4. Sequence Diagram: Forensic Investigation & Legal Custody Lifecycle

### Forensic Flow Diagram (Generated via Eraser API)
![Forensic Custody Sequence](https://storage.googleapis.com/second-petal-295822.appspot.com/elements/elements%3Acc35aa225964dcc750a7e8c46055fc71b149ce5961ed364dedad1dd2fece2272.png)
> **Open & Edit in Eraser**: [https://app.eraser.io/new?requestId=0OuxEuykvzR3MrOwT8gz&state=GRNjIKPdC6k5iopVcyY96](https://app.eraser.io/new?requestId=0OuxEuykvzR3MrOwT8gz&state=GRNjIKPdC6k5iopVcyY96)

### Interaction Sequence (Mermaid)

```mermaid
sequenceDiagram
    autonumber
    actor Investigator as SOC Investigator / Police Analyst
    participant UI as Analyst Dashboard
    participant API as FastAPI Gateway
    participant Hasher as SHA-256 Evidence Hasher
    participant Pipeline as Forensic Intelligence Engines
    participant Vault as Immutable Evidence Vault

    Investigator->>UI: Upload raw .eml evidence file
    UI->>API: POST /api/analyze (multipart/form-data)
    API->>Hasher: Calculate SHA-256 byte digest
    Hasher->>Vault: Store immutable copy & timestamped custody entry
    Vault-->>Hasher: Confirm custody record [Case ID, SHA-256]
    API->>Pipeline: Execute parallel forensics
    par Protocol Validation
        Pipeline->>Pipeline: Validate SPF, DKIM, DMARC alignment
    and Header Hop Provenance
        Pipeline->>Pipeline: Parse Received headers & resolve GeoIP/ASN
    and Adversarial De-obfuscation
        Pipeline->>Pipeline: Strip zero-width chars & normalize homoglyphs
    and Quishing Detection
        Pipeline->>Pipeline: Extract and decode embedded QR codes
    and Risk Vector Scoring
        Pipeline->>Pipeline: Compute 32-dimensional feature vector (Score 0-100)
    end
    Pipeline-->>API: Return structured forensic findings JSON
    API-->>UI: Deliver forensic intelligence package
    UI->>Investigator: Render visual hop map, radar risk gauge & IoC tables

    opt Request Legal Digital Evidence Certificate
        Investigator->>UI: Click "Generate Section 63 BSA 2023 Certificate"
        UI->>API: POST /api/evidence/certificate
        API->>Vault: Verify SHA-256 integrity against ingestion record
        Vault-->>API: Evidence Verified (Hash Match)
        API->>API: Compile Section 63 Certificate with finding citations [F-001...F-008]
        API-->>UI: Deliver printable forensic PDF/JSON certificate bundle
        UI-->>Investigator: Court-ready evidence certificate exported
    end
```

---

## 5. Entity-Relationship Data Model (ERD)

### Forensic Schema (Generated via Eraser API)
![Forensic Data Model ERD](https://storage.googleapis.com/second-petal-295822.appspot.com/elements/elements%3A360158b2f33af34cef7dd1539ab1f7c2f5e42e65c60e297d3f56767061d4cd47.png)
> **Open & Edit in Eraser**: [https://app.eraser.io/new?requestId=d22KO81Cp3vPtQv2MnGC&state=4jj6y20JA9DHfm5oKvNIs](https://app.eraser.io/new?requestId=d22KO81Cp3vPtQv2MnGC&state=4jj6y20JA9DHfm5oKvNIs)

### Relational Schema (Mermaid)

```mermaid
erDiagram
    EvidenceCase ||--|| EmailHeader : "has 1:1"
    EvidenceCase ||--|{ RelayHop : "contains 1:N"
    EvidenceCase ||--|| AuthenticationResult : "evaluates 1:1"
    EvidenceCase ||--|{ IoCIndicator : "yields 0:N"
    EvidenceCase ||--|{ ChainOfCustodyLog : "records 1:N"
    EvidenceCase ||--|| FeatureVector32D : "generates 1:1"

    EvidenceCase {
        string case_id PK
        string evidence_name
        string sha256_hash
        datetime ingested_at
        string investigator_id
        string status
        float fraud_score
        string risk_tier
    }

    EmailHeader {
        string header_id PK
        string case_id FK
        string from_header
        string return_path
        string reply_to
        string message_id
        string subject
        boolean identity_mismatch
        int lookalike_distance
    }

    RelayHop {
        string hop_id PK
        string case_id FK
        int hop_sequence
        string by_server
        string from_server
        string ip_address
        float latitude
        float longitude
        string country
        string city
        string asn
        string isp
        boolean is_cloud_or_vpn
        float transit_latency_ms
    }

    AuthenticationResult {
        string auth_id PK
        string case_id FK
        string spf_status
        string dkim_status
        string dmarc_status
        string dmarc_policy
        boolean alignment_pass
    }

    IoCIndicator {
        string ioc_id PK
        string case_id FK
        string ioc_type
        string ioc_value
        string risk_level
        string threat_category
    }

    ChainOfCustodyLog {
        string log_id PK
        string case_id FK
        string action
        string operator
        datetime timestamp
        string hash_at_action
    }

    FeatureVector32D {
        string vector_id PK
        string case_id FK
        float spf_weight
        float dkim_weight
        float dmarc_weight
        float homoglyph_density
        float urgency_score
        float credential_harvesting_risk
        float hop_anomaly_index
        string raw_vector_json
    }
```

---

## 6. Detailed Component Specifications

### 6.1 Multi-Pass Adversarial De-Obfuscation Pipeline
Attackers deliberately manipulate Unicode encoding to bypass signature and NLP filters:
1. **Pass 1 — Zero-Width Character Stripper**: Detects and purges invisible codepoints:
   - `\u200B` (Zero-width space)
   - `\u200C` (Zero-width non-joiner)
   - `\u200D` (Zero-width joiner)
   - `\uFEFF` (Zero-width no-break space / BOM)
   - `\u202A` through `\u202E` (Bidirectional override characters)
2. **Pass 2 — Unicode NFKC Homoglyph Normalization**: Normalizes lookalike characters from Cyrillic, Greek, and Cherokee scripts to Latin equivalents (e.g. Cyrillic `а` (`\u0430`) $\rightarrow$ Latin `a`, `о` (`\u043E`) $\rightarrow$ Latin `o`).
3. **Pass 3 — Levenshtein Lookalike Detection**: Computes edit distances between sender domains and top protected financial/enterprise brands (e.g., `micros0ft.com`, `paypa1-security.com`, `sbi-netbanking-verify.in`).

### 6.2 Quishing (QR-Code Phishing) Extraction Engine
Attackers embed phishing links inside image QR codes attached to emails to avoid textual link scrapers. The platform:
1. Parses email multipart MIME payloads for embedded inline images and file attachments (`image/png`, `image/jpeg`).
2. Runs OpenCV / QR decoding passes to extract raw payload URLs.
3. Passes decoded URLs through the domain lookalike and threat reputation analyzer.

### 6.3 Hop-by-Hop Relay Network Provenance
1. Parses all `Received:` header clauses chronologically from earliest bottom hop to boundary gateway.
2. Extracts receiving MTA, sender MTA, relay IP, and timestamp.
3. Filters RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and identifies the first *public originating hop IP*.
4. Annotates network metadata: Autonomous System Number (ASN), ISP name, geographic coordinates, and hosting classification (e.g., AWS, DigitalOcean, Tor Exit, Commercial VPN).

### 6.4 32-Dimensional Feature Vector & Explainable Fraud Score
The engine calculates a standardized 32-dimensional feature vector spanning:
- Protocol Authenticity ($V_1 - V_4$): SPF, DKIM, DMARC, Domain Alignment.
- Header Provenance ($V_5 - V_8$): Return-Path Mismatch, Reply-To Diversion, Message-ID Format, Hop Latency Spikes.
- Lexical & NLP ($V_9 - V_{14}$): Urgency markers, Authority claims, Financial payment keywords, Credential harvesting requests.
- Obfuscation Indicators ($V_{15} - V_{20}$): Zero-width count, Homoglyph density, URL redirection depth, Punycode usage.
- Attachment & Payload ($V_{21} - V_{26}$): Executable double extensions, Hash threat reputation, Quishing QR presence.
- Network Reputation ($V_{27} - V_{32}$): Bulletproof host ASN, Tor exit node, VPN hop count, High-risk registrar.

Normalized into a 0–100 **MailTrace Fraud Index**:
- **0 – 24 (LOW RISK)**: Legitimate authenticated correspondence.
- **25 – 49 (SUSPICIOUS)**: Minor alignment failure or untrusted ISP without malicious intent.
- **50 – 74 (MALICIOUS)**: Confirmed spoofing, high urgency, or lookalike domain.
- **75 – 100 (CRITICAL / THREAT)**: Active credential theft, quishing, or BEC impersonation with multi-vector evasion.

---

## 7. Legal Compliance & Forensic Custody (Section 63 BSA 2023)
Under the **Bharatiya Sakshya Adhiniyam, 2023 (Section 63)**, electronic records are admissible as primary or secondary evidence in Indian courts provided their integrity and chain of custody are verifiable:
1. **Byte-Level Ingestion Hashing**: Immediate SHA-256 digest computation before parsing or normalization.
2. **Deterministic Finding Citations**: Every analytical claim in the forensic narrative references an immutable finding ID (e.g., `[F-001: SPF Hardfail]`, `[F-002: Lookalike Levenshtein Distance = 1]`).
3. **Court-Ready Certificate Generator**: Produces an official Certificate under Section 63 BSA 2023 detailing:
   - Device & Ingestion Environment particulars
   - Custody officer identity & timestamp
   - Cryptographic SHA-256 evidence digest
   - Method of automated extraction & forensic safeguards
   - Statutory compliance statement signed by the forensic examiner.

---

## 8. Technology Stack Mapping

| Layer | Component | Selection | Rationale |
|---|---|---|---|
| **Frontend UI** | Modern SOC Dashboard | React 18 + Vite + TypeScript | High-performance reactive UI for real-time forensic exploration |
| **Styling** | Cyber SOC Aesthetic | Modern Tailwind / CSS Tokens | High-contrast dark cyber theme (`#090d16`), accessible forensic badges |
| **Geo Visualization** | Hop Route Trace Map | Leaflet.js / OpenStreetMap | Interactive global routing path visualization without proprietary API keys |
| **Charts** | Threat Vector Breakdown | HTML5 Canvas / SVG Gauges | 32D radar, risk dials, and relay latency timeline charts |
| **API Backend** | Forensic REST Service | FastAPI (Python 3.14) | Asynchronous, type-safe high-throughput forensic analysis endpoints |
| **MIME Parser** | RFC-822 Parsing | Python `email` & `mailbox` stdlib | Strict RFC-5322 compliance, header folding and MIME segment extraction |
| **De-Obfuscation** | Normalization Pipeline | `unicodedata` NFKC + Regex | Zero-overhead deterministic normalization of homoglyphs and ZWSP |
| **Hashing & Custody**| Evidence Ledger | `hashlib` (SHA-256 / SHA-512) | FIPS 180-4 compliant cryptographic integrity proofs |
| **Report Engine** | Section 63 BSA Export | ReportLab & HTML Print Engine | Clean court-admissible PDF forensic certificate generation |
| **Diagramming** | Architectural Models | Eraser.io API & Mermaid.js | Hosted diagrams with visual clarity and editable source |
