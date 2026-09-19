# CyberTrace / SkyBlaze — Detailed System Architecture

## Purpose of this file

This document explains the complete architecture of the CyberTrace (SkyBlaze) platform in **two ways**:

1. **Technical view** — the engineering terms, components, services, storage, data flow, and security controls.
2. **Simple view** — what each part means in normal language and why it exists.

The system is an **evidence-oriented email threat detection, geolocation, and forensic intelligence platform**. It does more than label an email as phishing: it preserves the original email, investigates its hidden content and routing path, traces network infrastructure, calculates an explainable risk score, correlates related attacks, and prepares evidence-backed reports. [file:106][file:104]

---

# 1. Architecture at a glance

## Technical view

CyberTrace follows a layered, event-driven architecture:

```text
React + TypeScript Web App
          |
          v
FastAPI API Gateway and Authentication Layer
          |
          +--------------------------+
          |                          |
          v                          v
PostgreSQL + pgvector          MinIO Object Storage
(cases, findings, users,       (original .eml evidence,
 reports, vectors, audits)      report bundles, checksums)
          |
          v
Redis + Celery Asynchronous Task Queue
          |
          v
Forensic Processing Pipeline
  1. Preservation
  2. MIME reconstruction
  3. Header/auth analysis
  4. URL/QR/attachment extraction
  5. GeoIP/RDAP/threat enrichment
  6. Risk synthesis
  7. Campaign correlation
  8. Evidence narrative and dossier
          |
          v
External Intelligence Services
(DNS, SPF/DKIM/DMARC, GeoIP/ASN, RDAP, reputation feeds)
```

## Simple view

The website is the front door. A user uploads a suspicious email. The backend sends the email through a secure investigation pipeline. The original email is locked safely, the system checks it from many angles, and the result is shown as one clear investigation case with a risk score, IP/geolocation details, findings, and an evidence report. [file:106]

---

# 2. Main building blocks

## 2.1 Presentation Layer — React Web Application

### Technical view

- **Technology:** React 19, TypeScript, Tailwind CSS, Cytoscape.js for relationship/attack graphs.
- **Role:** Provides the browser-based interface for public visitors and authenticated users.
- **Design system:** Uses the existing `design.md` rules: dark enterprise theme, Inter font, muted blue accent, no neon-cyan or AI-demo styling.
- **Access control:** Route guards ensure protected pages require valid authentication and role permissions.

### Simple view

This is what the analyst sees in the browser. It is the dashboard area where they upload an email, inspect risks, see the IP route and map, explore similar campaigns, and download reports.

### Main screens

- **Public Landing:** Basic textual introduction only; no internal data, dashboard data, or screenshots.
- **Login:** Secure sign-in for authorised users.
- **Overview:** Tenant-specific case and campaign metrics.
- **Upload:** Upload raw `.eml` file or paste raw email source.
- **Investigation:** Full evidence and analysis page for one email/case.
- **Threat Intelligence:** Related campaigns, indicators, and relationship graph.
- **Infrastructure:** Header hops, IPs, ASN, ISP, hosting, and geolocation association.
- **Reports & Evidence:** Evidence bundles, hashes, verification, and audit-related records.
- **Settings/Admin:** Tenant and user configuration where authorised.

The screen journey remains aligned with `AppFlow.md`.

---

## 2.2 API and Application Layer — FastAPI

### Technical view

- **Technology:** FastAPI with Python 3.12.
- **Role:** API gateway, authentication enforcement, request validation, orchestration, database access, and secure delivery of frontend data.
- **API style:** Versioned REST APIs, for example:
  - `POST /api/emails/ingest`
  - `GET /api/cases/{caseId}`
  - `GET /api/cases/{caseId}/findings`
  - `GET /api/cases/{caseId}/infrastructure`
  - `POST /api/cases/{caseId}/report`
  - `GET /api/campaigns`
  - `POST /api/evidence/{caseId}/verify`
- **Security controls:** JWT authentication, RBAC authorization, tenant context propagation, request validation, upload limits, and audit logging.

### Simple view

FastAPI is the coordinator. It receives requests from the website, checks whether the user is allowed to do that work, saves data, starts investigation jobs, and sends results back to the dashboard.

---

## 2.3 Asynchronous Processing Layer — Celery and Redis

### Technical view

- **Redis:** Message broker and short-lived job state/cache.
- **Celery workers:** Execute processing tasks outside the user request cycle.
- **Why asynchronous processing:** DNS, RDAP, GeoIP, QR scanning, model inference, report generation, and campaign correlation can take time or depend on external services.
- **Task orchestration:** A case starts with a pipeline job; independent enrichments can execute in parallel and update the case progressively.
- **Resilience:** Failed external lookups are marked as `UNAVAILABLE` or `RETRY_PENDING`; they do not block deterministic local analysis. [file:106]

### Simple view

Instead of making the user wait while everything is checked, the system sends heavy work to background workers. The dashboard can show “Analysis in progress” and then fill in results as each check finishes.

---

## 2.4 Relational Data Layer — PostgreSQL and pgvector

### Technical view

- **PostgreSQL 16:** Stores structured operational and forensic metadata.
- **pgvector:** Stores Attack DNA feature vectors and performs cosine-similarity searches for related cases/campaigns. [file:106][file:104]
- **Row-Level Security (RLS):** Enforces tenant separation at the database layer.
- **Primary data groups:**
  - Identity and tenancy: `tenants`, `users`, `roles`, `user_roles`
  - Core cases: `cases`, `emails`, `email_headers`, `email_urls`, `email_attachments`
  - Analysis: `auth_results`, `header_anomalies`, `origin_intel`, `domain_intel`, `analysis_results`
  - Correlation: `campaigns`, `campaign_emails`, `indicators`, `campaign_indicators`
  - Evidence and operations: `reports`, `case_actions`, `evidence_ledger`, `audit_logs`

### Simple view

PostgreSQL is the organised register of the whole platform. It remembers users, institutions, cases, email details, threat scores, IP findings, reports, and every important action.

`pgvector` helps it answer: “Have we seen another email that looks structurally similar to this one?”

---

## 2.5 Evidence Storage Layer — MinIO

### Technical view

- **Technology:** MinIO, an S3-compatible object storage service.
- **Role:** Stores large forensic artifacts separately from PostgreSQL:
  - Original raw `.eml` bytes
  - Evidence checksum files
  - Generated PDF dossiers
  - IoC JSON/CSV exports
  - Optional derived artifacts approved for storage
- **Immutability principle:** Original email bytes are written and hashed before parsing. The raw original is never overwritten. [file:104][file:106]

### Simple view

MinIO is the secure evidence locker. The original email is stored there exactly as it arrived. The system does not replace or edit that original file.

---

## 2.6 Evidence Integrity Layer — SHA-256, Custody Log, and Ledger

### Technical view

- **SHA-256:** Computes a cryptographic digest of raw email bytes before any parser accesses them.
- **Chain of custody:** Records who uploaded/accessed/exported evidence and when, using UTC timestamps.
- **Evidence ledger:** Stores evidence hash, case reference, event metadata, actor, and optional permissioned-ledger/blockchain transaction reference.
- **Verification:** Recalculate SHA-256 from stored raw email bytes and compare with recorded hash.
- **Legal positioning:** The platform prepares technical evidence and a Section 63 BSA-oriented documentation bundle; it does not itself declare evidence legally admissible. [file:104][file:106]

### Simple view

Before opening the email, we create its digital fingerprint. If even one character changes later, the fingerprint changes. This lets an investigator show that the saved email has not been altered.

---

# 3. End-to-end forensic workflow

## Stage 1 — Secure Intake and Preservation

### Technical workflow

1. An authenticated SOC analyst, investigator, or authorised institutional user uploads an `.eml` file.
2. FastAPI validates file size, type, tenant context, and user permission.
3. The raw byte stream is sent directly to MinIO without MIME parsing or normalisation.
4. SHA-256 is calculated over the untouched byte stream.
5. The system creates a `case`, `email`, custody event, and evidence hash record.
6. A Celery workflow begins for forensic processing. [file:104][file:106]

### Simple workflow

The user uploads an email. First, we lock the exact original email safely and create a unique fingerprint. Only after that do we start investigating it.

### Why this matters

Some parsers may change line endings, header formatting, or encoding. If the system hashes only after parsing, it may no longer prove what the original email looked like. Preservation before parsing prevents this problem. [file:104]

---

## Stage 2 — MIME Parsing and Adversarial Reconstruction

### Technical workflow

1. A worker reads a copy of preserved raw bytes for analysis.
2. The MIME parser walks all parts: text/plain, text/html, inline content, attachments, and nested MIME sections.
3. A multi-pass de-obfuscation pipeline records and detects:
  - Unicode format/zero-width characters such as `U+200B`.
  - Unicode NFKC normalization candidates and homoglyph indicators.
  - Punycode domain labels such as `xn--`.
  - CSS/DOM concealed content: `display:none`, `visibility:hidden`, `font-size:0`, or same-colour text/background.
4. The system retains both raw evidence and derived normalized analysis values.
5. It stores extracted headers, visible text, hidden text indicators, URLs, attachments, and anomalies. [file:104][file:106]

### Simple workflow

Attackers sometimes hide letters, words, or malicious links so normal filters cannot see them. This stage looks inside every part of the email and reveals those tricks.

### Example

A subject might visually look like “Urgent payment required”, but it could contain invisible characters to bypass keyword filters. We record both the original version and the cleaned version, so the trick itself becomes evidence.

---

## Stage 3 — URL, Attachment, and QR/Quishing Extraction

### Technical workflow

1. Extract URLs from plain text and HTML attributes such as `href`.
2. Canonicalize URLs and identify their effective domains.
3. Process attachments with safe metadata extraction: filename, MIME type, size, hash, and risk indicators.
4. Decode inline/attached images in memory using `BytesIO`, image loading, and QR decoding.
5. Treat a QR-decoded URL as a first-class indicator of compromise (IOC).

### Simple workflow

The system collects every link and attachment. It also checks images for QR codes, because an attacker may hide a dangerous link inside a QR image instead of writing it directly in the email. [file:104][file:106]

---

## Stage 4 — Header, Routing, and Authentication Forensics

### Technical workflow

1. Parse `Received` header sequence to reconstruct SMTP routing hops.
2. Identify likely earliest trustworthy public source hop while flagging private RFC 1918 addresses as internal/private hops.
3. Evaluate sender-authentication signals:
  - **SPF:** Whether the sending IP is allowed by the domain’s SPF policy.
  - **DKIM:** Whether the message signature and signed content validate.
  - **DMARC:** Whether SPF/DKIM alignment supports the visible From domain and the domain policy.
4. Detect anomalies such as Return-Path/Reply-To mismatch, display-name impersonation, suspicious Message-ID domain, and inconsistent routing.
5. Save results in `auth_results`, `email_headers`, and `header_anomalies`.

### Simple workflow

Every email passes through servers before reaching the recipient. The header is like a travel record. We read it to see the route, check whether the sender is genuine, and detect places where the claimed identity does not match the technical evidence.

---

## Stage 5 — IP Tracing, Geolocation, and Infrastructure Association

### Technical workflow

1. Extract relevant public IP addresses from reliable header hops.
2. Query GeoIP/ASN sources to obtain country, region/city estimate, ASN, ISP, and hosting organisation.
3. Identify VPN, proxy, Tor, cloud hosting, or suspicious infrastructure indicators where intelligence is available.
4. Query RDAP/domain sources for domain registration and age data.
5. Store results in `origin_intel` and `domain_intel`.
6. Render route timelines, infrastructure tables, and a map in the UI.

### Simple workflow

This stage traces the IP addresses in the email’s route. It tells us which network, hosting company, city, or country a server is associated with. It helps investigators understand the technical path and where to send ISP/hosting-provider requests.

### Important truth rule

GeoIP does **not** prove the attacker’s home address or physical location. It identifies the approximate location of network infrastructure, a server, VPN exit node, proxy, or hosting provider. The UI and report must label it as **Network Infrastructure Association**, not “Attacker Location.” [file:104][file:106]

---

## Stage 6 — Deterministic Risk Engine

### Technical workflow

The rule-based engine calculates an explainable, reproducible baseline risk score using factors such as:

- SPF, DKIM, and DMARC failures or alignment problems.
- Return-Path/Reply-To and sender identity mismatches.
- Newly registered or suspicious domains.
- High-risk URLs, attachments, QR payloads, and reputation hits.
- Obfuscation evidence: hidden text, homoglyphs, Punycode, zero-width characters.
- Infrastructure indicators: Tor/proxy flags, suspicious ASN/hosting context.

Each contributing factor becomes an explicit finding with an ID, such as `[F-001]`.

### Simple workflow

This is the rules-based part of the score. It checks facts that can be verified directly. For example: “DKIM failed”, “the Reply-To address is different”, or “a QR code points to a suspicious login page.”

---

## Stage 7 — AI Semantic Analysis

### Technical workflow

- **Model role:** A phishing-oriented NLP model such as fine-tuned RoBERTa analyses language patterns in cleaned subject/body text.
- **Output:** Semantic threat probability, probable intent labels, and supported explanation tags, for example urgency, credential harvesting, payment fraud, executive impersonation, or invoice scam language.
- **Scoring model:** The planned composite index uses approximately 70% deterministic/forensic signal and 30% AI semantic signal. [file:106]
- **Control:** AI semantic score adds context; it must not overwrite or invent deterministic evidence.

### Simple workflow

AI reads the language of the email. It notices scam-like wording such as “verify urgently”, “your account will be blocked”, or “make this payment now.” But AI is not trusted blindly: it is only one part of the final score.

---

## Stage 8 — Explainable Risk Synthesis

### Technical workflow

```text
Composite Threat Index (0–100)
= deterministic forensic score (target ~70%)
+ AI semantic score (target ~30%)
```

The output contains:

- Final score and severity band: Low, Medium, High, Critical.
- Deterministic contributing facts.
- AI semantic contribution.
- Confidence and limitations.
- Finding IDs that connect risk points to stored evidence.

### Simple workflow

The final score is not just an AI guess. Most of it comes from actual technical evidence; AI adds understanding of the email’s language. The analyst can always see why the score was given. [file:106]

---

## Stage 9 — Attack DNA and Campaign Correlation

### Technical workflow

1. Convert selected explainable signals into an Attack DNA feature vector:
   - Header traits.
   - Authentication results.
   - Sender/URL/domain indicators.
   - Infrastructure/ASN traits.
   - Obfuscation/QR behavior.
   - Content/intent signals.
2. Store a normalized vector in `pgvector`.
3. Run cosine similarity queries using suitable vector indexes.
4. Link similar cases into campaigns through `campaigns` and `campaign_emails`.
5. Associate shared IPs, URLs, domains, hashes, and other IOCs through `indicators` and `campaign_indicators`.

### Simple workflow

Every attack has a pattern—like a fingerprint. We compare the fingerprint of a new email with old emails. Even if attackers change one domain or IP, similar wording, hidden-text tricks, QR behavior, and header patterns can still reveal that the attacks are related. [file:104][file:106]

---

## Stage 10 — Evidence-Grounded Narrative Generation

### Technical workflow

1. Create verified structured findings, each with a stable Finding ID:

```text
[F-001] Reply-To address does not match the Return-Path domain.
[F-002] Three zero-width characters detected in subject.
[F-003] Embedded QR code decoded to a credential-harvesting URL.
[F-004] Origin infrastructure associated with ASN/hosting provider X.
```

2. Provide only these approved findings to the narrative generator.
3. Require citations in every output sentence.
4. Validate each citation against the case’s actual Finding ID registry.
5. Reject any sentence that has no valid citation.
6. Optionally perform a second evidence-entailment check before adding text to the final report.

### Simple workflow

The AI is allowed to turn technical findings into readable English, but it cannot freely invent a story. Every sentence must point to real evidence IDs. If it says something that is not supported, the system throws that sentence away.

### Correct claim to make

We should say: **“The final narrative contains no unsupported claims that pass our validation rules.”** We should not claim that the underlying LLM can never hallucinate internally. [file:104]

---

## Stage 11 — Evidence Dossier, Reports, and Verification

### Technical workflow

The evidence packaging service produces a downloadable bundle containing:

1. Original untouched `.eml` file.
2. SHA-256 checksum file.
3. Chain-of-custody log with UTC timestamps.
4. Structured findings and IoCs in JSON/CSV.
5. Investigation report in PDF.
6. Technical annexure designed to support Section 63 BSA documentation, including system/build details and a human signature section.
7. Optional STIX 2.1 export for sharing threat intelligence.

The report service records the artifact location, hash and generator in `reports`, `evidence_ledger`, and `audit_logs`.

### Simple workflow

At the end, the user can download one evidence package containing the original email, its fingerprint, the full investigation, important links/IPs, and a report. A human investigator still reviews and signs where required; the software supports the process but does not replace legal authority. [file:104][file:106]

---

# 4. User and institution security model

## Technical view

CyberTrace is a multi-tenant platform.

- A **tenant** is an organisation, for example a university, banking SOC, enterprise, or cyber cell.
- Every user belongs to one tenant.
- Every case and tenant-owned record carries `tenant_id`.
- PostgreSQL Row-Level Security prevents Tenant A from reading Tenant B’s records.
- RBAC controls actions by roles, for example:
  - Tier-1 Analyst
  - Senior Forensic Incident Responder
  - Police Investigating Officer
  - CISO / Security Lead
  - Administrator

Role access controls what users can upload, view, change, export, administer, or certify. The automated pipeline runs independently of human approval stages; roles control permissions over the completed evidence objects. [file:104]

## Simple view

A university’s security team sees only its own emails and cases. A police cyber cell sees only its own authorised data. Users have different powers depending on their role, but the automatic analysis does not wait for many people to manually approve each step.

---

# 5. Data ownership and key relationships

## Technical view

```text
Tenant 1 --- N Users
Tenant 1 --- N Cases
User   1 --- N Cases (reported_by)
Case   1 --- N Emails
Email  1 --- N Headers
Email  1 --- N URLs
Email  1 --- N Attachments
Email  1 --- N Findings / Anomalies
Email  1 --- 1 or N Authentication Results
Email  1 --- 1 or N Origin/Domain Intelligence Records
Email  1 --- N Analysis Results
Campaign N --- N Emails (through campaign_emails)
Campaign N --- N Indicators (through campaign_indicators)
Case   1 --- N Reports / Actions / Evidence Ledger Entries / Audit Logs
```

All tenant-owned data is scoped through `tenant_id` and protected with RLS.

## Simple view

An institution has users. Users create cases. A case can contain one or more suspicious emails. Each email has headers, links, attachments, risk results, location/network information, and findings. Similar emails are grouped into campaigns. Every case can later have reports and an evidence history.

---

# 6. Failure handling and safe defaults

## Technical view

- If GeoIP, RDAP, DNS, or a threat feed fails, deterministic local analysis still completes.
- External lookup result is stored as `UNAVAILABLE`, `FAILED`, or `RETRY_PENDING`, never silently treated as safe.
- Timeouts, retries, caching, and rate-limit handling occur in worker tasks.
- Unsafe attachment content is never executed by the normal parser.
- Untrusted image/QR analysis uses in-memory buffers where possible.
- UI shows confidence, source availability, and uncertainty labels.

## Simple view

If one external service is down, the whole case does not fail. The system still checks the email using the information it has and clearly says which outside lookup could not be completed. [file:106]

---

# 7. Architecture patterns used

## Technical view

- **Layered architecture:** UI, API/service, processing, data, integration layers.
- **Event-driven / asynchronous processing:** Celery tasks consume analysis jobs from Redis.
- **Pipeline pattern:** Email analysis flows through ordered forensic stages.
- **Strategy pattern:** Different risk scorers, campaign clustering approaches, or detectors can be plugged in without rewriting the pipeline.
- **Adapter pattern:** GeoIP, RDAP, DNS, and threat-intel providers are wrapped behind common interfaces.
- **Factory/Builder pattern:** Evidence dossier and report formats are created consistently.
- **Observer/event pattern:** Case state changes trigger audit logging, notifications, and report regeneration.
- **Open/Closed Principle:** Extend the platform with new detectors, feeds, or report types without modifying stable core behavior.

## Simple view

The system is designed in replaceable blocks. Later, we can add a new threat feed, a new AI model, or a new report format without rebuilding everything from scratch.

---

# 8. SIH MVP versus future expansion

## SIH MVP — must be working

- `.eml` upload and secure raw preservation.
- SHA-256 hash and chain-of-custody entry.
- MIME/header parsing.
- Zero-width character, Punycode, and basic hidden HTML detection.
- URL, attachment, and QR extraction.
- SPF/DKIM/DMARC result collection or realistic validation workflow.
- IP route extraction with GeoIP/ASN association.
- Deterministic risk score plus a lightweight semantic model/demo.
- Investigation dashboard with findings and reasons.
- PDF evidence report with raw hash, findings, and verification information.
- Multi-tenant login, RBAC basics, and tenant-scoped data.

## Future / scale-up features

- Fine-tuned transformer model with larger Indian phishing corpus.
- Full robust external feed integrations and caching.
- Advanced pgvector campaign clustering at scale.
- SIEM/SOAR connectors.
- STIX/TAXII automated sharing.
- Production-grade permissioned blockchain integration.
- Formal deployment integration with national and inter-agency systems.

## Simple view

For SIH, we prove the entire journey works from upload to report. The bigger, enterprise-scale integrations can be added later without changing the main architecture. [file:106]

---

# 9. One-sentence architecture explanation

**Technical:** CyberTrace is a multi-tenant, asynchronous forensic email-analysis platform that preserves raw evidence before parsing, performs adversarial MIME reconstruction and infrastructure enrichment, combines deterministic and semantic AI scoring, correlates Attack DNA through pgvector, and exports evidence-grounded BSA-oriented dossiers.

**Simple:** Our platform safely takes a suspicious email, finds hidden tricks and technical clues, traces its network path and approximate server location, calculates an explainable risk score, finds similar attacks, and produces an evidence-backed report.

---

# 10. Final principles

- Preserve first; parse second.
- Treat original email bytes as immutable evidence.
- Show geolocation as network infrastructure association, never as a proven attacker home location.
- Let deterministic forensic evidence lead; let AI add context.
- Do not allow unsupported AI claims into the final report.
- Keep institutions separated through tenant isolation and RBAC.
- Make every conclusion traceable to evidence, time, user action, and case ID.
- Extend through modular patterns rather than rewriting stable core components.

This architecture is the working blueprint for the CyberTrace/SkyBlaze SIH platform. It incorporates the forensic decisions and six-stage pipeline described in the supplied ADR and SkyBlaze material while expressing them in a practical, readable system design. [file:104][file:106]