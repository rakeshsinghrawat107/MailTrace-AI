# MailTrace AI — Autonomous Email Threat Intelligence & Forensic Platform
> **Smart India Hackathon (SIH 2026)**  
> **Problem Statement**: AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform  
> **Team Name**: CyberTrace Innovations | **Category**: Software | **Theme**: Cyber Security & Digital Forensics  
> **Official Repository**: [https://github.com/rakeshsinghrawat107/MailTrace-AI](https://github.com/rakeshsinghrawat107/MailTrace-AI)

---

## 📌 Overview
Traditional Secure Email Gateways (SEGs) act as opaque binary filters: they label emails as "Phishing: YES/NO" without explaining why, tracking hop provenance, or preserving court-admissible legal evidence.

**MailTrace AI** transforms raw `.eml` or RFC-822 email evidence into court-ready forensic intelligence:
- 🛡️ **Multi-Pass Adversarial De-Obfuscation**: Strips invisible zero-width spaces (`\u200B`, `\uFEFF`) and normalizes Cyrillic/Greek homoglyphs using Unicode NFKC.
- 🗺️ **Relay Hop Provenance & Trace Map**: Chronologically reconstructs the MTA hop path from `Received:` headers and maps geolocation, ASN ownership, and ISP context on an interactive world map.
- 📱 **Quishing (QR-Code Phishing) Extraction**: Detects embedded QR codes in attachments or inline HTML to uncover evasive credential theft landing pages.
- 📊 **32-Dimensional Explainable Feature Vector**: Generates a normalized 0–100 MailTrace Fraud Score with deterministic findings citations (`[F-001]`, `[F-002]`, etc.).
- ⚖️ **Section 63 BSA 2023 Digital Evidence Admissibility**: Implements cryptographic SHA-256 byte-level ingestion hashing, immutable audit logging, and automated generation of formal legal evidence certificates under the **Bharatiya Sakshya Adhiniyam, 2023 (Section 63)**.

---

## 🏛️ System Architecture

### Cloud Architecture Diagram (Generated via Eraser.io)
![MailTrace AI Architecture](https://storage.googleapis.com/second-petal-295822.appspot.com/elements/elements%3A6c747efc10b5a7e6110b607a19471691cadd9183dbc7bde643f95a3448563091.png)
> 🔗 **Open in Eraser Editor**: [Edit Cloud Architecture](https://app.eraser.io/new?requestId=3d3CcXTU9ERwvDw0g4g2&state=TNltlLesfKL3mcDqgXFgs)

### Forensic Custody & Section 63 BSA Flow
![Forensic Custody Sequence](https://storage.googleapis.com/second-petal-295822.appspot.com/elements/elements%3Acc35aa225964dcc750a7e8c46055fc71b149ce5961ed364dedad1dd2fece2272.png)
> 🔗 **Open in Eraser Editor**: [Edit Sequence Flow](https://app.eraser.io/new?requestId=0OuxEuykvzR3MrOwT8gz&state=GRNjIKPdC6k5iopVcyY96)

### Forensic Relational Data Model (ERD)
![Forensic Data Model](https://storage.googleapis.com/second-petal-295822.appspot.com/elements/elements%3A360158b2f33af34cef7dd1539ab1f7c2f5e42e65c60e297d3f56767061d4cd47.png)
> 🔗 **Open in Eraser Editor**: [Edit ERD](https://app.eraser.io/new?requestId=d22KO81Cp3vPtQv2MnGC&state=4jj6y20JA9DHfm5oKvNIs)

---

## 💻 Tech Stack

| Component | Technologies | Purpose |
|---|---|---|
| **Frontend UI** | React, TypeScript, Tailwind CSS, Leaflet.js, Chart.js, Lucide | SOC Analyst Cyber Dashboard, Interactive Hop Trace Map, 32D Radar |
| **API Gateway** | FastAPI (Python 3.14), Uvicorn | High-throughput async REST endpoints for RFC-822 analysis |
| **MIME & Headers** | Python `email`, `mailbox` | RFC-5322 parsing, hop extraction, transit latency delta calculation |
| **De-Obfuscation** | `unicodedata` NFKC, Regex, Levenshtein Distance | Zero-width stripping, Cyrillic-to-Latin homoglyph mapping, brand lookalike detection |
| **Custody & Hashing** | FIPS 180-4 SHA-256 (`hashlib`) | Byte-level evidence integrity verification and tamper prevention |
| **Legal Certificates** | ReportLab, Python standard library | Section 63 Bharatiya Sakshya Adhiniyam 2023 certified court reports |
| **Diagrams** | Eraser.io API & Mermaid.js | Architectural visualizations and data models |

---

## 🚀 Quickstart Guide

### 1. Clone the Repository
```bash
git clone https://github.com/rakeshsinghrawat107/MailTrace-AI.git
cd MailTrace-AI
```

### 2. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 3. Launch MailTrace AI
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
Open your browser and navigate to:
👉 **`http://localhost:8000/`**

---

## 🧪 Automated Testing & Evidence
The platform includes comprehensive automated tests covering unit logic, RFC-822 header parsing, adversarial de-obfuscation, network intelligence, threat scoring, and API endpoints.

Run all tests with:
```bash
python -m pytest tests/ -v
```
**Results**:
- `tests/test_api.py`: 6 passed (Health, Catalog, Spear-Phishing, Legitimate Gov, Certificate, IoC Export)
- `tests/test_forensics.py`: 9 passed (Zero-Width, Homoglyphs, Lookalikes, Hops, Protocols, Network, Quishing, 32D Vector, SHA-256 Custody)
- **15 passed in 0.60s (100% PASS RATE)**

---

## 📑 SIH 2026 Submission Artifacts
- **Official Presentation (PPTX)**: [`MailTrace_AI_SIH2026_Submission.pptx`](MailTrace_AI_SIH2026_Submission.pptx) (6 Slides strictly formatted to SIH 2026 Idea Presentation Template)
- **Official Submission PDF**: [`MailTrace_AI_SIH2026_Submission.pdf`](MailTrace_AI_SIH2026_Submission.pdf) (Directly uploadable to SIH portal)
- **System Architecture Spec**: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Batch Evaluation Reports**: [`reports/FORENSIC_EVALUATION_REPORT.md`](reports/FORENSIC_EVALUATION_REPORT.md)

---

## ⚖️ Statutory Legal Compliance (India)
In compliance with Section 63 of the **Bharatiya Sakshya Adhiniyam, 2023 (BSA)**:
1. Every ingested email is hashed (`SHA-256`) at byte-level before analysis.
2. Custody events are recorded in an append-only ledger.
3. Automated findings cite stable IDs (`[F-001]` to `[F-008]`) to guarantee zero AI hallucination.
4. Court-admissible certificates are generated with certifying examiner details and cryptographic verification seals.
