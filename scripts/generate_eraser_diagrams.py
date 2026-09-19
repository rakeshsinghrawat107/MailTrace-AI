"""
MailTrace.AI - Eraser.io Architecture Diagram Generator
Generates HLD, LLD, Sequence, ERD, and Threat Pipeline Diagrams
"""
import requests
import json
import os
from pathlib import Path

WORKSPACE = Path(__file__).resolve().parent.parent
DIAGRAMS_DIR = WORKSPACE / "docs" / "diagrams"
DIAGRAMS_DIR.mkdir(parents=True, exist_ok=True)

headers = {
    'Content-Type': 'application/json',
    'X-Skill-Source': 'gemini'
}

# 1. HLD - High Level System Architecture
hld_dsl = """
// MailTrace.AI - High-Level Architecture (HLD)
title MailTrace.AI v3.1.0 - High-Level System Architecture

Analyst Workstation [icon: monitor, color: blue, label: "SOC Forensics Webstation"]
Caddy Reverse Proxy [icon: shield, color: green, label: "TLS & Reverse Proxy"]
FastAPI Gateway [icon: fast-api, color: purple, label: "FastAPI Core Gateway"]

Analyst Workstation > Caddy Reverse Proxy: HTTPS / WSS
Caddy Reverse Proxy > FastAPI Gateway: Reverse Proxy :8000

group Ingestion & Custody Gate [color: cyan] {
  PreParse Hasher [icon: lock, label: "SHA-256 Pre-Parse Gate"]
  Custody Ledger [icon: database, label: "Append-Only Audit Ledger"]
  BSA Certifier [icon: award, label: "Sec 63 BSA 2023 Certifier"]
}

group Autonomous Forensic Micro-Engines [color: orange] {
  MIME Hop Parser [icon: git-commit, label: "Chronological Hop Parser"]
  Deobfuscator [icon: eye, label: "ZWSP & Homoglyph Engine"]
  Protocol Matrix [icon: check-circle, label: "SPF / DKIM / DMARC Matrix"]
  Quishing Scanner [icon: grid, label: "In-Memory QR Optical Decoder"]
  Network Intel [icon: globe, label: "Keyless GIS & Tor Classifier"]
}

group Behavioral ML & Intelligence Tier [color: red] {
  NLP Analyzer [icon: message-square, label: "Urgency & BEC Intent"]
  Vector Engine 32D [icon: sliders, label: "32D Feature Vector Synthesizer"]
  Campaign Clusterer [icon: share-2, label: "Attack DNA Cosine Matching"]
}

group Enterprise Storage Tier [color: blue] {
  PostgreSQL Vector [icon: database, label: "PostgreSQL 16 + pgvector"]
  Immutable Vault [icon: hard-drive, label: "Local Vault / MinIO S3"]
}

FastAPI Gateway > PreParse Hasher: Ingest Raw EML Bytes
PreParse Hasher > Custody Ledger: Record Ingestion Hash
FastAPI Gateway > MIME Hop Parser: RFC 5322 Reconstruction
FastAPI Gateway > Deobfuscator: Multi-Pass Adversarial Stripping
FastAPI Gateway > Protocol Matrix: Identity Alignment Check
FastAPI Gateway > Quishing Scanner: In-Memory Optical Scan
MIME Hop Parser > Network Intel: Reverse Hop Geolocation

Protocol Matrix > Vector Engine 32D: Auth Score
Deobfuscator > Vector Engine 32D: Evasion Score
Quishing Scanner > Vector Engine 32D: Optical Payload Score
Network Intel > Vector Engine 32D: Transit Risk Index
NLP Analyzer > Vector Engine 32D: Urgency & Wire Fraud Score

Vector Engine 32D > Campaign Clusterer: Normalized 32D Embedding
Vector Engine 32D > PostgreSQL Vector: Persist Vector & Case Findings
PreParse Hasher > Immutable Vault: Write-Once Read-Many (WORM)
Custody Ledger > BSA Certifier: Legal Admissibility Signature
"""

# 2. LLD - Low Level Micro-Engine Pipeline
lld_dsl = """
// MailTrace.AI - Low-Level Design (LLD)
title MailTrace.AI - Low-Level Forensic Micro-Engine Pipeline

Raw EML [icon: file-text, color: blue]
Byte Interceptor [icon: cpu, color: purple]
Raw SHA256 [icon: lock, color: green]

Raw EML > Byte Interceptor: Stream Raw Bytes
Byte Interceptor > Raw SHA256: FIPS 140-3 Cryptographic Hash

group Stage 1: Structural Extraction [color: blue] {
  Header Extractor [icon: list, label: "RFC 5322 Headers"]
  Received Chain [icon: git-branch, label: "Reverse Received Chains"]
  MIME Part Separator [icon: package, label: "Attachments & HTML/Text"]
}

group Stage 2: Adversarial Normalization [color: orange] {
  ZWSP Stripper [icon: minus-circle, label: "Pass 1: Strip Zero-Width Unicode"]
  NFKC Normalizer [icon: refresh-cw, label: "Pass 2: NFKC Homoglyph Unmasker"]
  Levenshtein Engine [icon: target, label: "Pass 3: Brand Lookalike Matcher"]
}

group Stage 3: Payload & Network Forensics [color: red] {
  QR In-Memory Extractor [icon: image, label: "PIL / Heuristic QR Decoder"]
  Tor Relay Evaluator [icon: zap, label: "Offline Tor Directory Lookup"]
  Hop Latency Calculator [icon: clock, label: "Delta-T Transit Calculator"]
}

group Stage 4: Scoring & Certification [color: green] {
  Feature Synthesizer [icon: bar-chart-2, label: "32D Vector Assembly"]
  Risk Classifier [icon: alert-triangle, label: "0-100 Weighted Fraud Score"]
  BSA Section 63 Engine [icon: file-check, label: "Court Certificate Generator"]
}

Byte Interceptor > Header Extractor: Parse Headers
Byte Interceptor > Received Chain: Parse Reverse Hops
Byte Interceptor > MIME Part Separator: Extract Payloads

MIME Part Separator > ZWSP Stripper: Feed Body Text
ZWSP Stripper > NFKC Normalizer: Cleaned Text Stream
NFKC Normalizer > Levenshtein Engine: Test Domains vs 50+ Brands

MIME Part Separator > QR In-Memory Extractor: Scan Inline Base64 Images
Received Chain > Tor Relay Evaluator: Check Public Transit IPs
Received Chain > Hop Latency Calculator: Compute MTA Transmission Latencies

Levenshtein Engine > Feature Synthesizer: Evasion Metrics
QR In-Memory Extractor > Feature Synthesizer: Optical Metrics
Tor Relay Evaluator > Feature Synthesizer: Network Risk Metrics
Feature Synthesizer > Risk Classifier: 32D Feature Array
Risk Classifier > BSA Section 63 Engine: Produce Forensic Dossier & Certificate
"""

# 3. Sequence Diagram
seq_dsl = """
title MailTrace.AI - End-to-End Forensic Investigation & Court Admissibility Flow

Analyst [icon: user, color: blue, label: "SOC Investigator"]
Dashboard [icon: monitor, color: cyan, label: "SOC Forensics UI"]
Gateway [icon: server, color: purple, label: "FastAPI Backend"]
Custody [icon: lock, color: green, label: "Custody Vault"]
Pipeline [icon: cpu, color: orange, label: "32D Forensic Pipeline"]
Court [icon: shield, color: red, label: "Court of Law"]

Analyst > Dashboard: Upload suspicious .EML file
Dashboard > Gateway: POST /api/analyze/upload (multipart/form-data)
Gateway > Custody: compute_sha256(raw_bytes)
Custody > Gateway: Return Raw SHA-256 Digest
Gateway > Custody: record_custody_event("INGESTION_SEALED")

Gateway > Pipeline: execute_parallel_forensics()
Pipeline > Pipeline: Pass 1-3 Deobfuscation (ZWSP, Homoglyphs, Brand Lookalikes)
Pipeline > Pipeline: MTA Hop Chronological Latency & Keyless Geolocation
Pipeline > Pipeline: In-Memory QR Optical Scan & Redirection Check
Pipeline > Pipeline: 32-Dimensional Vector Synthesis & Weighted Scoring
Pipeline > Gateway: Return Full 32D Threat Assessment & Findings [F-001..]

Gateway > Dashboard: Deliver Comprehensive Analysis JSON
Dashboard > Dashboard: Render Leaflet Esri Dark Hop Map, Threat Gauge & Radar
Dashboard > Analyst: Display Forensic Findings & MITRE ATT&CK Recommendations

Analyst > Dashboard: Request Section 63 BSA 2023 Certificate
Dashboard > Gateway: POST /api/evidence/certificate
Gateway > Custody: generate_section_63_certificate()
Custody > Custody: Record "BSA_CERTIFICATE_ISSUED" to Merkle-linked Ledger
Custody > Gateway: Return Signed Certificate & Unique Identifier
Gateway > Dashboard: Render Certificate Modal with <kbd>Esc</kbd> Trap

Analyst > Dashboard: Click "Export Court Dossier PDF"
Dashboard > Gateway: GET /api/cases/{case_id}/pdf
Gateway > Dashboard: Download Sealed PDF Evidence Dossier
Analyst > Court: Submit Evidence under Section 63 Bharatiya Sakshya Adhiniyam 2023
"""

# 4. Entity-Relationship Diagram (ERD)
erd_dsl = """
title MailTrace.AI - Enterprise Relational & Vector Data Model

Tenant [icon: users, color: blue] {
  id uuid pk
  name string
  code string uk
  created_at timestamp
}

User [icon: user, color: purple] {
  id uuid pk
  tenant_id uuid fk
  email string uk
  full_name string
  role string
  password_hash string
}

Case [icon: folder, color: orange] {
  id uuid pk
  tenant_id uuid fk
  investigator_id uuid fk
  case_number string uk
  status string
  threat_tier string
  fraud_score decimal
  created_at timestamp
}

EvidenceEmail [icon: mail, color: green] {
  id uuid pk
  case_id uuid fk
  filename string
  raw_sha256 string uk
  file_size_bytes int
  storage_uri string
  ingested_at timestamp
}

MTAHop [icon: git-commit, color: cyan] {
  id uuid pk
  email_id uuid fk
  hop_sequence int
  relay_ip string
  country string
  asn string
  latency_seconds decimal
  is_origin boolean
}

ForensicAnalysis [icon: activity, color: red] {
  id uuid pk
  email_id uuid fk
  fraud_score decimal
  risk_tier string
  overall_auth_pass boolean
  quishing_detected boolean
  zero_width_count int
  homoglyph_count int
  attack_dna_vector vector_32
  analyzed_at timestamp
}

CustodyEvent [icon: lock, color: gray] {
  id uuid pk
  case_id uuid fk
  sequence int
  action string
  operator string
  evidence_sha256 string
  parent_hash string
  event_hash string
  event_time timestamp
}

BSACertificate [icon: award, color: green] {
  id uuid pk
  case_id uuid fk
  certificate_number string uk
  raw_sha256 string
  certificate_body text
  examiner_name string
  issued_at timestamp
}

Tenant 1 -- * User
Tenant 1 -- * Case
User 1 -- * Case
Case 1 -- 1 EvidenceEmail
EvidenceEmail 1 -- * MTAHop
EvidenceEmail 1 -- 1 ForensicAnalysis
Case 1 -- * CustodyEvent
Case 1 -- 1 BSACertificate
"""

diagrams = [
    {"name": "architecture_hld", "code": hld_dsl, "type": "cloud-architecture-diagram"},
    {"name": "pipeline_lld", "code": lld_dsl, "type": "cloud-architecture-diagram"},
    {"name": "investigation_sequence", "code": seq_dsl, "type": "sequence-diagram"},
    {"name": "relational_erd", "code": erd_dsl, "type": "entity-relationship-diagram"},
]

results = {}

for d in diagrams:
    payload = {
        'elements': [{
            'type': 'diagram',
            'id': f"diagram-{d['name']}",
            'code': d['code'].strip(),
            'diagramType': d['type']
        }],
        'scale': 2,
        'theme': 'dark',
        'background': True
    }
    try:
        res = requests.post('https://app.eraser.io/api/render/elements', json=payload, headers=headers, timeout=30)
        if res.status_code == 200:
            data = res.json()
            image_url = data.get('imageUrl')
            editor_url = data.get('createEraserFileUrl')
            print(f"[{d['name']}] Status: 200")
            print(f"[{d['name']}] Image URL: {image_url}")
            print(f"[{d['name']}] Editor URL: {editor_url}")
            results[d['name']] = {
                "imageUrl": image_url,
                "createEraserFileUrl": editor_url
            }
            # Download image locally
            if image_url:
                img_res = requests.get(image_url, timeout=30)
                if img_res.status_code == 200:
                    img_path = DIAGRAMS_DIR / f"{d['name']}.png"
                    with open(img_path, "wb") as img_f:
                        img_f.write(img_res.content)
                    print(f"[{d['name']}] Downloaded {img_path}")
        else:
            print(f"[{d['name']}] Error: {res.status_code} - {res.text[:200]}")
    except Exception as e:
        print(f"[{d['name']}] Exception: {e}")

with open(DIAGRAMS_DIR / "eraser_diagram_manifest.json", "w") as out:
    json.dump(results, out, indent=2)

print("\nEraser diagram generation run complete.")
