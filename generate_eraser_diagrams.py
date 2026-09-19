import requests
import json
import os

headers = {
    'Content-Type': 'application/json',
    'X-Skill-Source': 'gemini'
}

# 1. Cloud Architecture Diagram
arch_dsl = """
// MailTrace AI Cloud Architecture
title MailTrace AI - Forensic Intelligence Platform

Analyst Dashboard [icon: react, color: blue]
API Gateway [icon: fast-api, color: purple]

Analyst Dashboard > API Gateway: REST / HTTPS

group Ingestion and Parsing [color: green] {
  MIME Parser [icon: file-text]
  Evidence Hasher [icon: lock]
  Deobfuscator [icon: refresh-cw]
}

group Detection and Intelligence Engines [color: orange] {
  Protocol Validator [icon: shield]
  NLP Heuristics [icon: cpu]
  Geo Intelligence [icon: globe]
  Quishing Detector [icon: grid]
}

group Correlation and Storage [color: red] {
  Graph Engine [icon: share-2]
  Feature Vector 32D [icon: bar-chart-2]
  Evidence Vault [icon: database]
}

API Gateway > MIME Parser: Raw EML Stream
MIME Parser > Evidence Hasher: Compute SHA-256
MIME Parser > Deobfuscator: Normalize NFKC & Strip ZWSP
Deobfuscator > Protocol Validator: Check SPF, DKIM, DMARC
Deobfuscator > NLP Heuristics: Social Engineering Analysis
MIME Parser > Geo Intelligence: Extract Received Hops
MIME Parser > Quishing Detector: Extract & Decode QR
Protocol Validator > Feature Vector 32D: Auth Score
NLP Heuristics > Feature Vector 32D: Urgency & Fraud Score
Geo Intelligence > Feature Vector 32D: Network Risk Index
Feature Vector 32D > Graph Engine: Campaign Clustering
Evidence Hasher > Evidence Vault: Immutable Section 63 BSA Custody
"""

# 2. Sequence Diagram
seq_dsl = """
title Forensic Investigation & Section 63 BSA Custody Flow

Investigator [icon: user, color: blue]
UI [icon: monitor, color: cyan, label: "SOC Dashboard"]
Backend [icon: server, color: purple, label: "FastAPI Core"]
Engines [icon: cpu, color: orange, label: "Forensic Engines"]
Vault [icon: database, color: green, label: "Evidence Vault"]

Investigator > UI: Upload raw .eml evidence
UI > Backend: POST /api/analyze (multipart/form-data)
Backend > Vault: Compute SHA-256 & Store Immutable Record
Vault > Backend: Return Evidence Hash & Timestamp
Backend > Engines: Execute Parallel Forensics (Hops, Deobf, QR, NLP)
Engines > Backend: Return Authentication, Geo Hops, 32D Vector, Threat Score
Backend > UI: Deliver Structured Investigation JSON
UI > Investigator: Render Trace Map, Risk Matrix & IoC Tables
Investigator > UI: Request Section 63 BSA 2023 Digital Certificate
UI > Backend: POST /api/evidence/certificate
Backend > Vault: Verify SHA-256 Custody Hash integrity
Backend > UI: Return Cryptographically Signed PDF Certificate
UI > Investigator: Download Court-Admissible Evidence Bundle
"""

# 3. Entity-Relationship Diagram (ERD)
erd_dsl = """
title MailTrace AI Forensic Data Model

EvidenceCase [icon: folder, color: blue] {
  case_id string pk
  evidence_name string
  sha256_hash string
  ingested_at datetime
  investigator_id string
  status string
}

EmailHeader [icon: mail, color: purple] {
  header_id string pk
  case_id string fk
  from_address string
  return_path string
  reply_to string
  message_id string
  subject string
}

RelayHop [icon: globe, color: orange] {
  hop_id string pk
  case_id string fk
  hop_sequence int
  by_server string
  from_server string
  ip_address string
  country string
  asn string
  isp string
  latency_ms float
}

AuthenticationResult [icon: shield, color: green] {
  auth_id string pk
  case_id string fk
  spf_status string
  dkim_status string
  dmarc_status string
  dmarc_policy string
  alignment_pass boolean
}

IoCIndicator [icon: crosshair, color: red] {
  ioc_id string pk
  case_id string fk
  ioc_type string
  ioc_value string
  risk_level string
  threat_source string
}

ChainOfCustodyLog [icon: lock, color: gray] {
  log_id string pk
  case_id string fk
  action string
  operator string
  timestamp datetime
  previous_hash string
  record_hash string
}

EvidenceCase 1 -- 1 EmailHeader
EvidenceCase 1 -- * RelayHop
EvidenceCase 1 -- 1 AuthenticationResult
EvidenceCase 1 -- * IoCIndicator
EvidenceCase 1 -- * ChainOfCustodyLog
"""

os.makedirs("docs/diagrams", exist_ok=True)

diagrams = [
    {"name": "architecture", "code": arch_dsl, "type": "cloud-architecture-diagram"},
    {"name": "sequence", "code": seq_dsl, "type": "sequence-diagram"},
    {"name": "erd", "code": erd_dsl, "type": "entity-relationship-diagram"},
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
    res = requests.post('https://app.eraser.io/api/render/elements', json=payload, headers=headers)
    if res.status_code == 200:
        data = res.json()
        print(f"[{d['name']}] Status: 200")
        print(f"[{d['name']}] Image URL: {data.get('imageUrl')}")
        print(f"[{d['name']}] Editor URL: {data.get('createEraserFileUrl')}")
        results[d['name']] = data
        # download image locally
        img_res = requests.get(data.get('imageUrl'))
        if img_res.status_code == 200:
            with open(f"docs/diagrams/{d['name']}.png", "wb") as img_f:
                img_f.write(img_res.content)
            print(f"[{d['name']}] Downloaded docs/diagrams/{d['name']}.png")
    else:
        print(f"[{d['name']}] Error: {res.status_code} - {res.text[:200]}")

with open("docs/diagrams/eraser_results.json", "w") as out:
    json.dump(results, out, indent=2)

print("All Eraser diagrams generated successfully!")
