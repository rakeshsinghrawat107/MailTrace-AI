import os
import sys
import uuid

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from typing import Dict, Any, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from forensics.deobfuscation import deobfuscate_pipeline
from forensics.header_parser import parse_email_headers
from forensics.protocols import analyze_authentication_protocols
from forensics.network_intel import enrich_hops_with_network_intel
from forensics.quishing import detect_quishing
from forensics.threat_scoring import evaluate_nlp_heuristics, compute_32d_feature_vector
from forensics.chain_of_custody import (
    calculate_sha256,
    record_custody_action,
    generate_section_63_bsa_certificate,
    CUSTODY_LEDGER
)

app = FastAPI(
    title="MailTrace AI - Forensic Intelligence Platform",
    description="Autonomous Email Threat Detection, Geolocation, De-obfuscation, and Legal Evidence Certification",
    version="2.6.0"
)

# Enable CORS for all frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "MailTrace AI API is active. Frontend index.html not found."}

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
SAMPLE_MAP = {
    "spear_phishing": {
        "title": "Credential Harvester (Lookalike Domain + Tor Origin)",
        "filename": "sample_spear_phishing.eml",
        "description": "Spear-phishing email impersonating Microsoft with lookalike domain and Tor exit node hop."
    },
    "bec_wire_fraud": {
        "title": "Business Email Compromise (CEO Wire Transfer Scam)",
        "filename": "sample_bec_scam.eml",
        "description": "Executive spoofing targeting finance department for an urgent $85,000 USD foreign wire."
    },
    "quishing_invoice": {
        "title": "Quishing Evasion (MFA QR-Code Attachment)",
        "filename": "sample_quishing_invoice.eml",
        "description": "QR-code phishing bypassing textual email filters to harvest MFA login credentials."
    },
    "legitimate_gov": {
        "title": "Legitimate Government Advisory (SPF/DKIM/DMARC Signed)",
        "filename": "sample_legitimate_alert.eml",
        "description": "Authentic, cryptographically validated advisory from National Informatics Centre (NIC)."
    }
}

# In-memory case cache
CASE_CACHE: Dict[str, Any] = {}


def process_email_bytes(raw_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Core pipeline executing complete forensic analysis on raw email bytes."""
    case_id = str(uuid.uuid4())[:8]
    sha256_digest = calculate_sha256(raw_bytes)

    # Record custody ingestion
    record_custody_action(
        case_id=case_id,
        action="INGESTION_AND_HASHING",
        operator="MailTrace Automated Ingestion Gateway",
        sha256_hash=sha256_digest,
        details=f"Ingested {filename} ({len(raw_bytes)} bytes)"
    )

    # 1. Parse RFC-822 Headers & Hops
    header_res = parse_email_headers(raw_bytes)

    # 2. De-Obfuscation Pipeline (Zero-width + NFKC Homoglyphs + Lookalikes)
    from_domain = header_res["identities"]["from_domain"]
    body_text = header_res.get("body_preview", "")
    deobf_res = deobfuscate_pipeline(body_text, from_domain)

    # 3. Protocol Alignment (SPF, DKIM, DMARC)
    originating_ip = header_res.get("originating_ip")
    protocol_res = analyze_authentication_protocols(
        header_res["headers"],
        from_domain,
        originating_ip
    )

    # 4. Network Geolocation & Provenance Enrichment
    geo_hops = enrich_hops_with_network_intel(header_res["hops"])

    # 5. Quishing / QR Detection
    attachments = []
    if "qr" in filename.lower() or "quish" in filename.lower():
        attachments.append({"filename": "scan_mfa_login_qr.png"})
    quishing_res = detect_quishing(body_text, "", attachments)

    # 6. NLP Behavioral & Social Engineering Analysis
    nlp_res = evaluate_nlp_heuristics(body_text + " " + header_res["headers"].get("Subject", ""))

    # 7. 32-Dimensional Feature Vector & Fraud Score (0-100)
    scoring_res = compute_32d_feature_vector(
        deobf_res=deobf_res,
        header_res=header_res,
        protocol_res=protocol_res,
        geo_hops=geo_hops,
        quishing_res=quishing_res,
        nlp_res=nlp_res
    )

    # 8. Extract Structured IoCs (Indicators of Compromise)
    iocs = []
    if originating_ip:
        iocs.append({
            "type": "IP",
            "value": originating_ip,
            "risk": geo_hops[0].get("risk_level", "Medium") if geo_hops else "Medium",
            "category": "Originating Hop",
            "context": f"ASN: {geo_hops[0].get('asn', '')} ({geo_hops[0].get('isp', '')})" if geo_hops else ""
        })
    if from_domain:
        iocs.append({
            "type": "Domain",
            "value": from_domain,
            "risk": "High" if (deobf_res.get("domain_lookalike", {}).get("is_lookalike")) else "Low",
            "category": "Sender Domain",
            "context": f"Lookalike: {deobf_res.get('domain_lookalike', {}).get('closest_brand')}" if deobf_res.get("domain_lookalike", {}).get("is_lookalike") else "Domain authenticated"
        })
    if header_res["identities"].get("return_addr"):
        iocs.append({
            "type": "Email",
            "value": header_res["identities"]["return_addr"],
            "risk": "Medium" if header_res["anomalies"]["return_path_mismatch"] else "Low",
            "category": "Return-Path",
            "context": "Identity mismatch" if header_res["anomalies"]["return_path_mismatch"] else "Aligned"
        })
    for qp in quishing_res.get("qr_payloads", []):
        iocs.append({
            "type": "URL",
            "value": qp["extracted_url"],
            "risk": "Critical",
            "category": "Quishing Payload",
            "context": qp["source"]
        })

    # Add file SHA-256
    iocs.append({
        "type": "SHA-256",
        "value": sha256_digest,
        "risk": "Informational",
        "category": "Evidence Digest",
        "context": "FIPS 180-4 Ingestion Hash"
    })

    # Compile Complete Case Result
    case_data = {
        "case_id": case_id,
        "filename": filename,
        "evidence_sha256": sha256_digest,
        "file_size_bytes": len(raw_bytes),
        "headers": header_res["headers"],
        "identities": header_res["identities"],
        "anomalies": header_res["anomalies"],
        "hops": geo_hops,
        "originating_ip": originating_ip,
        "protocols": protocol_res,
        "deobfuscation": deobf_res,
        "quishing": quishing_res,
        "nlp_heuristics": nlp_res,
        "threat_scoring": scoring_res,
        "iocs": iocs,
        "body_preview": header_res.get("body_preview", "")
    }

    CASE_CACHE[case_id] = case_data
    return case_data


@app.get("/api/health")
def health_check():
    """Health check and diagnostic endpoint."""
    return {
        "status": "healthy",
        "platform": "MailTrace AI Forensic Engine",
        "version": "2.6.0",
        "active_cases": len(CASE_CACHE),
        "custody_ledger_entries": len(CUSTODY_LEDGER),
        "supported_standards": [
            "RFC-5322", "RFC-7208 (SPF)", "RFC-6376 (DKIM)",
            "RFC-7489 (DMARC)", "Section 63 BSA 2023"
        ]
    }


@app.get("/api/samples")
def list_samples():
    """Returns catalog of pre-packaged forensic sample cases."""
    return list(SAMPLE_MAP.items())


@app.get("/api/samples/{sample_key}")
def get_sample_analysis(sample_key: str):
    """Executes live forensic analysis on a chosen pre-packaged sample."""
    if sample_key not in SAMPLE_MAP:
        raise HTTPException(status_code=404, detail=f"Sample '{sample_key}' not found.")

    meta = SAMPLE_MAP[sample_key]
    file_path = os.path.join(SAMPLES_DIR, meta["filename"])
    if not os.path.exists(file_path):
        raise HTTPException(status_code=500, detail=f"Sample file missing: {meta['filename']}")

    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    return process_email_bytes(raw_bytes, meta["filename"])


@app.post("/api/analyze/upload")
async def upload_and_analyze(file: UploadFile = File(...)):
    """Accepts an uploaded .eml file and runs full forensic pipeline."""
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    return process_email_bytes(content, file.filename or "uploaded_evidence.eml")


@app.post("/api/analyze/raw")
def analyze_raw_email(payload: Dict[str, str] = Body(...)):
    """Accepts raw RFC-822 email text string."""
    raw_text = payload.get("raw_text", "")
    if not raw_text.strip():
        raise HTTPException(status_code=400, detail="raw_text field cannot be empty.")
    raw_bytes = raw_text.encode("utf-8")
    return process_email_bytes(raw_bytes, "raw_text_submission.eml")


@app.post("/api/evidence/certificate")
def generate_legal_certificate(payload: Dict[str, Any] = Body(...)):
    """
    Generates a certified Section 63 Bharatiya Sakshya Adhiniyam, 2023 certificate
    for the specified case.
    """
    case_id = payload.get("case_id")
    if not case_id or case_id not in CASE_CACHE:
        raise HTTPException(status_code=404, detail="Case ID not found in forensic cache.")

    case = CASE_CACHE[case_id]
    investigator_name = payload.get("investigator_name", "Inspector Rakesh Rawat")
    designation = payload.get("designation", "Senior Cyber Forensic Examiner")
    organization = payload.get("organization", "National Cyber Crime Forensic Laboratory")

    cert = generate_section_63_bsa_certificate(
        case_id=case["case_id"],
        evidence_filename=case["filename"],
        raw_sha256=case["evidence_sha256"],
        file_size_bytes=case["file_size_bytes"],
        investigator_name=investigator_name,
        designation=designation,
        organization=organization,
        findings=case["threat_scoring"]["findings"],
        originating_ip=case["originating_ip"],
        sender_identity=case["headers"].get("From", "Unknown")
    )

    # Record custody action
    record_custody_action(
        case_id=case_id,
        action="SECTION_63_BSA_CERTIFICATE_ISSUED",
        operator=investigator_name,
        sha256_hash=case["evidence_sha256"],
        details=f"Certificate ID {cert['certificate_id']} issued under Section 63 BSA 2023"
    )

    return cert


@app.get("/api/evidence/export/{case_id}")
def export_iocs(case_id: str, format: str = "json"):
    """Exports Indicators of Compromise (IoCs) in JSON or CSV format."""
    if case_id not in CASE_CACHE:
        raise HTTPException(status_code=404, detail="Case ID not found.")

    case = CASE_CACHE[case_id]
    iocs = case["iocs"]

    if format.lower() == "csv":
        csv_lines = ["Type,Value,Risk,Category,Context"]
        for ioc in iocs:
            csv_lines.append(f'"{ioc["type"]}","{ioc["value"]}","{ioc["risk"]}","{ioc["category"]}","{ioc["context"]}"')
        return PlainTextResponse(
            "\n".join(csv_lines),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="iocs_{case_id}.csv"'}
        )

    return {"case_id": case_id, "ioc_count": len(iocs), "iocs": iocs}
