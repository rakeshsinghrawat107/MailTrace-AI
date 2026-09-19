"""
MailTrace.AI - REST API Router & Forensic Endpoints
Section 14 API Contract Implementation
"""
import uuid
import csv
import io
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.responses import JSONResponse, Response

from backend.app.core.config import SAMPLES_DIR, PLATFORM_NAME, VERSION, BUILD_EDITION, STATUTORY_COMPLIANCE
from backend.app.core.custody import custody_vault
from backend.app.forensics.header_parser import header_parser
from backend.app.forensics.protocols import protocol_validator
from backend.app.forensics.deobfuscation import deobfuscation_engine
from backend.app.forensics.quishing import quishing_detector
from backend.app.intelligence.network_intel import network_intel_engine
from backend.app.ml.threat_scoring import threat_scoring_engine
from backend.app.ml.campaign_clustering import campaign_engine
from backend.app.reports.pdf_generator import pdf_generator

router = APIRouter(prefix="/api")

# In-memory case storage for sub-millisecond retrieval
CASE_STORE: Dict[str, Dict[str, Any]] = {}

def execute_full_forensics(raw_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Orchestrates end-to-end 32D forensic micro-engine analysis on raw email bytes."""
    case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
    
    # 1. Pre-Parsing Cryptographic Preservation
    sha256_hash = custody_vault.compute_sha256(raw_bytes)
    hmac_digest = custody_vault.compute_hmac(raw_bytes)
    custody_vault.record_custody_event(
        case_id=case_id,
        action="EVIDENCE_INGESTED",
        operator="MailTrace-Autonomous-Gate",
        evidence_sha256=sha256_hash,
        details=f"Ingested {filename} ({len(raw_bytes):,} bytes)"
    )

    # 2. RFC 5322 MIME & Hop Parsing
    parsed = header_parser.parse(raw_bytes)
    
    # 3. Protocol & Identity Alignment
    protocols = protocol_validator.evaluate(parsed)

    # 4. Multi-Pass Adversarial De-Obfuscation
    full_text = parsed.get("subject", "") + " " + parsed.get("text_body", "")
    deobf = deobfuscation_engine.analyze(full_text, protocols.get("from_domain", ""))

    # 5. Autonomous Quishing Optical Scan
    quishing = quishing_detector.scan_text_and_html(
        parsed.get("text_body", ""),
        parsed.get("html_body", ""),
        parsed.get("attachments", [])
    )

    # 6. Keyless GIS & Network Intelligence
    enriched_hops = network_intel_engine.enrich_hops(parsed.get("hops", []))

    # 7. 32-Dimensional Threat Scoring & Behavioral Heuristics
    scoring = threat_scoring_engine.evaluate(parsed, protocols, deobf, quishing, enriched_hops)

    # Synthesize Complete Analysis Record
    analysis_record = {
        "case_id": case_id,
        "filename": filename,
        "file_size_bytes": len(raw_bytes),
        "evidence_sha256": sha256_hash,
        "hmac_digest": hmac_digest,
        "fraud_score": scoring["fraud_score"],
        "risk_tier": scoring["risk_tier"],
        "sub_scores": scoring["sub_scores"],
        "vector_32d": scoring["vector_32d"],
        "headers": {
            "subject": parsed["subject"],
            "from": parsed["from"],
            "to": parsed["to"],
            "return_path": parsed["return_path"],
            "reply_to": parsed["reply_to"],
            "date": parsed["date"],
            "message_id": parsed["message_id"],
            "auth_results": parsed["auth_results"]
        },
        "protocols": protocols,
        "deobfuscation": deobf,
        "quishing": quishing,
        "hops": enriched_hops,
        "nlp_analysis": scoring["nlp_analysis"],
        "findings": scoring["findings"],
        "attachments": parsed["attachments"],
        "raw_preview": parsed["text_body"][:500]
    }

    CASE_STORE[case_id] = analysis_record
    return analysis_record

@router.get("/health")
def health_check():
    """Diagnostic health probe reporting platform status, custody ledger count and version."""
    return {
        "status": "OPERATIONAL",
        "platform": PLATFORM_NAME,
        "version": VERSION,
        "edition": BUILD_EDITION,
        "statutory_compliance": STATUTORY_COMPLIANCE,
        "active_cases_in_memory": len(CASE_STORE),
        "custody_ledger_events": len(custody_vault.ledger),
        "zero_api_key_mode": True
    }

@router.get("/samples")
def list_samples(limit: int = 50, search: Optional[str] = None):
    """
    Dynamically lists real email samples from backend/samples/1/.
    Enables instant forensic exploration across the user's dataset.
    """
    if not SAMPLES_DIR.exists():
        return {"samples": [], "total_available": 0}

    all_files = list(SAMPLES_DIR.glob("*.eml"))
    if search:
        all_files = [f for f in all_files if search.lower() in f.name.lower()]

    sample_list = []
    for f in all_files[:limit]:
        sample_list.append({
            "sample_id": f.name,
            "filename": f.name,
            "size_bytes": f.stat().st_size,
            "path": f"samples/1/{f.name}"
        })

    return {
        "total_available": len(all_files),
        "returned": len(sample_list),
        "samples": sample_list
    }

@router.get("/samples/{sample_id}")
def analyze_sample(sample_id: str):
    """Executes full 32D forensic analysis on a specific sample from backend/samples/1/."""
    target_file = SAMPLES_DIR / sample_id
    if not target_file.exists() or not target_file.is_file():
        raise HTTPException(status_code=404, detail=f"Sample file '{sample_id}' not found.")

    raw_bytes = target_file.read_bytes()
    return execute_full_forensics(raw_bytes, sample_id)

@router.post("/analyze/upload")
async def upload_and_analyze(file: UploadFile = File(...)):
    """Multipart upload of custom RFC 5322 .eml file."""
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    return execute_full_forensics(raw_bytes, file.filename or "uploaded_email.eml")

@router.post("/evidence/certificate")
def generate_certificate(
    case_id: str = Form(...),
    examiner_name: str = Form("Cyber Forensic Examiner"),
    examiner_designation: str = Form("Digital Forensics Officer"),
    organization: str = Form("National Cyber Investigation Agency")
):
    """Generates Section 63 BSA 2023 Digital Evidence Certificate."""
    case = CASE_STORE.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")

    cert = custody_vault.generate_section_63_certificate(
        case_id=case_id,
        evidence_sha256=case["evidence_sha256"],
        filename=case["filename"],
        file_size_bytes=case["file_size_bytes"],
        fraud_score=case["fraud_score"],
        risk_tier=case["risk_tier"],
        examiner_name=examiner_name,
        examiner_designation=examiner_designation,
        organization=organization
    )
    custody_vault.record_custody_event(
        case_id=case_id,
        action="BSA_CERTIFICATE_ISSUED",
        operator=examiner_name,
        evidence_sha256=case["evidence_sha256"],
        details=f"Certificate {cert['certificate_id']} issued under Section 63 BSA 2023"
    )
    return cert

@router.get("/evidence/export/{case_id}")
def export_iocs(case_id: str, format: str = Query("json", pattern="^(json|csv)$")):
    """Exports forensic IoCs (IPs, domains, hashes) in JSON or CSV format."""
    case = CASE_STORE.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")

    iocs = []
    # SHA-256 Hash
    iocs.append({"type": "SHA256_DIGEST", "value": case["evidence_sha256"], "confidence": "CERTAIN"})
    # Domains
    if case["protocols"].get("from_domain"):
        iocs.append({"type": "SENDER_DOMAIN", "value": case["protocols"]["from_domain"], "confidence": "HIGH"})
    if case["protocols"].get("return_domain"):
        iocs.append({"type": "RETURN_PATH_DOMAIN", "value": case["protocols"]["return_domain"], "confidence": "HIGH"})
    # Relay IPs
    for h in case.get("hops", []):
        ip = h.get("relay_ip")
        if ip and not h.get("is_private_ip"):
            iocs.append({"type": "MTA_RELAY_IP", "value": ip, "confidence": "HIGH", "asn": h.get("asn")})
    # QR Payloads
    for qr in case.get("quishing", {}).get("qr_payloads", []):
        iocs.append({"type": "QUISHING_URL", "value": qr.get("decoded_uri"), "confidence": "CRITICAL"})

    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["type", "value", "confidence", "asn"])
        writer.writeheader()
        for ioc in iocs:
            writer.writerow({
                "type": ioc.get("type"),
                "value": ioc.get("value"),
                "confidence": ioc.get("confidence"),
                "asn": ioc.get("asn", "")
            })
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{case_id}_iocs.csv"'}
        )

    return {"case_id": case_id, "ioc_count": len(iocs), "iocs": iocs}

@router.get("/evidence/case/{case_id}")
def get_case(case_id: str):
    """Returns complete case record."""
    case = CASE_STORE.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
    return case

@router.get("/cases/{case_id}/pdf")
def get_case_pdf(case_id: str):
    """Generates and downloads court-admissible PDF forensic dossier."""
    case = CASE_STORE.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")

    # Generate or fetch cert
    cert = custody_vault.generate_section_63_certificate(
        case_id=case_id,
        evidence_sha256=case["evidence_sha256"],
        filename=case["filename"],
        file_size_bytes=case["file_size_bytes"],
        fraud_score=case["fraud_score"],
        risk_tier=case["risk_tier"]
    )
    pdf_bytes = pdf_generator.generate(case, cert)
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{case_id}_Forensic_Dossier.pdf"'}
    )

@router.post("/campaigns/correlate")
def correlate_campaign(case_id: str):
    """Correlates a target case against all stored cases using 32D vector cosine similarity."""
    target = CASE_STORE.get(case_id)
    if not target:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")

    matches = campaign_engine.correlate_cases(target, list(CASE_STORE.values()))
    return {
        "case_id": case_id,
        "correlated_campaign_count": len(matches),
        "correlations": matches
    }
