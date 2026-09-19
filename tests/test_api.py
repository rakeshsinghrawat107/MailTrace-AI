"""
MailTrace.AI - Integration Test Suite for FastAPI Endpoints
Section 14 REST API Contract Verification
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "OPERATIONAL"
    assert data["version"] == "3.1.0"
    assert "Section 63" in data["statutory_compliance"]

def test_api_list_samples():
    res = client.get("/api/samples?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "samples" in data
    assert data["total_available"] > 0
    assert len(data["samples"]) > 0

def test_api_upload_and_analyze():
    sample_email = (
        b"From: security@paypa1.com\r\n"
        b"To: victim@target.com\r\n"
        b"Subject: URGENT: Security Alert - Immediate Action Required\r\n"
        b"Return-Path: <attacker@scam-mail.ru>\r\n"
        b"Received: from scam-mail.ru (185.220.101.5) by mx.target.com; Sat, 19 Sep 2026 12:00:00 +0000\r\n"
        b"Authentication-Results: mx.target.com; spf=fail; dkim=fail\r\n"
        b"\r\n"
        b"Please scan the QR code to verify wire transfer immediately or your account will be suspended."
    )
    res = client.post(
        "/api/analyze/upload",
        files={"file": ("test_phish.eml", sample_email, "message/rfc822")}
    )
    assert res.status_code == 200
    data = res.json()
    assert "case_id" in data
    assert data["fraud_score"] > 50.0
    assert data["risk_tier"] in ("MALICIOUS", "CRITICAL")
    assert len(data["evidence_sha256"]) == 64
    assert len(data["hops"]) >= 1
    assert data["hops"][0]["is_tor_exit"] is True

    # Test Section 63 Certificate Generation
    case_id = data["case_id"]
    cert_res = client.post(
        "/api/evidence/certificate",
        data={
            "case_id": case_id,
            "examiner_name": "Special Agent Smith",
            "examiner_designation": "Digital Forensics Lead",
            "organization": "National Cyber Crime Unit"
        }
    )
    assert cert_res.status_code == 200
    cert_data = cert_res.json()
    assert "Section 63" in cert_data["statutory_law"]
    assert cert_data["case_id"] == case_id

    # Test IoC Export CSV
    csv_res = client.get(f"/api/evidence/export/{case_id}?format=csv")
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "MTA_RELAY_IP" in csv_res.text

    # Test Full Case JSON Retrieval
    case_res = client.get(f"/api/evidence/case/{case_id}")
    assert case_res.status_code == 200
    assert case_res.json()["case_id"] == case_id

    # Test Court PDF Dossier Generation
    pdf_res = client.get(f"/api/cases/{case_id}/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert len(pdf_res.content) > 1000

    # Test Campaign Correlation
    correlate_res = client.post(f"/api/campaigns/correlate?case_id={case_id}")
    assert correlate_res.status_code == 200
    assert "correlated_campaign_count" in correlate_res.json()

def test_frontend_index():
    res = client.get("/")
    assert res.status_code == 200
    assert "MailTrace" in res.text
    assert "leaflet-map" in res.text
