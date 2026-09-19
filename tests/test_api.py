"""
API Endpoint Test Suite for MailTrace AI REST Gateway
"""
import sys
import os
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))
from main import app

client = TestClient(app)


def test_api_health():
    """Verify /api/health endpoint returns healthy status and supported standards."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "2.6.0"
    assert "Section 63 BSA 2023" in data["supported_standards"]


def test_api_samples_catalog():
    """Verify /api/samples returns all 4 pre-packaged forensic sample cases."""
    response = client.get("/api/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) == 4
    keys = [s[0] for s in samples]
    assert "spear_phishing" in keys
    assert "bec_wire_fraud" in keys
    assert "quishing_invoice" in keys
    assert "legitimate_gov" in keys


def test_api_sample_spear_phishing_analysis():
    """Verify /api/samples/spear_phishing executes end-to-end and returns forensic findings."""
    response = client.get("/api/samples/spear_phishing")
    assert response.status_code == 200
    data = response.json()
    assert data["threat_scoring"]["fraud_score"] >= 60.0
    assert data["threat_scoring"]["risk_tier"] in ["MALICIOUS", "CRITICAL THREAT"]
    assert len(data["hops"]) >= 2
    assert len(data["iocs"]) >= 3
    assert data["evidence_sha256"] is not None


def test_api_sample_legitimate_gov():
    """Verify legitimate signed email receives a low risk score."""
    response = client.get("/api/samples/legitimate_gov")
    assert response.status_code == 200
    data = response.json()
    assert data["threat_scoring"]["fraud_score"] < 40.0
    assert data["threat_scoring"]["risk_tier"] == "LOW RISK (BENIGN)"
    assert data["protocols"]["overall_authentication_pass"] is True


def test_api_generate_certificate():
    """Verify Section 63 BSA 2023 certificate generation for an analyzed case."""
    # First analyze a sample to populate cache
    res_sample = client.get("/api/samples/bec_wire_fraud")
    case_id = res_sample.json()["case_id"]

    # Request certificate
    cert_res = client.post("/api/evidence/certificate", json={
        "case_id": case_id,
        "investigator_name": "Inspector Rakesh Rawat",
        "designation": "Senior Digital Forensic Examiner",
        "organization": "State Cyber Crime Investigation Bureau"
    })
    assert cert_res.status_code == 200
    cert = cert_res.json()
    assert cert["case_id"] == case_id
    assert "BSA2023-CERT" in cert["certificate_id"]
    assert "Inspector Rakesh Rawat" in cert["certificate_text"]
    assert "SECTION 63" in cert["certificate_text"]


def test_api_export_iocs():
    """Verify IoC export endpoint in JSON and CSV formats."""
    res_sample = client.get("/api/samples/quishing_invoice")
    case_id = res_sample.json()["case_id"]

    # Test JSON export
    res_json = client.get(f"/api/evidence/export/{case_id}?format=json")
    assert res_json.status_code == 200
    assert "iocs" in res_json.json()

    # Test CSV export
    res_csv = client.get(f"/api/evidence/export/{case_id}?format=csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "Type,Value,Risk" in res_csv.text
