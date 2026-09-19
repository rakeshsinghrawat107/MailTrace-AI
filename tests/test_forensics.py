"""
MailTrace.AI - Unit Test Suite for Forensic Micro-Engines
Statutory Cryptography, De-Obfuscation, 32D Scoring & PDF Verification
"""
import pytest
from backend.app.core.custody import custody_vault
from backend.app.forensics.header_parser import header_parser
from backend.app.forensics.protocols import protocol_validator
from backend.app.forensics.deobfuscation import deobfuscation_engine
from backend.app.forensics.quishing import quishing_detector
from backend.app.intelligence.network_intel import network_intel_engine
from backend.app.ml.threat_scoring import threat_scoring_engine
from backend.app.ml.campaign_clustering import campaign_engine
from backend.app.reports.pdf_generator import pdf_generator

def test_custody_sha256_and_hmac():
    raw_data = b"Pre-parsing raw electronic evidence stream for court admissibility"
    sha = custody_vault.compute_sha256(raw_data)
    assert len(sha) == 64
    hmac_val = custody_vault.compute_hmac(raw_data)
    assert len(hmac_val) == 64

def test_section_63_bsa_certificate():
    cert = custody_vault.generate_section_63_certificate(
        case_id="CASE-TEST-001",
        evidence_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        filename="phishing_attack.eml",
        file_size_bytes=4096,
        fraud_score=85.5,
        risk_tier="CRITICAL"
    )
    assert "Section 63" in cert["statutory_law"]
    assert "PART III: MANDATORY STATUTORY DECLARATION" in cert["certificate_text"]
    assert cert["fraud_score"] == 85.5

def test_zero_width_deobfuscation():
    # Injected zero-width space \u200B inside "p a y p a l"
    obfuscated = "p\u200Ba\u200By\u200Bp\u200Ba\u200Bl"
    zw_count, events, cleaned = deobfuscation_engine.detect_zero_width(obfuscated)
    assert zw_count == 5
    assert cleaned == "paypal"

def test_homoglyph_unmasking():
    # Cyrillic 'а' (\u0430) and 'о' (\u043E)
    spoofed = "micr\u043esoft-upd\u0430te.com"
    count, events, unmasked = deobfuscation_engine.unmask_homoglyphs(spoofed)
    assert count >= 2
    assert "microsoft-update.com" in unmasked

def test_brand_typosquatting_lookalike():
    res = deobfuscation_engine.detect_brand_lookalike("paypa1.com")
    assert res is not None
    assert res["impersonated_brand"] == "paypal"
    assert res["edit_distance"] in (0, 1)

def test_private_ip_detection():
    assert header_parser.is_private_ip("192.168.1.1") is True
    assert header_parser.is_private_ip("10.0.0.1") is True
    assert header_parser.is_private_ip("172.16.5.20") is True
    assert header_parser.is_private_ip("127.0.0.1") is True
    assert header_parser.is_private_ip("8.8.8.8") is False
    assert header_parser.is_private_ip("185.220.101.5") is False

def test_quishing_keyword_detection():
    text = "Please scan the QR code using your mobile device to verify your identity immediately."
    res = quishing_detector.scan_text_and_html(text, "", [])
    assert res["quishing_detected"] is True
    assert len(res["qr_payloads"]) > 0

def test_threat_scoring_32d():
    headers = {
        "subject": "URGENT: Verify your account immediately",
        "text_body": "Wire transfer requested to new account details before 24 hours.",
        "attachments": []
    }
    protocols = {
        "spf_status": "fail",
        "dkim_status": "fail",
        "dmarc_status": "fail",
        "domain_aligned": False,
        "reply_to_aligned": False
    }
    deobf = {
        "zero_width_count": 3,
        "homoglyphs_unmasked_count": 2,
        "brand_spoof": {"impersonated_brand": "paypal", "edit_distance": 1, "target_domain": "paypa1.com"}
    }
    quishing = {
        "quishing_detected": True,
        "qr_payloads": [{"decoded_uri": "https://fake.net", "is_credential_harvester": True}]
    }
    hops = [
        {"relay_ip": "185.220.101.5", "is_tor_exit": True, "latency_seconds": 12.5, "is_private_ip": False}
    ]
    scoring = threat_scoring_engine.evaluate(headers, protocols, deobf, quishing, hops)
    assert scoring["fraud_score"] >= 75.0
    assert scoring["risk_tier"] == "CRITICAL"
    assert len(scoring["vector_32d"]) == 32
    assert any(f["code"] == "[F-001]" for f in scoring["findings"])
    assert any(f["code"] == "[F-007]" for f in scoring["findings"])
    assert any(f["code"] == "[F-008]" for f in scoring["findings"])

def test_campaign_cosine_similarity():
    v1 = [1.0] * 32
    v2 = [1.0] * 32
    sim = campaign_engine.cosine_similarity(v1, v2)
    assert sim == 1.0

    v3 = [0.0] * 32
    sim_zero = campaign_engine.cosine_similarity(v1, v3)
    assert sim_zero == 0.0

def test_pdf_report_generation():
    mock_analysis = {
        "case_id": "CASE-TEST-PDF",
        "filename": "test_phish.eml",
        "evidence_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "fraud_score": 88.0,
        "risk_tier": "CRITICAL",
        "headers": {"from": "attacker@paypa1.com", "subject": "Account Alert"},
        "protocols": {"domain_aligned": False},
        "hops": [
            {"hop_sequence": 1, "relay_ip": "185.220.101.5", "city": "Frankfurt", "country_code": "DE", "asn": "AS208323", "latency_seconds": 2.1, "is_tor_exit": True, "is_private_ip": False}
        ],
        "findings": [
            {"code": "[F-001]", "category": "AUTH", "severity": "HIGH", "finding": "SPF failed", "mitre": "T1566"}
        ]
    }
    cert = custody_vault.generate_section_63_certificate(
        case_id="CASE-TEST-PDF",
        evidence_sha256=mock_analysis["evidence_sha256"],
        filename="test_phish.eml",
        file_size_bytes=1024,
        fraud_score=88.0,
        risk_tier="CRITICAL"
    )
    pdf_bytes = pdf_generator.generate(mock_analysis, cert)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF")
