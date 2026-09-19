"""
Automated Forensic Test Suite for MailTrace AI
Verifies De-obfuscator, RFC-822 Header Parser, Protocol Validator,
Network Intelligence, Threat Scoring, and Section 63 BSA 2023 Certification.
"""
import pytest
import os
import sys

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from forensics.deobfuscation import strip_zero_width, normalize_homoglyphs, analyze_domain_lookalike, deobfuscate_pipeline
from forensics.header_parser import parse_email_headers, parse_received_clause
from forensics.protocols import analyze_authentication_protocols
from forensics.network_intel import lookup_ip_intelligence
from forensics.quishing import detect_quishing
from forensics.threat_scoring import evaluate_nlp_heuristics, compute_32d_feature_vector
from forensics.chain_of_custody import calculate_sha256, generate_section_63_bsa_certificate


def test_zero_width_stripping():
    """Test detection and removal of invisible characters."""
    obfuscated_text = "p\u200Ba\u200Cy\u200Dp\uFEFFa\u2060l"
    cleaned, count = strip_zero_width(obfuscated_text)
    assert cleaned == "paypal"
    assert count == 5


def test_homoglyph_normalization():
    """Test Cyrillic to Latin homoglyph conversion."""
    # Cyrillic 'а' (\u0430) and 'о' (\u043e)
    cyrillic_spoof = "micr\u043es\u043eft"
    normalized, detected = normalize_homoglyphs(cyrillic_spoof)
    assert normalized == "microsoft"
    assert len(detected) == 2
    assert detected[0]["unicode"] == "U+043E"


def test_domain_lookalike_levenshtein():
    """Test Levenshtein distance detection against protected enterprise domains."""
    res1 = analyze_domain_lookalike("micros0ft.com")
    assert res1["is_lookalike"] is True
    assert res1["closest_brand"] == "microsoft.com"
    assert res1["edit_distance"] == 1

    res2 = analyze_domain_lookalike("microsoft.com")
    assert res2["is_lookalike"] is False  # Exact match, not a deceptive lookalike


def test_received_header_parsing():
    """Test extraction of MTA, IP, protocol, and timestamp from Received header."""
    clause = "from mail-out.attacker.com (mail-out.attacker.com [185.220.101.5]) by mx.google.com with ESMTPS id abc123xyz; Fri, 18 Sep 2026 09:14:22 +0000"
    parsed = parse_received_clause(clause)
    assert parsed["relay_ip"] == "185.220.101.5"
    assert "mx.google.com" in parsed["by_mta"]
    assert parsed["protocol"] == "ESMTPS"
    assert parsed["timestamp"] is not None


def test_authentication_protocols():
    """Test SPF, DKIM, and DMARC alignment validation."""
    headers = {
        "Received-SPF": "fail (domain of attacker.net does not designate 1.2.3.4 as permitted sender)",
        "Authentication-Results": "mx.victim.com; spf=fail; dkim=fail; dmarc=fail action=quarantine"
    }
    auth_res = analyze_authentication_protocols(headers, "company.com", "1.2.3.4")
    assert auth_res["spf"]["status"] == "fail"
    assert auth_res["dkim"]["status"] == "fail"
    assert auth_res["dmarc"]["status"] == "fail"
    assert auth_res["overall_authentication_pass"] is False
    assert len(auth_res["findings"]) >= 2


def test_network_intel_lookup():
    """Test Tor / Bulletproof classification and geolocation coordinates."""
    intel = lookup_ip_intelligence("185.220.101.5")
    assert intel["country"] == "Germany"
    assert intel["is_anonymizer"] is True
    assert intel["risk_level"] == "High"
    assert "Tor" in intel["isp"]


def test_quishing_detection():
    """Test QR code phishing evasion detection."""
    body = "Please scan the QR code attached to re-authenticate your mobile app."
    attachments = [{"filename": "scan_mfa_login_qr.png"}]
    res = detect_quishing(body, "", attachments)
    assert res["is_quishing_detected"] is True
    assert len(res["trigger_phrases"]) >= 1
    assert res["finding_id"] == "[F-006: Quishing Payload Detected]"


def test_32d_feature_vector_and_fraud_score():
    """Test 32-dimensional vector normalization and high-risk categorization."""
    deobf = deobfuscate_pipeline("verify immediately", "micros0ft.com")
    headers = {
        "anomalies": {"return_path_mismatch": True, "reply_to_mismatch": True, "display_name_spoof": True, "finding_id": "F-002"},
        "hop_count": 3
    }
    protocols = {
        "spf": {"status": "fail"},
        "dkim": {"status": "fail"},
        "dmarc": {"status": "fail", "aligned": False},
        "findings": ["[F-003: SPF FAIL]"]
    }
    geo_hops = [{"is_anonymizer": True, "risk_level": "High", "isp": "Tor Exit Network", "latency_seconds": 12.0}]
    quishing = {"is_quishing_detected": False, "finding_id": None}
    nlp = evaluate_nlp_heuristics("Immediate action required to avoid suspension. Verify password.")

    scoring = compute_32d_feature_vector(deobf, headers, protocols, geo_hops, quishing, nlp)
    assert len(scoring["vector_32d"]) == 32
    assert all(0.0 <= v <= 1.0 for v in scoring["vector_32d"])
    assert scoring["fraud_score"] >= 60.0
    assert scoring["risk_tier"] in ["MALICIOUS", "CRITICAL THREAT"]


def test_sha256_custody_and_bsa_certificate():
    """Test SHA-256 evidence integrity and Section 63 BSA 2023 certificate."""
    test_bytes = b"MIME-Version: 1.0\r\nSubject: Test Email\r\n\r\nHello World"
    digest = calculate_sha256(test_bytes)
    assert len(digest) == 64

    findings = [
        {"id": "F-001", "category": "Evasion", "description": "Homoglyphs detected"},
        {"id": "F-003", "category": "Auth", "description": "SPF Failure"}
    ]
    cert = generate_section_63_bsa_certificate(
        case_id="TEST-001",
        evidence_filename="test.eml",
        raw_sha256=digest,
        file_size_bytes=len(test_bytes),
        investigator_name="Inspector R. Rawat",
        designation="Forensic Examiner",
        organization="Cyber Forensic Lab",
        findings=findings,
        originating_ip="185.220.101.5",
        sender_identity="alerts@micros0ft.com"
    )
    assert "SECTION 63" in cert["certificate_text"]
    assert "BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023" in cert["certificate_text"]
    assert digest in cert["certificate_text"]
    assert cert["findings_count"] == 2
