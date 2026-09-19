"""
MailTrace AI - 32-Dimensional Explainable Feature Vector & Threat Scoring Engine
Generates normalized fraud score (0-100), risk tiering, and explainable citations.
"""
import re
from typing import Dict, List, Any

# NLP Heuristic Keywords
URGENCY_KEYWORDS = [
    "immediately", "urgent", "account suspended", "action required", "within 24 hours",
    "final notice", "immediate action", "unauthorized access", "terminate", "restricted"
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "payment", "bank account", "invoice", "swift", "remittance",
    "overdue", "fund transfer", "beneficiary", "crypto", "bitcoin", "routing number"
]

CREDENTIAL_KEYWORDS = [
    "verify password", "login here", "reset credentials", "confirm otp", "sign in",
    "update security", "mfa reset", "session expired", "click to login"
]


def evaluate_nlp_heuristics(text: str) -> Dict[str, Any]:
    """Scan text for social engineering, urgency, financial, and credential theft vectors."""
    text_lower = text.lower()

    found_urgency = [k for k in URGENCY_KEYWORDS if k in text_lower]
    found_financial = [k for k in FINANCIAL_KEYWORDS if k in text_lower]
    found_credential = [k for k in CREDENTIAL_KEYWORDS if k in text_lower]

    return {
        "urgency_detected": len(found_urgency) > 0,
        "urgency_markers": found_urgency,
        "financial_detected": len(found_financial) > 0,
        "financial_markers": found_financial,
        "credential_theft_detected": len(found_credential) > 0,
        "credential_markers": found_credential,
        "urgency_score": min(1.0, len(found_urgency) * 0.25),
        "financial_score": min(1.0, len(found_financial) * 0.3),
        "credential_score": min(1.0, len(found_credential) * 0.35)
    }


def compute_32d_feature_vector(
    deobf_res: Dict[str, Any],
    header_res: Dict[str, Any],
    protocol_res: Dict[str, Any],
    geo_hops: List[Dict[str, Any]],
    quishing_res: Dict[str, Any],
    nlp_res: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Constructs the standard 32-dimensional explainable feature vector
    where each dimension is normalized between 0.0 and 1.0.
    """
    v = [0.0] * 32

    # Dimensions 0-3: Protocol Authenticity
    v[0] = 0.0 if protocol_res["spf"]["status"] == "pass" else (0.8 if protocol_res["spf"]["status"] == "softfail" else 1.0)
    v[1] = 0.0 if protocol_res["dkim"]["status"] == "pass" else 1.0
    v[2] = 0.0 if protocol_res["dmarc"]["status"] == "pass" else 1.0
    v[3] = 0.0 if protocol_res["dmarc"]["aligned"] else 1.0

    # Dimensions 4-7: Header Integrity
    v[4] = 1.0 if header_res["anomalies"]["return_path_mismatch"] else 0.0
    v[5] = 1.0 if header_res["anomalies"]["reply_to_mismatch"] else 0.0
    v[6] = 1.0 if header_res["anomalies"]["display_name_spoof"] else 0.0
    v[7] = min(1.0, header_res["hop_count"] / 10.0)

    # Dimensions 8-11: Obfuscation Vectors
    v[8] = min(1.0, deobf_res["zero_width_count"] / 5.0)
    v[9] = min(1.0, len(deobf_res["homoglyphs_detected"]) / 5.0)
    lookalike_data = deobf_res.get("domain_lookalike") or {}
    v[10] = 1.0 if lookalike_data.get("is_lookalike") else 0.0
    v[11] = 1.0 if lookalike_data.get("is_punycode") else 0.0

    # Dimensions 12-15: NLP Behavioral Manipulation
    v[12] = nlp_res["urgency_score"]
    v[13] = nlp_res["financial_score"]
    v[14] = nlp_res["credential_score"]
    v[15] = 1.0 if (nlp_res["urgency_detected"] and nlp_res["credential_theft_detected"]) else 0.0

    # Dimensions 16-19: Payload & Quishing
    v[16] = 1.0 if quishing_res["is_quishing_detected"] else 0.0
    v[17] = min(1.0, len(quishing_res.get("qr_payloads", [])) / 2.0)
    v[18] = 0.0  # Executable attachment indicator
    v[19] = 0.0  # Macro attachment indicator

    # Dimensions 20-23: Network Infrastructure Risk
    originating_hop = geo_hops[0] if geo_hops else {}
    v[20] = 1.0 if originating_hop.get("is_anonymizer") else 0.0
    v[21] = 1.0 if originating_hop.get("risk_level") == "High" else (0.5 if originating_hop.get("risk_level") == "Medium" else 0.0)
    v[22] = 1.0 if "Tor" in originating_hop.get("isp", "") else 0.0
    v[23] = 1.0 if "Bulletproof" in originating_hop.get("infra_type", "") else 0.0

    # Dimensions 24-27: Hop Latency & Relay Anomalies
    max_hop_latency = max([h.get("latency_seconds", 0.0) for h in geo_hops] or [0.0])
    v[24] = min(1.0, max_hop_latency / 3600.0)  # Relay delay > 1hr is abnormal
    v[25] = 1.0 if len(geo_hops) > 6 else 0.0
    v[26] = 0.0  # IP country mismatch with claimed organization
    v[27] = 0.0  # High-risk registrar

    # Dimensions 28-31: Threat Intelligence & Historical Novelty
    v[28] = 1.0 if (v[0] > 0.5 and v[4] > 0.5) else 0.0  # Combined spoofing indicator
    v[29] = 1.0 if (v[10] > 0.5 and v[14] > 0.5) else 0.0  # Lookalike credential phish
    v[30] = 1.0 if (v[6] > 0.5 and v[13] > 0.5) else 0.0  # BEC CEO wire transfer
    v[31] = 1.0 if (v[16] > 0.5 and v[14] > 0.5) else 0.0  # Quishing credential harvesting

    # Weighted Fraud Score Calculation (0 - 100)
    weights = [
        12.0, 10.0, 10.0, 8.0,  # Auth
        10.0, 8.0, 12.0, 3.0,   # Headers
        10.0, 12.0, 15.0, 10.0, # Obfuscation
        8.0, 10.0, 12.0, 10.0,  # NLP
        15.0, 10.0, 10.0, 8.0,  # Quishing/Payload
        12.0, 10.0, 15.0, 15.0, # Network/Tor
        5.0, 4.0, 5.0, 5.0,     # Latency
        8.0, 10.0, 10.0, 10.0   # Compound
    ]

    weighted_sum = sum(v[i] * weights[i] for i in range(32))
    # Calibrated risk index: active severe indicators rapidly escalate severity
    base_score = (weighted_sum / 160.0) * 100.0

    # Compound threat escalation
    if v[10] > 0.5 and (v[0] > 0.5 or v[1] > 0.5):
        base_score = max(base_score, 72.0 + (weighted_sum / 25.0))
    if v[16] > 0.5 and v[14] > 0.5:  # Quishing + credential theft
        base_score = max(base_score, 75.0 + (weighted_sum / 25.0))
    if v[6] > 0.5 and v[13] > 0.5:  # BEC CEO spoof + financial wire
        base_score = max(base_score, 78.0 + (weighted_sum / 25.0))

    # If completely authenticated and no evasion vectors, retain benign score
    if protocol_res.get("overall_authentication_pass") and not deobf_res.get("evasion_detected") and not quishing_res.get("is_quishing_detected"):
        base_score = min(base_score, 15.0)

    fraud_score = round(min(100.0, max(0.0, base_score)), 1)

    if fraud_score >= 75.0:
        risk_tier = "CRITICAL THREAT"
        risk_color = "#dc2626"
    elif fraud_score >= 50.0:
        risk_tier = "MALICIOUS"
        risk_color = "#ea580c"
    elif fraud_score >= 25.0:
        risk_tier = "SUSPICIOUS"
        risk_color = "#eab308"
    else:
        risk_tier = "LOW RISK (BENIGN)"
        risk_color = "#16a34a"

    # Compile Structured Findings with Citations
    all_findings = []
    if deobf_res.get("finding_id"):
        all_findings.append({
            "id": "F-001",
            "category": "Adversarial Evasion",
            "description": f"Detected {deobf_res['zero_width_count']} zero-width characters and {len(deobf_res['homoglyphs_detected'])} homoglyphs in payload."
        })
    if header_res["anomalies"].get("finding_id"):
        all_findings.append({
            "id": "F-002",
            "category": "Identity Spoofing",
            "description": f"Identity divergence detected: Return-Path mismatch={header_res['anomalies']['return_path_mismatch']}, Reply-To mismatch={header_res['anomalies']['reply_to_mismatch']}."
        })
    if protocol_res.get("findings"):
        for idx, f in enumerate(protocol_res["findings"]):
            all_findings.append({
                "id": f"F-00{3 + idx}",
                "category": "Protocol Authentication",
                "description": f
            })
    if quishing_res.get("finding_id"):
        all_findings.append({
            "id": "F-006",
            "category": "Quishing Evasion",
            "description": "Embedded QR code with external redirection payload identified."
        })
    if nlp_res["urgency_detected"] and nlp_res["credential_theft_detected"]:
        all_findings.append({
            "id": "F-007",
            "category": "Social Engineering",
            "description": f"High behavioral urgency combined with credential theft requests: {', '.join(nlp_res['urgency_markers'])}."
        })
    if originating_hop.get("is_anonymizer"):
        all_findings.append({
            "id": "F-008",
            "category": "Network Provenance",
            "description": f"Originating IP {originating_hop.get('ip')} resolves to an anonymizer infrastructure ({originating_hop.get('infra_type')} via {originating_hop.get('isp')})."
        })

    return {
        "vector_32d": [round(val, 3) for val in v],
        "fraud_score": fraud_score,
        "risk_tier": risk_tier,
        "risk_color": risk_color,
        "findings": all_findings,
        "metrics": {
            "authentication_risk": round(sum(v[0:4]) / 4.0 * 100, 1),
            "header_anomaly_risk": round(sum(v[4:8]) / 4.0 * 100, 1),
            "obfuscation_risk": round(sum(v[8:12]) / 4.0 * 100, 1),
            "nlp_manipulation_risk": round(sum(v[12:16]) / 4.0 * 100, 1),
            "quishing_risk": round(sum(v[16:20]) / 4.0 * 100, 1),
            "infrastructure_risk": round(sum(v[20:24]) / 4.0 * 100, 1)
        }
    }
