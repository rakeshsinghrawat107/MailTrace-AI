"""
MailTrace.AI - 32-Dimensional Threat Scoring & Behavioral Intelligence Engine
Mathematical Vector Synthesis, Finding Citations [F-001..F-010] & MITRE ATT&CK Mitigations
"""
import re
from typing import Dict, Any, List, Tuple
from backend.app.core.config import WEIGHTS, TIERS

# NLP Behavioral Urgency & BEC Wire Fraud Indicators
URGENCY_REGEX = re.compile(
    r'\b(?:urgent|immediately|immediate action|suspend(?:ed)?|within 24 hours|'
    r'account termination|final notice|unauthorized access|security breach|'
    r'strictly confidential|do not discuss)\b',
    re.IGNORECASE
)

BEC_REGEX = re.compile(
    r'\b(?:wire transfer|bank details|new account details|swift|iban|'
    r'direct payment|invoice attached|remittance|gift card|payroll update|'
    r're-route funds|beneficiary)\b',
    re.IGNORECASE
)

class ThreatScoringEngine:
    """Computes a normalized 32-dimensional feature vector and weighted fraud score."""

    def evaluate_nlp(self, text: str) -> Dict[str, Any]:
        """Scans for urgency triggers and Business Email Compromise (BEC) wire cues."""
        urgency_matches = URGENCY_REGEX.findall(text)
        bec_matches = BEC_REGEX.findall(text)
        return {
            "urgency_count": len(urgency_matches),
            "urgency_keywords": list(set([m.lower() for m in urgency_matches])),
            "bec_count": len(bec_matches),
            "bec_keywords": list(set([m.lower() for m in bec_matches]))
        }

    def compute_32d_vector(
        self,
        headers: Dict[str, Any],
        protocols: Dict[str, Any],
        deobf: Dict[str, Any],
        quishing: Dict[str, Any],
        enriched_hops: List[Dict[str, Any]],
        nlp: Dict[str, Any]
    ) -> Tuple[List[float], Dict[str, float]]:
        """
        Constructs the strict 32-dimensional feature vector V in [0.0, 1.0]^32.
        Returns the raw vector and sub-category scores (0-100).
        """
        # Feature 1-5: Protocols & Alignment
        f1_spf = 1.0 if protocols.get("spf_status") in ("fail", "softfail") else 0.0
        f2_dkim = 1.0 if protocols.get("dkim_status") == "fail" else 0.0
        f3_dmarc = 1.0 if protocols.get("dmarc_status") == "fail" else 0.0
        f4_from_mismatch = 1.0 if not protocols.get("domain_aligned", True) else 0.0
        f5_reply_mismatch = 1.0 if not protocols.get("reply_to_aligned", True) else 0.0

        # Feature 6-11: Obfuscation
        zw_cnt = deobf.get("zero_width_count", 0)
        f6_zw_pres = 1.0 if zw_cnt > 0 else 0.0
        f7_zw_norm = min(1.0, zw_cnt / 10.0)
        
        homo_cnt = deobf.get("homoglyphs_unmasked_count", 0)
        f8_homo_pres = 1.0 if homo_cnt > 0 else 0.0
        f9_homo_norm = min(1.0, homo_cnt / 10.0)
        
        brand_spoof = deobf.get("brand_spoof")
        f10_brand = 1.0 if brand_spoof else 0.0
        f11_brand_dist = (1.0 / (brand_spoof["edit_distance"] + 1)) if brand_spoof else 0.0

        # Feature 12-13: Quishing
        f12_quish = 1.0 if quishing.get("quishing_detected") else 0.0
        f13_qr_cred = 1.0 if any(p.get("is_credential_harvester") for p in quishing.get("qr_payloads", [])) else 0.0

        # Feature 14-18: Network Transit & Provenance
        has_tor = any(h.get("is_tor_exit") for h in enriched_hops)
        has_bp = any(h.get("is_bulletproof") for h in enriched_hops)
        f14_tor = 1.0 if has_tor else 0.0
        f15_bp = 1.0 if has_bp else 0.0
        f16_hops_high = 1.0 if len(enriched_hops) > 6 else 0.0
        
        max_lat = max([h.get("latency_seconds", 0.0) for h in enriched_hops], default=0.0)
        f17_latency = min(1.0, max_lat / 300.0)
        
        first_hop_priv = enriched_hops[0].get("is_private_ip", False) if enriched_hops else False
        f18_origin_priv = 1.0 if (first_hop_priv and len(enriched_hops) > 1) else 0.0

        # Feature 19-20: NLP Behavioral
        f19_urgency = min(1.0, nlp.get("urgency_count", 0) / 4.0)
        f20_bec = min(1.0, nlp.get("bec_count", 0) / 3.0)

        # Feature 21-32: Extended Forensic Dimensions
        f21_unusual_hour = 0.0
        f22_exec_attach = 1.0 if any(a.get("filename", "").endswith(('.exe', '.bat', '.scr', '.vbs', '.js')) for a in headers.get("attachments", [])) else 0.0
        f23_macro_attach = 1.0 if any(a.get("filename", "").endswith(('.xlsm', '.docm', '.pptm')) for a in headers.get("attachments", [])) else 0.0
        f24_disp_mismatch = 1.0 if ('<' in headers.get("from", "") and '@' in headers.get("from", "").split('<')[0]) else 0.0
        f25_webmail = 1.0 if any(dom in protocols.get("from_domain", "") for dom in ["gmail.com", "yahoo.com", "hotmail.com"]) and nlp.get("bec_count", 0) > 0 else 0.0
        f26_susp_tld = 1.0 if any(protocols.get("from_domain", "").endswith(tld) for tld in [".top", ".xyz", ".club", ".icu", ".cam"]) else 0.0
        f27_hidden_b64 = 1.0 if "data:image" in headers.get("html_body", "") and zw_cnt > 0 else 0.0
        f28_short_links = 1.0 if any(short in headers.get("html_body", "") for short in ["bit.ly", "t.co", "tinyurl.com"]) else 0.0
        f29_ip_url = 1.0 if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', headers.get("html_body", "")) else 0.0
        f30_arc_fail = 1.0 if protocols.get("arc_status") == "fail" else 0.0
        f31_date_inconsist = 0.0
        f32_crypto_anomaly = 1.0 if (protocols.get("dkim_status") == "fail" and protocols.get("spf_status") == "pass") else 0.0

        vector = [
            f1_spf, f2_dkim, f3_dmarc, f4_from_mismatch, f5_reply_mismatch,
            f6_zw_pres, f7_zw_norm, f8_homo_pres, f9_homo_norm, f10_brand, f11_brand_dist,
            f12_quish, f13_qr_cred,
            f14_tor, f15_bp, f16_hops_high, f17_latency, f18_origin_priv,
            f19_urgency, f20_bec,
            f21_unusual_hour, f22_exec_attach, f23_macro_attach, f24_disp_mismatch,
            f25_webmail, f26_susp_tld, f27_hidden_b64, f28_short_links,
            f29_ip_url, f30_arc_fail, f31_date_inconsist, f32_crypto_anomaly
        ]

        # Calculate Sub-Scores (0.0 to 100.0)
        s_proto = (f1_spf * 35 + f2_dkim * 35 + f3_dmarc * 30)
        s_align = (f4_from_mismatch * 60 + f5_reply_mismatch * 40)
        s_deobf = min(100.0, (f6_zw_pres * 25 + f7_zw_norm * 25 + f8_homo_pres * 25 + f10_brand * 25))
        s_nlp = min(100.0, (f19_urgency * 50 + f20_bec * 50))
        s_quish = (f12_quish * 60 + f13_qr_cred * 40)
        s_net = min(100.0, (f14_tor * 60 + f15_bp * 30 + f16_hops_high * 10))

        sub_scores = {
            "protocol_auth": round(s_proto, 1),
            "header_alignment": round(s_align, 1),
            "deobfuscation": round(s_deobf, 1),
            "nlp_heuristics": round(s_nlp, 1),
            "quishing": round(s_quish, 1),
            "network_intel": round(s_net, 1)
        }

        return vector, sub_scores

    def evaluate(
        self,
        headers: Dict[str, Any],
        protocols: Dict[str, Any],
        deobf: Dict[str, Any],
        quishing: Dict[str, Any],
        enriched_hops: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Runs the complete forensic scoring algorithm."""
        full_text = headers.get("subject", "") + " " + headers.get("text_body", "")
        nlp = self.evaluate_nlp(full_text)

        vector, sub_scores = self.compute_32d_vector(headers, protocols, deobf, quishing, enriched_hops, nlp)

        # Weighted Total Score
        total_score = (
            sub_scores["protocol_auth"] * WEIGHTS["protocol_auth"] +
            sub_scores["header_alignment"] * WEIGHTS["header_alignment"] +
            sub_scores["deobfuscation"] * WEIGHTS["deobfuscation"] +
            sub_scores["nlp_heuristics"] * WEIGHTS["nlp_heuristics"] +
            sub_scores["quishing"] * WEIGHTS["quishing"] +
            sub_scores["network_intel"] * WEIGHTS["network_intel"]
        )
        total_score = round(max(0.0, min(100.0, total_score)), 1)

        # Map Risk Tier
        risk_tier = "BENIGN"
        for tier_name, (low, high) in TIERS.items():
            if low <= total_score <= high:
                risk_tier = tier_name
                break

        # Evidence-Grounded Findings [F-001] to [F-010]
        findings = []
        if protocols.get("spf_status") in ("fail", "softfail"):
            findings.append({
                "code": "[F-001]",
                "category": "AUTHENTICATION_FAILURE",
                "severity": "HIGH",
                "finding": f"Sender IP not authorized in domain SPF policy (result={protocols['spf_status']})",
                "mitre": "T1566.002 - Phishing: Spearphishing Link"
            })
        if protocols.get("dkim_status") == "fail":
            findings.append({
                "code": "[F-002]",
                "category": "CRYPTOGRAPHIC_INTEGRITY",
                "severity": "CRITICAL",
                "finding": "DKIM cryptographic signature verification failed (message body or headers altered in transit)",
                "mitre": "T1565.002 - Data Manipulation: Transmitted Data Manipulation"
            })
        if not protocols.get("domain_aligned", True):
            findings.append({
                "code": "[F-003]",
                "category": "IDENTITY_IMPERSONATION",
                "severity": "CRITICAL",
                "finding": f"From header domain '{protocols.get('from_domain')}' does not match Return-Path '{protocols.get('return_domain')}'",
                "mitre": "T1656 - Impersonation"
            })
        if deobf.get("zero_width_count", 0) > 0:
            findings.append({
                "code": "[F-004]",
                "category": "DEFENSE_EVASION",
                "severity": "HIGH",
                "finding": f"Detected {deobf['zero_width_count']} zero-width characters injected into text stream to evade keyword detection",
                "mitre": "T1027 - Obfuscated Files or Information"
            })
        if deobf.get("homoglyphs_unmasked_count", 0) > 0:
            findings.append({
                "code": "[F-005]",
                "category": "DEFENSE_EVASION",
                "severity": "HIGH",
                "finding": f"Unmasked {deobf['homoglyphs_unmasked_count']} Cyrillic/Greek homoglyphs visually spoofing Latin characters",
                "mitre": "T1036.007 - Masquerading: Double File Extension / IDN Spoofing"
            })
        if deobf.get("brand_spoof"):
            findings.append({
                "code": "[F-006]",
                "category": "BRAND_SPOOFING",
                "severity": "CRITICAL",
                "finding": f"Domain '{deobf['brand_spoof']['target_domain']}' is an adversarial lookalike of authentic brand '{deobf['brand_spoof']['impersonated_brand']}'",
                "mitre": "T1566.002 - Spearphishing Link"
            })
        if quishing.get("quishing_detected"):
            findings.append({
                "code": "[F-007]",
                "category": "QUISHING_OPTICAL_THREAT",
                "severity": "CRITICAL",
                "finding": "Message contains QR code payload engineered to bypass standard email URL security filters",
                "mitre": "T1566 - Phishing: Quishing"
            })
        if any(h.get("is_tor_exit") for h in enriched_hops):
            findings.append({
                "code": "[F-008]",
                "category": "ANONYMIZED_INFRASTRUCTURE",
                "severity": "CRITICAL",
                "finding": "MTA transit path originates from or traverses a verified Tor Anonymity Network Exit Relay",
                "mitre": "T1090.003 - Proxy: Multi-hop Proxy (Tor)"
            })
        if nlp.get("bec_count", 0) > 0:
            findings.append({
                "code": "[F-009]",
                "category": "FINANCIAL_FRAUD_BEC",
                "severity": "HIGH",
                "finding": f"High concentration of wire transfer / bank diversion terms detected: {nlp['bec_keywords']}",
                "mitre": "T1656 - Impersonation / BEC"
            })
        if nlp.get("urgency_count", 0) > 2:
            findings.append({
                "code": "[F-010]",
                "category": "BEHAVIORAL_COERCION",
                "severity": "MEDIUM",
                "finding": f"Coercive urgency language engineered to induce hasty action: {nlp['urgency_keywords']}",
                "mitre": "T1204 - User Execution"
            })

        return {
            "fraud_score": total_score,
            "risk_tier": risk_tier,
            "sub_scores": sub_scores,
            "vector_32d": vector,
            "nlp_analysis": nlp,
            "findings": findings
        }

threat_scoring_engine = ThreatScoringEngine()
