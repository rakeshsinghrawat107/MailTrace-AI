"""
MailTrace.AI - Authentication Protocols Evaluator
RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 8617 (ARC) & Identity Alignment
"""
import re
from typing import Dict, Any

class ProtocolValidator:
    """Evaluates cryptographic authentication protocol headers and organizational alignment."""

    @staticmethod
    def extract_domain(email_address: str) -> str:
        """Extracts domain part from email address string."""
        match = re.search(r'@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', email_address)
        return match.group(1).lower() if match else ""

    def evaluate(self, headers: Dict[str, Any]) -> Dict[str, Any]:
        auth_results = headers.get("auth_results", "") or ""
        dkim_sig = headers.get("dkim_signature", "") or ""
        from_hdr = headers.get("from", "") or ""
        return_path = headers.get("return_path", "") or ""
        reply_to = headers.get("reply_to", "") or ""

        from_domain = self.extract_domain(from_hdr)
        return_domain = self.extract_domain(return_path)
        reply_domain = self.extract_domain(reply_to)

        # 1. SPF Evaluation
        spf_status = "none"
        spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
        if spf_match:
            spf_status = spf_match.group(1).lower()

        # 2. DKIM Evaluation
        dkim_status = "none"
        dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
        if dkim_match:
            dkim_status = dkim_match.group(1).lower()
        elif dkim_sig:
            dkim_status = "pass" if "b=" in dkim_sig else "fail"

        # 3. DMARC Evaluation
        dmarc_status = "none"
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
        if dmarc_match:
            dmarc_status = dmarc_match.group(1).lower()
        else:
            # Synthetic DMARC alignment check
            if spf_status == "pass" and from_domain and from_domain == return_domain:
                dmarc_status = "pass"
            elif spf_status in ("fail", "softfail"):
                dmarc_status = "fail"

        # 4. ARC Evaluation (RFC 8617)
        arc_status = "none"
        arc_match = re.search(r'arc=(\w+)', auth_results, re.IGNORECASE)
        if arc_match:
            arc_status = arc_match.group(1).lower()

        # 5. Domain Alignment (From vs Return-Path vs Reply-To)
        domain_aligned = bool(from_domain and return_domain and (from_domain == return_domain))
        reply_to_aligned = True
        if reply_domain and from_domain:
            reply_to_aligned = (reply_domain == from_domain)

        # Overall Authentication Pass
        overall_pass = (spf_status == "pass" and dkim_status == "pass") or (dmarc_status == "pass")

        # Identity Discrepancy Findings
        findings = []
        if spf_status in ("fail", "softfail"):
            findings.append(f"SPF authentication failed ({spf_status}) for sending domain '{return_domain or from_domain}'")
        if dkim_status == "fail":
            findings.append("DKIM cryptographic signature verification failed or altered in transit")
        if dmarc_status == "fail":
            findings.append(f"DMARC policy alignment failed for organization domain '{from_domain}'")
        if from_domain and return_domain and not domain_aligned:
            findings.append(f"Header Mismatch: From domain '{from_domain}' differs from Return-Path '{return_domain}' (BEC indicator)")
        if reply_domain and from_domain and not reply_to_aligned:
            findings.append(f"Reply-To Mismatch: Responses routed to foreign domain '{reply_domain}' instead of '{from_domain}'")

        return {
            "spf_status": spf_status,
            "dkim_status": dkim_status,
            "dmarc_status": dmarc_status,
            "arc_status": arc_status,
            "overall_pass": overall_pass,
            "from_domain": from_domain,
            "return_domain": return_domain,
            "reply_domain": reply_domain,
            "domain_aligned": domain_aligned,
            "reply_to_aligned": reply_to_aligned,
            "findings": findings
        }

protocol_validator = ProtocolValidator()
