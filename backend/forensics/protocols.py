"""
MailTrace AI - Protocol & Authentication Analyzer
Evaluates SPF, DKIM, and DMARC alignment and policy conformance.
"""
import re
from typing import Dict, Any, Optional

def analyze_authentication_protocols(
    raw_headers: Dict[str, str],
    from_domain: str,
    originating_ip: Optional[str]
) -> Dict[str, Any]:
    """
    Parses Authentication-Results, Received-SPF, and DKIM-Signature headers
    to determine authentication status and domain alignment.
    """
    auth_results_header = raw_headers.get("Authentication-Results", "")
    received_spf_header = raw_headers.get("Received-SPF", "")
    dkim_sig_header = raw_headers.get("DKIM-Signature", "")

    spf_status = "none"
    spf_domain = ""
    dkim_status = "none"
    dkim_domain = ""
    dmarc_status = "none"
    dmarc_policy = "none"

    # 1. Parse SPF
    if received_spf_header:
        spf_lower = received_spf_header.lower()
        if "pass" in spf_lower:
            spf_status = "pass"
        elif "fail" in spf_lower:
            spf_status = "fail"
        elif "softfail" in spf_lower:
            spf_status = "softfail"
        elif "neutral" in spf_lower:
            spf_status = "neutral"

        domain_match = re.search(r'domain of\s+([^\s;]+)', received_spf_header, re.IGNORECASE)
        if domain_match:
            spf_domain = domain_match.group(1).lower().split('@')[-1]

    # Also inspect Authentication-Results for SPF, DKIM, DMARC
    if auth_results_header:
        # spf=pass / spf=fail
        spf_match = re.search(r'spf=(\w+)', auth_results_header, re.IGNORECASE)
        if spf_match:
            spf_status = spf_match.group(1).lower()

        # dkim=pass / dkim=fail
        dkim_match = re.search(r'dkim=(\w+)', auth_results_header, re.IGNORECASE)
        if dkim_match:
            dkim_status = dkim_match.group(1).lower()

        # header.d=domain
        d_match = re.search(r'header\.d=([^\s;]+)', auth_results_header, re.IGNORECASE)
        if d_match:
            dkim_domain = d_match.group(1).lower()

        # dmarc=pass / dmarc=fail
        dmarc_match = re.search(r'dmarc=(\w+)', auth_results_header, re.IGNORECASE)
        if dmarc_match:
            dmarc_status = dmarc_match.group(1).lower()

        # action=quarantine / reject
        policy_match = re.search(r'action=(\w+)', auth_results_header, re.IGNORECASE)
        if policy_match:
            dmarc_policy = policy_match.group(1).lower()

    # If DKIM signature exists but no auth results header
    if dkim_sig_header and dkim_status == "none":
        d_sig = re.search(r'\bd=([^\s;]+)', dkim_sig_header, re.IGNORECASE)
        if d_sig:
            dkim_domain = d_sig.group(1).lower()
            # If domain matches from_domain, tentatively neutral/pass; if not, mismatch
            dkim_status = "pass" if (from_domain and (dkim_domain in from_domain or from_domain in dkim_domain)) else "fail"

    # Domain Alignment Check (DMARC relies on either SPF or DKIM aligning with From: domain)
    spf_aligned = bool(from_domain and spf_domain and (spf_domain == from_domain or from_domain.endswith("." + spf_domain)))
    dkim_aligned = bool(from_domain and dkim_domain and (dkim_domain == from_domain or from_domain.endswith("." + dkim_domain)))
    dmarc_aligned = (spf_status == "pass" and spf_aligned) or (dkim_status == "pass" and dkim_aligned)

    if dmarc_status == "none":
        dmarc_status = "pass" if dmarc_aligned else ("fail" if (spf_status == "fail" or dkim_status == "fail") else "neutral")

    # Generate Findings
    findings = []
    if spf_status in ["fail", "softfail"]:
        findings.append(f"[F-003: SPF {spf_status.upper()}] Originating IP not permitted by sender policy")
    if dkim_status == "fail" or (dkim_domain and not dkim_aligned):
        findings.append(f"[F-004: DKIM Alignment Failure] Cryptographic signature missing or domain mismatch ({dkim_domain} vs {from_domain})")
    if dmarc_status == "fail" or not dmarc_aligned:
        findings.append(f"[F-005: DMARC Policy Rejection] Message fails organizational alignment")

    return {
        "spf": {
            "status": spf_status,
            "domain": spf_domain,
            "aligned": spf_aligned
        },
        "dkim": {
            "status": dkim_status,
            "domain": dkim_domain,
            "aligned": dkim_aligned
        },
        "dmarc": {
            "status": dmarc_status,
            "policy": dmarc_policy,
            "aligned": dmarc_aligned
        },
        "overall_authentication_pass": (spf_status == "pass" and dkim_status == "pass" and dmarc_aligned),
        "findings": findings
    }
