"""
MailTrace AI - RFC-822 Header & Relay Hop Provenance Parser
Extracts sender identities, return paths, reply-tos, and chronologically orders
Received: hops with IP and transit delay extraction.
"""
import re
import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Any, Optional
from datetime import datetime

# Regex to capture IPv4 and IPv6 addresses
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}')

# Private/loopback ranges
PRIVATE_IP_PATTERNS = [
    re.compile(r'^127\.'),
    re.compile(r'^10\.'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^fc00:'),
    re.compile(r'^fe80:'),
    re.compile(r'^::1$'),
]


def is_private_ip(ip: str) -> bool:
    """Check if IP is local, loopback, or RFC 1918 private."""
    return any(p.match(ip) for p in PRIVATE_IP_PATTERNS)


def extract_ips_from_string(text: str) -> List[str]:
    """Find all valid IPs inside a header segment."""
    ips = IPV4_REGEX.findall(text)
    ips.extend(IPV6_REGEX.findall(text))
    return ips


def parse_received_clause(raw_clause: str) -> Dict[str, Any]:
    """
    Parses an individual Received: header clause.
    Example: 'from mail-relay1.attacker.net (mail-relay1.attacker.net [185.220.101.5])
              by mx.google.com with ESMTPS id abc123; Fri, 18 Sep 2026 10:14:22 +0000'
    """
    normalized = " ".join(raw_clause.split())

    from_match = re.search(r'from\s+([^\s;]+(?:\s+\([^)]+\))?)', normalized, re.IGNORECASE)
    by_match = re.search(r'by\s+([^\s;]+)', normalized, re.IGNORECASE)
    with_match = re.search(r'with\s+([^\s;]+)', normalized, re.IGNORECASE)
    id_match = re.search(r'id\s+([^\s;]+)', normalized, re.IGNORECASE)

    # Date usually follows the semicolon
    timestamp = None
    date_str = None
    if ';' in normalized:
        parts = normalized.split(';')
        date_candidate = parts[-1].strip()
        try:
            timestamp = parsedate_to_datetime(date_candidate)
            date_str = timestamp.isoformat()
        except Exception:
            date_str = date_candidate

    ips = extract_ips_from_string(normalized)
    public_ips = [ip for ip in ips if not is_private_ip(ip)]

    return {
        "raw": normalized,
        "from_mta": from_match.group(1) if from_match else "unknown",
        "by_mta": by_match.group(1) if by_match else "unknown",
        "protocol": with_match.group(1) if with_match else "SMTP",
        "message_id": id_match.group(1) if id_match else "",
        "timestamp": date_str,
        "datetime_obj": timestamp,
        "all_ips": ips,
        "public_ips": public_ips,
        "relay_ip": public_ips[0] if public_ips else (ips[0] if ips else None)
    }


def parse_email_headers(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parses complete RFC-822 email headers and structures relay hops.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)

    from_header = msg.get('From', '')
    to_header = msg.get('To', '')
    subject = msg.get('Subject', '(No Subject)')
    date_header = msg.get('Date', '')
    return_path = msg.get('Return-Path', '')
    reply_to = msg.get('Reply-To', '')
    message_id = msg.get('Message-ID', '')

    from_name, from_addr = parseaddr(from_header)
    return_name, return_addr = parseaddr(return_path)
    reply_name, reply_addr = parseaddr(reply_to)

    from_domain = from_addr.split('@')[-1].lower() if '@' in from_addr else ""
    return_domain = return_addr.split('@')[-1].lower() if '@' in return_addr else ""
    reply_domain = reply_addr.split('@')[-1].lower() if '@' in reply_addr else ""

    # Identity alignment anomalies
    return_path_mismatch = bool(return_domain and from_domain and return_domain != from_domain)
    reply_to_mismatch = bool(reply_domain and from_domain and reply_domain != from_domain)
    display_name_spoof = bool(from_name and any(brand in from_name.lower() for brand in ["microsoft", "google", "paypal", "admin", "security", "support", "ceo", "director", "bank"]) and not any(brand in from_domain for brand in ["microsoft", "google", "paypal", "admin", "security", "support", "ceo", "director", "bank"]))

    # Parse Received: headers (chronological: earliest is at bottom of list)
    received_headers = msg.get_all('Received', [])
    raw_hops = [parse_received_clause(h) for h in received_headers]

    # Reconstruct chronological path: index 0 = Earliest Originating MTA
    hops_chronological = list(reversed(raw_hops))

    # Calculate transit latencies between hops
    hops_with_latency = []
    prev_time = None
    for idx, hop in enumerate(hops_chronological):
        latency_seconds = 0.0
        curr_time = hop.get("datetime_obj")
        if prev_time and curr_time:
            try:
                diff = (curr_time - prev_time).total_seconds()
                latency_seconds = max(0.0, diff)
            except Exception:
                latency_seconds = 0.0
        prev_time = curr_time or prev_time

        hops_with_latency.append({
            "hop_sequence": idx + 1,
            "from_mta": hop["from_mta"],
            "by_mta": hop["by_mta"],
            "protocol": hop["protocol"],
            "relay_ip": hop["relay_ip"],
            "timestamp": hop["timestamp"],
            "latency_seconds": latency_seconds,
            "is_originating_hop": (idx == 0)
        })

    # Earliest reliable public IP
    originating_ip = None
    for hop in hops_with_latency:
        if hop["relay_ip"] and not is_private_ip(hop["relay_ip"]):
            originating_ip = hop["relay_ip"]
            break

    # Body extraction for inspection
    body_text = ""
    body_html = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                try:
                    body_text += part.get_content()
                except Exception:
                    pass
            elif ctype == 'text/html' and 'attachment' not in cdispo:
                try:
                    body_html += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body_text = msg.get_content()
        except Exception:
            body_text = ""

    all_headers = {k: str(v) for k, v in msg.items()}
    all_headers.update({
        "From": from_header,
        "To": to_header,
        "Subject": subject,
        "Date": date_header,
        "Return-Path": return_path,
        "Reply-To": reply_to,
        "Message-ID": message_id
    })

    return {
        "headers": all_headers,
        "identities": {
            "from_name": from_name,
            "from_addr": from_addr,
            "from_domain": from_domain,
            "return_addr": return_addr,
            "return_domain": return_domain,
            "reply_addr": reply_addr,
            "reply_domain": reply_domain
        },
        "anomalies": {
            "return_path_mismatch": return_path_mismatch,
            "reply_to_mismatch": reply_to_mismatch,
            "display_name_spoof": display_name_spoof,
            "finding_id": "[F-002: Identity Divergence]" if (return_path_mismatch or reply_to_mismatch or display_name_spoof) else None
        },
        "hops": hops_with_latency,
        "originating_ip": originating_ip,
        "hop_count": len(hops_with_latency),
        "body_preview": body_text[:1500] if body_text else (body_html[:1500] if body_html else "")
    }
