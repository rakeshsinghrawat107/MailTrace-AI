"""
MailTrace.AI - Header & MTA Hop Parser
Deterministic RFC 5322 MIME & Chronological Transit Path Reconstruction
"""
import re
import email
from email import policy
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_REGEX = re.compile(r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b', re.IGNORECASE)

class HeaderParser:
    """Parses raw email byte streams into structured headers and chronological MTA hops."""

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Determines if an IPv4 address is within private RFC 1918 or loopback space."""
        parts = [int(p) for p in ip.split('.') if p.isdigit()]
        if len(parts) != 4:
            return False
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and (16 <= parts[1] <= 31):
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # 127.0.0.0/8 (Loopback)
        if parts[0] == 127:
            return True
        return False

    def parse(self, raw_bytes: bytes) -> Dict[str, Any]:
        """Parses email bytes into headers, bodies, attachments, and MTA hops."""
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        # Standard Headers
        subject = str(msg.get("Subject", "") or "")
        sender_from = str(msg.get("From", "") or "")
        recipient_to = str(msg.get("To", "") or "")
        return_path = str(msg.get("Return-Path", "") or "")
        reply_to = str(msg.get("Reply-To", "") or "")
        date_str = str(msg.get("Date", "") or "")
        message_id = str(msg.get("Message-ID", "") or "")
        auth_results = str(msg.get("Authentication-Results", "") or "")
        dkim_sig = str(msg.get("DKIM-Signature", "") or "")
        
        # Body Extraction
        text_body = ""
        html_body = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get_content_disposition() or "")
                
                if disposition == "attachment":
                    attachments.append({
                        "filename": part.get_filename() or "unnamed_attachment",
                        "content_type": content_type,
                        "size_bytes": len(part.get_payload(decode=True) or b"")
                    })
                elif content_type == "text/plain" and not text_body:
                    try:
                        text_body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        text_body = str(part.get_payload() or "")
                elif content_type == "text/html" and not html_body:
                    try:
                        html_body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        html_body = str(part.get_payload() or "")
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True) or b""
            try:
                decoded = payload.decode("utf-8", errors="replace")
            except Exception:
                decoded = str(msg.get_payload() or "")
            if content_type == "text/html":
                html_body = decoded
            else:
                text_body = decoded

        # Chronological MTA Hops
        received_headers = msg.get_all("Received", []) or []
        hops = self._reconstruct_hops(received_headers)

        return {
            "subject": subject,
            "from": sender_from,
            "to": recipient_to,
            "return_path": return_path,
            "reply_to": reply_to,
            "date": date_str,
            "message_id": message_id,
            "auth_results": auth_results,
            "dkim_signature": dkim_sig,
            "text_body": text_body,
            "html_body": html_body,
            "attachments": attachments,
            "hops": hops,
            "hop_count": len(hops)
        }

    def _reconstruct_hops(self, received_headers: List[str]) -> List[Dict[str, Any]]:
        """
        Reconstructs chronological hops by reversing Received headers.
        The bottom Received header is the first sender MTA (Hop 1).
        """
        raw_hops = list(reversed(received_headers))
        hops = []
        prev_dt: Optional[datetime] = None

        for idx, rec in enumerate(raw_hops):
            hop_seq = idx + 1
            ip_matches = IPV4_REGEX.findall(rec)
            relay_ip = ip_matches[0] if ip_matches else "127.0.0.1"
            is_priv = self.is_private_ip(relay_ip)

            # From MTA extraction
            from_mta = "Unknown"
            from_match = re.search(r'from\s+([^\s;]+)', rec, re.IGNORECASE)
            if from_match:
                from_mta = from_match.group(1)

            # By MTA extraction
            by_mta = "Unknown"
            by_match = re.search(r'by\s+([^\s;]+)', rec, re.IGNORECASE)
            if by_match:
                by_mta = by_match.group(1)

            # Timestamp parsing
            hop_dt = None
            date_match = re.search(r';\s*(.+)$', rec, re.DOTALL)
            if date_match:
                raw_date = date_match.group(1).strip()
                try:
                    hop_dt = parsedate_to_datetime(raw_date)
                except Exception:
                    hop_dt = None

            # Inter-hop latency calculation
            latency_sec = 0.0
            if prev_dt and hop_dt:
                delta = (hop_dt - prev_dt).total_seconds()
                latency_sec = max(0.0, delta)
            if hop_dt:
                prev_dt = hop_dt

            hops.append({
                "hop_sequence": hop_seq,
                "from_mta": from_mta,
                "by_mta": by_mta,
                "relay_ip": relay_ip,
                "is_private_ip": is_priv,
                "timestamp": hop_dt.isoformat() if hop_dt else "",
                "latency_seconds": latency_sec,
                "is_origin": (hop_seq == 1),
                "raw_received": rec.strip()
            })

        return hops

header_parser = HeaderParser()
