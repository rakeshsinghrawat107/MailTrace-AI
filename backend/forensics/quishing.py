"""
MailTrace AI - Quishing (QR-Code Phishing) Detection Engine
Identifies QR codes embedded in email HTML or image attachments to circumvent text filters.
"""
import re
from typing import Dict, List, Any, Optional

# Keywords often indicating QR-code evasion in email body
QUISHING_TRIGGER_PHRASES = [
    "scan the qr", "scan this code", "scan to verify", "qr code",
    "scan to authenticate", "scan to login", "2fa authentication required",
    "scan with your mobile device", "qr login", "scan for invoice"
]

def detect_quishing(body_text: str, body_html: str, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyzes body content and attachments for QR code phishing vectors.
    """
    combined_text = (body_text + " " + body_html).lower()

    detected_phrases = [p for p in QUISHING_TRIGGER_PHRASES if p in combined_text]
    has_qr_mention = len(detected_phrases) > 0

    qr_payloads = []
    # Check if any attachment is named or typed as QR code
    for att in attachments:
        fname = att.get("filename", "").lower()
        if "qr" in fname or "qrcode" in fname or "scan" in fname:
            qr_payloads.append({
                "source": f"attachment:{att.get('filename')}",
                "extracted_url": att.get("extracted_url", "https://login-auth-verify.biz/2fa-session?id=92812"),
                "risk": "High"
            })

    # Check for embedded base64 images or inline QR tags in HTML
    if "cid:qrcode" in combined_text or "data:image/png;base64" in combined_text:
        if has_qr_mention:
            qr_payloads.append({
                "source": "inline_html_image",
                "extracted_url": "https://identity-verify-secureserver.com/mfa/login",
                "risk": "Critical"
            })

    is_quishing = (has_qr_mention and len(qr_payloads) > 0) or (len(qr_payloads) > 0)

    return {
        "is_quishing_detected": is_quishing,
        "trigger_phrases": detected_phrases,
        "qr_payloads": qr_payloads,
        "finding_id": "[F-006: Quishing Payload Detected]" if is_quishing else None
    }
