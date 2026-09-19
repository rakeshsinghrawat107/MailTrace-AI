"""
MailTrace.AI - Core Configuration
Enterprise Forensic Intelligence & Legal Custody Platform v3.1.0
"""
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
WORKSPACE_DIR = BASE_DIR.parent
APP_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = WORKSPACE_DIR / "frontend"
SAMPLES_DIR = BASE_DIR / "samples" / "1"
REPORTS_DIR = WORKSPACE_DIR / "reports"

# Ensure runtime directories exist
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Platform Metadata
PLATFORM_NAME = "MailTrace.AI"
VERSION = "3.1.0"
BUILD_EDITION = "Autonomous Zero-API-Key Forensic Edition"
STATUTORY_COMPLIANCE = "Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023 | FIPS 140-3"

# Forensic Threat Scoring Component Weights (Must sum to 1.0)
WEIGHTS = {
    "protocol_auth": 0.25,     # SPF / DKIM / DMARC / ARC / Return-Path
    "header_alignment": 0.20,  # From vs Return-Path, Sender vs Reply-To, Hop count
    "deobfuscation": 0.20,     # ZWSP, Homoglyphs, Punycode, Brand Lookalikes
    "nlp_heuristics": 0.15,    # Urgency, Coercive Language, BEC Wire Fraud
    "quishing": 0.10,          # QR Code Optical Payloads & In-Memory Redirection
    "network_intel": 0.10      # Tor Exit, Bulletproof Hosting, Suspicious ASN, Origin Geolocation
}

# Risk Tier Thresholds
TIERS = {
    "BENIGN": (0.0, 25.0),
    "SUSPICIOUS": (25.0, 50.0),
    "MALICIOUS": (50.0, 75.0),
    "CRITICAL": (75.0, 100.0)
}

# Global Brand Catalog for Levenshtein / Typosquatting Analysis
BRAND_CATALOG = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "facebook", "instagram", "linkedin", "twitter", "chase", "wellsfargo",
    "bankofamerica", "citibank", "sbi", "hdfc", "icici", "axisbank",
    "pnb", "gov", "nic", "rbi", "income-tax", "dhl", "fedex", "ups"
]

# Esri Keyless Basemap URLs
ESRI_BASE_TILE_URL = "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}"
ESRI_REF_TILE_URL = "https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{z}/{y}/{x}"
