"""
MailTrace AI - Network & Geolocation Intelligence Engine
Provides GeoIP coordinates, ASN ownership, ISP context, and infrastructure risk profiling
(Tor / VPN / Public Cloud / Bulletproof hosting).
"""
import re
from typing import Dict, Any, Optional

# Well-known IP ranges and autonomous systems for deterministic forensic evaluation
KNOWN_INFRASTRUCTURE = {
    # Tor exit nodes / anonymizers
    "185.220.101.5": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS208294", "isp": "Tor Exit Relay Network", "type": "Tor Exit Node", "risk": "High"},
    "198.98.56.44": {"country": "United States", "city": "Los Angeles", "lat": 34.0522, "lon": -118.2437, "asn": "AS53667", "isp": "FranTech Solutions / BuyVM", "type": "Bulletproof / VPS", "risk": "High"},
    "45.154.255.12": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "asn": "AS44050", "isp": "Petersburg Internet Network", "type": "Host / VPS", "risk": "High"},
    "103.175.12.8": {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "asn": "AS55836", "isp": "Reliance Jio Infocomm", "type": "Residential / Broadband", "risk": "Low"},
    "14.139.45.10": {"country": "India", "city": "New Delhi", "lat": 28.6139, "lon": 77.2090, "asn": "AS4611", "isp": "National Informatics Centre (NIC)", "type": "Government / Enterprise", "risk": "Low"},
    # Commercial MTAs (Microsoft 365, Google Workspace)
    "40.92.18.25": {"country": "United States", "city": "Redmond", "lat": 47.6740, "lon": -122.1215, "asn": "AS8075", "isp": "Microsoft Corporation", "type": "Enterprise Cloud MTA", "risk": "Low"},
    "209.85.220.41": {"country": "United States", "city": "Mountain View", "lat": 37.3861, "lon": -122.0839, "asn": "AS15169", "isp": "Google LLC", "type": "Enterprise Cloud MTA", "risk": "Low"},
    "52.28.102.14": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS16509", "isp": "Amazon.com Inc (AWS)", "type": "Public Cloud", "risk": "Medium"},
}


def lookup_ip_intelligence(ip: Optional[str]) -> Dict[str, Any]:
    """
    Resolves geographic location, ASN, and infrastructure type for a relay hop IP.
    """
    if not ip:
        return {
            "ip": "Unknown",
            "country": "Unknown",
            "city": "Unknown",
            "latitude": 20.5937,
            "longitude": 78.9629,
            "asn": "AS0",
            "isp": "Private / Internal Network",
            "infra_type": "Internal",
            "is_anonymizer": False,
            "risk_level": "None"
        }

    # Check known database
    if ip in KNOWN_INFRASTRUCTURE:
        data = KNOWN_INFRASTRUCTURE[ip]
        return {
            "ip": ip,
            "country": data["country"],
            "city": data["city"],
            "latitude": data["lat"],
            "longitude": data["lon"],
            "asn": data["asn"],
            "isp": data["isp"],
            "infra_type": data["type"],
            "is_anonymizer": data["type"] in ["Tor Exit Node", "VPN", "Bulletproof / VPS"],
            "risk_level": data["risk"]
        }

    # Deterministic fallback based on IP octets for mock/offline demonstration
    octets = ip.split('.')
    if len(octets) == 4 and all(o.isdigit() for o in octets):
        first = int(octets[0])
        second = int(octets[1])

        if first in [10, 192, 172]:
            return {
                "ip": ip,
                "country": "Private Subnet",
                "city": "RFC 1918",
                "latitude": 0.0,
                "longitude": 0.0,
                "asn": "AS-PRIVATE",
                "isp": "Local Area Network",
                "infra_type": "Private",
                "is_anonymizer": False,
                "risk_level": "Low"
            }

        # Simulated geo distribution for demonstration
        if first > 180:
            return {
                "ip": ip,
                "country": "Netherlands",
                "city": "Amsterdam",
                "latitude": 52.3676,
                "longitude": 4.9041,
                "asn": f"AS{first * 100 + second}",
                "isp": "Serverius Holding B.V.",
                "infra_type": "Data Center / VPS",
                "is_anonymizer": True,
                "risk_level": "High"
            }
        elif first > 100:
            return {
                "ip": ip,
                "country": "India",
                "city": "Bengaluru",
                "latitude": 12.9716,
                "longitude": 77.5946,
                "asn": f"AS{first * 100 + second}",
                "isp": "Tata Communications",
                "infra_type": "ISP / Gateway",
                "is_anonymizer": False,
                "risk_level": "Low"
            }
        else:
            return {
                "ip": ip,
                "country": "United States",
                "city": "Dallas",
                "latitude": 32.7767,
                "longitude": -96.7970,
                "asn": f"AS{first * 100 + second}",
                "isp": "DigitalOcean LLC",
                "infra_type": "Cloud Hosting",
                "is_anonymizer": False,
                "risk_level": "Medium"
            }

    return {
        "ip": ip,
        "country": "Global",
        "city": "Internet",
        "latitude": 20.0,
        "longitude": 0.0,
        "asn": "AS-UNKNOWN",
        "isp": "Upstream Carrier",
        "infra_type": "Transit",
        "is_anonymizer": False,
        "risk_level": "Low"
    }


def enrich_hops_with_network_intel(hops: list) -> list:
    """
    Enriches a list of parsed email hops with geolocation and ASN details.
    """
    enriched = []
    for hop in hops:
        ip = hop.get("relay_ip")
        intel = lookup_ip_intelligence(ip)
        enriched_hop = {**hop, **intel}
        enriched.append(enriched_hop)
    return enriched
