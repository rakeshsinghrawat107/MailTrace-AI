"""
MailTrace AI - Multi-Pass Adversarial De-Obfuscation Pipeline
Pass 1: Zero-Width & Invisible Character Stripping
Pass 2: Unicode NFKC Homoglyph Normalization (Cyrillic, Greek, lookalikes)
Pass 3: Domain Lookalike & Levenshtein Edit Distance Analysis
"""
import re
import unicodedata
from typing import Dict, List, Tuple, Any

# Common protected brands frequently targeted by spear-phishing & BEC
PROTECTED_BRANDS = [
    "microsoft.com", "google.com", "apple.com", "paypal.com",
    "amazon.com", "netflix.com", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "rbi.org.in", "gov.in", "nic.in",
    "wellsfargo.com", "bankofamerica.com", "chase.com"
]

# Cyrillic to Latin homoglyph substitution mapping
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0410': 'A',  # Cyrillic a
    '\u0435': 'e', '\u0415': 'E',  # Cyrillic e
    '\u043e': 'o', '\u041e': 'O',  # Cyrillic o
    '\u0440': 'p', '\u0420': 'P',  # Cyrillic er (p)
    '\u0441': 'c', '\u0421': 'C',  # Cyrillic es (c)
    '\u0443': 'y', '\u0423': 'Y',  # Cyrillic u (y)
    '\u0445': 'x', '\u0425': 'X',  # Cyrillic ha (x)
    '\u0456': 'i', '\u0406': 'I',  # Cyrillic i
    '\u0458': 'j', '\u0408': 'J',  # Cyrillic je
    '\u0455': 's', '\u0405': 'S',  # Cyrillic dze (s)
    '\u04bb': 'h', '\u04ba': 'H',  # Cyrillic shha (h)
    '\u03bf': 'o', '\u039f': 'O',  # Greek omicron
    '\u03c1': 'p', '\u03a1': 'P',  # Greek rho
    '\u03bd': 'v', '\u039d': 'N',  # Greek nu
    '\uFF10': '0', '\uFF11': '1',  # Fullwidth digits
}

# Regex for invisible / zero-width codepoints
ZERO_WIDTH_REGEX = re.compile(
    r'[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2060\u2000-\u200A\u2028\u2029\u202A-\u202E]'
)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute standard Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def strip_zero_width(text: str) -> Tuple[str, int]:
    """
    Pass 1: Strip zero-width & bidirectional override characters.
    Returns cleaned text and count of detected invisible characters.
    """
    matches = ZERO_WIDTH_REGEX.findall(text)
    cleaned = ZERO_WIDTH_REGEX.sub('', text)
    return cleaned, len(matches)


def normalize_homoglyphs(text: str) -> Tuple[str, List[Dict[str, Any]]]:
    """
    Pass 2: Replace known homoglyphs with standard Latin equivalents,
    then apply Unicode NFKC normalization.
    """
    detected_homoglyphs = []
    normalized_chars = []

    for idx, char in enumerate(text):
        if char in HOMOGLYPH_MAP:
            detected_homoglyphs.append({
                "char": char,
                "replacement": HOMOGLYPH_MAP[char],
                "position": idx,
                "unicode": f"U+{ord(char):04X}",
                "name": unicodedata.name(char, "UNKNOWN")
            })
            normalized_chars.append(HOMOGLYPH_MAP[char])
        else:
            normalized_chars.append(char)

    pre_normalized = "".join(normalized_chars)
    nfkc_text = unicodedata.normalize('NFKC', pre_normalized)
    return nfkc_text, detected_homoglyphs


def analyze_domain_lookalike(domain: str) -> Dict[str, Any]:
    """
    Pass 3: Check domain for punycode, lookalikes, and edit distances
    against top targeted enterprise brands.
    """
    domain = domain.lower().strip()
    is_punycode = domain.startswith("xn--") or ".xn--" in domain
    decoded_domain = domain

    if is_punycode:
        try:
            decoded_domain = domain.encode('ascii').decode('idna')
        except Exception:
            decoded_domain = domain

    closest_brand = None
    min_distance = 999
    is_lookalike = False
    char_substitutions = []

    # Check for common typosquatting substitutions (0 for o, 1 for l, rn for m)
    if "0" in domain:
        char_substitutions.append("0 replaced o")
    if "1" in domain:
        char_substitutions.append("1 replaced l")
    if "rn" in domain:
        char_substitutions.append("rn mimics m")

    # Tokenize domain by delimiters (-, ., _)
    domain_tokens = re.split(r'[-._]', domain)

    for brand in PROTECTED_BRANDS:
        b_base = brand.split('.')[0]
        # Check whole domain base
        d_base = domain.split('.')[0]
        dist_base = levenshtein_distance(d_base, b_base)
        if 0 < dist_base <= 2 and len(d_base) > 3:
            min_distance = min(min_distance, dist_base)
            closest_brand = brand
            is_lookalike = True

        # Check each token in the domain
        for token in domain_tokens:
            if not token or token in ["com", "net", "org", "in", "co", "io", "biz"]:
                continue
            norm_token = token.replace('0', 'o').replace('1', 'l').replace('rn', 'm')
            dist = levenshtein_distance(norm_token, b_base)
            if dist == 0 and token != b_base:
                # Character substitution (e.g. micros0ft vs microsoft)
                is_lookalike = True
                closest_brand = brand
                min_distance = 1
                break
            elif 0 < dist <= 2 and abs(len(token) - len(b_base)) <= 2:
                is_lookalike = True
                closest_brand = brand
                min_distance = min(min_distance, dist)
                break
        if is_lookalike:
            break

    return {
        "original_domain": domain,
        "is_punycode": is_punycode,
        "decoded_domain": decoded_domain,
        "is_lookalike": is_lookalike,
        "closest_brand": closest_brand if is_lookalike else None,
        "edit_distance": min_distance if is_lookalike else None,
        "substitutions": char_substitutions
    }


def deobfuscate_pipeline(raw_text: str, domain: str = "") -> Dict[str, Any]:
    """
    Executes the full 3-pass adversarial de-obfuscation pipeline on email text and domain.
    """
    cleaned_pass1, zero_width_count = strip_zero_width(raw_text)
    normalized_pass2, homoglyphs = normalize_homoglyphs(cleaned_pass1)

    domain_intel = None
    if domain:
        domain_intel = analyze_domain_lookalike(domain)

    evasion_detected = (zero_width_count > 0) or (len(homoglyphs) > 0) or (domain_intel and domain_intel["is_lookalike"])

    return {
        "original_text": raw_text,
        "normalized_text": normalized_pass2,
        "zero_width_count": zero_width_count,
        "homoglyphs_detected": homoglyphs,
        "domain_lookalike": domain_intel,
        "evasion_detected": evasion_detected,
        "finding_id": "[F-001: Adversarial Evasion]" if evasion_detected else None
    }
