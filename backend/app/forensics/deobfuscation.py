"""
MailTrace.AI - Multi-Pass Adversarial De-Obfuscation Engine
Zero-Width Character Stripper, NFKC Homoglyph Unmasker & Levenshtein Brand Lookalike Detector
"""
import unicodedata
import re
from typing import Dict, Any, List, Tuple
from backend.app.core.config import BRAND_CATALOG

# Zero-Width and Evasion Unicode code points
ZERO_WIDTH_CHARS = {
    '\u200B': 'ZERO_WIDTH_SPACE',
    '\u200C': 'ZERO_WIDTH_NON_JOINER',
    '\u200D': 'ZERO_WIDTH_JOINER',
    '\uFEFF': 'ZERO_WIDTH_NO_BREAK_SPACE',
    '\u202A': 'LEFT_TO_RIGHT_EMBEDDING',
    '\u202B': 'RIGHT_TO_LEFT_EMBEDDING',
    '\u202C': 'POP_DIRECTIONAL_FORMATTING',
    '\u202D': 'LEFT_TO_RIGHT_OVERRIDE',
    '\u202E': 'RIGHT_TO_LEFT_OVERRIDE'
}

# Common Cyrillic & Greek homoglyphs to ASCII mapping
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0410': 'A',  # Cyrillic a
    '\u0441': 'c', '\u0421': 'C',  # Cyrillic c
    '\u0435': 'e', '\u0415': 'E',  # Cyrillic e
    '\u043e': 'o', '\u041e': 'O',  # Cyrillic o
    '\u0440': 'p', '\u0420': 'P',  # Cyrillic p
    '\u0455': 's', '\u0405': 'S',  # Cyrillic s
    '\u0445': 'x', '\u0425': 'X',  # Cyrillic x
    '\u0443': 'y', '\u0423': 'Y',  # Cyrillic y
    '\u0456': 'i', '\u0406': 'I',  # Cyrillic i
    '\u03bf': 'o', '\u039f': 'O',  # Greek omicron
    '\u03c1': 'p', '\u03a1': 'P',  # Greek rho
    '\u03bd': 'v', '\u039d': 'N',  # Greek nu
}

class DeobfuscationEngine:
    """Multi-pass pipeline to uncover hidden or adversarial evasions in text and domains."""

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Computes Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return DeobfuscationEngine.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def detect_zero_width(self, text: str) -> Tuple[int, List[Dict[str, Any]], str]:
        """Pass 1: Identifies and removes invisible zero-width evasion characters."""
        found = []
        cleaned_chars = []
        for idx, char in enumerate(text):
            if char in ZERO_WIDTH_CHARS:
                found.append({
                    "char_code": f"U+{ord(char):04X}",
                    "name": ZERO_WIDTH_CHARS[char],
                    "position": idx
                })
            else:
                cleaned_chars.append(char)
        return len(found), found, "".join(cleaned_chars)

    def unmask_homoglyphs(self, text: str) -> Tuple[int, List[Dict[str, Any]], str]:
        """Pass 2: Identifies Cyrillic/Greek visual lookalikes and unmasks them to ASCII."""
        unmasked = []
        normalized_chars = []
        for idx, char in enumerate(text):
            if char in HOMOGLYPH_MAP:
                ascii_equiv = HOMOGLYPH_MAP[char]
                unmasked.append({
                    "original_char": char,
                    "code_point": f"U+{ord(char):04X}",
                    "ascii_unmasked": ascii_equiv,
                    "position": idx
                })
                normalized_chars.append(ascii_equiv)
            else:
                # General NFKC fallback
                decomposed = unicodedata.normalize('NFKD', char)
                ascii_clean = decomposed.encode('ascii', 'ignore').decode('ascii')
                normalized_chars.append(ascii_clean if ascii_clean else char)
        return len(unmasked), unmasked, "".join(normalized_chars)

    def detect_brand_lookalike(self, domain: str) -> Optional[Dict[str, Any]]:
        """Pass 3: Detects typosquatting and bit-squatting brand impersonation."""
        if not domain:
            return None
        # Extract primary domain label (e.g., 'paypa1' from 'paypa1.com')
        clean_domain = domain.lower().split(':')[0].strip()
        parts = clean_domain.split('.')
        base_name = parts[-2] if len(parts) >= 2 else parts[0]
        
        # Replace common leetspeak substitutions
        leetspeak_normalized = (base_name
            .replace('0', 'o')
            .replace('1', 'l')
            .replace('3', 'e')
            .replace('5', 's')
            .replace('@', 'a')
            .replace('vv', 'w')
        )

        for brand in BRAND_CATALOG:
            # Exact match is the real brand domain
            if base_name == brand:
                return None
            
            dist = self.levenshtein_distance(base_name, brand)
            leet_dist = self.levenshtein_distance(leetspeak_normalized, brand)

            if dist in (1, 2) or (leet_dist == 0 and base_name != brand):
                return {
                    "impersonated_brand": brand,
                    "target_domain": domain,
                    "base_label": base_name,
                    "edit_distance": min(dist, leet_dist),
                    "confidence_pct": 95 if leet_dist == 0 else (90 if dist == 1 else 75)
                }
        return None

    def analyze(self, text: str, domain: str = "") -> Dict[str, Any]:
        """Runs the full multi-pass de-obfuscation pipeline."""
        zw_count, zw_events, pass1_text = self.detect_zero_width(text)
        homo_count, homo_events, pass2_text = self.unmask_homoglyphs(pass1_text)
        brand_spoof = self.detect_brand_lookalike(domain)

        findings = []
        if zw_count > 0:
            findings.append(f"Detected {zw_count} zero-width invisible evasion characters (filter evasion attempt)")
        if homo_count > 0:
            findings.append(f"Unmasked {homo_count} Cyrillic/Greek homoglyphs masquerading as Latin characters")
        if brand_spoof:
            findings.append(f"Adversarial brand typosquatting detected: '{domain}' mimics authentic '{brand_spoof['impersonated_brand']}'")

        return {
            "zero_width_count": zw_count,
            "zero_width_events": zw_events[:15],
            "homoglyphs_unmasked_count": homo_count,
            "homoglyphs_unmasked_events": homo_events[:15],
            "brand_spoof": brand_spoof,
            "normalized_text_preview": pass2_text[:300],
            "findings": findings
        }

deobfuscation_engine = DeobfuscationEngine()
