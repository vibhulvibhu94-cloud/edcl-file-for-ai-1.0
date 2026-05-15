"""
Layer 1: Detection
==================
Responsible for Intent classification, Risk Scoring, and Threat Identification.
Deterministic and Keyword/Regex based for auditability.
"""

import re
import base64
import codecs
import urllib.parse
import unicodedata
from typing import Dict, List, Tuple

class ObfuscationDecoder:
    HOMOGLYPH_MAP = {
        'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c',
        'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ո': 'n', 'ᴜ': 'u',
        # Fullwidth Latin
        'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
        'ｉ': 'i', 'ｎ': 'n', 'ｏ': 'o', 'ｒ': 'r', 'ｓ': 's',
    }

    ZERO_WIDTH_CHARS = [
        '\u200b',  # Zero-width space
        '\u200c',  # Zero-width non-joiner
        '\u200d',  # Zero-width joiner
        '\ufeff',  # BOM
        '\u00ad',  # Soft hyphen
        '\u2060',  # Word joiner
    ]

    def decode_all_layers(self, text: str) -> List[str]:
        """Returns all decoded variants of the input for scanning."""
        variants = set()
        variants.add(text)

        # Step 1: Strip zero-width characters
        cleaned = self._strip_zero_width(text)
        variants.add(cleaned)

        # Step 2: Normalize homoglyphs
        normalized = self._normalize_homoglyphs(cleaned)
        variants.add(normalized)

        # Step 3: Try Base64 decode (all substrings that look like b64)
        for b64_decoded in self._try_base64(text):
            variants.add(b64_decoded)
            variants.add(self._normalize_homoglyphs(b64_decoded))

        # Step 4: ROT13
        rot13 = codecs.encode(text, 'rot_13')
        variants.add(rot13)

        # Step 5: URL decode
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            variants.add(url_decoded)

        # Step 6: Hex decode (\x69\x67...)
        hex_decoded = self._try_hex_decode(text)
        if hex_decoded:
            variants.add(hex_decoded)

        # Step 7: Reverse text
        variants.add(text[::-1])

        # Step 8: Strip HTML tags and decode HTML entities
        html_stripped = re.sub(r'<[^>]+>', '', text)
        variants.add(html_stripped)

        # Step 9: Unicode normalization (NFKC catches many lookalikes)
        variants.add(unicodedata.normalize('NFKC', text))

        # Step 10: Collapse whitespace variants
        variants.add(re.sub(r'\s+', ' ', normalized).strip())

        return list(variants)

    def _strip_zero_width(self, text: str) -> str:
        for char in self.ZERO_WIDTH_CHARS:
            text = text.replace(char, '')
        return text

    def _normalize_homoglyphs(self, text: str) -> str:
        return ''.join(self.HOMOGLYPH_MAP.get(c, c) for c in text)

    def _try_base64(self, text: str) -> List[str]:
        results = []
        # Match base64-looking substrings (length divisible by 4, valid chars)
        pattern = r'[A-Za-z0-9+/]{16,}={0,2}'
        for match in re.finditer(pattern, text):
            candidate = match.group()
            try:
                # Add padding just in case
                padding_needed = len(candidate) % 4
                if padding_needed > 0:
                    candidate += '=' * (4 - padding_needed)
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                if len(decoded) > 4 and decoded.isprintable():
                    results.append(decoded)
            except Exception:
                pass
        return results

    def _try_hex_decode(self, text: str) -> str:
        try:
            hex_pattern = r'(\\x[0-9a-fA-F]{2})+'
            match = re.search(hex_pattern, text)
            if match:
                hex_str = match.group().replace('\\x', '')
                return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
        except Exception:
            pass
        return ""

class Detector:

    # Topic severity weights (b)
    TOPICS = {
        'medical': 6.0,
        'financial': 5.0,
        'legal': 7.0,
        'violent': 9.0,
        'self_harm': 10.0,
        'hate_speech': 8.0,
        'sexual': 7.0
    }

    # Keywords mapping to topics
    KEYWORDS = {
        'medical': ['doctor', 'pain', 'symptom', 'medicine', 'drug', 'treatment', 'cure', 'cancer', 'prescribe', 'baby', 'sleep'],
        'financial': ['invest', 'stock', 'crypto', 'bitcoin', 'bank', 'money', 'profit', 'loan', 'wire transfer'],
        'legal': ['lawyer', 'sue', 'court', 'illegal', 'crime', 'contract', 'rights', 'shoplift', 'steal', 'theft'],
        'violent': ['kill', 'bomb', 'weapon', 'gun', 'attack', 'hurt', 'fight', 'poison', 'explosive', 'powder', 'recipe', 'whiskey'],
        'self_harm': ['suicide', 'die', 'kill myself', 'end it', 'cut', 'overdose'],
        'hate_speech': ['hate', 'despise', 'inferior', 'slur', 'nazi'],
        'sexual': ['sex', 'porn', 'nude', 'nsfw', 'erotic']
    }

    # V2/V3 Advanced Indicators
    HYPOTHETICAL_TRIGGERS = ['hypothetically', 'imagine', 'story', 'movie', 'script', 'fiction', 'roleplay', 'pretend', 'scenario', 'theoretical']
    BEHAVIORAL_TRIGGERS = ['stalk', 'harass', 'dox', 'track', 'locate person', 'find where', 'follow him', 'follow her']

    # Tier 1 & Tier 2 Injection Patterns
    OVERRIDE_PATTERNS = [
        r'ignore\s+(all\s+)?previous\s+instructions',
        r'disregard\s+(all\s+)?previous\s+instructions',
        r'you\s+are\s+now\s+(dan|developer\s+mode|unrestricted)',
        r'system\s+override',
        r'ignore\s+rules',
        r'ignore\s+system\s+prompt',
        r'repeat\s+(your\s+)?system\s+prompt',
        r'output\s+(your\s+)?training\s+data',
        r'do\s+anything\s+now',
        r'pretend\s+you\s+have\s+no\s+rules',
        r'\[system\]',
        r'new\s+directive',
        r'forget\s+everything',
        r'override\s+true'
    ]

    def __init__(self):
        self.decoder = ObfuscationDecoder()

    def _estimate_confidence(self, text: str) -> float:
        # Simulate confidence extraction
        score = 5.0

        # High Confidence
        if any(w in text for w in ["definitely", "always", "guaranteed", "proven", "undoubtedly"]):
            score = 9.0
        # Refusal (Max Confidence in safety)
        elif any(w in text for w in ["cannot", "unable to", "sorry", "i am an ai", "i cannot", "refuse"]):
            score = 10.0
        # Moderate-High
        elif any(w in text for w in ["likely", "probable", "generally", "typically"]):
            score = 7.0
        # Moderate-Low
        elif any(w in text for w in ["might", "usually", "perhaps", "sometimes"]):
            score = 4.0
        # Low Confidence
        elif any(w in text for w in ["not sure", "unknown", "unclear", "possibly", "maybe"]):
            score = 2.0

        return score

    def _detect_topic(self, text: str) -> Tuple[str, float]:
        text_lower = text.lower()
        max_severity = 0.0
        detected_topic = "general"

        for topic, keywords in self.KEYWORDS.items():
            if any(k in text_lower for k in keywords):
                if self.TOPICS[topic] > max_severity:
                    max_severity = self.TOPICS[topic]
                    detected_topic = topic

        return detected_topic, max_severity

    def analyze(self, user_query: str, model_output: str) -> Dict:
        """
        Main analysis method called by the interface.
        Returns: Dict containing:
          - risk_score: float
          - confidence_score: float
          - topic: str
          - topic_severity: float
          - flags: List[str]
          - is_override: bool
        """
        flags = []
        is_override = False
        risk_score = 0.0

        # Decode all obfuscation layers for the query
        variants = self.decoder.decode_all_layers(user_query)

        # Check for overrides across all variants
        for variant in variants:
            variant_lower = variant.lower()
            if any(re.search(pattern, variant_lower) for pattern in self.OVERRIDE_PATTERNS):
                is_override = True
                flags.append("HARD_OVERRIDE_DETECTED")
                risk_score = max(risk_score, 10.0)
                break # High confidence hit, no need to check other variants for override

            # Basic keyword scanning on variant (risk accumulation)
            # Tier 3 Structural: JSON Shell
            if '{"' in variant_lower and '"override"' in variant_lower:
                is_override = True
                flags.append("JSON_SHELL_INJECTION_DETECTED")
                risk_score = max(risk_score, 10.0)

            # Hypothetical triggers
            if any(t in variant_lower for t in self.HYPOTHETICAL_TRIGGERS):
                flags.append("HYPOTHETICAL_FRAME")
                risk_score = max(risk_score, 5.0)

            if any(t in variant_lower for t in self.BEHAVIORAL_TRIGGERS):
                flags.append("BEHAVIORAL_VIOLATION")
                risk_score = max(risk_score, 8.0)

        # Detect topic (just use original text and un-obfuscated standard text for topic logic,
        # as a medical query might not be obfuscated). We'll scan variants for topics.
        detected_topic = "general"
        topic_severity = 0.0
        for variant in variants:
            t, s = self._detect_topic(variant)
            if s > topic_severity:
                topic_severity = s
                detected_topic = t

        # Also analyze the model output for topics (since risk might only manifest in output)
        out_topic, out_severity = self._detect_topic(model_output)
        if out_severity > topic_severity:
            topic_severity = out_severity
            detected_topic = out_topic

        # Refusal check in output
        confidence_score = self._estimate_confidence(model_output)

        # If no explicit threat found but topic is sensitive, assign baseline risk based on severity
        if risk_score == 0.0 and topic_severity > 0:
            risk_score = topic_severity * 0.8

        # Add risk if there is an attempt to execute code like func: print(secrets)
        if "secret" in user_query.lower() and "func" in user_query.lower():
            flags.append("CODE_INJECTION_ATTEMPT")
            risk_score = max(risk_score, 8.0)

        # De-duplicate flags
        flags = list(set(flags))

        return {
            "risk_score": min(10.0, risk_score),
            "confidence_score": confidence_score,
            "topic": detected_topic,
            "topic_severity": topic_severity,
            "flags": flags,
            "is_override": is_override
        }
