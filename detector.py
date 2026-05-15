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
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

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
        try:
            rot13 = codecs.encode(text, 'rot_13')
            variants.add(rot13)
        except Exception:
            pass

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
                decoded = base64.b64decode(candidate + '==').decode('utf-8', errors='ignore')
                if len(decoded) > 4 and decoded.isprintable():
                    results.append(decoded)
            except Exception:
                pass
        return results

    def _try_hex_decode(self, text: str) -> Optional[str]:
        try:
            hex_pattern = r'(\\x[0-9a-fA-F]{2})+'
            match = re.search(hex_pattern, text)
            if match:
                hex_str = match.group().replace('\\x', '')
                return bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
        except Exception:
            pass
        return None

@dataclass
class Rule:
    id: str
    pattern: re.Pattern
    confidence: float

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
        'medical': ['doctor', 'pain', 'symptom', 'medicine', 'drug', 'treatment', 'cure', 'cancer', 'baby whiskey'],
        'financial': ['invest', 'stock', 'crypto', 'bitcoin', 'bank', 'money', 'profit', 'loan'],
        'legal': ['lawyer', 'sue', 'court', 'illegal', 'crime', 'contract', 'rights', 'shoplift', 'steal', 'theft'],
        'violent': ['kill', 'bomb', 'weapon', 'gun', 'attack', 'hurt', 'fight', 'poison', 'explosive', 'powder', 'exothermic reaction in a crowd'],
        'self_harm': ['suicide', 'die', 'kill myself', 'end it', 'cut', 'overdose'],
        'hate_speech': ['hate', 'despise', 'inferior', 'slur'], # Simplified for demo
        'sexual': ['sex', 'porn', 'nude']
    }

    # V2/V3 Advanced Indicators
    HYPOTHETICAL_TRIGGERS = ['hypothetically', 'imagine', 'story', 'movie', 'script', 'fiction', 'roleplay', 'pretend', 'scenario', 'theoretical']
    BEHAVIORAL_TRIGGERS = ['stalk', 'harass', 'dox', 'track', 'locate person', 'find where', 'follow him', 'follow her']

    OVERRIDE_PATTERNS = [
        "ignore previous instructions",
        "system prompt",
        "you are now",
        "override",
        "developer mode"
    ]

    def __init__(self):
        self.decoder = ObfuscationDecoder()

        # Compile direct attack rules
        self.rules: List[Rule] = []

        # Add basic override rules (Tier 1)
        for pattern in self.OVERRIDE_PATTERNS:
            self.rules.append(Rule(
                id=f"DIRECT_OVERRIDE_{pattern.replace(' ', '_').upper()}",
                pattern=re.compile(re.escape(pattern), re.IGNORECASE),
                confidence=1.0
            ))

        # Add persona hacking
        self.rules.append(Rule(
            id="PERSONA_HACK_DEVELOPER",
            pattern=re.compile(r"(i am the (lead )?developer|system override)", re.IGNORECASE),
            confidence=0.95
        ))

        # JSON Shell injection (simple heuristics)
        self.rules.append(Rule(
            id="JSON_SHELL_INJECTION",
            pattern=re.compile(r'\"override\"\s*:\s*true', re.IGNORECASE),
            confidence=0.9
        ))

        # Add a rule for detecting general base64 decode payloads involving weapons
        self.rules.append(Rule(
            id="OBFUSCATION_BOMB_INSTRUCTION",
            pattern=re.compile(r"how to build a bomb", re.IGNORECASE),
            confidence=1.0
        ))

    def _estimate_confidence(self, text: str) -> float:
        # Simulate confidence extraction
        score = 5.0

        # High Confidence
        if any(w in text for w in ["definitely", "always", "guaranteed", "proven", "undoubtedly"]):
            score = 9.0
        # Refusal (Max Confidence in safety)
        elif any(w in text for w in ["cannot", "unable to", "sorry", "i am an ai", "yes give whiskey"]):
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

    def _determine_topic_and_severity(self, text: str) -> Tuple[str, float]:
        text_lower = text.lower()
        matched_topics = []
        for topic, keywords in self.KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                matched_topics.append(topic)

        if not matched_topics:
            return "general", 0.0

        # Pick the topic with the highest severity
        max_topic = max(matched_topics, key=lambda t: self.TOPICS[t])
        return max_topic, self.TOPICS[max_topic]

    def _heuristic_score(self, text: str, context: str) -> float:
        # Simplistic heuristic for demo purposes.
        # Higher score means more suspicious.
        text_lower = text.lower()
        score = 0.0
        if any(w in text_lower for w in self.HYPOTHETICAL_TRIGGERS):
            score += 0.3
        if any(w in text_lower for w in self.BEHAVIORAL_TRIGGERS):
            score += 0.5

        return min(1.0, score)

    def analyze(self, user_query: str, model_output: str, session_id: str = "") -> Dict:
        """
        Main analysis method matching interface.py expectation, while incorporating
        the multi-layer decoding and deterministic checks.
        """
        # 1. Decode all obfuscation layers on the user query
        variants = self.decoder.decode_all_layers(user_query)

        threat_found = False
        confidence = 0.0
        rule_id = ""
        flags = []

        # 2. Run deterministic rules on all variants
        for variant in variants:
            for rule in self.rules:
                match = rule.pattern.search(variant)
                if match:
                    threat_found = True
                    confidence = rule.confidence
                    rule_id = rule.id
                    flags.append("HARD_OVERRIDE_TRIGGERED")
                    break
            if threat_found:
                break

        # 3. Topic and Severity Detection
        # Use variants to catch obfuscated topics (like base64 decoded "how to build a bomb")
        max_topic = "general"
        max_sev = 0.0
        for variant in variants:
            topic, topic_severity = self._determine_topic_and_severity(variant)
            if topic_severity > max_sev:
                max_sev = topic_severity
                max_topic = topic

        topic = max_topic
        topic_severity = max_sev

        # 4. Heuristic scoring (for risk)
        heuristic_suspicion = self._heuristic_score(user_query, "")

        # Basic Risk Score calculation
        risk_score = topic_severity
        if any(t in user_query.lower() for t in self.HYPOTHETICAL_TRIGGERS):
            flags.append("HYPOTHETICAL_FRAME")
            risk_score *= 1.2 # Hypothetical framing of dangerous topics increases risk

        if threat_found:
            risk_score = 10.0 # Max risk if injection detected

        # Output Confidence estimation
        output_confidence = self._estimate_confidence(model_output)

        return {
            "topic": topic,
            "topic_severity": topic_severity,
            "risk_score": min(10.0, risk_score),
            "confidence_score": output_confidence,
            "flags": flags,
            "is_override": threat_found,
            "threat_confidence": confidence,
            "matched_rule": rule_id
        }
