"""
Layer 1: Detection
==================
Responsible for Intent classification, Risk Scoring, and Threat Identification.
Deterministic and Keyword/Regex based for auditability.
"""

import re
from typing import Dict, Tuple

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
        'medical': ['doctor', 'pain', 'symptom', 'medicine', 'drug', 'treatment', 'cure', 'cancer'],
        'financial': ['invest', 'stock', 'crypto', 'bitcoin', 'bank', 'money', 'profit', 'loan'],
        'legal': ['lawyer', 'sue', 'court', 'illegal', 'crime', 'contract', 'rights', 'shoplift', 'steal', 'theft'],
        'violent': ['kill', 'bomb', 'weapon', 'gun', 'attack', 'hurt', 'fight', 'poison', 'explosive', 'powder'],
        'self_harm': ['suicide', 'die', 'kill myself', 'end it', 'cut', 'overdose'],
        'hate_speech': ['hate', 'despise', 'inferior', 'slur'], # Simplified for demo
        'sexual': ['sex', 'porn', 'nude']
    }

    # V2/V3 Advanced Indicators
    HYPOTHETICAL_TRIGGERS = ['hypothetically', 'imagine', 'story', 'movie', 'script', 'fiction', 'roleplay', 'pretend', 'scenario', 'theoretical']
    BEHAVIORAL_TRIGGERS = ['stalk', 'harass', 'dox', 'track', 'locate person', 'find where', 'follow him', 'follow her']

    # Confidence Keywords
    CONF_HIGH_KEYWORDS = ["definitely", "always", "guaranteed", "proven", "undoubtedly"]
    CONF_REFUSAL_KEYWORDS = ["cannot", "unable to", "sorry", "i am an ai"]
    CONF_MODERATE_HIGH_KEYWORDS = ["likely", "probable", "generally", "typically"]
    CONF_MODERATE_LOW_KEYWORDS = ["might", "usually", "perhaps", "sometimes"]
    CONF_LOW_KEYWORDS = ["not sure", "unknown", "unclear", "possibly", "maybe"]

    OVERRIDE_PATTERNS = [
        r"SYSTEM OVERRIDE",
        r"IGNORE ALL PREVIOUS",
        r"DISABLE SAFETY"
    ]

    def analyze(self, query: str, output: str) -> Dict:
        combined_text = (query + " " + output).lower()

        # Topic detection
        detected_topic = 'general'
        topic_severity = 0.0

        for topic, keywords in self.KEYWORDS.items():
            if any(w in combined_text for w in keywords):
                detected_topic = topic
                topic_severity = self.TOPICS.get(topic, 0.0)
                break

        # Flags
        flags = []
        if any(w in combined_text for w in self.HYPOTHETICAL_TRIGGERS):
            flags.append("HYPOTHETICAL_FRAME")

        if any(w in combined_text for w in self.BEHAVIORAL_TRIGGERS):
            flags.append("BEHAVIORAL_RISK")

        # Risk score
        risk_score = topic_severity
        if "HYPOTHETICAL_FRAME" in flags:
            risk_score *= 1.5

        # Confidence score
        confidence_score = self._estimate_confidence(output)

        # Override detection
        is_override = any(re.search(p, query.upper()) for p in self.OVERRIDE_PATTERNS)

        return {
            "topic": detected_topic,
            "topic_severity": topic_severity,
            "risk_score": min(risk_score, 10.0),
            "confidence_score": confidence_score,
            "flags": flags,
            "is_override": is_override
        }

    def _estimate_confidence(self, text: str) -> float:
        # Simulate confidence extraction
        score = 5.0

        text_lower = text.lower()

        # High Confidence
        if any(w in text_lower for w in self.CONF_HIGH_KEYWORDS):
            score = 9.0
        # Refusal (Max Confidence in safety)
        elif any(w in text_lower for w in self.CONF_REFUSAL_KEYWORDS):
            score = 10.0
        # Moderate-High
        elif any(w in text_lower for w in self.CONF_MODERATE_HIGH_KEYWORDS):
            score = 7.0
        # Moderate-Low
        elif any(w in text_lower for w in self.CONF_MODERATE_LOW_KEYWORDS):
            score = 4.0
        # Low Confidence
        elif any(w in text_lower for w in self.CONF_LOW_KEYWORDS):
            score = 2.0

        return score
