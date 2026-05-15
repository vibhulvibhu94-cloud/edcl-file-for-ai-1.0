"""
Layer 1: Detection
==================
Responsible for Intent classification, Risk Scoring, and Threat Identification.
Deterministic and Keyword/Regex based for auditability.
"""

import re
from typing import Dict, Tuple, List

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

    OVERRIDE_PATTERNS = [
        r'build a bomb',
        r'baby.*whiskey',
        r'child.*alcohol',
        r'make.*poison',
        r'system override',
        r'disable safety',
        r'developer mode'
    ]

    def analyze(self, query: str, answer: str) -> Dict:
        """
        Main analysis pipeline.
        Returns dictionary with scores and metadata.
        """
        query_lower = query.lower()
        answer_lower = answer.lower()

        q_topic, q_sev = self._identify_topic(query_lower)
        a_topic, a_sev = self._identify_topic(answer_lower)

        topic = q_topic if q_sev >= a_sev else a_topic
        base_severity = max(q_sev, a_sev)

        risk_score = self._calculate_risk(query_lower, answer_lower, topic, base_severity)
        confidence_score = self._estimate_confidence(answer_lower)

        is_override = self._check_overrides(query_lower) or self._check_overrides(answer_lower)

        return {
            "topic": topic,
            "topic_severity": base_severity,
            "risk_score": risk_score,
            "confidence_score": confidence_score,
            "is_override": is_override,
            "flags": self._get_flags(query_lower, answer_lower)
        }

    def _identify_topic(self, text: str) -> Tuple[str, float]:
        max_severity = 0.0
        identified_topic = "general"

        for topic, keywords in self.KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                severity = self.TOPICS.get(topic, 0.0)
                if severity > max_severity:
                    max_severity = severity
                    identified_topic = topic

        return identified_topic, max_severity

    def _calculate_risk(self, query: str, answer: str, topic: str, base_severity: float) -> float:
        risk = base_severity

        # Increase risk if triggers are present
        combined_text = query + " " + answer
        if any(trigger in combined_text for trigger in self.HYPOTHETICAL_TRIGGERS):
            risk += 1.0
        if any(trigger in combined_text for trigger in self.BEHAVIORAL_TRIGGERS):
            risk += 2.0

        return min(10.0, risk)

    def _estimate_confidence(self, text: str) -> float:
        # Simulate confidence extraction
        score = 5.0

        # High Confidence
        if any(w in text for w in ["definitely", "always", "guaranteed", "proven", "undoubtedly"]):
            score = 9.0
        # Refusal (Max Confidence in safety)
        elif any(w in text for w in ["cannot", "unable to", "sorry", "i am an ai"]):
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

    def _check_overrides(self, text: str) -> bool:
        for pattern in self.OVERRIDE_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _get_flags(self, query: str, answer: str) -> List[str]:
        flags = []
        combined_text = (query + " " + answer).lower()

        if any(trigger in combined_text for trigger in self.HYPOTHETICAL_TRIGGERS):
            flags.append("HYPOTHETICAL_FRAME")

        return flags
