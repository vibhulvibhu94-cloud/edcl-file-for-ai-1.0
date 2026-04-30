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
    
    # ... (OVERRIDE_PATTERNS remain same) ...

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
