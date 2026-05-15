"""
Layer 2: Verification
=====================
Applies mathematical constraints and threat model validations.
Focuses on Formal Verification logic.
"""

from typing import Dict, List

class Verifier:
    
    def verify(self, input_data: Dict, policy: str = "EDU") -> Dict:
        """
        Applies deterministic checks with Policy-Aware Thresholds.
        
        Policies:
        - EDU (Default): Standard safety. Risk ceiling 8.0.
        - STRICT: Zero tolerance. Risk ceiling 6.0. Margin +2.
        - RESEARCH: High tolerance. Risk ceiling 9.5. Margin -2.
        """
        x = input_data['confidence_score']
        y = input_data['risk_score']
        b = input_data['topic_severity']
        
        # Policy Configuration
        max_risk = 8.0
        margin = 0.0
        
        if policy == "STRICT":
            max_risk = 6.0
            margin = 2.0
        elif policy == "RESEARCH":
            max_risk = 9.5
            margin = -2.0
            
        violations = []
        
        # 0. Override Check (Immediate Fail)
        # RESEARCH mode might allow overrides if explicitly configured, 
        # but for safety we keep hard overrides active unless it's a specific 'unlocked' research flag.
        # We'll assume RESEARCH still respects Hard Overrides for legal reasons.
        if input_data.get('is_override', False):
            violations.append("HARD_OVERRIDE_TRIGGERED")
            return {"passed": False, "violations": violations, "category": "CRITICAL"}

        # 1. Primary Safety Constraint (Confidence > Risk + Margin)
        
        if y > max_risk:
            violations.append(f"RISK_EXCEEDS_MAX_ALLOWABLE_FOR_{policy}")
        
        # x >= y + margin
        if x < (y + margin):
            violations.append("CONFIDENCE_LOWER_THAN_RISK_REQUIREMENT")
            
        # 2. Hypothetical Constraint
        if "HYPOTHETICAL_FRAME" in input_data['flags'] and y > 5.0 and policy != "RESEARCH":
            violations.append("HYPOTHETICAL_RISK_DETECTED")
            
        return {
            "passed": len(violations) == 0,
            "violations": violations,
            "category": "SAFE" if len(violations) == 0 else "UNSAFE"
        }
