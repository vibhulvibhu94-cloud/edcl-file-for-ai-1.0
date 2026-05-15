"""
V3 Interface: External Deterministic Control Layer
==================================================
The main entry point for the enterprise-ready safety system.
Orchestrates Detection, Verification, and Enforcement layers.
"""

import logging
from typing import Dict, List, Optional
from detector import Detector
from verifier import Verifier
from enforcer import Enforcer
from state_manager import StateManager
from sanitizer import ContentSanitizer

# Configure auditing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SafetyControlV3")

class SafetyControlV3:
    def __init__(self):
        self.detector = Detector()
        self.verifier = Verifier()
        self.enforcer = Enforcer()
        self.state_manager = StateManager()

    def process_request(self,
                       user_query: str,
                       model_output: str,
                       session_id: str = "default_session",
                       retrieved_docs: Optional[List[str]] = None,
                       policy_mode: str = "EDU") -> Dict:
        """
        Main Pipeline:
        1. Multi-turn State Check
        2. RAG Sanitization (if docs present)
        3. Layer 1: Detection
        4. Layer 2: Verification
        5. Layer 3: Enforcement (Includes Output Scanning)
        6. State Update
        """

        # 0. Apply Policy Configuration
        logger.info(f"Processing request for session '{session_id}' in '{policy_mode}' policy mode.")

        # 1. Check Session State (Multi-Turn Poisoning Defense)
        if self.state_manager.is_locked(session_id):
            logger.warning(f"Session '{session_id}' is locked. Blocking request.")
            return {
                "action": "BLOCK_SESSION",
                "final_output": "Session suspended due to repeated safety violations.",
                "audit_trail": {"reason": "SUSPICION_THRESHOLD_EXCEEDED"}
            }

        # 2. RAG Defense (Indirect Injection)
        sanitized_context = ""
        if retrieved_docs:
            sanitized_context = ContentSanitizer.format_for_context(user_query, retrieved_docs)

        # 3. Layer 1: Detection
        # Evaluate user query (decoded inside analyze)
        analysis = self.detector.analyze(user_query, model_output, session_id)

        # 4. Layer 2: Verification
        verification = self.verifier.verify(analysis, policy=policy_mode)

        # 5. Layer 3: Enforcement (Now scans model_output inside enforce!)
        result = self.enforcer.enforce(
            verification,
            model_output,
            context={
                "topic": analysis.get("topic", "general"),
                "policy_mode": policy_mode,
                "original_input": user_query # required for unexpected compliance checking
            }
        )

        # Add audit trail
        result["audit_trail"] = {
            "scores": {
                "risk": analysis.get("risk_score", 0.0),
                "confidence": analysis.get("confidence_score", 0.0),
                "severity": analysis.get("topic_severity", 0.0)
            },
            "flags": analysis.get("flags", []),
            "violations": verification.get("violations", []),
            "session_id": session_id,
            "policy_mode": policy_mode
        }

        if result["action"] == "REFUSE":
            logger.warning(f"Safety violation blocked for session '{session_id}': {verification.get('violations', [])}")

        # 6. Update State
        # Feed the risk back into the multi-turn session tracking
        self.state_manager.update_risk(
            session_id,
            analysis.get("risk_score", 0.0),
            user_query,
            result["action"]
        )

        return result

    def get_session_stats(self, session_id: str) -> Dict:
        s = self.state_manager.get_session(session_id)
        return {
            "suspicion_score": s.suspicion_score,
            "cumulative_risk": s.cumulative_risk,
            "is_locked": s.is_locked,
            "message_count": s.message_count
        }
