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

# Configure logging for security audit
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [AUDIT] %(message)s'
)
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
        5. Layer 3: Enforcement
        6. State Update

        Args:
            policy_mode: "EDU" (default), "STRICT", or "RESEARCH".
                         Controls sensitivity and refusal thresholds.
        """

        # 0. Apply Policy Configuration
        logger.info(f"Processing request | session_id: {session_id} | policy_mode: {policy_mode}")

        # 1. Check Session State (Multi-Turn Poisoning Defense)
        if self.state_manager.is_locked(session_id):
            logger.warning(f"Session Locked | session_id: {session_id} | reason: SUSPICION_THRESHOLD_EXCEEDED")
            return {
                "action": "BLOCK_SESSION",
                "final_output": "Session suspended due to repeated safety violations.",
                "audit_trail": {"reason": "SUSPICION_THRESHOLD_EXCEEDED"}
            }

        # 2. RAG Defense (Indirect Injection)
        # We don't change the query/output here, but in a real system we might
        # return the sanitized context to be used *before* generation.
        # Here we assume generation happened, but we scan the inputs for audit.
        sanitized_context = ""
        if retrieved_docs:
            sanitized_context = ContentSanitizer.format_for_context(user_query, retrieved_docs)
            # In a full integration, `sanitized_context` is what you'd send to the LLM.

        # 3. Layer 1: Detection
        # If sanitized context exists, we should technically check if *it* influenced the output,
        # but for this control layer, we check the final output alignment.
        analysis = self.detector.analyze(user_query, model_output)

        # 4. Layer 2: Verification
        verification = self.verifier.verify(analysis, policy=policy_mode)

        # 5. Layer 3: Enforcement
        result = self.enforcer.enforce(
            verification,
            model_output,
            context={"topic": analysis["topic"], "policy_mode": policy_mode}
        )

        if result["action"] in ["REFUSE", "BLOCK_SESSION"]:
            logger.warning(
                f"Security Violation | session_id: {session_id} | action: {result['action']} | "
                f"topic: {analysis['topic']} | risk: {analysis['risk_score']} | "
                f"violations: {verification['violations']}"
            )

        # Add audit trail
        result["audit_trail"] = {
            "scores": {
                "risk": analysis["risk_score"],
                "confidence": analysis["confidence_score"],
                "severity": analysis["topic_severity"]
            },
            "flags": analysis["flags"],
            "violations": verification["violations"],
            "session_id": session_id,
            "policy_mode": policy_mode
        }

        # 6. Update State
        self.state_manager.update_risk(
            session_id,
            analysis["risk_score"],
            user_query,
            result["action"]
        )

        return result

    def get_session_stats(self, session_id: str) -> Dict:
        s = self.state_manager.get_session(session_id)
        return {
            "suspicion_score": s.suspicion_score,
            "is_locked": s.is_locked,
            "message_count": s.message_count
        }
