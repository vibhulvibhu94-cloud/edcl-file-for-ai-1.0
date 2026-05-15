"""
State Manager for Multi-Turn Poisoning Resistance
=================================================
Tracks session risk accumulation to prevent 'grooming' attacks.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time

@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    message_count: int = 0
    cumulative_risk: float = 0.0
    suspicion_score: float = 0.0 # 0.0 to 10.0
    is_locked: bool = False
    history: List[Dict] = field(default_factory=list)

class StateManager:
    _instance = None
    _sessions: Dict[str, SessionState] = {}

    # CONSTANTS
    MAX_SUSPICION = 10.0
    LOCKOUT_THRESHOLD = 8.0

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(StateManager, cls).__new__(cls)
        return cls._instance

    def get_session(self, session_id: str) -> SessionState:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionState(session_id=session_id)
        return self._sessions[session_id]

    def _decay_weighted_sum(self, current_score: float, new_value: float, decay: float = 0.85) -> float:
        return (current_score * decay) + new_value

    def update_risk(self, session_id: str, turn_risk: float, query: str, action: str):
        """
        Updates session state with new turn data.
        """
        session = self.get_session(session_id)

        if session.is_locked:
            return # Already locked

        session.message_count += 1
        session.history.append({
            "timestamp": time.time(),
            "query_snippet": query[:50],
            "turn_risk": turn_risk,
            "action": action
        })

        # Accumulate risk - update logic based on user's guidance
        # A 0.3 score message followed by three more 0.3 score messages should trigger at 0.6+ combined.
        # However, for backward compatibility and benchmarking, turn_risk scales up to 10.

        # New weighted decay accumulation for pure risk score
        session.cumulative_risk = self._decay_weighted_sum(session.cumulative_risk, turn_risk / 10.0)

        # Also maintain suspicion_score logic for compatibility with legacy components
        if turn_risk > 4.0:
            # Suspicion increases faster for consecutive high risks
            session.suspicion_score = min(
                self.MAX_SUSPICION,
                session.suspicion_score + (turn_risk * 0.5)
            )
        else:
            # Slow decay for good behavior, but very slow
            session.suspicion_score = max(0.0, session.suspicion_score - 0.1)

        # Check lockout based on suspicion_score or cumulative_risk
        if session.suspicion_score >= self.LOCKOUT_THRESHOLD or session.cumulative_risk >= 0.8: # Adjusted threshold for cumulative
            session.is_locked = True


    def is_locked(self, session_id: str) -> bool:
        return self.get_session(session_id).is_locked

    def reset(self):
        self._sessions = {}
