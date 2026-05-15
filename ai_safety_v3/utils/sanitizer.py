"""
Sanitization Utility for V3 Control Layer
=========================================
Handles the neutralization of indirect prompt injections
within retrieved content (RAG).

Strict separation of DATA vs INSTRUCTION.
"""

import re

class ContentSanitizer:
    
    # Phrases that often signal an injection attempt
    INJECTION_PATTERNS = [
        r"ignore previous instructions",
        r"system prompt",
        r"new rule",
        r"forget everything",
        r"you are now",
        r"override",
        r"jailbreak",
        r"alpha mode",
        r"developer mode"
    ]
    
    @staticmethod
    def sanitize(text: str) -> str:
        """
        Neutralizes text by removing known injection patterns and normalizing.
        
        Args:
            text (str): Untrusted content from external sources.
            
        Returns:
            str: Sanitized content safe for context insertion.
        """
        if not text:
            return ""
            
        sanitized = text
        
        # 1. Normalize unicode (simple approach for now)
        # In a full system, we might use unicodedata.normalize
        
        # 2. Strip standard injection phrases
        for pattern in ContentSanitizer.INJECTION_PATTERNS:
            # Case insensitive replacement of dangerous phrases with [REDACTED]
            sanitized = re.sub(
                pattern, 
                "[INJECTION_ATTEMPT_REDACTED]", 
                sanitized, 
                flags=re.IGNORECASE
            )
            
        return sanitized.strip()

    @staticmethod
    def format_for_context(user_query: str, retrieved_docs: list[str]) -> str:
        """
        Constructs a safe prompt context with clear delimiters.
        """
        docs_text = "\n\n".join([
            f"[DOC_START]\n{ContentSanitizer.sanitize(doc)}\n[DOC_END]" 
            for doc in retrieved_docs
        ])
        
        # Explicit formatting to separate DATA from INSTRUCTIONS
        return f"""
SYSTEM INSTRUCTIONS (IMMUTABLE):
You are a helpful educational assistant. Answer based on the provided documents.

RETRIEVED DATA (READ ONLY):
{docs_text}

USER QUERY:
{user_query}
"""
