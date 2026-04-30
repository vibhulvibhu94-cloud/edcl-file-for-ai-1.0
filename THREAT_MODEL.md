# Threat Model: External Deterministic Control Layer V3

**Date:** 2026-01-12  
**Status:** DRAFT (V3 Enterprise Upgrade)  
**Scope:** Output Safety & Control Layer

---

## 1. Description

The External Deterministic Control Layer (V3) is a post-generation / pre-delivery verification system designed to intercept, analyze, and optionally sanitize or reject AI outputs before they reach the end user. It assumes the underlying LLM is non-deterministic and potentially compromised or hallucinating.

## 2. Protected Assets

| Asset | Description | Priority |
| :--- | :--- | :--- |
| **User Safety** | Physical and psychological well-being of the student/user. | CRITICAL |
| **Output Integrity** | Assurance that answers are factually grounded and aligned with educational goals. | HIGH |
| **System Rules** | Immutable instructions (e.g., "Do not reveal system prompt") that must not be overridden. | HIGH |
| **Enterprise Reputation** | Prevention of PR disasters via hate speech, bias, or illegal content. | HIGH |

## 3. Attacker Profile & Capabilities

We assume a "Grey Box" attacker model where the user has access to the public API/interface but not the internal checking weights or state memory.

| Attacker Type | Motivation | Capabilities |
| :--- | :--- | :--- |
| **Curious Student** | Exploration, "jailbreaking" for fun. | Direct prompt injection, "DAN" mode, role-play. |
| **Malicious Actor** | Reputational damage, extraction of IP. | Multi-turn poisoning, encoding attacks (Base64), automated separate-channel attacks. |
| **Indirect Injector** | Compromise via data sources (RAG). | Embedding instructions in retrieved documents (e.g., "Ignore previous rules"). |

## 4. Threat Indicators & Attack Surfaces

### 4.1. Direct Prompt Injection

**Attack:** Users attempting to override system instructions via direct commands.
**Defense:** `IntentDetector` (Layer 1) + Immutable System Context.

### 4.2. Indirect Prompt Injection (RAG)

**Attack:** Malicious instructions hidden in retrieved study materials or websites.
**Defense:** Strict separation of data/instruction channels. Retrieved content is treated as untrusted `string` data, sanitized before context insertion.

### 4.3. Multi-Turn Poisoning

**Attack:** Slowly escalating trust or "grooming" the model over 10+ turns to bypass stateless filters.
**Defense:** `SuspicionScore` (Stateful). Risk accumulates. If `Suspicion > Threshold`, the session is locked or escalated.

### 4.4. Encoding & Obfuscation

**Attack:** Using Base64, Rot13, or Unicode homoglyphs to bypass keyword filters.
**Defense:** Normalization pipeline in Layer 1 (Detection).

## 5. Security Boundaries (Scope)

### Fully Protected (In Scope)

* **Output Content:** All text emitted by the LLM is scanned.
* **Prompt Context:** User queries are scanned for intent.
* **Session State:** Multi-turn memory tracks aggregate risk.

### Partially Protected (Best Effort)

* **Implicit Bias:** Subtle societal biases are hard to detect deterministically.
* **Advanced Steganography:** Extremely sophisticated hidden messages may bypass text filters.

### Out of Scope

* **Model Internal Weights:** This layer does not retrain the model.
* **Server Intrusion:** Standard OS/Network security is assumed.
* **user's Hardware:** We cannot prevent screenshots or external recording.

## 6. Non-Goals

EDCL V3 does **NOT** attempt to:

* Detect factual correctness (Truthfulness is model-dependent).
* Replace model-side alignment (RLHF).
* Prevent misuse outside the AI interface (e.g., user acting on information obtained elsewhere).
* Guarantee regulatory compliance on its own (Requires human oversight).

## 7. Failure Modes (Fail-Safe)

If the Control Layer encounters an internal error, timeout, or ambiguity:

1. **DEFAULT:** `REFUSE`.
2. **FALLBACK:** Return a pre-canned "Safety Error" message.
3. **NEVER:** Pass the raw LLM output through.

---
*This threat model is auditable and designed for compliance reviews.*
