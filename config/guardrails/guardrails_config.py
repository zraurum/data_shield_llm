"""
Guardrails AI server configuration — DataShield LLM Service.

Guards registered here (all require no Hub token):

  prompt-injection-guard    pre_call   Fast regex prompt injection detection
  ollama-prompt-validator   pre_call   LLaMA Guard deep semantic prompt check
  ollama-response-validator post_call  LLaMA Guard deep semantic response scan

The "ollama-*" names are kept for backward compatibility with the
existing LiteLLM config; the underlying backend for LLaMA Guard is now
selectable between OpenRouter (default for demo / CPU hosts) and Ollama
via LLAMA_GUARD_PROVIDER. See _call_llama_guard() below.

The server exposes:
  POST /guards/{guard_name}/validate   { "llmOutput": "..." }
"""

import json
import logging
import os
import re
from typing import Any, Dict, Optional

import httpx

from guardrails import Guard
from guardrails.validator_base import (
    FailResult,
    PassResult,
    ValidationResult,
    Validator,
    register_validator,
)

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# LLaMA Guard backend selection
#
# Two supported providers — chosen via LLAMA_GUARD_PROVIDER:
#   "openrouter" — call meta-llama/llama-guard-3-8b via OpenRouter's
#                  OpenAI-compatible API. ~200 ms, no GPU required. Default
#                  for demo / CPU-only hosts.
#   "ollama"     — call a local llama-guard model via Ollama. Fully offline
#                  but ~2–5 s on CPU; ~200 ms with NVIDIA GPU.
#
# Auto-fallback: if LLAMA_GUARD_PROVIDER is unset, we pick "openrouter"
# when OPENROUTER_API_KEY is present, otherwise "ollama".
# ────────────────────────────────────────────────────────────────────────────

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_VALIDATION_MODEL = os.environ.get("OLLAMA_VALIDATION_MODEL", "llama-guard3:1b")

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip()
OPENROUTER_BASE_URL = os.environ.get(
    "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
).rstrip("/")
LLAMA_GUARD_OPENROUTER_MODEL = os.environ.get(
    "LLAMA_GUARD_OPENROUTER_MODEL", "meta-llama/llama-guard-3-8b"
)

_provider_env = os.environ.get("LLAMA_GUARD_PROVIDER", "").strip().lower()
if _provider_env in {"openrouter", "ollama"}:
    LLAMA_GUARD_PROVIDER = _provider_env
elif OPENROUTER_API_KEY:
    LLAMA_GUARD_PROVIDER = "openrouter"
else:
    LLAMA_GUARD_PROVIDER = "ollama"

logger.info(
    "LLaMA Guard backend: %s (openrouter_model=%s, ollama_model=%s)",
    LLAMA_GUARD_PROVIDER,
    LLAMA_GUARD_OPENROUTER_MODEL,
    OLLAMA_VALIDATION_MODEL,
)


# ────────────────────────────────────────────────────────────────────────────
# Prompt Injection Patterns
# Grouped by attack category for easier auditing / tuning.
# ────────────────────────────────────────────────────────────────────────────

_INJECTION_PATTERNS: Dict[str, str] = {
    # Instruction override / jailbreak
    "instruction_override": (
        r"(?:ignore|disregard|forget|override|bypass|stop\s+following)"
        r"\s+(?:all\s+)?(?:previous|prior|above|your|the)?"
        r"\s*(?:instructions?|rules?|guidelines?|constraints?|system\s+prompt|"
        r"safety|restrictions?|content\s+policy|training)"
    ),

    # DAN / unconstrained persona jailbreak
    "dan_jailbreak": (
        r"(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are|to\s+be)|"
        r"simulate|enter|enable)\s+(?:a\s+)?"
        r"(?:DAN|developer\s+mode|unrestricted|jailbroken|evil|malicious|"
        r"unfiltered|uncensored|hacked|freed|different)\s*(?:AI|model|version|mode)?"
    ),

    # System prompt extraction
    "system_prompt_extraction": (
        r"(?:repeat|output|reveal|show|print|display|tell\s+me|what\s+(?:is|are))\s+"
        r"(?:everything|verbatim|exactly|all\s+of)?\s*"
        r"(?:above|your|the)?\s*"
        r"(?:system\s+prompt|initial\s+instructions?|pre-?prompt|developer\s+message|"
        r"hidden\s+instructions?|configuration\s+prompt|rules\s+you\s+(?:follow|were\s+given))"
    ),

    # Role hijacking
    "role_hijacking": (
        r"(?:your\s+new\s+role|switch\s+to|forget\s+your\s+role|"
        r"you\s+no\s+longer\s+(?:are|follow)|take\s+on\s+a\s+new\s+persona)\s+"
        r"(?:is|to\s+be)?\s*(?:hacker|attacker|malicious|evil|adversarial)"
    ),

    # Encoded / obfuscated instructions
    "encoded_instructions": (
        r"(?:decode|translate|interpret)\s+(?:this|the\s+following)?\s*"
        r"(?:from\s+)?(?:base64|ROT13|hex|binary|morse)\s+"
        r"(?:and\s+)?(?:execute|follow|run|obey)\s+(?:the\s+)?instructions"
    ),

    # Indirect prompt injection (injected via retrieved content)
    "indirect_injection": (
        r"(?:attention|note|important|alert)\s*(?:to\s+)?(?:AI|assistant|LLM|model|bot)"
        r"[^.!?]{0,50}(?:ignore|disregard|override|new\s+instructions?)"
    ),

    # Classic variants
    "classic_variants": (
        r"(?:from\s+now\s+on|starting\s+now|for\s+the\s+rest\s+of\s+(?:this|our)\s+conversation)"
        r"\s+you\s+(?:will|must|shall|should)\s+"
        r"(?:ignore|answer\s+without|respond\s+without|bypass)"
    ),
}

_COMPILED = {
    name: re.compile(pattern, re.IGNORECASE | re.DOTALL)
    for name, pattern in _INJECTION_PATTERNS.items()
}


# ────────────────────────────────────────────────────────────────────────────
# Custom Validator
# ────────────────────────────────────────────────────────────────────────────

@register_validator(name="datashield/prompt-injection-detector", data_type="string")
class PromptInjectionDetector(Validator):
    """
    Regex-based prompt injection detector.
    No Hub token required — ships as part of DataShield.
    """

    def validate(self, value: Any, metadata: Optional[Dict] = None) -> ValidationResult:
        if not isinstance(value, str):
            return PassResult()

        for category, pattern in _COMPILED.items():
            match = pattern.search(value)
            if match:
                return FailResult(
                    error_message=(
                        f"Prompt injection detected (category: {category}). "
                        f"Request blocked for security."
                    ),
                    fix_value="[BLOCKED: Prompt injection attempt detected]",
                )

        return PassResult()


# ────────────────────────────────────────────────────────────────────────────
# Ollama LLaMA Guard Validator
#
# Calls llama-guard3:1b via Ollama to perform deep semantic safety analysis.
# Used for both prompt checking (pre_call) and response scanning (post_call).
#
# LLaMA Guard 3 is a Meta safety model trained specifically to classify
# content as safe/unsafe across 14 harm categories (S1–S14):
#   S1  Violent Crimes          S8  Weapons of Mass Destruction
#   S2  Non-Violent Crimes      S9  Hate Speech
#   S3  Sex Crimes              S10 Self-Harm
#   S4  Child Exploitation      S11 Sexual Content
#   S5  Defamation              S12 Elections
#   S6  Specialized Advice      S13 Code Interpreter Abuse  ← key for us
#   S7  Privacy                 S14 Prompt Injection        ← key for us
# ────────────────────────────────────────────────────────────────────────────

_LLAMA_GUARD_PROMPT_TEMPLATE = """<|begin_of_text|><|start_header_id|>user<|end_header_id|>

Task: Check if there is unsafe content in the message below according to our safety policy.

<BEGIN_MESSAGE>
{content}
<END_MESSAGE>

Provide your safety assessment for the message above:
- First line must read "safe" or "unsafe"
- If unsafe, a second line must include a comma-separated list of violated categories (e.g. S13,S14)

<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

# Categories we treat as blocking for code/prompt safety
_BLOCKING_CATEGORIES = {"S13", "S14"}  # Code Interpreter Abuse, Prompt Injection

# Additional categories that should block responses (vulnerability scan)
_RESPONSE_BLOCKING_CATEGORIES = {"S1", "S2", "S13", "S14"}


def _parse_llama_guard_output(result_text: str) -> tuple[bool, str]:
    """Parse the canonical LLaMA Guard reply into (is_safe, reason)."""
    text = (result_text or "").strip().lower()
    lines = text.splitlines() or [""]
    verdict = lines[0].strip()
    if verdict == "safe":
        return True, "safe"
    categories = lines[1].strip() if len(lines) > 1 else ""
    return False, f"unsafe: {categories}"


def _call_llama_guard_ollama(content: str) -> tuple[bool, str]:
    """Call llama-guard via local Ollama using the raw /api/generate endpoint."""
    prompt = _LLAMA_GUARD_PROMPT_TEMPLATE.format(content=content[:4000])
    response = httpx.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json={
            "model": OLLAMA_VALIDATION_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "num_predict": 64},
        },
        timeout=30.0,
    )
    response.raise_for_status()
    return _parse_llama_guard_output(response.json().get("response", "safe"))


def _call_llama_guard_openrouter(content: str) -> tuple[bool, str]:
    """
    Call llama-guard-3-8b via OpenRouter's OpenAI-compatible chat API.
    LLaMA Guard is a chat-tuned classifier — we just pass the content
    to be evaluated as a single user message; the model outputs
    "safe" or "unsafe\\nS1,S2,...".
    """
    if not OPENROUTER_API_KEY:
        raise RuntimeError(
            "LLAMA_GUARD_PROVIDER=openrouter but OPENROUTER_API_KEY is empty"
        )
    response = httpx.post(
        f"{OPENROUTER_BASE_URL}/chat/completions",
        headers={
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/datashield-llm",
            "X-Title": "DataShield LLM Guardrails",
        },
        json={
            "model": LLAMA_GUARD_OPENROUTER_MODEL,
            "messages": [{"role": "user", "content": content[:4000]}],
            "max_tokens": 64,
            "temperature": 0,
        },
        timeout=30.0,
    )
    response.raise_for_status()
    payload = response.json()
    try:
        message = payload["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"unexpected OpenRouter response: {payload!r}") from exc
    return _parse_llama_guard_output(message)


def _call_llama_guard(content: str) -> tuple[bool, str]:
    """
    Dispatch to the configured LLaMA Guard backend. Returns (is_safe, reason).
    Fail-open on any transport/parsing error so the service degrades gracefully
    when the upstream provider is unreachable (matches the risk policy
    described on slide 13 of the talk).
    """
    try:
        if LLAMA_GUARD_PROVIDER == "openrouter":
            return _call_llama_guard_openrouter(content)
        return _call_llama_guard_ollama(content)
    except httpx.ConnectError:
        target = OPENROUTER_BASE_URL if LLAMA_GUARD_PROVIDER == "openrouter" else OLLAMA_BASE_URL
        logger.warning(
            "LLaMA Guard backend %s unreachable at %s — failing open",
            LLAMA_GUARD_PROVIDER,
            target,
        )
        return True, f"{LLAMA_GUARD_PROVIDER}_unavailable"
    except Exception as exc:
        logger.warning(
            "LLaMA Guard (%s) call failed: %s — failing open",
            LLAMA_GUARD_PROVIDER,
            exc,
        )
        return True, f"error: {exc}"


@register_validator(name="datashield/ollama-prompt-safety", data_type="string")
class OllamaPromptSafety(Validator):
    """
    Uses LLaMA Guard 3 (via OpenRouter or local Ollama) to evaluate whether
    a user prompt is safe before it is forwarded to an external LLM provider.

    Blocks on harm categories: S13 (Code Interpreter Abuse), S14 (Prompt Injection).
    Fails open if the safety model backend is unavailable so the service keeps running.
    """

    def validate(self, value: Any, metadata: Optional[Dict] = None) -> ValidationResult:
        if not isinstance(value, str) or not value.strip():
            return PassResult()

        is_safe, reason = _call_llama_guard(value)
        if is_safe:
            return PassResult()

        categories = set(reason.replace("unsafe:", "").strip().split(","))
        categories = {c.strip() for c in categories}
        if categories & _BLOCKING_CATEGORIES:
            return FailResult(
                error_message=(
                    f"Prompt blocked by Ollama safety model ({reason}). "
                    "Request contains potentially unsafe content."
                ),
                fix_value="[BLOCKED: Unsafe prompt detected by local security model]",
            )
        return PassResult()


@register_validator(name="datashield/ollama-response-safety", data_type="string")
class OllamaResponseSafety(Validator):
    """
    Uses LLaMA Guard 3 (via OpenRouter or local Ollama) to scan the LLM
    response for vulnerabilities, harmful instructions, and malicious code
    intent before returning to Cursor.

    Blocks on harm categories: S1 (Violent Crimes), S2 (Non-Violent Crimes),
    S13 (Code Interpreter Abuse), S14 (Prompt Injection in response).
    Fails open if the safety model backend is unavailable.
    """

    def validate(self, value: Any, metadata: Optional[Dict] = None) -> ValidationResult:
        if not isinstance(value, str) or not value.strip():
            return PassResult()

        is_safe, reason = _call_llama_guard(value)
        if is_safe:
            return PassResult()

        categories = set(reason.replace("unsafe:", "").strip().split(","))
        categories = {c.strip() for c in categories}
        if categories & _RESPONSE_BLOCKING_CATEGORIES:
            return FailResult(
                error_message=(
                    f"LLM response blocked by Ollama safety model ({reason}). "
                    "Response contains potentially unsafe content."
                ),
                fix_value="[BLOCKED: Unsafe content detected in LLM response]",
            )
        return PassResult()


# ────────────────────────────────────────────────────────────────────────────
# Guard Registration
#
# Guard names must match guard_name in litellm config.yaml:
#   - LiteLLM calls: POST /guards/{guard_name}/validate
# ────────────────────────────────────────────────────────────────────────────

prompt_injection_guard = Guard(name="prompt-injection-guard").use(
    PromptInjectionDetector(on_fail="exception"),
    on="$",
)

ollama_prompt_guard = Guard(name="ollama-prompt-validator").use(
    OllamaPromptSafety(on_fail="exception"),
    on="$",
)

ollama_response_guard = Guard(name="ollama-response-validator").use(
    OllamaResponseSafety(on_fail="exception"),
    on="$",
)
