"""
Thin facade over the scanner's Gemini stack for validation modules.

Uses the same API key, models, and JSON extraction as llm_layer.
"""

from __future__ import annotations

from typing import Any, Optional


class LLMClient:
    """
    JSON completion helper for file context, finding validation, and gap validation.
    """

    def complete_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        quality: bool = False,
        layer: Optional[str] = None,
    ) -> Any:
        """
        Call Gemini and parse JSON from the response (dict or list).

        :param quality: if True, prefer a heavier model tier (layer3).
        :param layer: override tier key from LLM_TIERS (e.g. \"layer1\" for large file context).
        """
        # Lazy import avoids circular imports with llm_layer
        from dpdp_scanner.llm_layer import (
            GEMINI_API_KEY,
            _call_llm_raw,
            _extract_json,
            genai,
        )

        if not GEMINI_API_KEY or genai is None:
            return None

        lyr = layer or ("layer3" if quality else "layer2")
        raw = _call_llm_raw(system_prompt, user_prompt, layer=lyr)
        if not raw:
            return None
        try:
            parsed = _extract_json(raw)
        except Exception:
            return None
        return parsed
