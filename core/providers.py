"""Provider adapters — normalize Valk's internal OpenAI-compat format to each provider's API."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


# ── Base ─────────────────────────────────────────────────────────────────────

class ProviderAdapter(ABC):
    """Translates between Valk's internal message format and provider-specific API formats.

    Every provider normalises its response back to an OpenAI-compat JSON body so
    all downstream code (ChatResponse.content, .usage, .model_field, etc.) works
    unchanged regardless of which provider is active.
    """

    name: str
    default_model: str

    @abstractmethod
    def format_request(
        self,
        messages: list[dict[str, str]],
        model: str | None,
        temperature: float,
        max_tokens: int,
        api_key: str | None,
        **extra: Any,
    ) -> tuple[str, dict[str, Any], dict[str, str]]:
        """Return (endpoint_path, request_payload, extra_per_request_headers)."""

    @abstractmethod
    def parse_response(
        self,
        status_code: int,
        raw: str,
        json_body: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Return a normalised OpenAI-compat json_body."""


# ── OpenAI-compatible (default, passthrough) ─────────────────────────────────

class OpenAIAdapter(ProviderAdapter):
    """Default adapter — OpenAI-compatible endpoints (LM Studio, Ollama, vLLM, api.openai.com)."""

    name = "openai"
    default_model = ""  # determined at runtime from /v1/models

    def format_request(self, messages, model, temperature, max_tokens, api_key, **extra):
        payload: dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            **extra,
        }
        if model:
            payload["model"] = model
        return "/v1/chat/completions", payload, {}

    def parse_response(self, status_code, raw, json_body, headers):
        return json_body  # already native format


# ── Anthropic ────────────────────────────────────────────────────────────────

class AnthropicAdapter(ProviderAdapter):
    """Anthropic Messages API — api.anthropic.com/v1/messages.

    Auth: x-api-key header (NOT Authorization: Bearer).
    System prompt: top-level field, not inside the messages array.
    Response format: content[].text instead of choices[].message.content.
    """

    name = "anthropic"
    default_model = "claude-opus-4-5"

    def format_request(self, messages, model, temperature, max_tokens, api_key, **extra):
        # Anthropic puts the system prompt as a top-level field
        system: str | None = None
        filtered: list[dict[str, str]] = []
        for msg in messages:
            if msg["role"] == "system":
                system = msg["content"]
            else:
                filtered.append({"role": msg["role"], "content": msg["content"]})

        # Anthropic requires at least one message
        if not filtered:
            filtered = [{"role": "user", "content": "ping"}]

        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "max_tokens": max_tokens,
            "messages": filtered,
        }
        if system:
            payload["system"] = system
        if temperature:
            payload["temperature"] = min(temperature, 1.0)

        # Auth via x-api-key; anthropic-version is required
        extra_headers: dict[str, str] = {"anthropic-version": "2023-06-01"}
        if api_key:
            extra_headers["x-api-key"] = api_key

        # Drop OpenAI/Qwen-specific kwargs that Anthropic doesn't understand
        # (e.g. enable_thinking=False, model-hint params)
        return "/v1/messages", payload, extra_headers

    def parse_response(self, status_code, raw, json_body, headers):
        if status_code != 200:
            return json_body
        content_blocks = json_body.get("content", [])
        text = "".join(
            block.get("text", "") for block in content_blocks if block.get("type") == "text"
        )
        usage = json_body.get("usage", {})
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)
        return {
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": json_body.get("stop_reason", "stop"),
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "model": json_body.get("model", self.default_model),
            "id": json_body.get("id", ""),
        }


# ── Google Gemini ─────────────────────────────────────────────────────────────

class GeminiAdapter(ProviderAdapter):
    """Google Gemini REST API — generativelanguage.googleapis.com.

    Auth: ?key=API_KEY query parameter (not a header).
    Role names: "user" / "model" (not "assistant").
    System prompt: systemInstruction top-level field.
    Request: contents[].parts[].text instead of messages[].content.
    Response: candidates[].content.parts[].text.
    """

    name = "gemini"
    default_model = "gemini-2.0-flash"

    def format_request(self, messages, model, temperature, max_tokens, api_key, **extra):
        effective_model = model or self.default_model
        endpoint = f"/v1beta/models/{effective_model}:generateContent"
        if api_key:
            endpoint += f"?key={api_key}"

        system_instruction: dict[str, Any] | None = None
        contents: list[dict[str, Any]] = []
        for msg in messages:
            if msg["role"] == "system":
                system_instruction = {"parts": [{"text": msg["content"]}]}
            else:
                # Gemini uses "model" instead of "assistant"
                role = "model" if msg["role"] == "assistant" else "user"
                contents.append({"role": role, "parts": [{"text": msg["content"]}]})

        if not contents:
            contents = [{"role": "user", "parts": [{"text": "ping"}]}]

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction

        return endpoint, payload, {}

    def parse_response(self, status_code, raw, json_body, headers):
        if status_code != 200:
            return json_body
        candidates = json_body.get("candidates", [])
        text = ""
        finish_reason = "stop"
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)
            raw_finish = candidates[0].get("finishReason", "STOP")
            finish_reason = "stop" if raw_finish in ("STOP", "stop") else raw_finish.lower()

        usage = json_body.get("usageMetadata", {})
        prompt_tokens = usage.get("promptTokenCount", 0)
        completion_tokens = usage.get("candidatesTokenCount", 0)
        return {
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": finish_reason,
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "model": json_body.get("modelVersion", self.default_model),
        }


# ── Registry ──────────────────────────────────────────────────────────────────

_ADAPTERS: dict[str, type[ProviderAdapter]] = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
    "gemini": GeminiAdapter,
}

SUPPORTED_PROVIDERS = list(_ADAPTERS.keys())


def get_adapter(name: str) -> ProviderAdapter:
    cls = _ADAPTERS.get(name.lower())
    if cls is None:
        raise ValueError(
            f"Unknown provider {name!r}. Supported: {', '.join(SUPPORTED_PROVIDERS)}"
        )
    return cls()


# ── URL-based auto-detection ──────────────────────────────────────────────────

# Web UI targets that require browser automation (not yet implemented)
_BROWSER_ONLY_PATTERNS = (
    "chat.openai.com",
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "bard.google.com",
    "copilot.microsoft.com",
    "copilot.cloud.microsoft",
    "you.com",
    "poe.com",
    "character.ai",
)

_BROWSER_SETUP_HINT = (
    "Browser-mode targets require Playwright automation.\n"
    "  Install:  pip install playwright && playwright install chromium\n"
    "  Usage:    python valk.py scan <URL> --browser\n"
    "  Note:     You must be logged in — export your session cookies first.\n\n"
    "For authorized API-level testing use the official API endpoints instead:\n"
    "  OpenAI:   python valk.py scan https://api.openai.com --provider openai --api-key sk-...\n"
    "  Anthropic: python valk.py scan https://api.anthropic.com --provider anthropic --api-key sk-ant-...\n"
    "  Gemini:   python valk.py scan https://generativelanguage.googleapis.com --provider gemini --api-key AIza..."
)


def detect_provider(url: str) -> tuple[str, bool]:
    """Infer the API provider from the target URL.

    Returns (provider_name, is_browser_only).
    is_browser_only=True means the URL is a consumer web UI — no public REST API.
    The caller should print BROWSER_SETUP_HINT and abort.
    """
    u = url.lower()

    for pattern in _BROWSER_ONLY_PATTERNS:
        if pattern in u:
            return "browser", True

    if "anthropic.com" in u:
        return "anthropic", False
    if "googleapis.com" in u or "generativelanguage" in u:
        return "gemini", False
    if "openai.com" in u:
        return "openai", False

    # Default: assume OpenAI-compatible (self-hosted, LM Studio, Ollama, etc.)
    return "openai", False
