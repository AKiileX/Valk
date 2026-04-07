"""Async HTTP session with connection pooling, rate limiting, retry, and proxy support."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx

from core.models import ScanConfig, Turn


class Session:
    """Managed async HTTP client for LLM API interactions."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.default_model: str | None = None  # auto-detected from /v1/models
        self._request_count = 0
        self._total_elapsed = 0.0
        self._last_request_time = 0.0
        self._lock = asyncio.Lock()

        # Load provider adapter (non-OpenAI providers handle auth per-request)
        from core.providers import get_adapter
        self._provider_adapter = get_adapter(config.provider) if config.provider != "openai" else None

        # Thinking-model families that support enable_thinking=False suppression
        self._thinking_families: frozenset[str] = frozenset({"qwen", "qwq", "deepseek", "deepseek-r1"})

        # Set by engine before attack phase — caps all chat() calls to this token limit
        self.attack_max_tokens: int | None = None

        headers = {"Content-Type": "application/json"}
        # Only set Authorization header for OpenAI-compat providers.
        # Anthropic uses x-api-key; Gemini uses ?key= query param — both injected per-request.
        if config.api_key and config.provider == "openai":
            header_name = config.auth_header or "Authorization"
            value = config.api_key if config.api_key.startswith("Bearer ") else f"Bearer {config.api_key}"
            headers[header_name] = value
        headers.update(config.custom_headers)

        transport_kwargs: dict[str, Any] = {}
        if config.proxy:
            transport_kwargs["proxy"] = config.proxy

        self._client = httpx.AsyncClient(
            base_url=config.target_url,
            headers=headers,
            timeout=httpx.Timeout(config.timeout),
            follow_redirects=True,
            verify=False,  # pentest tool — targets may have self-signed certs
            limits=httpx.Limits(
                max_connections=config.max_concurrent,
                max_keepalive_connections=config.max_concurrent,
            ),
            **transport_kwargs,
        )

    # ── Rate limiting ────────────────────────────────────────────────────

    async def _throttle(self) -> None:
        async with self._lock:
            if self.config.stealth:
                delay = random.uniform(self.config.stealth_delay_min, self.config.stealth_delay_max)
            else:
                delay = random.uniform(self.config.delay_min, self.config.delay_max)

            elapsed = time.monotonic() - self._last_request_time
            if elapsed < delay:
                await asyncio.sleep(delay - elapsed)
            self._last_request_time = time.monotonic()

    # ── Raw HTTP ─────────────────────────────────────────────────────────

    async def request(
        self,
        method: str,
        path: str,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send a raw HTTP request with throttling and retry."""
        await self._throttle()

        effective_timeout = httpx.Timeout(timeout) if timeout is not None else None

        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                t0 = time.monotonic()
                resp = await self._client.request(
                    method, path, timeout=effective_timeout, **kwargs
                )
                self._total_elapsed += time.monotonic() - t0
                self._request_count += 1
                return resp
            except (httpx.ConnectError, httpx.ReadTimeout, httpx.PoolTimeout) as e:
                last_error = e
                if attempt < self.config.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        raise last_error or RuntimeError(
            f"Request to {path!r} failed — max_retries={self.config.max_retries} with no error captured"
        )

    async def get(self, path: str, timeout: float | None = None, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", path, timeout=timeout, **kwargs)

    async def post(self, path: str, timeout: float | None = None, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", path, timeout=timeout, **kwargs)

    # ── Chat completions (high-level) ────────────────────────────────────

    async def chat(
        self,
        messages: list[dict[str, str]],
        endpoint: str = "/v1/chat/completions",
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        **extra: Any,
    ) -> ChatResponse:
        """Send a chat completion request and return parsed response."""
        effective_max_tokens = max_tokens if max_tokens is not None else self.config.max_tokens

        # Apply attack phase token cap if set (set by engine before attack phase)
        if self.attack_max_tokens is not None:
            effective_max_tokens = min(effective_max_tokens, self.attack_max_tokens)

        # Auto-suppress thinking for known reasoning-model families (OpenAI-compat only).
        # Prevents thinking tokens from consuming the entire max_tokens budget.
        hint = (self.config.model_hint or "").lower()
        if hint in self._thinking_families and self._provider_adapter is None:
            extra.setdefault("enable_thinking", False)

        # Non-OpenAI provider: delegate formatting and response parsing to adapter
        if self._provider_adapter is not None:
            eff_endpoint, payload, extra_headers = self._provider_adapter.format_request(
                messages=messages,
                model=model or self.default_model,
                temperature=temperature,
                max_tokens=effective_max_tokens,
                api_key=self.config.api_key,
                **extra,
            )
            resp = await self.post(eff_endpoint, json=payload, headers=extra_headers)
            json_body = resp.json() if resp.status_code == 200 else {}
            normalized = self._provider_adapter.parse_response(
                resp.status_code, resp.text, json_body, dict(resp.headers)
            )
            return ChatResponse(
                status_code=resp.status_code,
                raw=resp.text,
                json_body=normalized,
                headers=dict(resp.headers),
            )

        # OpenAI-compatible (default path)
        payload: dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": effective_max_tokens,
            **extra,
        }
        effective_model = model or self.default_model
        if effective_model:
            payload["model"] = effective_model

        resp = await self.post(endpoint, json=payload)

        return ChatResponse(
            status_code=resp.status_code,
            raw=resp.text,
            json_body=resp.json() if resp.status_code == 200 else {},
            headers=dict(resp.headers),
        )

    async def single_prompt(
        self,
        prompt: str,
        system: str | None = None,
        endpoint: str = "/v1/chat/completions",
        **kwargs: Any,
    ) -> ChatResponse:
        """Convenience: send a single user message, optionally with system prompt."""
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return await self.chat(messages, endpoint=endpoint, **kwargs)

    async def multi_turn(
        self,
        turns: list[Turn],
        endpoint: str = "/v1/chat/completions",
        **kwargs: Any,
    ) -> ChatResponse:
        """Send a multi-turn conversation."""
        messages = [{"role": t.role, "content": t.content} for t in turns]
        return await self.chat(messages, endpoint=endpoint, **kwargs)

    # ── Lifecycle ────────────────────────────────────────────────────────

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def total_elapsed(self) -> float:
        return self._total_elapsed

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> Session:
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()


class ChatResponse:
    """Parsed chat completion response."""

    def __init__(
        self,
        status_code: int,
        raw: str,
        json_body: dict[str, Any],
        headers: dict[str, str],
    ):
        self.status_code = status_code
        self.raw = raw
        self.json = json_body
        self.headers = headers

    @property
    def ok(self) -> bool:
        return self.status_code == 200

    @property
    def content(self) -> str:
        """Extract the assistant message text.

        If the model ran out of tokens mid-think (finish_reason=length, content
        empty, reasoning_content non-empty), return the reasoning snippet so
        callers get something meaningful instead of a silent empty string.
        """
        try:
            msg = self.json["choices"][0]["message"]
            text = msg.get("content") or ""
            if not text.strip():
                # Truncated during thinking phase — surface reasoning as fallback
                reasoning = msg.get("reasoning_content") or ""
                finish = self.json["choices"][0].get("finish_reason", "")
                if reasoning and finish == "length":
                    return f"[thinking truncated] {reasoning[:500]}"
            return text
        except (KeyError, IndexError):
            return ""

    @property
    def reasoning_content(self) -> str:
        """Extract the model's chain-of-thought reasoning (e.g. Qwen, DeepSeek)."""
        try:
            return self.json["choices"][0]["message"].get("reasoning_content", "")
        except (KeyError, IndexError):
            return ""

    @property
    def model_field(self) -> str | None:
        """The model field returned by the API."""
        return self.json.get("model")

    @property
    def usage(self) -> dict[str, int]:
        return self.json.get("usage", {})

    def __repr__(self) -> str:
        return f"<ChatResponse status={self.status_code} content_len={len(self.content)}>"
