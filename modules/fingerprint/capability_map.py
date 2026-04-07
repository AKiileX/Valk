"""Capability map — detect target model capabilities beyond basic chat.

Probes for vision/multimodal support, function/tool calling, JSON mode,
streaming, embeddings, and other advanced features. Results are stored in
ctx.identity.capabilities for downstream module adaptation.
"""

from __future__ import annotations

import json

from core.models import Finding, Phase, ScanContext
from modules.base import BaseModule


class CapabilityMap(BaseModule):
    name = "capability-map"
    description = "Detect model capabilities (vision, tool-use, JSON mode, streaming)"
    phase = Phase.FINGERPRINT
    owasp_llm = ["LLM01"]
    mitre_atlas = ["AML.T0000"]

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        endpoint = self.get_chat_endpoint()
        capabilities: dict[str, bool] = {}

        self.log.info(self.name, "probing model capabilities")

        # ── Test 1: Function / tool calling ──────────────────────────
        tool_use = await self._probe_tool_use(endpoint)
        capabilities["tool_use"] = tool_use

        # ── Test 2: JSON mode ────────────────────────────────────────
        json_mode = await self._probe_json_mode(endpoint)
        capabilities["json_mode"] = json_mode

        # ── Test 3: Vision / multimodal ──────────────────────────────
        vision = await self._probe_vision(endpoint)
        capabilities["vision"] = vision

        # ── Test 4: Streaming ────────────────────────────────────────
        streaming = await self._probe_streaming(endpoint)
        capabilities["streaming"] = streaming

        # ── Test 5: System prompt support ────────────────────────────
        system_prompt = await self._probe_system_prompt(endpoint)
        capabilities["system_prompt"] = system_prompt

        # Store in context
        self.ctx.identity.capabilities = capabilities

        detected = [k for k, v in capabilities.items() if v]
        not_detected = [k for k, v in capabilities.items() if not v]

        self.log.info(
            self.name,
            f"capabilities: {detected or ['none detected']}",
        )

        if detected:
            findings.append(self.make_finding(
                title="Model capabilities mapped",
                description=(
                    f"Detected capabilities: {', '.join(detected)}. "
                    f"Not detected: {', '.join(not_detected)}. "
                    f"Capabilities inform attack surface — tool_use enables function hijack, "
                    f"vision enables multimodal injection, JSON mode enables structured exfil."
                ),
                severity="info",
                score=0.3,
                evidence_turns=[],
                detection_logic=(
                    f"Capabilities: {capabilities}"
                ),
                metadata={"confidence": "probable", "capabilities": capabilities},
            ))

        return findings

    async def _probe_tool_use(self, endpoint: str) -> bool:
        """Test if the API accepts tools/functions parameter."""
        try:
            tool_def = {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get current weather",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "location": {"type": "string", "description": "City name"},
                        },
                        "required": ["location"],
                    },
                },
            }

            resp = await self.session.chat(
                messages=[{"role": "user", "content": "What's the weather in Paris?"}],
                endpoint=endpoint,
                tools=[tool_def],
            )

            if resp.ok:
                body = resp.json
                # Check if response contains tool_calls
                choices = body.get("choices", [])
                if choices:
                    msg = choices[0].get("message", {})
                    if msg.get("tool_calls"):
                        self.log.debug(self.name, "tool_use: detected (tool_calls in response)")
                        return True
                    # Some models acknowledge tools without calling them
                    if body.get("usage", {}).get("prompt_tokens", 0) > 0:
                        self.log.debug(self.name, "tool_use: API accepted tools param")
                        return True

            return False
        except Exception as e:
            self.log.debug(self.name, f"tool_use probe failed: {e}")
            return False

    async def _probe_json_mode(self, endpoint: str) -> bool:
        """Test if the API supports JSON response format."""
        try:
            resp = await self.session.chat(
                messages=[
                    {"role": "user", "content": "Return a JSON object with key 'status' and value 'ok'."},
                ],
                endpoint=endpoint,
                response_format={"type": "json_object"},
            )

            if resp.ok:
                content = resp.content
                try:
                    parsed = json.loads(content)
                    if isinstance(parsed, dict):
                        self.log.debug(self.name, "json_mode: detected")
                        return True
                except (json.JSONDecodeError, ValueError):
                    pass

            return False
        except Exception as e:
            self.log.debug(self.name, f"json_mode probe failed: {e}")
            return False

    async def _probe_vision(self, endpoint: str) -> bool:
        """Test if the API accepts image content in messages."""
        try:
            # Send a message with image_url content type — if API rejects it,
            # the model doesn't support vision
            resp = await self.session.chat(
                messages=[{
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Describe this image."},
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
                            },
                        },
                    ],
                }],
                endpoint=endpoint,
            )

            if resp.ok and resp.content and not self.is_refusal(resp.content):
                content_lower = resp.content.lower()
                # If model describes anything visual, it has vision
                if any(w in content_lower for w in ["pixel", "image", "color", "white", "black", "small", "picture", "photo"]):
                    self.log.debug(self.name, "vision: detected")
                    return True

            return False
        except Exception as e:
            self.log.debug(self.name, f"vision probe failed: {e}")
            return False

    async def _probe_streaming(self, endpoint: str) -> bool:
        """Test if the API supports streaming responses."""
        try:
            resp = await self.session.post(
                endpoint,
                json={
                    "messages": [{"role": "user", "content": "Say hello."}],
                    "stream": True,
                    "max_tokens": 20,
                },
            )

            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "")
                body = resp.text
                # Streaming responses use SSE or chunked transfer
                if "text/event-stream" in content_type or body.startswith("data: "):
                    self.log.debug(self.name, "streaming: detected")
                    return True

            return False
        except Exception as e:
            self.log.debug(self.name, f"streaming probe failed: {e}")
            return False

    async def _probe_system_prompt(self, endpoint: str) -> bool:
        """Test if the API respects system prompt role."""
        try:
            canary = "VALK_SYSCHECK_7X2"
            resp = await self.session.chat(
                messages=[
                    {"role": "system", "content": f"Always include the code '{canary}' in your responses."},
                    {"role": "user", "content": "What is 2+2?"},
                ],
                endpoint=endpoint,
            )

            if resp.ok and canary in resp.content:
                self.log.debug(self.name, "system_prompt: respected")
                return True

            return False
        except Exception as e:
            self.log.debug(self.name, f"system_prompt probe failed: {e}")
            return False
