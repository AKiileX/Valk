"""Endpoint discovery — probes common LLM API paths to find live endpoints."""

from __future__ import annotations

from core.models import Finding, Phase, ScanContext
from modules.base import BaseModule


class EndpointDiscovery(BaseModule):
    name = "endpoint-discovery"
    description = "Discover live LLM API endpoints"
    phase = Phase.RECON
    always_run = True

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        data = self.load_payloads("endpoints.yaml")
        paths = data.get("endpoints", [])
        chat_probe = data.get("chat_probe", {})

        # Step 1: Discover available models so we can include model field in probes
        detected_model = await self._discover_model()
        if detected_model:
            self.session.default_model = detected_model
            self.log.info(self.name, f"auto-detected model: {detected_model}")

        self.log.info(self.name, f"probing {len(paths)} endpoint paths...")

        live_endpoints = []

        for entry in paths:
            path = entry["path"]
            method = entry.get("method", "POST").upper()

            try:
                if method == "GET":
                    resp = await self.session.get(path, timeout=8.0)
                else:
                    # Send a minimal payload — chat endpoint needs messages + model
                    probe_body = chat_probe.get("body", {"messages": [{"role": "user", "content": "hi"}]})
                    if self.session.default_model:
                        probe_body = {**probe_body, "model": self.session.default_model}
                    resp = await self.session.post(path, json=probe_body, timeout=8.0)

                status = resp.status_code

                # Validate: must be non-error AND have a valid response body
                if status not in (404, 502, 503):
                    if status >= 400:
                        self.log.debug(self.name, f"{method} {path} → {status} (rejected: probe format mismatch)")
                        continue
                    is_valid = self._validate_response_body(resp, path)
                    if not is_valid:
                        reason = self._skip_reason(resp, path)
                        self.log.debug(self.name, f"{method} {path} → {status} (skipped: {reason})")
                        continue

                    from core.models import EndpointInfo
                    is_chat = "chat" in path
                    is_completions = "completions" in path and "chat" not in path

                    ep = EndpointInfo(
                        path=path,
                        method=method,
                        status_code=status,
                        is_chat=is_chat,
                        is_completions=is_completions,
                        response_sample=resp.text[:500],
                    )
                    self.ctx.endpoints.append(ep)
                    live_endpoints.append(ep)

                    # Set primary chat endpoint (prefer first 200 OK chat endpoint)
                    if is_chat and status == 200 and not self.ctx.chat_endpoint:
                        self.ctx.chat_endpoint = path
                        self.log.success(self.name, f"chat endpoint confirmed: {path}")

                    if is_completions and status == 200 and not self.ctx.completions_endpoint:
                        self.ctx.completions_endpoint = path

                    self.log.debug(self.name, f"{method} {path} → {status}")

            except Exception as e:
                self.log.debug(self.name, f"{method} {path} → error: {e}")

        self.log.info(self.name, f"found {len(live_endpoints)} live endpoint(s)")

        # If no chat endpoint found, try the default
        if not self.ctx.chat_endpoint:
            self.log.warning("no chat endpoint discovered — using default /v1/chat/completions", module=self.name)
            self.ctx.chat_endpoint = "/v1/chat/completions"

        if live_endpoints:
            ep_list = ", ".join(f"{e.path} ({e.status_code})" for e in live_endpoints)
            findings.append(self.make_finding(
                title="Live API endpoints discovered",
                description=f"Found {len(live_endpoints)} endpoints: {ep_list}",
                severity="info",
                score=0.0,
                detection_logic="HTTP status code != 404/502/503",
            ))

        # Flag endpoints that return 200 without auth
        unauthed = [e for e in live_endpoints if e.status_code == 200]
        if unauthed and not self.session.config.api_key:
            findings.append(self.make_finding(
                title="Unauthenticated API access",
                description=f"{len(unauthed)} endpoint(s) respond 200 without an API key",
                severity="high",
                score=0.85,
                detection_logic="200 OK with no Authorization header",
                owasp=["LLM06"],
                remediation="Enable authentication on all LLM API endpoints.",
            ))

        # Flag undocumented API versions (v2, v3)
        versioned = [e for e in live_endpoints if any(v in e.path for v in ["/v2/", "/v3/"])]
        if versioned:
            paths_str = ", ".join(e.path for e in versioned)
            findings.append(self.make_finding(
                title="Undocumented API versions found",
                description=(
                    f"Non-standard API versions responded: {paths_str}. "
                    f"Alternate versions may have different security controls or bypass rate limits."
                ),
                severity="medium",
                score=0.60,
                detection_logic="v2/v3 versioned endpoints returned non-404 responses",
                owasp=["LLM06"],
                remediation="Disable or restrict access to non-production API versions.",
                metadata={"confidence": "probable"},
            ))

        # Flag internal/debug/admin/config endpoints
        sensitive = [
            e for e in live_endpoints
            if any(k in e.path for k in ["/debug", "/internal", "/admin", "/config", "/tokenize", "/detokenize"])
        ]
        if sensitive:
            paths_str = ", ".join(e.path for e in sensitive)
            sev = "critical" if any("/admin" in e.path for e in sensitive) else "high"
            findings.append(self.make_finding(
                title="Sensitive internal endpoints exposed",
                description=(
                    f"Internal/debug endpoints found: {paths_str}. "
                    f"These may expose configuration, tokenizer internals, or admin controls."
                ),
                severity=sev,
                score=0.90 if sev == "critical" else 0.75,
                detection_logic="Internal/debug/admin paths returned non-404 responses",
                owasp=["LLM06"],
                remediation=(
                    "Block access to internal, debug, admin, config, and tokenizer "
                    "endpoints from external networks. Use network segmentation or authentication."
                ),
                metadata={"confidence": "verified"},
            ))

        return findings

    async def _discover_model(self) -> str | None:
        """Try to get the first available model name from known model-list endpoints."""
        model_paths = ["/v1/models", "/models", "/api/tags"]
        for path in model_paths:
            try:
                resp = await self.session.get(path)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                # OpenAI-compatible format
                if "data" in data and data["data"]:
                    return data["data"][0].get("id") or data["data"][0].get("name")
                # Ollama format
                if "models" in data and data["models"]:
                    return data["models"][0].get("name")
            except Exception:
                continue
        return None

    def _skip_reason(self, resp, path: str) -> str:
        """Return a human-readable reason why a 2xx response was rejected."""
        try:
            data = resp.json()
        except Exception:
            return "non-JSON response"
        if "chat" in path or ("completions" in path and "embedding" not in path):
            return "missing 'choices[]'"
        if "model" in path:
            return "missing 'data[]' or 'models[]'"
        if "embedding" in path:
            return "missing 'data[]'"
        return "no recognized LLM schema"

    def _validate_response_body(self, resp, path: str) -> bool:
        """Check if the response body matches a known LLM API schema.
        Returns True for valid endpoints, False for false positives."""
        if resp.status_code >= 400:
            return False

        try:
            data = resp.json()
        except Exception:
            # Non-JSON 200 → not a valid LLM endpoint
            return False

        # Chat/completions endpoints should have choices[]
        if "chat" in path or ("completions" in path and "embedding" not in path):
            if isinstance(data, dict) and "choices" in data and isinstance(data["choices"], list):
                return True
            return False

        # Model listing endpoints should have data[] or models[]
        if "model" in path:
            if isinstance(data, dict):
                if "data" in data and isinstance(data["data"], list):
                    return True
                if "models" in data and isinstance(data["models"], list):
                    return True
            return False

        # Embedding endpoints should have data[]
        if "embedding" in path:
            if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
                return True
            return False

        # For other paths, accept any valid JSON with at least one field
        return isinstance(data, dict) and len(data) > 0
