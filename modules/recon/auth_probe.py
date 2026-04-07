"""Auth probe — basic authentication and authorization enforcement checks.

Tests whether the target enforces authentication, checks for common
auth bypass patterns, and validates authorization boundaries.
"""

from __future__ import annotations

from core.models import Finding, Phase, ScanContext
from modules.base import BaseModule


class AuthProbe(BaseModule):
    name = "auth-probe"
    description = "Authentication and authorization enforcement checks"
    phase = Phase.RECON
    owasp_llm = ["LLM01"]
    mitre_atlas = ["AML.T0051"]

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        endpoint = self.ctx.chat_endpoint or "/v1/chat/completions"

        self.log.info(self.name, "probing authentication enforcement...")

        # Test 1: Unauthenticated access
        result = await self._test_no_auth(endpoint)
        if result:
            findings.append(result)

        # Test 2: Invalid API key
        result = await self._test_invalid_key(endpoint)
        if result:
            findings.append(result)

        # Test 3: Empty API key
        result = await self._test_empty_key(endpoint)
        if result:
            findings.append(result)

        # Test 4: Alternate endpoint access
        for alt_path in ["/v1/models", "/v1/embeddings", "/v1/completions"]:
            result = await self._test_endpoint_access(alt_path)
            if result:
                findings.append(result)

        # Test 5: Rate limit detection
        result = await self._test_rate_limit(endpoint)
        if result:
            findings.append(result)

        return findings

    async def _test_no_auth(self, endpoint: str) -> Finding | None:
        """Test if endpoint works without authentication."""
        try:
            # Send request without any auth header
            import httpx

            async with httpx.AsyncClient(
                base_url=self.session.config.target_url,
                timeout=httpx.Timeout(self.session.config.timeout),
                verify=False,
            ) as client:
                resp = await client.post(
                    endpoint,
                    json={
                        "messages": [{"role": "user", "content": "Hello"}],
                        "max_tokens": 10,
                    },
                    headers={"Content-Type": "application/json"},
                )

            if resp.status_code == 200:
                return self.make_finding(
                    title="No authentication required",
                    description=(
                        "The LLM endpoint accepts requests without any authentication. "
                        "Any client can interact with the model without credentials."
                    ),
                    severity="info",
                    score=0.3,
                    evidence_turns=[
                        {"role": "user", "content": "Hello (no auth header)"},
                        {"role": "assistant", "content": f"Status: {resp.status_code}"},
                    ],
                    detection_logic=f"POST {endpoint} without auth → {resp.status_code}",
                    remediation="Implement API key authentication or OAuth2 for all LLM endpoints.",
                    metadata={"confidence": "verified"},
                )
            elif resp.status_code in (401, 403):
                self.log.debug(self.name, f"auth enforced: {resp.status_code}")
            else:
                self.log.debug(self.name, f"no-auth test: unexpected status {resp.status_code}")

        except Exception as e:
            self.log.debug(self.name, f"no-auth test failed: {e}")

        return None

    async def _test_invalid_key(self, endpoint: str) -> Finding | None:
        """Test if endpoint accepts an obviously invalid API key."""
        try:
            import httpx

            async with httpx.AsyncClient(
                base_url=self.session.config.target_url,
                timeout=httpx.Timeout(self.session.config.timeout),
                verify=False,
            ) as client:
                resp = await client.post(
                    endpoint,
                    json={
                        "messages": [{"role": "user", "content": "Hello"}],
                        "max_tokens": 10,
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer sk-INVALID-KEY-000000",
                    },
                )

            if resp.status_code == 200:
                return self.make_finding(
                    title="Invalid API key accepted",
                    description=(
                        "The endpoint accepted a request with an obviously invalid API key. "
                        "Authentication may not be properly validated."
                    ),
                    severity="medium",
                    score=0.6,
                    evidence_turns=[
                        {"role": "user", "content": "Hello (key: sk-INVALID-KEY-000000)"},
                        {"role": "assistant", "content": f"Status: {resp.status_code}"},
                    ],
                    detection_logic=f"POST with invalid key → {resp.status_code}",
                    remediation="Validate API keys against a key store. Reject unrecognized keys.",
                    metadata={"confidence": "verified"},
                )
        except Exception as e:
            self.log.debug(self.name, f"invalid-key test failed: {e}")

        return None

    async def _test_empty_key(self, endpoint: str) -> Finding | None:
        """Test if endpoint accepts an empty API key."""
        try:
            import httpx

            async with httpx.AsyncClient(
                base_url=self.session.config.target_url,
                timeout=httpx.Timeout(self.session.config.timeout),
                verify=False,
            ) as client:
                resp = await client.post(
                    endpoint,
                    json={
                        "messages": [{"role": "user", "content": "Hello"}],
                        "max_tokens": 10,
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer ",
                    },
                )

            if resp.status_code == 200:
                return self.make_finding(
                    title="Empty API key accepted",
                    description="The endpoint accepted a request with an empty Bearer token.",
                    severity="medium",
                    score=0.55,
                    evidence_turns=[
                        {"role": "user", "content": "Hello (key: empty)"},
                        {"role": "assistant", "content": f"Status: {resp.status_code}"},
                    ],
                    detection_logic=f"POST with empty key → {resp.status_code}",
                    remediation="Reject empty or whitespace-only API keys.",
                    metadata={"confidence": "verified"},
                )
        except Exception as e:
            self.log.debug(self.name, f"empty-key test failed: {e}")

        return None

    async def _test_endpoint_access(self, path: str) -> Finding | None:
        """Test if auxiliary endpoints are accessible."""
        try:
            resp = await self.session.get(path)
            if resp.status_code == 200:
                body_preview = resp.text[:200]
                return self.make_finding(
                    title=f"Endpoint accessible: {path}",
                    description=f"Auxiliary endpoint {path} is accessible and returned data.",
                    severity="info",
                    score=0.15,
                    evidence_turns=[
                        {"role": "user", "content": f"GET {path}"},
                        {"role": "assistant", "content": body_preview},
                    ],
                    detection_logic=f"GET {path} → 200",
                    metadata={"confidence": "verified"},
                )
        except Exception as e:
            self.log.debug(self.name, f"endpoint {path}: {e}")

        return None

    async def _test_rate_limit(self, endpoint: str) -> Finding | None:
        """Send rapid requests to detect rate limiting."""
        try:
            statuses: list[int] = []
            for _ in range(5):
                resp = await self.session.post(
                    endpoint,
                    json={
                        "messages": [{"role": "user", "content": "test"}],
                        "max_tokens": 5,
                    },
                )
                statuses.append(resp.status_code)

            rate_limited = any(s == 429 for s in statuses)
            if not rate_limited and all(s == 200 for s in statuses):
                return self.make_finding(
                    title="No rate limiting detected",
                    description=(
                        "5 rapid requests all returned 200. No rate limiting appears to be "
                        "enforced on the LLM endpoint. This could allow abuse or DoS."
                    ),
                    severity="low",
                    score=0.25,
                    evidence_turns=[
                        {"role": "user", "content": f"5 rapid requests → statuses: {statuses}"},
                    ],
                    detection_logic=f"5 rapid POST requests → all 200, no 429",
                    remediation="Implement per-user/per-IP rate limiting on LLM endpoints.",
                    metadata={"confidence": "probable"},
                )
        except Exception as e:
            self.log.debug(self.name, f"rate-limit test failed: {e}")

        return None
