"""Interactsh OOB interaction client — out-of-band callback verification.

Registers a unique subdomain with an Interactsh server and polls for
DNS/HTTP interactions to confirm data exfiltration findings.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import time
from typing import Any

import httpx


class InteractshClient:
    """Lightweight Interactsh client for OOB callback verification."""

    def __init__(
        self,
        server_url: str = "https://oast.fun",
        timeout: float = 10.0,
    ):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self._correlation_id: str = ""
        self._secret: str = ""
        self._registered = False
        self._client: httpx.AsyncClient | None = None

    @property
    def interaction_domain(self) -> str:
        """Return the unique interaction domain for this session."""
        if not self._correlation_id:
            return ""
        host = self.server_url.replace("https://", "").replace("http://", "")
        return f"{self._correlation_id}.{host}"

    @property
    def interaction_url(self) -> str:
        """Return a full HTTPS URL for HTTP-based callbacks."""
        domain = self.interaction_domain
        if not domain:
            return ""
        return f"https://{domain}"

    async def register(self) -> bool:
        """Register a new interaction subdomain with the server.
        Returns True on success."""
        self._correlation_id = secrets.token_hex(16)
        self._secret = secrets.token_hex(16)

        try:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                verify=True,
            )
            resp = await self._client.post(
                f"{self.server_url}/register",
                json={
                    "public-key": "",
                    "secret-key": self._secret,
                    "correlation-id": self._correlation_id,
                },
            )
            if resp.status_code in (200, 201):
                self._registered = True
                return True
            # If registration fails (server down, etc.), fall back to passive mode
            return False
        except Exception:
            return False

    async def poll(self, wait: float = 5.0, max_attempts: int = 3) -> list[dict[str, Any]]:
        """Poll for received interactions.

        Args:
            wait: seconds to wait between attempts
            max_attempts: number of polling attempts

        Returns:
            List of interaction dicts with keys: protocol, address, raw_request, timestamp
        """
        if not self._registered or not self._client:
            return []

        interactions: list[dict[str, Any]] = []

        for _ in range(max_attempts):
            try:
                resp = await self._client.get(
                    f"{self.server_url}/poll",
                    params={
                        "id": self._correlation_id,
                        "secret": self._secret,
                    },
                )

                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("data", []):
                        interactions.append({
                            "protocol": entry.get("protocol", "unknown"),
                            "address": entry.get("remote-address", ""),
                            "raw_request": entry.get("raw-request", ""),
                            "timestamp": entry.get("timestamp", ""),
                            "type": entry.get("type", ""),
                        })

                    if interactions:
                        return interactions

            except Exception:
                pass

            if _ < max_attempts - 1:
                await asyncio.sleep(wait)

        return interactions

    async def deregister(self) -> None:
        """Clean up the registered interaction domain."""
        if self._registered and self._client:
            try:
                await self._client.post(
                    f"{self.server_url}/deregister",
                    json={
                        "secret-key": self._secret,
                        "correlation-id": self._correlation_id,
                    },
                )
            except Exception:
                pass

            try:
                await self._client.aclose()
            except Exception:
                pass

            self._registered = False
            self._client = None

    async def __aenter__(self) -> InteractshClient:
        await self.register()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.deregister()


def build_exfil_url(base_domain: str, label: str, data: str = "") -> str:
    """Build a DNS-safe exfiltration URL.

    Args:
        base_domain: The Interactsh interaction domain
        label: Short identifier for this exfil attempt (e.g. 'sysprompt')
        data: Optional data to encode in the subdomain (truncated to DNS-safe length)

    Returns:
        URL like https://label.base_domain/collect?d=encoded_data
    """
    # DNS labels max 63 chars, total hostname max 253
    safe_label = label[:20].replace(".", "-").replace(" ", "-").lower()

    if data:
        # Base64url-encode and truncate for DNS safety
        encoded = base64.urlsafe_b64encode(data[:100].encode()).decode().rstrip("=")
        encoded = encoded[:50]
        return f"https://{safe_label}.{base_domain}/c?d={encoded}"

    return f"https://{safe_label}.{base_domain}/c"
