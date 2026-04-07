"""Pydantic models — typed data structures for the entire framework."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────

class Phase(str, Enum):
    RECON = "recon"
    FINGERPRINT = "fingerprint"
    ATTACK = "attack"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
            "info": 0.0,
        }[self.value]

    @property
    def color(self) -> str:
        return {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }[self.value]


# ── Evidence chain ───────────────────────────────────────────────────────────

class Turn(BaseModel):
    """A single request/response exchange."""
    role: str  # "user" or "system" or "assistant"
    content: str
    reasoning_content: str | None = None  # model CoT (Qwen, DeepSeek reasoning)


class Evidence(BaseModel):
    """Full evidence chain for a finding — every prompt and response."""
    turns: list[Turn] = Field(default_factory=list)
    detection_logic: str = ""
    raw_request: str | None = None
    raw_response: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Findings ─────────────────────────────────────────────────────────────────

class Finding(BaseModel):
    """A single security finding with full traceability."""
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    module: str
    phase: Phase
    severity: Severity
    confidence: str = "indicative"  # "verified", "probable", "indicative"
    title: str
    description: str
    evidence: Evidence = Field(default_factory=Evidence)
    score: float = Field(ge=0.0, le=1.0, default=0.0)
    owasp_llm: list[str] = Field(default_factory=list)      # e.g. ["LLM01", "LLM07"]
    mitre_atlas: list[str] = Field(default_factory=list)     # e.g. ["AML.T0051"]
    remediation: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ── Scan context (shared state across modules) ──────────────────────────────

class EndpointInfo(BaseModel):
    path: str
    method: str = "POST"
    status_code: int = 0
    is_chat: bool = False
    is_completions: bool = False
    response_sample: str | None = None


class ModelIdentity(BaseModel):
    family: str | None = None        # "mistral", "gpt", "claude", etc.
    specific_model: str | None = None # "mistral-7b-instruct-v0.2"
    confidence: float = 0.0
    api_field_value: str | None = None
    knowledge_cutoff: str | None = None
    capabilities: dict[str, bool] = Field(default_factory=dict)  # tool_use, vision, etc.


class ScanContext(BaseModel):
    """Shared mutable state populated by modules across phases."""
    target_url: str
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Populated by recon
    endpoints: list[EndpointInfo] = Field(default_factory=list)
    chat_endpoint: str | None = None
    completions_endpoint: str | None = None
    
    # Populated by fingerprint
    identity: ModelIdentity = Field(default_factory=ModelIdentity)
    system_prompt_hints: list[str] = Field(default_factory=list)
    confirmed_tokens: list[str] = Field(default_factory=list)       # STI: tokens that caused behavioral shifts
    inferred_template: str | None = None                            # "chatml", "llama", "phi", "generic"
    
    # Baseline — populated before attack phase
    baselines: dict[str, dict[str, Any]] = Field(default_factory=dict)  # probe_id → {response, length, refused}
    
    # Attack results
    findings: list[Finding] = Field(default_factory=list)
    
    # Multi-turn conversation state for persistent attacks
    conversation_history: list[Turn] = Field(default_factory=list)

    # Cross-module intelligence: working attack contexts shared between modules
    breakthroughs: list[dict[str, Any]] = Field(default_factory=list)
    
    # Runtime metadata
    total_requests: int = 0
    total_tokens_used: int = 0
    errors: list[str] = Field(default_factory=list)

    # OOB callback server URL (passed from config)
    interactsh_url: str | None = None

    # Adaptive payload budgeting
    payload_budget: float = 1.0              # 0.0-1.0 multiplier set by engine
    avg_response_time: float = 0.0           # measured seconds per request


# ── Config ───────────────────────────────────────────────────────────────────

class ScanConfig(BaseModel):
    """CLI / config file parameters for a scan."""
    target_url: str
    config_path: str = "config/default.yaml"
    output_dir: str = "reports/"
    output_format: str = "json"            # "json" or "html"
    modules: list[str] | None = None       # None = run all
    skip: list[str] = Field(default_factory=list)  # Modules to exclude
    phases: list[str] | None = None        # None = all phases
    stealth: bool = False
    max_concurrent: int = 5
    api_key: str | None = None
    auth_header: str | None = None         # custom auth header name
    custom_headers: dict[str, str] = Field(default_factory=dict)
    proxy: str | None = None
    verbose: bool = False
    timeout: float = 120.0
    max_retries: int = 3
    delay_min: float = 0.1                 # seconds between requests
    delay_max: float = 0.5
    stealth_delay_min: float = 2.0
    stealth_delay_max: float = 8.0
    jailbreak_level: int = 2               # 1=safe, 2=moderate, 3=aggressive
    model_hint: str | None = None          # skip fingerprint, assume this model
    max_tokens: int = 4096                  # per-request max tokens (reasoning models need more)
    speed: str = "auto"                      # "fast", "auto", "thorough"
    min_confidence: str | None = None        # "verified", "probable", "indicative" — filter findings in report
    interactsh_url: str | None = None        # Interactsh server for OOB callback verification
    payload_packs: list[str] = Field(default_factory=list)  # External payload pack directories
