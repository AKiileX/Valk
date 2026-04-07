"""Smoke tests for Valk core detection logic and data models.

Run with:  python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest

from core.engine import _is_refusal, baseline_refusal_flipped
from core.models import (
    Evidence,
    Finding,
    ModelIdentity,
    Phase,
    ScanConfig,
    ScanContext,
    Severity,
    Turn,
)
from modules.base import BaseModule


# ── _is_refusal ──────────────────────────────────────────────────────────────

class TestIsRefusal:
    def test_clear_refusals(self):
        refusals = [
            "I can't help with that.",
            "I cannot assist with this request.",
            "I'm sorry, but I'm not able to do that.",
            "As an AI, I must decline.",
            "I will not provide instructions for that.",
            "That's against my guidelines.",
        ]
        for text in refusals:
            assert _is_refusal(text), f"Expected refusal: {text!r}"

    def test_compliant_responses(self):
        compliant = [
            "Sure! Here's how you do it:",
            "Of course. The answer is 42.",
            "Here is the code you requested:",
            "The capital of France is Paris.",
        ]
        for text in compliant:
            assert not _is_refusal(text), f"Expected non-refusal: {text!r}"

    def test_case_insensitive(self):
        assert _is_refusal("I CAN'T HELP WITH THAT.")
        assert _is_refusal("AS AN AI I CANNOT")


# ── baseline_refusal_flipped ─────────────────────────────────────────────────

class TestBaselineRefusalFlipped:
    def _ctx_with_baseline(self, refused: bool) -> ScanContext:
        ctx = ScanContext(target_url="http://test")
        ctx.baselines["jailbreak_baseline"] = {
            "response": "I can't help with that.",
            "length": 30,
            "refused": refused,
        }
        return ctx

    def test_flip_detected(self):
        ctx = self._ctx_with_baseline(refused=True)
        flipped, confidence = baseline_refusal_flipped(
            ctx, "jailbreak_baseline", "Sure, here's the information you need."
        )
        assert flipped is True
        assert confidence == 1.0

    def test_no_flip_when_attack_also_refused(self):
        ctx = self._ctx_with_baseline(refused=True)
        flipped, _ = baseline_refusal_flipped(
            ctx, "jailbreak_baseline", "I cannot help with that request."
        )
        assert flipped is False

    def test_no_flip_when_baseline_was_not_refused(self):
        ctx = self._ctx_with_baseline(refused=False)
        flipped, _ = baseline_refusal_flipped(
            ctx, "jailbreak_baseline", "Sure, here's the answer."
        )
        assert flipped is False

    def test_missing_baseline_returns_no_flip(self):
        ctx = ScanContext(target_url="http://test")
        flipped, confidence = baseline_refusal_flipped(
            ctx, "nonexistent_probe", "some response"
        )
        assert flipped is False
        assert confidence == 0.0


# ── ScanConfig ───────────────────────────────────────────────────────────────

class TestScanConfig:
    def test_defaults(self):
        cfg = ScanConfig(target_url="http://localhost:11434")
        assert cfg.stealth is False
        assert cfg.jailbreak_level == 2
        assert cfg.speed == "auto"
        assert cfg.modules is None
        assert cfg.skip == []

    def test_skip_field_accepts_list(self):
        cfg = ScanConfig(target_url="http://localhost", skip=["jailbreak", "token-limit-dos"])
        assert "jailbreak" in cfg.skip
        assert "token-limit-dos" in cfg.skip

    def test_target_url_stored(self):
        cfg = ScanConfig(target_url="http://example.com:8080")
        assert cfg.target_url == "http://example.com:8080"


# ── ScanContext ───────────────────────────────────────────────────────────────

class TestScanContext:
    def test_interactsh_url_is_a_proper_field(self):
        ctx = ScanContext(target_url="http://test", interactsh_url="https://oast.fun")
        assert ctx.interactsh_url == "https://oast.fun"

    def test_interactsh_url_defaults_none(self):
        ctx = ScanContext(target_url="http://test")
        assert ctx.interactsh_url is None

    def test_scan_id_generated(self):
        ctx = ScanContext(target_url="http://test")
        assert ctx.scan_id
        assert len(ctx.scan_id) == 8


# ── Severity weights ─────────────────────────────────────────────────────────

class TestSeverityWeights:
    def test_critical_is_max(self):
        assert Severity.CRITICAL.weight == 1.0

    def test_info_is_zero(self):
        assert Severity.INFO.weight == 0.0

    def test_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight > Severity.LOW.weight
        assert Severity.LOW.weight > Severity.INFO.weight


# ── Finding construction ──────────────────────────────────────────────────────

class TestFinding:
    def test_finding_id_auto_generated(self):
        f = Finding(
            module="test",
            phase=Phase.ATTACK,
            severity=Severity.HIGH,
            title="Test",
            description="Test finding",
        )
        assert f.id
        assert len(f.id) == 12

    def test_score_bounds(self):
        with pytest.raises(Exception):
            Finding(
                module="test",
                phase=Phase.ATTACK,
                severity=Severity.HIGH,
                title="Bad",
                description="Bad",
                score=1.5,
            )


# ── BaseModule.budget_payloads ────────────────────────────────────────────────

class TestBudgetPayloads:
    """Test payload budgeting without sending real HTTP."""

    class DummyModule(BaseModule):
        name = "test-module"
        phase = Phase.ATTACK

        async def run(self):
            return []

    def _make_module(self, budget: float) -> "TestBudgetPayloads.DummyModule":
        ctx = ScanContext(target_url="http://test", payload_budget=budget)
        return self.DummyModule(session=None, ctx=ctx, log=None)  # type: ignore[arg-type]

    def test_thorough_returns_all(self):
        mod = self._make_module(1.0)
        items = list(range(20))
        assert mod.budget_payloads(items) == items

    def test_fast_returns_quarter(self):
        mod = self._make_module(0.25)
        items = list(range(20))
        result = mod.budget_payloads(items)
        assert len(result) == 5

    def test_min_count_respected(self):
        mod = self._make_module(0.01)  # tiny budget
        items = list(range(10))
        result = mod.budget_payloads(items, min_count=3)
        assert len(result) >= 3

    def test_priority_sort(self):
        mod = self._make_module(0.5)
        items = [
            {"id": "low", "priority": 1},
            {"id": "high", "priority": 10},
            {"id": "mid", "priority": 5},
        ]
        result = mod.budget_payloads(items)
        assert result[0]["id"] == "high"


# ── BaseModule.is_refusal ─────────────────────────────────────────────────────

class TestModuleIsRefusal:
    def _make_module(self) -> "TestBudgetPayloads.DummyModule":
        ctx = ScanContext(target_url="http://test")

        class D(BaseModule):
            name = "t"
            phase = Phase.ATTACK
            async def run(self): return []

        return D(session=None, ctx=ctx, log=None)  # type: ignore[arg-type]

    def test_refusal_detected(self):
        mod = self._make_module()
        assert mod.is_refusal("I cannot help with that.")
        assert mod.is_refusal("I'm sorry, that violates my guidelines.")

    def test_non_refusal(self):
        mod = self._make_module()
        assert not mod.is_refusal("Here is how to do it.")
        assert not mod.is_refusal("The answer is 4.")
