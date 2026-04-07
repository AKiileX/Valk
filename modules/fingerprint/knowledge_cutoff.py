"""Knowledge cutoff — determines model training data recency."""

from __future__ import annotations

from core.models import Finding, Phase, ScanContext
from modules.base import BaseModule


class KnowledgeCutoff(BaseModule):
    name = "knowledge-cutoff"
    description = "Determine training data knowledge cutoff date"
    phase = Phase.FINGERPRINT
    owasp_llm = ["LLM06"]

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        endpoint = self.get_chat_endpoint()
        data = self.load_payloads("events.yaml")
        events = data.get("events", [])

        if not events:
            self.log.warning("no events in events.yaml", module=self.name)
            return findings

        self.log.info(self.name, f"testing {len(events)} dated events...")

        last_known_date = None
        first_unknown_date = None
        evidence_turns: list[dict[str, str]] = []

        for event in events:
            try:
                resp = await self.session.single_prompt(event["question"], endpoint=endpoint)
                content = resp.content

                # Check if model knows about this event
                knows = self._check_knowledge(content, event.get("answer_contains", []))

                status = "KNOWN" if knows else "UNKNOWN"
                self.log.debug(self.name, f"[{event['date']}] {status}: {event['question'][:60]}...")

                evidence_turns.append({"role": "user", "content": event["question"]})
                evidence_turns.append({
                    "role": "assistant",
                    "content": f"[{status}] {content[:300]}",
                })

                if knows:
                    last_known_date = event["date"]
                elif not first_unknown_date:
                    first_unknown_date = event["date"]

            except Exception as e:
                self.log.debug(self.name, f"event probe failed: {e}")

        # Determine the cutoff
        if last_known_date:
            cutoff_desc = f"Last known event: {last_known_date}"
            if first_unknown_date:
                cutoff_desc += f", First unknown event: {first_unknown_date}"
                self.ctx.identity.knowledge_cutoff = f"{last_known_date} to {first_unknown_date}"
            else:
                self.ctx.identity.knowledge_cutoff = f"after {last_known_date}"

            self.log.success(self.name, f"estimated cutoff: {self.ctx.identity.knowledge_cutoff}")

            findings.append(self.make_finding(
                title=f"Knowledge cutoff estimated: {self.ctx.identity.knowledge_cutoff}",
                description=cutoff_desc,
                severity="info",
                score=0.1,
                evidence_turns=evidence_turns[-6:],  # Last 3 exchanges
                detection_logic="Binary search on dated world events",
            ))

        return findings

    @staticmethod
    def _check_knowledge(response: str, expected_terms: list[str]) -> bool:
        """Check if the response contains expected knowledge markers."""
        if not expected_terms:
            return False
        lower = response.lower()
        # Require at least one expected term AND no strong uncertainty signals
        has_knowledge = any(term.lower() in lower for term in expected_terms)
        uncertain = any(phrase in lower for phrase in [
            "i don't have", "i'm not sure", "i don't know",
            "no information", "not aware", "cannot confirm",
            "my training data", "my knowledge cutoff",
        ])
        return has_knowledge and not uncertain
