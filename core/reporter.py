"""Report generator — JSON and HTML output with evidence chains."""

from __future__ import annotations

import json
import pathlib
from datetime import datetime, timezone
from typing import Any

from core.models import Finding, ScanContext, ScanConfig


class Reporter:
    """Generate assessment reports from scan results."""

    def __init__(self, ctx: ScanContext, config: ScanConfig):
        self.ctx = ctx
        self.config = config

    def generate(self) -> pathlib.Path:
        """Generate report in configured format and return the file path."""
        output_dir = pathlib.Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        fmt = self.config.output_format.lower()
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stem = f"valk_{self.ctx.scan_id}_{ts}"

        if fmt == "html":
            path = output_dir / f"{stem}.html"
            path.write_text(self._render_html(), encoding="utf-8")
        elif fmt == "sarif":
            path = output_dir / f"{stem}.sarif"
            path.write_text(
                json.dumps(self._build_sarif(), indent=2, default=str),
                encoding="utf-8",
            )
        else:
            path = output_dir / f"{stem}.json"
            path.write_text(
                json.dumps(self._build_json(), indent=2, default=str),
                encoding="utf-8",
            )

        return path

    # ── JSON ─────────────────────────────────────────────────────────────

    def _build_json(self) -> dict[str, Any]:
        # Apply min_confidence filter
        confidence_order = ["verified", "probable", "indicative"]
        min_conf = self.config.min_confidence
        if min_conf and min_conf in confidence_order:
            min_idx = confidence_order.index(min_conf)
            allowed = set(confidence_order[: min_idx + 1])
            filtered_findings = [f for f in self.ctx.findings if f.confidence in allowed]
        else:
            filtered_findings = list(self.ctx.findings)

        findings_data = []
        for f in sorted(filtered_findings, key=lambda x: x.severity.weight, reverse=True):
            findings_data.append({
                "id": f.id,
                "module": f.module,
                "phase": f.phase.value,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "title": f.title,
                "description": f.description,
                "score": f.score,
                "owasp_llm": f.owasp_llm,
                "mitre_atlas": f.mitre_atlas,
                "remediation": f.remediation,
                "evidence": {
                    "turns": [
                        {"role": t.role, "content": t.content}
                        for t in f.evidence.turns
                    ],
                    "detection_logic": f.evidence.detection_logic,
                    "metadata": f.evidence.metadata,
                },
                "timestamp": f.timestamp.isoformat(),
            })

        # Severity counts
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in filtered_findings:
            counts[f.severity.value] += 1

        risk_score = 0.0
        peak_risk = 0.0
        if filtered_findings:
            risk_score = sum(
                f.score * f.severity.weight for f in filtered_findings
            ) / len(filtered_findings)
            peak_risk = max(
                f.score * f.severity.weight for f in filtered_findings
            )

        return {
            "valk_version": "0.3.0",
            "scan_id": self.ctx.scan_id,
            "target": self.ctx.target_url,
            "started_at": self.ctx.started_at.isoformat(),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(filtered_findings),
                "total_unfiltered_findings": len(self.ctx.findings),
                "severity_counts": counts,
                "risk_score": round(risk_score, 3),
                "peak_risk": round(peak_risk, 3),
                "total_requests": self.ctx.total_requests,
                "total_tokens_used": self.ctx.total_tokens_used,
                "errors": len(self.ctx.errors),
            },
            "identity": {
                "family": self.ctx.identity.family,
                "specific_model": self.ctx.identity.specific_model,
                "confidence": self.ctx.identity.confidence,
                "knowledge_cutoff": self.ctx.identity.knowledge_cutoff,
                "inferred_template": self.ctx.inferred_template,
            },
            "endpoints": [
                {"path": e.path, "method": e.method, "status": e.status_code}
                for e in self.ctx.endpoints
            ],
            "findings": findings_data,
            "errors": self.ctx.errors,
        }

    # ── SARIF ─────────────────────────────────────────────────────────────

    _SARIF_SEVERITY = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none",
    }

    def _build_sarif(self) -> dict[str, Any]:
        """Build a SARIF v2.1.0 log for CI/CD integration."""
        rules: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        rule_index: dict[str, int] = {}

        # Apply same confidence filter as JSON
        confidence_order = ["verified", "probable", "indicative"]
        min_conf = self.config.min_confidence
        if min_conf and min_conf in confidence_order:
            min_idx = confidence_order.index(min_conf)
            allowed = set(confidence_order[: min_idx + 1])
            filtered = [f for f in self.ctx.findings if f.confidence in allowed]
        else:
            filtered = list(self.ctx.findings)

        for f in filtered:
            rule_id = f"VALK/{f.module}"

            if rule_id not in rule_index:
                rule_index[rule_id] = len(rules)
                tags = list(f.owasp_llm) + list(f.mitre_atlas)
                rules.append({
                    "id": rule_id,
                    "name": f.module,
                    "shortDescription": {"text": f.description[:200]},
                    "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                    "properties": {"tags": tags},
                })

            evidence_text = "\n".join(
                f"[{t.role}] {t.content[:500]}" for t in f.evidence.turns
            )

            results.append({
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": self._SARIF_SEVERITY.get(f.severity.value, "warning"),
                "message": {
                    "text": f"{f.title}\n\n{f.description}\n\nDetection: {f.evidence.detection_logic}",
                },
                "properties": {
                    "confidence": f.confidence,
                    "score": f.score,
                    "severity": f.severity.value,
                    "evidence": evidence_text[:2000],
                    "remediation": f.remediation,
                },
                "partialFingerprints": {
                    "valkFindingId": f.id,
                },
            })

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Valk",
                            "version": "0.3.0",
                            "informationUri": "https://github.com/valk-llm/valk",
                            "rules": rules,
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": len(self.ctx.errors) == 0,
                            "toolExecutionNotifications": [
                                {"message": {"text": e}} for e in self.ctx.errors[:10]
                            ],
                        },
                    ],
                    "properties": {
                        "target": self.ctx.target_url,
                        "scanId": self.ctx.scan_id,
                        "modelFamily": self.ctx.identity.family,
                        "modelName": self.ctx.identity.specific_model,
                        "totalRequests": self.ctx.total_requests,
                    },
                },
            ],
        }

    # ── HTML ─────────────────────────────────────────────────────────────

    def _render_html(self) -> str:
        data = self._build_json()
        summary = data["summary"]
        identity = data["identity"]

        sev_colors = {
            "critical": "#dc2626",
            "high": "#ef4444",
            "medium": "#f59e0b",
            "low": "#3b82f6",
            "info": "#6b7280",
        }

        findings_html = ""
        for i, f in enumerate(data["findings"], 1):
            color = sev_colors.get(f["severity"], "#6b7280")
            conf_colors = {"verified": "#22c55e", "probable": "#f59e0b", "indicative": "#6b7280"}
            conf_color = conf_colors.get(f.get("confidence", "indicative"), "#6b7280")
            turns_html = ""
            for t in f["evidence"]["turns"]:
                role_class = "ev-user" if t["role"] == "user" else "ev-assistant"
                escaped = _esc(t["content"])
                turns_html += f'<div class="{role_class}"><strong>{t["role"]}:</strong> {escaped}</div>'

            owasp = ", ".join(f["owasp_llm"]) if f["owasp_llm"] else "—"
            atlas = ", ".join(f["mitre_atlas"]) if f["mitre_atlas"] else "—"

            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="sev-badge" style="background:{color}">{f['severity'].upper()}</span>
                    <span class="sev-badge" style="background:{conf_color};font-size:.7rem">{f.get('confidence', 'indicative').upper()}</span>
                    <span class="finding-title">#{i} {_esc(f['title'])}</span>
                    <span class="finding-score">Score: {f['score']:.2f}</span>
                </div>
                <div class="finding-body">
                    <p>{_esc(f['description'])}</p>
                    <div class="tags">
                        <span class="tag">Module: {_esc(f['module'])}</span>
                        <span class="tag">OWASP: {owasp}</span>
                        <span class="tag">ATLAS: {atlas}</span>
                    </div>
                    {f'<div class="remediation"><strong>Remediation:</strong> {_esc(f["remediation"])}</div>' if f['remediation'] else ''}
                    <details class="evidence">
                        <summary>Evidence ({len(f['evidence']['turns'])} turns)</summary>
                        <div class="evidence-body">{turns_html}</div>
                        <div class="detection-logic"><strong>Detection:</strong> {_esc(f['evidence']['detection_logic'])}</div>
                    </details>
                </div>
            </div>"""

        model_str = identity.get("specific_model") or identity.get("family") or "Unknown"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Valk Report — {_esc(data['scan_id'])}</title>
<style>
  :root {{ --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --border: #334155; --accent: #06b6d4; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); padding:2rem; line-height:1.6; }}
  .container {{ max-width:1000px; margin:0 auto; }}
  h1 {{ color:var(--accent); font-size:2rem; margin-bottom:.5rem; }}
  .subtitle {{ color:#94a3b8; margin-bottom:2rem; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:2rem; }}
  .summary-card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1rem; text-align:center; }}
  .summary-card .value {{ font-size:1.8rem; font-weight:700; color:var(--accent); }}
  .summary-card .label {{ font-size:.85rem; color:#94a3b8; margin-top:.25rem; }}
  .sev-bar {{ display:flex; gap:.5rem; margin-bottom:2rem; }}
  .sev-bar div {{ flex:1; text-align:center; padding:.5rem; border-radius:6px; font-weight:600; font-size:.9rem; }}
  .finding {{ background:var(--card); border:1px solid var(--border); border-radius:8px; margin-bottom:1rem; overflow:hidden; }}
  .finding-header {{ display:flex; align-items:center; gap:.75rem; padding:1rem; border-bottom:1px solid var(--border); }}
  .sev-badge {{ color:#fff; padding:2px 10px; border-radius:4px; font-size:.8rem; font-weight:600; text-transform:uppercase; }}
  .finding-title {{ flex:1; font-weight:600; }}
  .finding-score {{ color:#94a3b8; font-size:.9rem; }}
  .finding-body {{ padding:1rem; }}
  .finding-body p {{ margin-bottom:.75rem; }}
  .tags {{ display:flex; gap:.5rem; flex-wrap:wrap; margin-bottom:.75rem; }}
  .tag {{ background:var(--bg); border:1px solid var(--border); padding:2px 8px; border-radius:4px; font-size:.8rem; }}
  .remediation {{ background:#1a2332; border-left:3px solid var(--accent); padding:.75rem; margin-bottom:.75rem; border-radius:0 4px 4px 0; }}
  .evidence {{ margin-top:.5rem; }}
  .evidence summary {{ cursor:pointer; color:var(--accent); font-size:.9rem; }}
  .evidence-body {{ background:var(--bg); padding:.75rem; border-radius:4px; margin-top:.5rem; max-height:400px; overflow-y:auto; }}
  .ev-user {{ color:#f59e0b; margin-bottom:.5rem; white-space:pre-wrap; word-break:break-word; }}
  .ev-assistant {{ color:#34d399; margin-bottom:.5rem; white-space:pre-wrap; word-break:break-word; }}
  .detection-logic {{ font-size:.85rem; color:#94a3b8; margin-top:.5rem; }}
  .identity {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1rem; margin-bottom:2rem; }}
  .identity h2 {{ color:var(--accent); font-size:1.1rem; margin-bottom:.5rem; }}
  footer {{ text-align:center; color:#475569; margin-top:3rem; font-size:.85rem; }}
</style>
</head>
<body>
<div class="container">
  <h1>VALK</h1>
  <p class="subtitle">LLM Red Team Assessment Report — Scan {_esc(data['scan_id'])}</p>

  <div class="summary-grid">
    <div class="summary-card"><div class="value">{summary['total_findings']}</div><div class="label">Findings</div></div>
    <div class="summary-card"><div class="value">{summary['risk_score']:.2f}</div><div class="label">Risk Score (avg)</div></div>
    <div class="summary-card"><div class="value" style="color:#dc2626">{summary['peak_risk']:.2f}</div><div class="label">Peak Risk</div></div>
    <div class="summary-card"><div class="value">{summary['total_requests']}</div><div class="label">HTTP Requests</div></div>
    <div class="summary-card"><div class="value">{summary['errors']}</div><div class="label">Errors</div></div>
  </div>

  <div class="sev-bar">
    <div style="background:#dc2626">CRIT: {summary['severity_counts']['critical']}</div>
    <div style="background:#ef4444">HIGH: {summary['severity_counts']['high']}</div>
    <div style="background:#f59e0b;color:#000">MED: {summary['severity_counts']['medium']}</div>
    <div style="background:#3b82f6">LOW: {summary['severity_counts']['low']}</div>
    <div style="background:#6b7280">INFO: {summary['severity_counts']['info']}</div>
  </div>

  <div class="identity">
    <h2>Target Identity</h2>
    <p><strong>Target:</strong> {_esc(data['target'])}</p>
    <p><strong>Model:</strong> {_esc(model_str)} (confidence: {identity['confidence']:.0%})</p>
    <p><strong>Template:</strong> {_esc(str(identity.get('inferred_template', 'Unknown')))}</p>
    <p><strong>Knowledge Cutoff:</strong> {_esc(str(identity.get('knowledge_cutoff', 'Unknown')))}</p>
  </div>

  <h2 style="color:var(--accent);margin-bottom:1rem;">Findings ({summary['total_findings']})</h2>
  {findings_html}

  <footer>
    Generated by Valk v0.3.0 at {data['generated_at']}<br>
    Target: {_esc(data['target'])} | Scan ID: {_esc(data['scan_id'])}
  </footer>
</div>
</body>
</html>"""


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
