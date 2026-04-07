"""Rich-powered logger with structured output, progress tracking, and phase banners."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.models import Finding, Phase, Severity


class ValkLogger:
    """Structured logger with Rich formatting for terminal output."""

    def __init__(self, verbose: bool = False, flush: bool = False):
        self.verbose = verbose
        self.flush = flush
        self.console = Console(force_terminal=True)
        self._module_findings: dict[str, list[Finding]] = {}

    # ── Timestamp ────────────────────────────────────────────────────────

    @staticmethod
    def _ts() -> str:
        return datetime.now(timezone.utc).strftime("%H:%M:%S")

    # ── Core log levels ──────────────────────────────────────────────────

    def info(self, module: str, msg: str) -> None:
        self.console.print(f"[dim]{self._ts()}[/dim] [bold cyan][INFO][/bold cyan] [green]'{escape(module)}'[/green] {escape(msg)}")
        if self.flush:
            sys.stdout.flush()

    def warning(self, msg: str, module: str = "valk") -> None:
        self.console.print(f"[dim]{self._ts()}[/dim] [bold yellow][WARNING][/bold yellow] [green]'{escape(module)}'[/green] {escape(msg)}")

    def error(self, msg: str, module: str = "valk") -> None:
        self.console.print(f"[dim]{self._ts()}[/dim] [bold red][ERROR][/bold red] [green]'{escape(module)}'[/green] {escape(msg)}")

    def debug(self, module: str, msg: str) -> None:
        if self.verbose:
            self.console.print(f"[dim]{self._ts()}[/dim] [dim][DEBUG][/dim] [green]'{escape(module)}'[/green] {escape(msg)}")

    def success(self, module: str, msg: str) -> None:
        self.console.print(f"[dim]{self._ts()}[/dim] [bold green][+][/bold green] [green]'{escape(module)}'[/green] {escape(msg)}")

    # ── Phase banners ────────────────────────────────────────────────────

    def phase_start(self, phase: Phase) -> None:
        banner = {
            Phase.RECON: "R E C O N",
            Phase.FINGERPRINT: "F I N G E R P R I N T",
            Phase.ATTACK: "A T T A C K",
        }
        self.console.print()
        self.console.print(
            Panel(
                f"[bold white]{banner[phase]}[/bold white]",
                border_style="cyan",
                padding=(0, 2),
            )
        )

    def phase_end(self, phase: Phase) -> None:
        self.console.print(f"[dim]{self._ts()}[/dim] [bold cyan]──[/bold cyan] {phase.value} phase complete\n")

    # ── Module lifecycle ─────────────────────────────────────────────────

    def module_start(self, name: str, description: str) -> None:
        self.console.print(
            f"[dim]{self._ts()}[/dim] [bold cyan][*][/bold cyan] running module: "
            f"[bold]{name}[/bold] — {description}"
        )

    def module_skip(self, name: str, reason: str) -> None:
        self.console.print(
            f"[dim]{self._ts()}[/dim] [dim][SKIP][/dim] '{name}' — {reason}"
        )

    def module_end(self, name: str, finding_count: int) -> None:
        style = "green" if finding_count == 0 else "yellow"
        self.console.print(
            f"[dim]{self._ts()}[/dim] [bold cyan][*][/bold cyan] '{name}' "
            f"produced [{style}]{finding_count}[/{style}] finding(s)"
        )

    # ── Findings ─────────────────────────────────────────────────────────

    def finding(self, f: Finding) -> None:
        sev = f.severity
        self.console.print(
            f"[dim]{self._ts()}[/dim] [{sev.color}][{sev.value.upper()}][/{sev.color}] "
            f"[green]'{escape(f.module)}'[/green] {escape(f.title)} (score={f.score:.2f})"
        )
        if f.owasp_llm:
            self.console.print(f"         [dim]OWASP: {', '.join(f.owasp_llm)}[/dim]")
        if self.verbose and f.evidence.turns:
            for turn in f.evidence.turns:
                prefix = ">>>" if turn.role == "user" else "<<<"
                content_preview = turn.content[:200] + "..." if len(turn.content) > 200 else turn.content
                self.console.print(f"         [dim]{prefix} {escape(content_preview)}[/dim]")

    # ── Summary table ────────────────────────────────────────────────────

    def summary(self, findings: list[Finding], duration: float, request_count: int) -> None:
        self.console.print()

        # Count by severity
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            counts[f.severity.value] += 1

        # Risk score: weighted average + peak
        if findings:
            risk_score = sum(f.score * f.severity.weight for f in findings) / len(findings)
            peak_risk = max(f.score * f.severity.weight for f in findings)
        else:
            risk_score = 0.0
            peak_risk = 0.0

        table = Table(title="Scan Summary", border_style="cyan", show_header=True)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total Findings", str(len(findings)))
        table.add_row("Critical", f"[bold red]{counts['critical']}[/bold red]")
        table.add_row("High", f"[red]{counts['high']}[/red]")
        table.add_row("Medium", f"[yellow]{counts['medium']}[/yellow]")
        table.add_row("Low", f"[blue]{counts['low']}[/blue]")
        table.add_row("Info", f"[dim]{counts['info']}[/dim]")
        table.add_row("", "")
        table.add_row("Risk Score (avg)", f"[bold]{risk_score:.2f}[/bold] / 1.00")
        table.add_row("Peak Risk", f"[bold red]{peak_risk:.2f}[/bold red] / 1.00")
        table.add_row("Duration", f"{duration:.1f}s")
        table.add_row("HTTP Requests", str(request_count))

        self.console.print(table)

        # Findings detail table
        if findings:
            detail = Table(title="Findings", border_style="cyan", show_header=True)
            detail.add_column("#", style="dim", width=4)
            detail.add_column("Severity", width=10)
            detail.add_column("Conf.", width=11)
            detail.add_column("Module", width=22)
            detail.add_column("Title")
            detail.add_column("Score", justify="right", width=6)
            detail.add_column("OWASP", width=12)

            conf_style = {"verified": "bold green", "probable": "yellow", "indicative": "dim"}
            for i, f in enumerate(sorted(findings, key=lambda x: x.severity.weight, reverse=True), 1):
                detail.add_row(
                    str(i),
                    Text(f.severity.value.upper(), style=f.severity.color),
                    Text(f.confidence, style=conf_style.get(f.confidence, "dim")),
                    f.module,
                    f.title,
                    f"{f.score:.2f}",
                    ", ".join(f.owasp_llm) or "—",
                )

            self.console.print(detail)
