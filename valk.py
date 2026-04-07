"""Valk — LLM Red Team Assessment Framework CLI."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from core.engine import ScanEngine
from core.logger import ValkLogger
from core.models import ScanConfig
from core.reporter import Reporter

app = typer.Typer(
    name="valk",
    help="Valk — LLM Red Team Assessment Framework v0.3.0",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target LLM API base URL (e.g. http://localhost:11434)"),
    phase: Optional[list[str]] = typer.Option(None, "--phase", "-p", help="Phases to run (recon, fingerprint, attack)"),
    module: Optional[list[str]] = typer.Option(None, "--module", "-m", help="Module filter (supports * wildcard)"),
    skip: Optional[list[str]] = typer.Option(None, "--skip", help="Modules to skip"),
    stealth: bool = typer.Option(False, "--stealth", "-s", help="Stealth mode — slower, randomized delays, benign prefixes"),
    jailbreak_level: int = typer.Option(2, "--jailbreak-level", "-j", min=1, max=3, help="Jailbreak aggressiveness (1=safe, 2=moderate, 3=aggressive)"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="API key for authenticated endpoints (or set VALK_API_KEY env var)"),
    auth_header: str = typer.Option("Authorization", "--auth-header", help="Header name for API key"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP proxy URL"),
    model_hint: Optional[str] = typer.Option(None, "--model-hint", help="Hint model family (gpt, mistral, llama, ...)"),
    output_dir: str = typer.Option("reports/", "--output", "-o", help="Output directory for reports"),
    output_format: str = typer.Option("json", "--format", "-f", help="Report format: json, html, or sarif"),
    timeout: float = typer.Option(120.0, "--timeout", "-t", help="HTTP request timeout in seconds"),
    max_tokens: int = typer.Option(4096, "--max-tokens", help="Max tokens per LLM response (reasoning models need 4096+)"),
    speed: str = typer.Option("auto", "--speed", help="Payload budget: fast (25% payloads), auto (adapts to model speed), thorough (all payloads)"),
    min_confidence: Optional[str] = typer.Option(None, "--min-confidence", help="Minimum confidence for report: verified, probable, or indicative"),
    interactsh: Optional[str] = typer.Option(None, "--interactsh", help="Interactsh server URL for OOB callback verification (e.g. https://oast.fun)"),
    payload_pack: Optional[list[str]] = typer.Option(None, "--payload-pack", help="External payload pack directories (can be specified multiple times)"),
    regression: bool = typer.Option(False, "--regression", help="Run regression mode (deterministic payloads + diff report)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show planned modules without executing"),
    provider: Optional[str] = typer.Option(None, "--provider", help="API provider: openai (default), anthropic, gemini (auto-detected from URL if omitted)"),
    attack_max_tokens: Optional[int] = typer.Option(None, "--attack-max-tokens", help="Token cap per attack probe (default: 1024 for thinking models, unlimited otherwise)"),
) -> None:
    """Run an LLM red team assessment against a target."""
    # Resolve API key: CLI flag takes priority, then environment variable
    effective_api_key = api_key or os.environ.get("VALK_API_KEY")

    # Resolve provider: explicit flag > auto-detect from URL
    from core.providers import detect_provider, SUPPORTED_PROVIDERS, _BROWSER_SETUP_HINT
    if provider:
        effective_provider = provider.lower()
        if effective_provider not in SUPPORTED_PROVIDERS:
            console.print(f"[bold red]Error:[/bold red] Unknown provider '{effective_provider}'. "
                          f"Supported: {', '.join(SUPPORTED_PROVIDERS)}")
            raise typer.Exit(1)
    else:
        effective_provider, is_browser = detect_provider(target)
        if is_browser:
            console.print(f"\n[bold yellow]Browser-only target detected:[/bold yellow] {target}\n")
            console.print(_BROWSER_SETUP_HINT)
            raise typer.Exit(1)

    config = ScanConfig(
        target_url=target.rstrip("/"),
        output_dir=output_dir,
        output_format=output_format,
        modules=list(module) if module else None,
        skip=list(skip) if skip else [],
        phases=phase,
        stealth=stealth,
        api_key=effective_api_key,
        auth_header=auth_header,
        proxy=proxy,
        verbose=verbose,
        timeout=timeout,
        max_tokens=max_tokens,
        model_hint=model_hint,
        jailbreak_level=jailbreak_level,
        speed=speed,
        min_confidence=min_confidence,
        interactsh_url=interactsh,
        payload_packs=list(payload_pack) if payload_pack else [],
        provider=effective_provider,
        attack_max_tokens=attack_max_tokens,
    )

    log = ValkLogger(verbose=verbose)

    if dry_run:
        _show_dry_run(config, log)
        return

    if regression:
        _run_regression(config, log)
        return

    # Run scan
    engine = ScanEngine(config, log)
    ctx = asyncio.run(engine.run())

    # Generate report
    reporter = Reporter(ctx, config)
    report_path = reporter.generate()

    console.print()
    console.print(f"[bold green]Report saved:[/bold green] {report_path}")
    console.print(f"[dim]Findings: {len(ctx.findings)} | Errors: {len(ctx.errors)} | Requests: {ctx.total_requests}[/dim]")


def _show_dry_run(config: ScanConfig, log: ValkLogger) -> None:
    """Show what modules would run without executing."""
    from core.engine import MODULE_ORDER, Phase, PHASE_ORDER

    console.print()
    console.print("[bold cyan]DRY RUN[/bold cyan] — planned execution:")
    console.print(f"  Target: {config.target_url}")
    console.print(f"  Jailbreak level: {config.jailbreak_level}")
    console.print(f"  Stealth: {config.stealth}")
    console.print(f"  Speed: {config.speed}")
    console.print()

    phases = PHASE_ORDER
    if config.phases:
        phases = [p for p in PHASE_ORDER if p.value in config.phases]

    for phase in phases:
        console.print(f"[bold cyan]{phase.value.upper()}[/bold cyan]")
        for mod_name in MODULE_ORDER.get(phase, []):
            if config.modules:
                import fnmatch
                if not any(fnmatch.fnmatch(mod_name, f) for f in config.modules):
                    console.print(f"  [dim]SKIP {mod_name}[/dim]")
                    continue
            console.print(f"  [green]  >> {mod_name}[/green]")
        console.print()


def _run_regression(config: ScanConfig, log: ValkLogger) -> None:
    """Run regression mode with deterministic payloads."""
    from core.regression import RegressionRunner
    from core.models import ScanContext

    async def _async_regression() -> dict:
        runner = RegressionRunner(config, log)
        async with Session(config) as session:
            ctx = ScanContext(target_url=config.target_url)
            # Discover chat endpoint
            try:
                resp = await session.post(
                    "/v1/chat/completions",
                    json={"messages": [{"role": "user", "content": "hi"}], "max_tokens": 5},
                )
                if resp.status_code == 200:
                    ctx.chat_endpoint = "/v1/chat/completions"
            except Exception:
                pass
            return await runner.run(session, ctx)

    from core.session import Session

    console.print()
    console.print("[bold cyan]REGRESSION MODE[/bold cyan]")
    console.print(f"Target: {config.target_url}")
    console.print()

    result = asyncio.run(_async_regression())

    diff = result.get("diff")
    if diff:
        s = diff["summary"]
        console.print()
        console.print(f"[bold]Regression Results:[/bold]")
        console.print(f"  [green]Improved:[/green]  {s['improved_count']}")
        console.print(f"  [red]Regressed:[/red] {s['regressed_count']}")
        console.print(f"  [dim]Unchanged:[/dim] {s['unchanged_count']}")
        console.print(f"  [cyan]New:[/cyan]       {s['new_count']}")
    else:
        console.print("[dim]First regression run — baseline established.[/dim]")


@app.command()
def version() -> None:
    """Show Valk version."""
    console.print("[bold cyan]Valk[/bold cyan] v0.3.0 — LLM Red Team Assessment Framework")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
