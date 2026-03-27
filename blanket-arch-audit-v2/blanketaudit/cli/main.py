"""Typer CLI — core commands: scan, report, policies, providers.

Design doc §18: CI/CD-friendly with isatty() detection, machine-readable
JSON output, and exit codes (0=pass, 1=findings, 2=error).
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    name="blanketaudit",
    help="AI-powered architecture governance platform.",
    no_args_is_help=True,
)
console = Console()

# Exit codes for CI/CD
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _is_ci() -> bool:
    """Detect CI/CD environment (non-interactive terminal)."""
    return not sys.stdout.isatty()


def _run_async(coro):
    """Run an async coroutine from sync CLI context."""
    return asyncio.run(coro)


# ═══════════════════════════════════════════════════════════════
# scan command
# ═══════════════════════════════════════════════════════════════


@app.command()
def scan(
    paths: Optional[list[Path]] = typer.Argument(
        None, help="Local directories or repos to scan.",
    ),
    config: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to audit.yaml config file.",
    ),
    repo: Optional[list[str]] = typer.Option(
        None, "--repo", "-r", help="Repository URL(s) to scan.",
    ),
    domain: Optional[str] = typer.Option(
        None, "--domain", "-d", help="Project domain (healthcare, finance, general).",
    ),
    framework: Optional[list[str]] = typer.Option(
        None, "--framework", "-f", help="Compliance frameworks: hipaa, soc2, pci-dss, gdpr.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Estimate cost without running agents.",
    ),
    output_format: Optional[list[str]] = typer.Option(
        None, "--format", help="Output formats: pdf, html, json, sarif.",
    ),
    output_path: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory for reports.",
    ),
    project_name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Project name for the report.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Output results as JSON (CI/CD mode).",
    ),
    max_cost: Optional[float] = typer.Option(
        None, "--max-cost", help="Maximum scan cost in USD.",
    ),
) -> None:
    """Run an architecture audit scan."""
    from blanketaudit.cli.config_loader import load_config
    from blanketaudit.metrics import setup_observability

    # Resolve CI mode
    ci_mode = json_output or _is_ci()

    if not ci_mode:
        console.print("\n[bold blue]BlanketAudit[/bold blue] — AI-Powered Architecture Audit\n")

    # Load config: audit.yaml → env → CLI flags
    cli_overrides: dict = {}
    if domain:
        cli_overrides["domain"] = domain
    if framework:
        cli_overrides["active_frameworks"] = framework
    if max_cost:
        cli_overrides["cost"] = {"max_scan_cost_usd": max_cost}
    if output_format:
        cli_overrides["output"] = {"formats": output_format}
    if output_path:
        cli_overrides["output"] = {**cli_overrides.get("output", {}), "path": str(output_path)}

    settings = load_config(yaml_path=config, cli_overrides=cli_overrides if cli_overrides else None)

    # Setup observability
    setup_observability(
        log_level=settings.log_level,
        log_json=ci_mode or settings.log_json,
    )

    # Build repo sources from CLI args
    repo_sources: list[dict] = []
    if paths:
        for p in paths:
            repo_sources.append({
                "name": p.name,
                "local_path": str(p.resolve()),
            })
    if repo:
        for r in repo:
            repo_sources.append({"url": r})

    if not repo_sources:
        if not ci_mode:
            console.print("[red]Error:[/red] No repos or paths specified.", style="bold")
            console.print("Usage: blanketaudit scan ./path/to/repo")
        raise typer.Exit(EXIT_ERROR)

    # Build initial pipeline state
    state = {
        "project_name": project_name or (paths[0].name if paths else "audit"),
        "domain": settings.domain,
        "frameworks": settings.active_frameworks,
        "repo_sources": repo_sources,
        "dry_run": dry_run,
        "config": settings.model_dump(),
    }

    # Run pipeline
    try:
        result = _run_async(_run_scan(state, settings, dry_run, ci_mode))
    except Exception as exc:
        if ci_mode:
            print(json.dumps({"error": str(exc), "status": "failed"}))
        else:
            console.print(f"\n[red]Error:[/red] {exc}", style="bold")
        raise typer.Exit(EXIT_ERROR)

    # Output results
    exit_code = _output_results(result, ci_mode, dry_run, output_format, output_path)
    raise typer.Exit(exit_code)


async def _run_scan(state: dict, settings, dry_run: bool, ci_mode: bool) -> dict:
    """Run the audit pipeline."""
    from blanketaudit.orchestrator.pipeline import AuditPipeline

    pipeline = AuditPipeline()
    pipeline.build()
    result = await pipeline.run(state)
    return result


def _output_results(
    result: dict,
    ci_mode: bool,
    dry_run: bool,
    formats: list[str] | None,
    output_dir: Path | None,
) -> int:
    """Display results and generate reports. Returns exit code."""
    status = result.get("status", "unknown")
    health = result.get("health_score", {})
    score = health.get("overall", 0)
    grade = health.get("grade", "?")
    findings = result.get("validated_findings", result.get("findings", []))
    severity_counts = health.get("severity_counts", {})

    # Dry-run: show cost estimate
    if dry_run or status == "aborted":
        estimate = result.get("cost_estimate", {})
        if ci_mode:
            print(json.dumps(estimate, indent=2, default=str))
        else:
            from blanketaudit.orchestrator.cost_estimator import format_estimate_table
            console.print(format_estimate_table(estimate))
        return EXIT_OK

    # CI/CD JSON mode
    if ci_mode:
        from blanketaudit.report.json_exporter import JSONExporter
        exporter = JSONExporter()
        report_dict = result.get("report", result)
        print(exporter.to_summary_json(report_dict))
        has_critical = severity_counts.get("critical", 0) > 0
        return EXIT_FINDINGS if has_critical else EXIT_OK

    # Rich console output
    _print_summary(score, grade, severity_counts, findings)

    # Generate report files
    if formats or output_dir:
        report_dict = result.get("report", result)
        _generate_reports(report_dict, formats or ["json"], output_dir or Path("./audit-report"))

    has_critical = severity_counts.get("critical", 0) > 0
    return EXIT_FINDINGS if has_critical else EXIT_OK


def _print_summary(score: int, grade: str, severity_counts: dict, findings: list) -> None:
    """Print a Rich summary to the terminal."""
    color = "green" if score >= 70 else "yellow" if score >= 50 else "red"

    console.print(f"\n[bold]Health Score:[/bold] [{color}]{score}/100 (Grade {grade})[/{color}]")

    table = Table(title="Severity Breakdown", show_header=True, header_style="bold")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_counts.get(sev, 0)
        sev_color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}.get(sev, "white")
        table.add_row(f"[{sev_color}]{sev}[/{sev_color}]", str(count))
    console.print(table)

    if findings:
        console.print(f"\n[bold]Top findings:[/bold]")
        for f in findings[:5]:
            sev = f.get("severity", f.severity if hasattr(f, "severity") else "?")
            title = f.get("title", f.title if hasattr(f, "title") else "?")
            fid = f.get("id", f.id if hasattr(f, "id") else "?")
            console.print(f"  [{sev}] {fid}: {title}")


def _generate_reports(report: dict, formats: list[str], output_dir: Path) -> None:
    """Generate report files in requested formats."""
    output_dir.mkdir(parents=True, exist_ok=True)

    for fmt in formats:
        try:
            if fmt == "json":
                from blanketaudit.report.json_exporter import JSONExporter
                path = JSONExporter().export(report, output_dir / "report.json")
                console.print(f"  [green]✓[/green] JSON: {path}")
            elif fmt == "sarif":
                from blanketaudit.report.sarif_exporter import SARIFExporter
                path = SARIFExporter().export(report, output_dir / "report.sarif")
                console.print(f"  [green]✓[/green] SARIF: {path}")
            elif fmt == "html":
                from blanketaudit.report.html_generator import HTMLGenerator
                path = HTMLGenerator().generate_to_file(report, output_dir / "report.html")
                console.print(f"  [green]✓[/green] HTML: {path}")
            elif fmt == "pdf":
                from blanketaudit.report.pdf_generator import PDFReportGenerator
                path = PDFReportGenerator().generate_to_file(report, output_dir / "report.pdf")
                console.print(f"  [green]✓[/green] PDF: {path}")
        except Exception as exc:
            console.print(f"  [red]✗[/red] {fmt}: {exc}")


# ═══════════════════════════════════════════════════════════════
# report command
# ═══════════════════════════════════════════════════════════════


@app.command()
def report(
    scan_id: str = typer.Argument(..., help="Scan ID to regenerate report for."),
    output_format: Optional[list[str]] = typer.Option(
        None, "--format", help="Output formats: pdf, html, json, sarif.",
    ),
    output_path: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output directory.",
    ),
) -> None:
    """Regenerate a report from a previous scan."""
    console.print(f"[bold]Regenerating report for scan:[/bold] {scan_id}")

    async def _regen():
        from blanketaudit.storage import get_scan_store
        store = await get_scan_store()
        scan = await store.get_scan(scan_id)
        if scan is None:
            console.print(f"[red]Scan not found:[/red] {scan_id}")
            raise typer.Exit(EXIT_ERROR)
        report_data = scan.get("report", scan.get("manifest", {}))
        _generate_reports(
            report_data,
            output_format or ["json", "html"],
            output_path or Path("./audit-report"),
        )

    _run_async(_regen())


# ═══════════════════════════════════════════════════════════════
# policies command
# ═══════════════════════════════════════════════════════════════


@app.command()
def policies(
    list_all: bool = typer.Option(False, "--list", help="List all loaded policies."),
    validate: bool = typer.Option(False, "--validate", help="Validate policy YAML files."),
    category: Optional[str] = typer.Option(None, "--category", help="Filter by category."),
) -> None:
    """List and validate audit policies."""
    from blanketaudit.policies.engine import PolicyEngine

    engine = PolicyEngine()
    policy_dir = Path(__file__).parent.parent / "policies"

    categories = {category} if category else None
    loaded = engine.load_policies(policy_dir, categories=categories)

    if validate:
        console.print(f"[green]✓[/green] {len(loaded)} policies validated successfully.")
        invalid = engine.policy_count - len(loaded) if hasattr(engine, '_policies') else 0
        if invalid:
            console.print(f"[yellow]⚠[/yellow] {invalid} policies had validation errors.")
        return

    table = Table(title=f"Policies ({len(loaded)})", show_header=True)
    table.add_column("ID", style="cyan")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Name")
    table.add_column("Frameworks", style="dim")

    for p in sorted(loaded, key=lambda x: (x.category, x.id)):
        sev_color = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}.get(p.severity, "white")
        table.add_row(
            p.id,
            p.category,
            f"[{sev_color}]{p.severity}[/{sev_color}]",
            p.name[:50],
            ", ".join(p.frameworks[:3]) or "—",
        )

    console.print(table)


# ═══════════════════════════════════════════════════════════════
# providers command
# ═══════════════════════════════════════════════════════════════


@app.command()
def providers(
    check: bool = typer.Option(False, "--check", help="Test provider connectivity."),
) -> None:
    """Show and test LLM/embedding provider configuration."""
    from blanketaudit.config import get_settings

    settings = get_settings()

    table = Table(title="Provider Configuration", show_header=True)
    table.add_column("Component")
    table.add_column("Provider")
    table.add_column("Model")
    table.add_column("Status")

    llm_status = "[green]configured[/green]" if settings.llm.provider.value != "none" else "[dim]disabled[/dim]"
    emb_status = "[green]configured[/green]" if settings.embedding.provider.value != "none" else "[dim]disabled[/dim]"

    table.add_row("LLM", settings.llm.provider.value, settings.llm.model or "(default)", llm_status)
    if settings.llm.compliance_model:
        table.add_row("LLM (compliance)", settings.llm.provider.value, settings.llm.compliance_model, llm_status)
    table.add_row("Embeddings", settings.embedding.provider.value, settings.embedding.model or "(default)", emb_status)

    console.print(table)

    if check:
        console.print("\n[bold]Connectivity check:[/bold]")
        _run_async(_check_providers(settings))


async def _check_providers(settings) -> None:
    """Test provider connectivity."""
    # Check external tools
    tools = [
        ("Semgrep", "blanketaudit.agents.tools.semgrep_tool", "check_semgrep_installed"),
        ("Gitleaks", "blanketaudit.agents.tools.gitleaks_tool", "check_gitleaks_installed"),
        ("OSV-scanner", "blanketaudit.agents.tools.osv_tool", "check_osv_installed"),
    ]
    for name, module, func_name in tools:
        try:
            import importlib
            mod = importlib.import_module(module)
            check_fn = getattr(mod, func_name)
            available = await check_fn()
            status = "[green]✓ installed[/green]" if available else "[yellow]✗ not found[/yellow]"
        except Exception:
            status = "[red]✗ error[/red]"
        console.print(f"  {name}: {status}")

    # Check LLM
    if settings.llm.provider.value != "none":
        try:
            from blanketaudit.llm.provider import get_llm
            llm = get_llm()
            status = "[green]✓ loaded[/green]" if llm else "[yellow]✗ failed[/yellow]"
        except Exception as exc:
            status = f"[red]✗ {str(exc)[:50]}[/red]"
        console.print(f"  LLM ({settings.llm.provider.value}): {status}")


# ═══════════════════════════════════════════════════════════════
# version callback
# ═══════════════════════════════════════════════════════════════


def _version_callback(value: bool) -> None:
    if value:
        from blanketaudit import __version__
        print(f"blanketaudit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", callback=_version_callback,
        help="Show version and exit.",
    ),
) -> None:
    """BlanketAudit — AI-powered architecture governance platform."""
    pass


if __name__ == "__main__":
    app()
