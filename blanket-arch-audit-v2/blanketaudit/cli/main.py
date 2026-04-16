import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
import typer
from rich.console import Console
from rich.table import Table

load_dotenv()

app = typer.Typer(
    name="blanket-audit",
    help="AI-powered architecture governance platform.",
    no_args_is_help=True,
)

console = Console()
# exit codes
EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

def _is_ci() -> bool:
    """Detect CI/CD environment (non-interactive terminal)."""
    return not sys.stdout.isatty()


def _run_async(coro):
    """Run an async coroutine from sync CLI context."""
    return asyncio.run(coro)

# scan command
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
    """Run an architecture audit scan"""
    from blanketaudit.cli.config_loader import load_config
    from blanketaudit.metrics import setup_observability

    #is script running from command prompt or from ci/cd -- this is very important
    _is_ci =


