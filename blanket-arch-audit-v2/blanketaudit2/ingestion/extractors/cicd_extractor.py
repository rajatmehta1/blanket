"""CI/CD pipeline extractor — GitHub Actions and GitLab CI."""
from __future__ import annotations

import re
from typing import Any

import yaml
import structlog

logger = structlog.get_logger()

from pydantic import BaseModel


class CICDStep(BaseModel):
    """One step/job in a CI/CD pipeline."""
    name: str
    uses: str = ""         # GitHub Action: actions/checkout@v4
    run: str = ""          # Shell command
    image: str = ""        # Docker image for the step
    secrets_used: list[str] = []  # ${{ secrets.XXX }} references


class CICDPipeline(BaseModel):
    """Extracted CI/CD pipeline."""
    file_path: str
    platform: str          # "github_actions" or "gitlab_ci"
    triggers: list[str] = []  # push, pull_request, schedule, etc.
    jobs: list[str] = []
    steps: list[CICDStep] = []
    uses_secrets: bool = False
    has_security_scan: bool = False


class CICDExtractor:
    """Extract security-relevant info from CI/CD pipeline files."""

    def extract(self, file_path: str, content: str) -> CICDPipeline:
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            logger.warning("cicd_extractor.parse_error", file=file_path, error=str(exc)[:200])
            return CICDPipeline(file_path=file_path, platform="unknown")

        if not isinstance(data, dict):
            return CICDPipeline(file_path=file_path, platform="unknown")

        # Detect platform
        if "jobs" in data and ("on" in data or True in data):
            return self._extract_github_actions(file_path, data)
        elif "stages" in data or any(
            isinstance(v, dict) and "script" in v for v in data.values() if isinstance(v, dict)
        ):
            return self._extract_gitlab_ci(file_path, data)

        return CICDPipeline(file_path=file_path, platform="unknown")

    def _extract_github_actions(self, file_path: str, data: dict) -> CICDPipeline:
        pipeline = CICDPipeline(file_path=file_path, platform="github_actions")

        # Triggers
        on = data.get("on") or data.get(True, {})
        if isinstance(on, str):
            pipeline.triggers = [on]
        elif isinstance(on, list):
            pipeline.triggers = on
        elif isinstance(on, dict):
            pipeline.triggers = list(on.keys())

        # Jobs
        jobs = data.get("jobs", {})
        if isinstance(jobs, dict):
            pipeline.jobs = list(jobs.keys())

            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                steps = job_data.get("steps", [])
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    cicd_step = CICDStep(
                        name=step.get("name", ""),
                        uses=step.get("uses", ""),
                        run=step.get("run", ""),
                    )

                    # Detect secrets usage
                    step_str = str(step)
                    secrets = re.findall(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", step_str)
                    cicd_step.secrets_used = secrets
                    if secrets:
                        pipeline.uses_secrets = True

                    # Detect security scanning actions
                    uses = step.get("uses", "")
                    if any(s in uses.lower() for s in ("semgrep", "codeql", "snyk", "trivy", "gitleaks", "osv")):
                        pipeline.has_security_scan = True

                    pipeline.steps.append(cicd_step)

        return pipeline

    def _extract_gitlab_ci(self, file_path: str, data: dict) -> CICDPipeline:
        pipeline = CICDPipeline(file_path=file_path, platform="gitlab_ci")

        # Stages
        pipeline.triggers = data.get("stages", [])

        # Jobs (top-level keys that aren't reserved)
        reserved = {"stages", "variables", "image", "before_script", "after_script",
                     "cache", "services", "include", "default", "workflow"}

        for key, value in data.items():
            if key in reserved or not isinstance(value, dict):
                continue
            pipeline.jobs.append(key)

            scripts = value.get("script", [])
            if isinstance(scripts, str):
                scripts = [scripts]

            image = value.get("image", "")

            for script in scripts:
                step = CICDStep(
                    name=key,
                    run=script if isinstance(script, str) else str(script),
                    image=image if isinstance(image, str) else "",
                )
                pipeline.steps.append(step)

                # Check for security scans in scripts
                if isinstance(script, str) and any(s in script.lower() for s in ("semgrep", "trivy", "gitleaks", "osv-scanner")):
                    pipeline.has_security_scan = True

        return pipeline
