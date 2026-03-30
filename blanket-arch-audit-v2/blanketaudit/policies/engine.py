"""YAML policy loader + dual-layer executor.

Design doc §4: each policy has static_checks (deterministic) that run FIRST,
then ai_analysis (LLM) that filters false positives and adds context.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import structlog
import yaml

from blanketaudit.exceptions import PolicyError
from blanketaudit.policies.schema import Policy, StaticCheck, validate_policy_dict

logger = structlog.get_logger()


# ── Static check result ──────────────────────────────────────


class StaticCandidate:
    """A candidate finding produced by a static check (before AI filtering)."""

    def __init__(
        self,
        policy_id: str,
        file_path: str,
        line_start: int,
        line_end: int,
        code_snippet: str,
        tool: str,
        message: str = "",
    ) -> None:
        self.policy_id = policy_id
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.code_snippet = code_snippet
        self.tool = tool
        self.message = message

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "tool": self.tool,
            "message": self.message,
        }


# ── Policy engine ────────────────────────────────────────────


class PolicyEngine:
    """Load policies from YAML files and execute dual-layer analysis."""

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}

    @property
    def policies(self) -> list[Policy]:
        return list(self._policies.values())

    @property
    def policy_count(self) -> int:
        return len(self._policies)

    # ── Loading ──────────────────────────────────────────────

    def load_policies(
        self,
        policy_dir: str | Path,
        *,
        categories: set[str] | None = None,
        frameworks: set[str] | None = None,
    ) -> list[Policy]:
        """Load and validate YAML policies from a directory.

        Parameters
        ----------
        policy_dir:
            Directory containing policy YAML files (recursive).
        categories:
            If provided, only load policies matching these categories.
        frameworks:
            If provided, only load policies that reference these frameworks.

        Returns
        -------
        List of valid ``Policy`` objects.  Invalid files are logged and skipped.
        """
        policy_dir = Path(policy_dir)
        if not policy_dir.is_dir():
            raise PolicyError(
                f"Policy directory does not exist: {policy_dir}",
                details={"path": str(policy_dir)},
            )

        loaded: list[Policy] = []

        for yaml_file in sorted(policy_dir.rglob("*.y*ml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                logger.warning(
                    "policy.parse_error",
                    file=str(yaml_file),
                    error=str(exc)[:200],
                )
                continue

            if not isinstance(data, dict):
                continue

            policy = validate_policy_dict(data)
            if policy is None:
                logger.warning("policy.validation_failed", file=str(yaml_file))
                continue

            # Filter by category
            if categories and policy.category not in categories:
                continue

            # Filter by framework
            if frameworks and not any(
                any(fw_filter.lower() in fw.lower() for fw_filter in frameworks)
                for fw in policy.frameworks
            ):
                # No framework match — skip unless policy has no frameworks
                if policy.frameworks:
                    continue

            self._policies[policy.id] = policy
            loaded.append(policy)

        logger.info(
            "policy.loaded",
            count=len(loaded),
            dir=str(policy_dir),
        )
        return loaded

    def load_policy_from_dict(self, data: dict) -> Policy | None:
        """Load a single policy from a dict (for testing)."""
        policy = validate_policy_dict(data)
        if policy:
            self._policies[policy.id] = policy
        return policy

    def get_policy(self, policy_id: str) -> Policy | None:
        return self._policies.get(policy_id)

    # ── Static check execution ───────────────────────────────

    def execute_static_checks(
        self,
        policy: Policy,
        file_contents: dict[str, str],
    ) -> list[StaticCandidate]:
        """Run deterministic static checks for a policy.

        Parameters
        ----------
        policy:
            The policy whose ``static_checks`` to execute.
        file_contents:
            ``{file_path: source_code}`` mapping.

        Returns
        -------
        List of candidate findings (before AI filtering).
        """
        candidates: list[StaticCandidate] = []

        # Filter files by policy's file_patterns (if specified).
        # This prevents e.g. Docker policies from scanning .py files.
        filtered_contents = self._filter_files(policy, file_contents)

        for check in policy.static_checks:
            if check.tool == "regex" and check.regex:
                candidates.extend(
                    self._run_regex_check(policy, check, filtered_contents)
                )
            elif check.tool == "ast" and check.pattern:
                candidates.extend(
                    self._run_ast_check(policy, check, filtered_contents)
                )
            # semgrep, gitleaks, osv are run via subprocess tools
            # (handled by agent tools, not inline here)

        logger.info(
            "policy.static_candidates",
            policy_id=policy.id,
            count=len(candidates),
        )
        return candidates

    @staticmethod
    def _filter_files(
        policy: Policy,
        file_contents: dict[str, str],
    ) -> dict[str, str]:
        """Filter file_contents to only files matching policy.file_patterns.

        If policy.file_patterns is empty, all files are included (backward compat).
        """
        if not policy.file_patterns:
            return file_contents

        filtered: dict[str, str] = {}
        for file_path, content in file_contents.items():
            # Normalize path separators for cross-platform matching
            normalized = file_path.replace("\\", "/")
            for pattern in policy.file_patterns:
                if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(
                    normalized.split("/")[-1], pattern.split("/")[-1]
                ):
                    filtered[file_path] = content
                    break
        return filtered

    def _run_regex_check(
        self,
        policy: Policy,
        check: StaticCheck,
        file_contents: dict[str, str],
    ) -> list[StaticCandidate]:
        """Run a regex-based static check across all files."""
        candidates: list[StaticCandidate] = []
        try:
            pattern = re.compile(check.regex, re.MULTILINE | re.IGNORECASE)
        except re.error as exc:
            logger.warning(
                "policy.bad_regex",
                policy_id=policy.id,
                regex=check.regex,
                error=str(exc),
            )
            return candidates

        for file_path, content in file_contents.items():
            for match in pattern.finditer(content):
                line_num = content[:match.start()].count("\n") + 1
                snippet_start = max(0, match.start() - 50)
                snippet_end = min(len(content), match.end() + 50)
                candidates.append(StaticCandidate(
                    policy_id=policy.id,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=content[snippet_start:snippet_end],
                    tool="regex",
                    message=f"Regex match: {match.group(0)[:100]}",
                ))

        return candidates

    def _run_ast_check(
        self,
        policy: Policy,
        check: StaticCheck,
        file_contents: dict[str, str],
    ) -> list[StaticCandidate]:
        """Run an AST pattern check.

        This is a simplified in-process check.  For full AST analysis,
        the agent tools use tree-sitter directly.
        """
        candidates: list[StaticCandidate] = []
        if not check.pattern:
            return candidates

        # For AST checks with text_matches conditions, we fall back to
        # regex matching as a heuristic (full tree-sitter matching is
        # done by the agent tools).
        for cond in check.pattern.conditions:
            if cond.text_matches:
                try:
                    pattern = re.compile(cond.text_matches, re.MULTILINE | re.IGNORECASE)
                except re.error:
                    continue
                for file_path, content in file_contents.items():
                    for match in pattern.finditer(content):
                        line_num = content[:match.start()].count("\n") + 1
                        candidates.append(StaticCandidate(
                            policy_id=policy.id,
                            file_path=file_path,
                            line_start=line_num,
                            line_end=line_num,
                            code_snippet=match.group(0)[:200],
                            tool="ast",
                            message=f"AST pattern match: {check.pattern.node_type}",
                        ))

        return candidates

    # ── AI analysis execution ────────────────────────────────

    async def execute_ai_analysis(
        self,
        policy: Policy,
        candidates: list[StaticCandidate],
        llm: Any,
    ) -> list[dict]:
        """Send static candidates to LLM for contextual analysis.

        Parameters
        ----------
        policy:
            The policy (contains ``ai_analysis.prompt_template``).
        candidates:
            Output of ``execute_static_checks``.
        llm:
            A LangChain ``BaseChatModel``.

        Returns
        -------
        List of enriched finding dicts (ready for validation pipeline).
        """
        if not policy.ai_analysis or not candidates or llm is None:
            # No AI → return candidates as-is (static-only)
            return [c.to_dict() for c in candidates]

        from langchain_core.messages import HumanMessage, SystemMessage

        results: list[dict] = []
        template = policy.ai_analysis.prompt_template

        for candidate in candidates:
            prompt = template.replace("{code_context}", candidate.code_snippet)
            prompt = prompt.replace("{file_path}", candidate.file_path)

            try:
                response = await llm.ainvoke([
                    SystemMessage(content="You are an expert code auditor."),
                    HumanMessage(content=prompt),
                ])
                # The LLM response should be parsed by the output validator
                # Here we return the raw candidate + LLM assessment
                results.append({
                    **candidate.to_dict(),
                    "ai_response": response.content,
                })
            except Exception as exc:
                logger.warning(
                    "policy.ai_analysis_failed",
                    policy_id=policy.id,
                    error=str(exc)[:200],
                )
                # Graceful degradation: keep the static candidate
                results.append(candidate.to_dict())

        return results

    # ── Full dual-layer execution ────────────────────────────

    async def execute_policy(
        self,
        policy: Policy,
        file_contents: dict[str, str],
        llm: Any = None,
    ) -> list[dict]:
        """Execute full dual-layer analysis for one policy.

        1. Run static checks (deterministic).
        2. Run AI analysis on candidates (contextual, if LLM available).

        Returns list of finding dicts.
        """
        # Layer 1: Static
        candidates = self.execute_static_checks(policy, file_contents)

        if not candidates:
            return []

        # Layer 2: AI (graceful degradation if no LLM)
        if llm is not None and policy.ai_analysis:
            return await self.execute_ai_analysis(policy, candidates, llm)

        # Static-only fallback
        return [c.to_dict() for c in candidates]
