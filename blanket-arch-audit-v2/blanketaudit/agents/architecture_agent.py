"""Architecture agent — dep graph + call graph + layer inference → AI.

Design doc §5.3: analyse file-level dependency graph and method-level
call graph to detect circular deps, layer violations, God classes,
tight coupling, and missing abstractions.

Guardrails:
- Don't flag monorepo cross-package imports as violations
- Don't flag generated code (protobuf, codegen, migrations)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

import structlog

from blanketaudit.agents.base_agent import BaseAgent
from blanketaudit.llm.guardrails import INJECTION_DEFENSE_PREFIX, wrap_code_content
from blanketaudit.llm.resilience import safe_llm_call
from blanketaudit.models.finding import AuditFinding
from blanketaudit.orchestrator.state import AuditState

logger = structlog.get_logger()

# ── Layer inference from folder structure ────────────────────

_LAYER_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("presentation", re.compile(r"(routes?|controllers?|handlers?|views?|endpoints?|api)[/\\]", re.I)),
    ("business", re.compile(r"(services?|use.?cases?|domain|business|managers?|providers?)[/\\]", re.I)),
    ("data", re.compile(r"(repositories?|stores?|dao|db|database|models?|entities)[/\\]", re.I)),
    ("infrastructure", re.compile(r"(infra|config|utils?|helpers?|common|shared|lib)[/\\]", re.I)),
]

# Generated code patterns — skip these
_GENERATED_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"_pb2\.py$", r"_pb2_grpc\.py$", r"\.generated\.",
        r"codegen", r"auto.?gen", r"migration", r"alembic/versions",
        r"\.min\.(js|css)$", r"\.d\.ts$", r"vendor/", r"node_modules/",
    )
]

# Monorepo package patterns — don't flag cross-package imports
_MONOREPO_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"packages/[^/]+/", r"services/[^/]+/", r"libs/[^/]+/",
        r"apps/[^/]+/", r"modules/[^/]+/",
    )
]

# Finding ID counter
_COUNTER = 0


def _next_id() -> str:
    global _COUNTER
    _COUNTER += 1
    return f"BLK-{_COUNTER:03d}"


def _reset_counter(start: int = 0) -> None:
    global _COUNTER
    _COUNTER = start


def _is_generated(path: str) -> bool:
    return any(p.search(path) for p in _GENERATED_PATTERNS)


def _is_monorepo_cross_package(source: str, target: str) -> bool:
    """Check if import is cross-package in a monorepo (not a violation)."""
    for pattern in _MONOREPO_PATTERNS:
        s_match = pattern.search(source)
        t_match = pattern.search(target)
        if s_match and t_match:
            # Both in recognized package dirs — cross-package is OK
            return True
    return False


def infer_layer(file_path: str) -> str:
    """Infer the architectural layer from a file path."""
    for layer_name, pattern in _LAYER_PATTERNS:
        if pattern.search(file_path):
            return layer_name
    return "unknown"


class ArchitectureAgent(BaseAgent):
    """Architecture analysis agent.

    Static: build dep graph, detect cycles, infer layers, find God classes.
    AI: assess coupling, detect anti-patterns, suggest refactoring.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__("architecture", **kwargs)

    # ── Static checks ────────────────────────────────────────

    async def run_static_checks(self, state: AuditState) -> list[AuditFinding]:
        """Run architecture static analysis.

        1. Infer layers from folder structure
        2. Detect circular dependencies
        3. Detect layer violations (data → presentation)
        4. Detect God classes (>20 methods or >500 LOC)
        5. Run architecture policies
        """
        findings: list[AuditFinding] = []
        files = state.get("files", [])
        repo_name = ""
        if state.get("repo_paths"):
            repo_name = state["repo_paths"][0].get("repo_name", "")

        # Build layer map
        layer_map = self._build_layer_map(files)

        # Build import graph from analysis contexts
        import_graph = self._build_import_graph(state)

        # Detect circular dependencies
        findings.extend(self._detect_cycles(import_graph, repo_name))

        # Detect layer violations
        findings.extend(self._detect_layer_violations(import_graph, layer_map, repo_name))

        # Detect God classes
        findings.extend(self._detect_god_classes(state, repo_name))

        # Run architecture policies
        findings.extend(await self._run_policy_checks(state))

        logger.info("architecture_agent.static_done", findings=len(findings))
        return findings

    def _build_layer_map(self, files: list[dict]) -> dict[str, str]:
        """Assign each file to an architectural layer."""
        layer_map: dict[str, str] = {}
        for f in files:
            path = f.get("path", "")
            if not _is_generated(path):
                layer_map[path] = infer_layer(path)
        return layer_map

    def _build_import_graph(self, state: AuditState) -> dict[str, set[str]]:
        """Build file→imports graph from analysis contexts."""
        graph: dict[str, set[str]] = defaultdict(set)
        for ctx in state.get("analysis_contexts", []):
            if isinstance(ctx, dict):
                imports = ctx.get("imports", [])
            else:
                imports = getattr(ctx, "imports", [])

            for imp in imports:
                if isinstance(imp, dict):
                    source = imp.get("source_file", "")
                    module = imp.get("imported_module", "")
                else:
                    source = getattr(imp, "source_file", "")
                    module = getattr(imp, "imported_module", "")

                if source and module:
                    # Convert module to approximate file path
                    target = module.replace(".", "/") + ".py"
                    graph[source].add(target)

        return dict(graph)

    def _detect_cycles(
        self,
        import_graph: dict[str, set[str]],
        repo_name: str,
    ) -> list[AuditFinding]:
        """Detect circular import dependencies."""
        findings: list[AuditFinding] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []
        found_cycles: list[list[str]] = []

        for node in import_graph:
            if node not in visited:
                self._dfs_cycles(node, import_graph, visited, rec_stack, path, found_cycles)

        for cycle in found_cycles[:10]:  # Cap at 10
            if any(_is_generated(f) for f in cycle):
                continue
            findings.append(self._make_static_finding(
                finding_id=_next_id(),
                policy_id="ARCH-001",
                title=f"Circular dependency: {' → '.join(c.split('/')[-1] for c in cycle[:4])}",
                description=f"Circular import chain: {' → '.join(cycle)}",
                severity="high",
                category="architecture",
                file_path=cycle[0],
                repo_name=repo_name,
                line_start=1, line_end=1,
                code_snippet=" → ".join(cycle),
                tool="dep_graph",
                confidence=0.9,
            ))

        return findings

    def _dfs_cycles(
        self,
        node: str,
        graph: dict[str, set[str]],
        visited: set[str],
        rec_stack: set[str],
        path: list[str],
        cycles: list[list[str]],
    ) -> None:
        if len(cycles) >= 10:
            return
        visited.add(node)
        rec_stack.add(node)
        path.append(node)

        for neighbor in graph.get(node, set()):
            if neighbor not in visited:
                self._dfs_cycles(neighbor, graph, visited, rec_stack, path, cycles)
            elif neighbor in rec_stack:
                idx = path.index(neighbor) if neighbor in path else -1
                if idx >= 0:
                    cycles.append(path[idx:] + [neighbor])

        path.pop()
        rec_stack.discard(node)

    def _detect_layer_violations(
        self,
        import_graph: dict[str, set[str]],
        layer_map: dict[str, str],
        repo_name: str,
    ) -> list[AuditFinding]:
        """Detect imports that violate the layered architecture.

        Violations: data → presentation, infrastructure → presentation,
        data → business (sometimes OK, depends on pattern).
        """
        findings: list[AuditFinding] = []
        # Lower layers should NOT import from higher layers
        layer_rank = {"presentation": 0, "business": 1, "data": 2, "infrastructure": 3, "unknown": 4}

        violations = [
            ("data", "presentation"),
            ("infrastructure", "presentation"),
        ]

        for source, targets in import_graph.items():
            if _is_generated(source):
                continue
            source_layer = layer_map.get(source, "unknown")

            for target in targets:
                if _is_generated(target):
                    continue
                if _is_monorepo_cross_package(source, target):
                    continue

                target_layer = layer_map.get(target, "unknown")

                for bad_from, bad_to in violations:
                    if source_layer == bad_from and target_layer == bad_to:
                        findings.append(self._make_static_finding(
                            finding_id=_next_id(),
                            policy_id="ARCH-003",
                            title=f"Layer violation: {source_layer} → {target_layer}",
                            description=(
                                f"{source} ({source_layer} layer) imports from "
                                f"{target} ({target_layer} layer). "
                                f"Lower layers should not depend on higher layers."
                            ),
                            severity="high",
                            category="architecture",
                            file_path=source,
                            repo_name=repo_name,
                            line_start=1, line_end=1,
                            code_snippet=f"import from {target}",
                            tool="layer_analysis",
                            confidence=0.8,
                        ))

        return findings

    def _detect_god_classes(
        self,
        state: AuditState,
        repo_name: str,
    ) -> list[AuditFinding]:
        """Detect classes with too many methods or too many lines."""
        findings: list[AuditFinding] = []

        for ctx in state.get("analysis_contexts", []):
            classes = ctx.get("classes", []) if isinstance(ctx, dict) else getattr(ctx, "classes", [])

            for cls in classes:
                if isinstance(cls, dict):
                    name = cls.get("name", "")
                    methods = cls.get("methods", [])
                    loc = cls.get("loc", 0)
                    file_path = cls.get("file_path", "")
                    line_start = cls.get("line_start", 1)
                    line_end = cls.get("line_end", 1)
                else:
                    name = getattr(cls, "name", "")
                    methods = getattr(cls, "methods", [])
                    loc = getattr(cls, "loc", 0)
                    file_path = getattr(cls, "file_path", "")
                    line_start = getattr(cls, "line_start", 1)
                    line_end = getattr(cls, "line_end", 1)

                if _is_generated(file_path):
                    continue

                if len(methods) > 20 or loc > 500:
                    findings.append(self._make_static_finding(
                        finding_id=_next_id(),
                        policy_id="ARCH-002",
                        title=f"God class: {name} ({len(methods)} methods, {loc} LOC)",
                        description=(
                            f"Class {name} has {len(methods)} methods and {loc} lines of code. "
                            f"Consider splitting into smaller, focused classes."
                        ),
                        severity="medium",
                        category="architecture",
                        file_path=file_path,
                        repo_name=repo_name,
                        line_start=line_start,
                        line_end=line_end,
                        code_snippet=f"class {name}: # {len(methods)} methods, {loc} LOC",
                        tool="ast",
                        confidence=0.85,
                    ))

        return findings

    async def _run_policy_checks(self, state: AuditState) -> list[AuditFinding]:
        """Run architecture policy YAML checks."""
        findings: list[AuditFinding] = []
        try:
            from blanketaudit.policies.engine import PolicyEngine
            from pathlib import Path

            engine = PolicyEngine()
            policy_dir = Path(__file__).parent.parent / "policies" / "architecture"
            if not policy_dir.exists():
                return findings

            policies = engine.load_policies(policy_dir)
            file_contents = self._load_file_contents(state)
            repo_name = ""
            if state.get("repo_paths"):
                repo_name = state["repo_paths"][0].get("repo_name", "")

            for policy in policies:
                candidates = engine.execute_static_checks(policy, file_contents)
                for c in candidates:
                    if _is_generated(c.file_path):
                        continue
                    findings.append(self._make_static_finding(
                        finding_id=_next_id(),
                        policy_id=policy.id,
                        title=policy.name,
                        description=policy.description or policy.name,
                        severity=policy.severity,
                        category="architecture",
                        file_path=c.file_path,
                        repo_name=repo_name,
                        line_start=c.line_start,
                        line_end=c.line_end,
                        code_snippet=c.code_snippet[:500],
                        tool=c.tool,
                        confidence=0.7,
                    ))
        except Exception as exc:
            logger.warning("architecture_agent.policy_failed", error=str(exc)[:200])

        return findings

    # ── AI analysis ──────────────────────────────────────────

    async def run_ai_analysis(
        self,
        state: AuditState,
        candidates: list[AuditFinding],
    ) -> list[AuditFinding] | None:
        """AI analysis: assess coupling, detect anti-patterns, suggest refactoring."""
        if not candidates:
            return candidates

        enriched: list[AuditFinding] = []
        for candidate in candidates:
            try:
                result = await self._analyze_one(state, candidate)
                if result is not None:
                    enriched.append(result)
            except Exception as exc:
                logger.warning(
                    "architecture_agent.ai_one_failed",
                    finding_id=candidate.id,
                    error=str(exc)[:200],
                )
                enriched.append(candidate)

        return enriched if enriched else None

    async def _analyze_one(
        self,
        state: AuditState,
        candidate: AuditFinding,
    ) -> AuditFinding:
        """AI analysis for one architecture finding."""
        from langchain_core.messages import HumanMessage, SystemMessage

        evidence = candidate.evidence[0] if candidate.evidence else None
        code_context = evidence.code_snippet if evidence else ""
        file_path = evidence.file_path if evidence else ""

        system_prompt = (
            f"{INJECTION_DEFENSE_PREFIX}\n\n"
            "You are a software architect reviewing code structure.\n"
            "Respond with JSON: {\"is_real_issue\": bool, \"confidence\": float, "
            "\"explanation\": str, \"fix_suggestion\": str, \"effort_hours\": float}\n"
            "Consider if this might be a false positive due to:\n"
            "- Monorepo cross-package imports (acceptable)\n"
            "- Generated code (skip)\n"
            "- Intentional architectural decisions\n"
        )

        user_prompt = (
            f"Architecture finding: {candidate.title}\n"
            f"Policy: {candidate.policy_id}\n"
            f"File: {file_path}\n"
            f"Code:\n{wrap_code_content(code_context, file_path)}\n"
            "Is this a real architecture issue? Provide analysis."
        )

        response = await safe_llm_call(
            self.llm,
            [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)],
            agent_name=self.name,
            cost_tracker=self.cost_tracker,
            circuit_breaker=self.circuit_breaker,
        )

        return self._parse_ai_response(candidate, response.content)

    def _parse_ai_response(
        self,
        candidate: AuditFinding,
        response_text: str,
    ) -> AuditFinding | None:
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            return candidate.model_copy(update={
                "ai_explanation": response_text[:2000],
                "source": "ai",
            })

        if not data.get("is_real_issue", True):
            logger.info("architecture_agent.false_positive", finding_id=candidate.id)
            return None

        return candidate.model_copy(update={
            "ai_explanation": data.get("explanation", "")[:2000],
            "fix_code": data.get("fix_suggestion", ""),
            "effort_hours": data.get("effort_hours", candidate.effort_hours),
            "confidence": min(1.0, max(0.0, data.get("confidence", candidate.confidence))),
            "source": "corroborated" if candidate.source == "static" else "ai",
        })

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _load_file_contents(state: AuditState) -> dict[str, str]:
        """Load file contents from repo paths."""
        from pathlib import Path
        contents: dict[str, str] = {}
        for repo in state.get("repo_paths", []):
            local_path = Path(repo.get("local_path", ""))
            if not local_path.exists():
                continue
            for f in state.get("files", []):
                fp = local_path / f.get("path", "")
                if fp.exists() and fp.stat().st_size < 500_000:
                    try:
                        contents[f["path"]] = fp.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        pass
        return contents
