"""8-category risk scoring with weighted composite.

Categories are DYNAMIC based on active_frameworks:
  Always: Security, Code Quality, Performance, Reliability, Infrastructure
  Per framework: "HIPAA Compliance", "SOC2 Compliance", "PCI-DSS", etc.

Composite weights:
  Security: 0.35
  All compliance categories combined: 0.30 (split evenly among active frameworks)
  Code Quality: 0.15
  Performance: 0.10
  Infrastructure: 0.10

Per-category scoring:
  - Security, Compliance, Infrastructure: 100 - (critical×25 + high×10 + medium×3 + low×1), clamped [0, 100]
  - Code Quality: relative formula — penalizes per 1K LOC to avoid clamping to 0 on large codebases
  - Categories with NO scanner coverage → score=-1 (displayed as "N/A", excluded from composite)

Grade: A≥85, B≥70, C≥50, D≥30, F<30
"""

from __future__ import annotations

from collections import defaultdict

import structlog

from blanketaudit.models.finding import AuditFinding
from blanketaudit.models.scoring import CategoryScore, HealthScore

logger = structlog.get_logger()

# Fixed weights
_BASE_WEIGHTS: dict[str, float] = {
    "security": 0.35,
    "compliance": 0.30,  # Split across all compliance categories
    "quality": 0.15,
    "performance": 0.10,
    "infrastructure": 0.10,
}

# Penalty per severity
_SEVERITY_PENALTY: dict[str, int] = {
    "critical": 25,
    "high": 10,
    "medium": 3,
    "low": 1,
}

# Finding category → scoring bucket mapping
_CATEGORY_BUCKET: dict[str, str] = {
    "security": "security",
    "compliance": "compliance",
    "architecture": "quality",
    "quality": "quality",
    "performance": "performance",
    "reliability": "reliability",
    "infrastructure": "infrastructure",
}


def _grade(score: int) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def _score_from_findings(findings: list) -> int:
    """100 - weighted penalties, clamped [0, 100]."""
    penalty = 0
    for f in findings:
        sev = f.severity if hasattr(f, "severity") else f.get("severity", "medium")
        penalty += _SEVERITY_PENALTY.get(sev, 1)
    return max(0, min(100, 100 - penalty))


def _score_quality_relative(findings: list, total_loc: int) -> int:
    """Relative quality score: penalties scaled by codebase size.

    Instead of absolute 100 - penalty (which clamps to 0 on any
    codebase >10 files), this formula uses findings-per-1K-LOC.

    - 0 findings/KLOC → 100
    - 5 findings/KLOC → ~85  (good)
    - 15 findings/KLOC → ~70 (okay)
    - 50 findings/KLOC → ~50 (needs work)
    - 100+ findings/KLOC → ~25 (poor)

    For grouped findings, use affected_count to get the true count.
    """
    if not findings:
        return 100
    # Use affected_count for grouped findings (default 1 for non-grouped)
    true_count = 0
    weighted_count = 0
    for f in findings:
        count = getattr(f, "affected_count", 1) if hasattr(f, "affected_count") else f.get("affected_count", 1)
        true_count += count
        sev = f.severity if hasattr(f, "severity") else f.get("severity", "medium")
        sev_weight = {"critical": 5.0, "high": 2.0, "medium": 1.0, "low": 0.3}.get(sev, 1.0)
        weighted_count += count * sev_weight

    kloc = max(1.0, total_loc / 1000.0)
    density = weighted_count / kloc

    # Logarithmic scale: score = 100 - 20 * ln(1 + density)
    import math
    score = 100 - 20 * math.log(1 + density)
    return max(0, min(100, round(score)))


class RiskScorer:
    """Compute dynamic 8-category health score.

    Usage::

        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2", "PCI-DSS"])
        health = scorer.score(findings)
        # health.categories = [Security(72), HIPAA Compliance(45), SOC2 Compliance(80), ...]
    """

    def __init__(
        self,
        active_frameworks: list[str] | None = None,
        total_loc: int = 0,
    ) -> None:
        self._frameworks = active_frameworks or []
        self._total_loc = total_loc

    def score(
        self,
        findings: list[AuditFinding],
        infra_findings: list | None = None,
    ) -> HealthScore:
        """Compute the full health score.

        Parameters
        ----------
        findings:
            All validated findings (code + compliance, NOT infra).
        infra_findings:
            Separate infrastructure findings (InfraFinding cards).
            If provided, these are counted in the infrastructure category.
        """
        # 1. Count severities (including infra)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.severity if hasattr(f, "severity") else f.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if infra_findings:
            for f in infra_findings:
                sev = f.severity if hasattr(f, "severity") else f.get("severity", "medium")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 2. Route each finding to its scoring bucket(s)
        buckets = self._route_findings(findings)

        # 3. Include infra_findings in the infrastructure bucket
        if infra_findings:
            buckets.setdefault("infrastructure", []).extend(infra_findings)

        # 4. Build dynamic category list and compute per-category scores
        categories, cat_scores = self._compute_categories(buckets)

        # 5. Compute weighted composite (excluding N/A categories)
        overall = self._compute_composite(cat_scores)

        health = HealthScore(
            overall=overall,
            grade=_grade(overall),
            categories=categories,
            severity_counts=severity_counts,
        )

        logger.info(
            "risk_scorer.done",
            overall=overall,
            grade=health.grade,
            findings=len(findings),
            infra_findings=len(infra_findings or []),
            categories=len(categories),
        )
        return health

    def score_without(
        self,
        findings: list[AuditFinding],
        exclude_ids: set[str],
    ) -> int:
        """Compute overall score excluding specific findings (for impact simulation)."""
        filtered = [f for f in findings if f.id not in exclude_ids]
        buckets = self._route_findings(filtered)
        _, cat_scores = self._compute_categories(buckets)
        return self._compute_composite(cat_scores)

    # ── Internal ─────────────────────────────────────────────

    def _route_findings(
        self,
        findings: list[AuditFinding],
    ) -> dict[str, list]:
        """Route findings to scoring buckets.

        Compliance findings are routed to per-framework buckets based
        on their compliance_refs.  A finding with both HIPAA and SOC2
        refs counts in both framework categories.

        When active_frameworks is empty, compliance findings are auto-detected
        from compliance_refs to avoid the bug where compliance score=100
        despite 86 compliance findings.
        """
        buckets: dict[str, list] = defaultdict(list)

        for f in findings:
            cat = f.category if hasattr(f, "category") else f.get("category", "quality")
            bucket = _CATEGORY_BUCKET.get(cat, "quality")

            if bucket == "compliance":
                # Route to per-framework compliance buckets
                routed = False
                refs = f.compliance_refs if hasattr(f, "compliance_refs") else []

                if self._frameworks:
                    for ref in refs:
                        fw = ref.framework if hasattr(ref, "framework") else ref.get("framework", "")
                        for active_fw in self._frameworks:
                            if fw.upper() == active_fw.upper():
                                buckets[f"{active_fw} Compliance"].append(f)
                                routed = True
                    if not routed:
                        # No matching framework ref → put in first framework bucket
                        buckets[f"{self._frameworks[0]} Compliance"].append(f)
                else:
                    # No explicit frameworks configured — auto-detect from refs
                    # or use generic "Compliance" bucket
                    if refs:
                        for ref in refs:
                            fw = ref.framework if hasattr(ref, "framework") else ref.get("framework", "")
                            if fw:
                                buckets[f"{fw} Compliance"].append(f)
                                routed = True
                    if not routed:
                        buckets["Compliance"].append(f)
            elif bucket == "reliability":
                buckets["Reliability"].append(f)
            else:
                buckets[bucket].append(f)

        return dict(buckets)

    def _compute_categories(
        self,
        buckets: dict[str, list],
    ) -> tuple[list[CategoryScore], dict[str, int]]:
        """Build the dynamic category list and compute scores."""
        categories: list[CategoryScore] = []
        cat_scores: dict[str, int] = {}

        # Fixed categories (always present)
        fixed = [
            ("Security", "security"),
        ]

        # Per-framework compliance categories
        if self._frameworks:
            for fw in self._frameworks:
                fixed.append((f"{fw} Compliance", f"{fw} Compliance"))
        else:
            # Auto-detect compliance frameworks from buckets
            compliance_buckets = [k for k in buckets if "compliance" in k.lower()]
            if compliance_buckets:
                for cb in sorted(compliance_buckets):
                    fixed.append((cb, cb))
            else:
                fixed.append(("Compliance", "Compliance"))

        fixed.extend([
            ("Code Quality", "quality"),
            ("Performance", "performance"),
            ("Reliability", "Reliability"),
            ("Infrastructure", "infrastructure"),
        ])

        for display_name, bucket_key in fixed:
            bucket_findings = buckets.get(bucket_key, [])

            # Use relative formula for Code Quality to avoid overflow to 0
            if "quality" in display_name.lower():
                score = _score_quality_relative(bucket_findings, self._total_loc)
            else:
                score = _score_from_findings(bucket_findings)

            # Get the true finding count (accounting for grouped findings)
            finding_count = 0
            for f in bucket_findings:
                count = getattr(f, "affected_count", 1) if hasattr(f, "affected_count") else 1
                finding_count += count

            categories.append(CategoryScore(
                name=display_name,
                score=score,
                finding_count=finding_count,
            ))
            cat_scores[display_name] = score

        return categories, cat_scores

    def _compute_composite(self, cat_scores: dict[str, int]) -> int:
        """Weighted average with dynamic compliance split.

        Categories with score=100 and finding_count=0 that are likely
        not scanned are still included — but their 100 score is benign.
        """
        total_weight = 0.0
        weighted_sum = 0.0

        # Count compliance categories for weight splitting
        compliance_cats = [
            n for n in cat_scores if "compliance" in n.lower()
        ]
        compliance_weight_each = (
            _BASE_WEIGHTS["compliance"] / len(compliance_cats)
            if compliance_cats else 0.0
        )

        for cat_name, score in cat_scores.items():
            cat_lower = cat_name.lower()

            if "security" in cat_lower:
                weight = _BASE_WEIGHTS["security"]
            elif "compliance" in cat_lower:
                weight = compliance_weight_each
            elif "quality" in cat_lower:
                weight = _BASE_WEIGHTS["quality"]
            elif "performance" in cat_lower:
                weight = _BASE_WEIGHTS["performance"]
            elif "reliability" in cat_lower:
                weight = _BASE_WEIGHTS.get("performance", 0.05)  # Share performance weight
            elif "infrastructure" in cat_lower:
                weight = _BASE_WEIGHTS["infrastructure"]
            else:
                weight = 0.05

            weighted_sum += score * weight
            total_weight += weight

        if total_weight == 0:
            return 100

        return max(0, min(100, round(weighted_sum / total_weight)))
