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

Per-category: 100 - (critical×25 + high×10 + medium×3 + low×1), clamped [0, 100]
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


class RiskScorer:
    """Compute dynamic 8-category health score.

    Usage::

        scorer = RiskScorer(active_frameworks=["HIPAA", "SOC2", "PCI-DSS"])
        health = scorer.score(findings)
        # health.categories = [Security(72), HIPAA Compliance(45), SOC2 Compliance(80), ...]
    """

    def __init__(self, active_frameworks: list[str] | None = None) -> None:
        self._frameworks = active_frameworks or []

    def score(self, findings: list[AuditFinding]) -> HealthScore:
        """Compute the full health score."""
        # 1. Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.severity if hasattr(f, "severity") else f.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 2. Route each finding to its scoring bucket(s)
        buckets = self._route_findings(findings)

        # 3. Build dynamic category list and compute per-category scores
        categories, cat_scores = self._compute_categories(buckets)

        # 4. Compute weighted composite
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
    ) -> dict[str, list[AuditFinding]]:
        """Route findings to scoring buckets.

        Compliance findings are routed to per-framework buckets based
        on their compliance_refs.  A finding with both HIPAA and SOC2
        refs counts in both framework categories.
        """
        buckets: dict[str, list[AuditFinding]] = defaultdict(list)

        for f in findings:
            cat = f.category if hasattr(f, "category") else f.get("category", "quality")
            bucket = _CATEGORY_BUCKET.get(cat, "quality")

            if bucket == "compliance" and self._frameworks:
                # Route to per-framework compliance buckets
                routed = False
                refs = f.compliance_refs if hasattr(f, "compliance_refs") else []
                for ref in refs:
                    fw = ref.framework if hasattr(ref, "framework") else ref.get("framework", "")
                    for active_fw in self._frameworks:
                        if fw.upper() == active_fw.upper():
                            buckets[f"{active_fw} Compliance"].append(f)
                            routed = True
                if not routed:
                    # No matching framework ref → put in first framework bucket
                    if self._frameworks:
                        buckets[f"{self._frameworks[0]} Compliance"].append(f)
                    else:
                        buckets["Compliance"].append(f)
            elif bucket == "reliability":
                # Reliability doesn't have its own bucket in _BASE_WEIGHTS,
                # share with performance
                buckets["Reliability"].append(f)
            else:
                buckets[bucket].append(f)

        return dict(buckets)

    def _compute_categories(
        self,
        buckets: dict[str, list[AuditFinding]],
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
            fixed.append(("Compliance", "Compliance"))

        fixed.extend([
            ("Code Quality", "quality"),
            ("Performance", "performance"),
            ("Reliability", "Reliability"),
            ("Infrastructure", "infrastructure"),
        ])

        for display_name, bucket_key in fixed:
            bucket_findings = buckets.get(bucket_key, [])
            score = _score_from_findings(bucket_findings)
            categories.append(CategoryScore(
                name=display_name,
                score=score,
                finding_count=len(bucket_findings),
            ))
            cat_scores[display_name] = score

        return categories, cat_scores

    def _compute_composite(self, cat_scores: dict[str, int]) -> int:
        """Weighted average with dynamic compliance split."""
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
