"""Deterministic risk scoring for migration analysis."""

from __future__ import annotations

from migrate_risk.models import AnalysisConfig, Finding, RiskLevel, TableStats

SEVERITY_BASE_SCORES: dict[RiskLevel, int] = {
    RiskLevel.LOW: 8,
    RiskLevel.MEDIUM: 18,
    RiskLevel.HIGH: 32,
    RiskLevel.CRITICAL: 45,
}


def _table_stats(config: AnalysisConfig, table: str | None) -> TableStats:
    if table and table in config.tables:
        return config.tables[table]
    return TableStats()


def _table_size_multiplier(stats: TableStats, config: AnalysisConfig) -> float:
    rows = stats.estimated_rows
    settings = config.settings
    if rows >= settings.critical_table_row_threshold:
        return 1.5
    if rows >= settings.large_table_row_threshold:
        return 1.25
    if rows > 0:
        return 1.1
    return 1.0


def _criticality_multiplier(stats: TableStats) -> float:
    return {
        "low": 1.0,
        "medium": 1.1,
        "high": 1.25,
        "critical": 1.4,
    }.get(stats.criticality.lower(), 1.0)


def _write_qps_multiplier(stats: TableStats) -> float:
    if stats.write_qps >= 200:
        return 1.2
    if stats.write_qps >= 50:
        return 1.1
    return 1.0


def score_finding(finding: Finding, config: AnalysisConfig) -> int:
    """Compute numeric contribution of a single finding (0-100 scale component)."""
    base = SEVERITY_BASE_SCORES[finding.severity]
    stats = _table_stats(config, finding.table)

    score = base * _table_size_multiplier(stats, config)
    score *= _criticality_multiplier(stats)
    score *= _write_qps_multiplier(stats)

    if not finding.reversible:
        score *= 1.15
    if finding.may_lock_table:
        score *= 1.1
    if finding.may_rewrite_table:
        score *= 1.15

    confidence_factor = {"low": 0.85, "medium": 1.0, "high": 1.05}.get(finding.confidence, 1.0)
    score *= confidence_factor

    return min(int(round(score)), 100)


def compute_overall_score(findings: list[Finding], config: AnalysisConfig) -> int:
    """
    Combine finding severities into a single 0-100 score.

    Scoring model:
    - Start from the maximum individual finding score.
    - Add a penalty for additional findings (capped).
    - Cap at 100.
    """
    if not findings:
        return 0

    individual = [score_finding(f, config) for f in findings]
    max_score = max(individual)
    extra_penalty = min(len(findings) - 1, 5) * 3
    return min(max_score + extra_penalty, 100)


def overall_risk_level(score: int) -> RiskLevel:
    return RiskLevel.from_score(score)


def meets_fail_threshold(
    risk_level: RiskLevel,
    threshold: RiskLevel | None,
) -> bool:
    """Return True if risk meets or exceeds the fail-on threshold."""
    if threshold is None:
        return False
    order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    return order.index(risk_level) >= order.index(threshold)
