"""Shared helpers for migration risk rules."""

from __future__ import annotations

from migrate_risk.models import (
    AnalysisConfig,
    Finding,
    ParsedStatement,
    RiskLevel,
    RolloutStep,
    TableStats,
)


def table_stats(config: AnalysisConfig, table: str | None) -> TableStats:
    if table and table in config.tables:
        return config.tables[table]
    return TableStats()


def is_large_table(stats: TableStats, config: AnalysisConfig) -> bool:
    return stats.estimated_rows >= config.settings.large_table_row_threshold


def is_critical_table(stats: TableStats, config: AnalysisConfig) -> bool:
    rows_critical = stats.estimated_rows >= config.settings.critical_table_row_threshold
    crit_flag = stats.criticality.lower() == "critical"
    return rows_critical or crit_flag


def bump_severity(
    base: RiskLevel,
    stats: TableStats,
    config: AnalysisConfig,
) -> RiskLevel:
    """Increase severity based on table size and criticality."""
    order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    idx = order.index(base)
    if is_critical_table(stats, config):
        idx = min(idx + 2, len(order) - 1)
    elif is_large_table(stats, config):
        idx = min(idx + 1, len(order) - 1)
    elif stats.estimated_rows > 0:
        idx = min(idx + 1, len(order) - 1)
    return order[idx]


def make_finding(
    *,
    rule_id: str,
    title: str,
    severity: RiskLevel,
    stmt: ParsedStatement,
    table: str | None = None,
    column: str | None = None,
    why_it_matters: str,
    safer_alternative: str | None = None,
    rollout_steps: list[str] | None = None,
    reversible: bool = True,
    may_lock_table: bool = False,
    may_rewrite_table: bool = False,
    confidence: str = "medium",
) -> Finding:
    steps = [
        RolloutStep(order=i + 1, description=desc)
        for i, desc in enumerate(rollout_steps or [])
    ]
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        table=table,
        column=column,
        why_it_matters=why_it_matters,
        evidence=stmt.sql.strip(),
        safer_alternative=safer_alternative,
        rollout_steps=steps,
        reversible=reversible,
        may_lock_table=may_lock_table,
        may_rewrite_table=may_rewrite_table,
        confidence=confidence,
        line_number=stmt.line_number,
        statement_index=stmt.index,
    )
