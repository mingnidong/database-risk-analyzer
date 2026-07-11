"""Main migration analysis orchestration."""

from __future__ import annotations

from pathlib import Path

from migrate_risk.models import MigrationAnalysis, ParsedSchema
from migrate_risk.parser import load_config, load_migration, parse_migration, parse_schema
from migrate_risk.rollout import build_rollout_plan
from migrate_risk.rules import get_rules
from migrate_risk.rules.postgres import check_missing_rollback
from migrate_risk.scoring import compute_overall_score, overall_risk_level


def analyze_migration(
    migration_path: Path,
    *,
    schema_path: Path | None = None,
    config_path: Path | None = None,
    database: str = "postgres",
) -> MigrationAnalysis:
    """Analyze a migration file and return structured results."""
    sql = load_migration(migration_path)
    config = load_config(config_path)
    config.database = database

    schema = ParsedSchema()
    warnings: list[str] = list(schema.warnings)

    if schema_path:
        try:
            schema_sql = schema_path.read_text(encoding="utf-8")
            schema = parse_schema(schema_sql)
            warnings.extend(schema.warnings)
        except OSError as exc:
            warnings.append(f"Could not read schema file: {exc}")

    statements = parse_migration(sql)
    rules = get_rules(database)
    findings = []

    for stmt in statements:
        for rule in rules:
            findings.extend(rule(stmt, config, schema, statements, sql))

    findings.extend(check_missing_rollback(statements, sql))

    # Deduplicate by rule_id + evidence
    seen: set[tuple[str, str]] = set()
    unique_findings = []
    for f in findings:
        key = (f.rule_id, f.evidence)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    affected_tables = sorted({f.table for f in unique_findings if f.table})
    affected_columns = sorted(
        {f"{f.table}.{f.column}" for f in unique_findings if f.table and f.column}
    )

    score = compute_overall_score(unique_findings, config)
    risk = overall_risk_level(score)
    rollout = build_rollout_plan(unique_findings)

    return MigrationAnalysis(
        migration_file=str(migration_path.resolve()),
        database=database,
        overall_risk=risk,
        risk_score=score,
        findings=unique_findings,
        affected_tables=affected_tables,
        affected_columns=affected_columns,
        rollout_plan=rollout,
        warnings=warnings,
        statement_count=len(statements),
    )
