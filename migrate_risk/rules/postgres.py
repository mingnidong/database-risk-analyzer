"""PostgreSQL-specific migration risk rules."""

from __future__ import annotations

import re
from collections.abc import Callable

from sqlglot import exp

from migrate_risk.models import (
    AnalysisConfig,
    Finding,
    ParsedSchema,
    ParsedStatement,
    RiskLevel,
    RolloutStep,
)
from migrate_risk.parser import (
    get_table_from_ast,
    migration_has_rollback_comment,
    strip_sql_comments,
)
from migrate_risk.rules.common import (
    bump_severity,
    is_critical_table,
    is_large_table,
    make_finding,
    table_stats,
)

VOLATILE_DEFAULTS = frozenset(
    {
        "now",
        "gen_random_uuid",
        "uuid_generate_v4",
        "random",
        "clock_timestamp",
    }
)

RuleFunc = Callable[
    [ParsedStatement, AnalysisConfig, ParsedSchema, list[ParsedStatement], str],
    list[Finding],
]


def _alter_actions(stmt: ParsedStatement) -> list[exp.Expression]:
    ast = stmt.ast
    if not isinstance(ast, exp.Alter):
        return []
    return list(ast.args.get("actions") or ast.expressions or [])


def _column_name_from_def(action: exp.Expression) -> str | None:
    if isinstance(action, exp.ColumnDef):
        return action.name
    if isinstance(action, exp.AlterColumn):
        col = action.find(exp.Column)
        return col.name if col else None
    return None


def rule_not_null_without_backfill(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(stmt.ast, exp.Alter):
        return findings

    table = get_table_from_ast(stmt.ast)
    for action in _alter_actions(stmt):
        if not isinstance(action, exp.ColumnDef):
            continue
        has_not_null = any(
            isinstance(c.kind, exp.NotNullColumnConstraint)
            for c in action.find_all(exp.ColumnConstraint)
        )
        if not has_not_null:
            continue

        stats = table_stats(config, table)
        severity = bump_severity(RiskLevel.HIGH, stats, config)
        findings.append(
            make_finding(
                rule_id="PG001",
                title="Adding NOT NULL column without safe backfill path",
                severity=severity,
                stmt=stmt,
                table=table,
                column=action.name,
                why_it_matters=(
                    "Existing rows need a value. This may fail or require a table rewrite "
                    "depending on the operation and Postgres version."
                ),
                safer_alternative=(
                    f"ALTER TABLE {table} ADD COLUMN {action.name} <type>; "
                    "then backfill in batches before adding NOT NULL."
                ),
                rollout_steps=[
                    f"Add nullable column {action.name} on {table}.",
                    "Deploy application code that writes the new column.",
                    "Backfill existing rows in batches.",
                    "Validate no nulls remain.",
                    "Add NOT NULL constraint after validation.",
                ],
                may_lock_table=True,
                may_rewrite_table=True,
                confidence="high" if stats.estimated_rows > 0 else "medium",
            )
        )
    return findings


def rule_add_column_with_default(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(stmt.ast, exp.Alter):
        return findings

    table = get_table_from_ast(stmt.ast)
    for action in _alter_actions(stmt):
        if not isinstance(action, exp.ColumnDef):
            continue
        default_constraint = next(
            (c for c in action.find_all(exp.ColumnConstraint) if isinstance(c.kind, exp.DefaultColumnConstraint)),
            None,
        )
        if default_constraint is None:
            continue

        stats = table_stats(config, table)
        severity = bump_severity(RiskLevel.MEDIUM, stats, config)
        default_sql = default_constraint.kind.this.sql(dialect="postgres") if default_constraint.kind.this else ""

        findings.append(
            make_finding(
                rule_id="PG002",
                title="Adding column with DEFAULT on table",
                severity=severity,
                stmt=stmt,
                table=table,
                column=action.name,
                why_it_matters=(
                    "Defaults can cause table rewrites or long locks depending on Postgres version "
                    "and default expression, especially on large tables."
                ),
                safer_alternative=(
                    f"ALTER TABLE {table} ADD COLUMN {action.name} <type>; "
                    "backfill in batches; set default afterward if needed."
                ),
                rollout_steps=[
                    f"Add nullable column {action.name} without default.",
                    "Backfill existing rows in batches.",
                    "Set default afterward if needed.",
                ],
                may_rewrite_table=is_large_table(stats, config),
                may_lock_table=is_large_table(stats, config),
                confidence="high",
            )
        )

        # Check volatile defaults (rule 3)
        default_lower = default_sql.lower()
        for volatile in VOLATILE_DEFAULTS:
            if volatile in default_lower:
                findings.append(
                    make_finding(
                        rule_id="PG003",
                        title="Volatile default expression",
                        severity=bump_severity(RiskLevel.MEDIUM, stats, config),
                        stmt=stmt,
                        table=table,
                        column=action.name,
                        why_it_matters=(
                            f"Volatile default ({volatile}) may behave differently per row and "
                            "makes migrations harder to reason about."
                        ),
                        safer_alternative="Backfill values explicitly in application code or batched UPDATE.",
                        rollout_steps=[
                            "Add column without volatile default.",
                            "Populate values via batched UPDATE or application writes.",
                        ],
                        confidence="high",
                    )
                )
                break

    return findings


def rule_create_index_without_concurrently(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    ast = stmt.ast
    if not isinstance(ast, exp.Create):
        return findings
    index = ast.find(exp.Index)
    if index is None:
        return findings

    # Check for CONCURRENTLY keyword in raw SQL
    if re.search(r"\bCONCURRENTLY\b", stmt.sql, re.IGNORECASE):
        return findings

    table_expr = ast.find(exp.Table)
    table = table_expr.name if table_expr else None
    stats = table_stats(config, table)
    severity = bump_severity(RiskLevel.HIGH, stats, config)
    idx_name = index.name or "idx_new"
    col = index.find(exp.Column)
    col_name = col.name if col else "column"

    findings.append(
        make_finding(
            rule_id="PG004",
            title="CREATE INDEX without CONCURRENTLY",
            severity=severity,
            stmt=stmt,
            table=table,
            why_it_matters=(
                "Creating a normal index on a large write-heavy table can block writes "
                "for the duration of the index build."
            ),
            safer_alternative=f"CREATE INDEX CONCURRENTLY {idx_name} ON {table}({col_name});",
            rollout_steps=[
                "Run CREATE INDEX CONCURRENTLY outside a transaction.",
                "Monitor lock waits and replication lag.",
                "Retry safely if interrupted.",
            ],
            may_lock_table=True,
            confidence="high",
        )
    )
    return findings


def rule_unique_constraint(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(stmt.ast, exp.Alter):
        return findings

    table = get_table_from_ast(stmt.ast)
    for action in _alter_actions(stmt):
        is_unique = isinstance(action, exp.UniqueColumnConstraint) or (
            isinstance(action, exp.Constraint)
            and action.kind
            and "UNIQUE" in action.sql(dialect="postgres").upper()
        )
        if not is_unique and not re.search(r"\bUNIQUE\b", action.sql(dialect="postgres"), re.I):
            unique_in_sql = "UNIQUE" in stmt.sql.upper() and "ADD CONSTRAINT" in stmt.sql.upper()
            if not unique_in_sql:
                continue

        if "UNIQUE" not in stmt.sql.upper():
            continue

        stats = table_stats(config, table)
        findings.append(
            make_finding(
                rule_id="PG005",
                title="Adding UNIQUE constraint on table",
                severity=bump_severity(RiskLevel.HIGH, stats, config),
                stmt=stmt,
                table=table,
                why_it_matters="May scan the entire table and fail if duplicates exist.",
                safer_alternative=(
                    "Check duplicates first; create unique index CONCURRENTLY; "
                    "attach constraint using existing index."
                ),
                rollout_steps=[
                    "Query for duplicate values before migration.",
                    "CREATE UNIQUE INDEX CONCURRENTLY on target column(s).",
                    "ALTER TABLE ADD CONSTRAINT USING INDEX.",
                ],
                may_lock_table=True,
                confidence="high",
            )
        )
        break
    return findings


def rule_foreign_key_without_not_valid(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    sql_upper = stmt.sql.upper()
    if "FOREIGN KEY" not in sql_upper and not (
        isinstance(stmt.ast, exp.Alter)
        and any(isinstance(a, exp.ForeignKey) for a in _alter_actions(stmt))
    ):
        return findings

    if "NOT VALID" in sql_upper:
        return findings

    table = get_table_from_ast(stmt.ast) if stmt.ast else None
    if not table:
        match = re.search(r"ALTER\s+TABLE\s+(\w+)", stmt.sql, re.I)
        table = match.group(1) if match else None

    stats = table_stats(config, table)
    findings.append(
        make_finding(
            rule_id="PG006",
            title="Adding FOREIGN KEY without NOT VALID",
            severity=bump_severity(RiskLevel.HIGH, stats, config),
            stmt=stmt,
            table=table,
            why_it_matters="Validating a foreign key can lock tables and scan all existing rows.",
            safer_alternative=(
                f"ALTER TABLE {table} ADD CONSTRAINT ... FOREIGN KEY (...) "
                "REFERENCES ... NOT VALID; then VALIDATE CONSTRAINT separately."
            ),
            rollout_steps=[
                "Add constraint with NOT VALID to avoid immediate validation.",
                "Validate constraint separately during low-traffic window.",
                "Monitor lock waits during validation.",
            ],
            may_lock_table=True,
            confidence="high",
        )
    )
    return findings


def rule_column_type_change(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    ast = stmt.ast
    if not isinstance(ast, exp.Alter):
        return findings

    table = get_table_from_ast(ast)
    for action in _alter_actions(stmt):
        if not isinstance(action, exp.AlterColumn):
            continue
        action_sql = action.sql(dialect="postgres").upper()
        if not action.find(exp.DataType) and "DATA TYPE" not in action_sql and "TYPE" not in action_sql:
            continue

        col = action.find(exp.Column)
        col_name = col.name if col else None
        stats = table_stats(config, table)
        findings.append(
            make_finding(
                rule_id="PG007",
                title="Changing column type",
                severity=bump_severity(RiskLevel.HIGH, stats, config),
                stmt=stmt,
                table=table,
                column=col_name,
                why_it_matters=(
                    "Type changes may rewrite the entire table and break application assumptions."
                ),
                safer_alternative=(
                    "Add new column, dual-write, backfill, switch reads, drop old column later."
                ),
                rollout_steps=[
                    "Add new column with target type.",
                    "Dual-write from application.",
                    "Backfill in batches.",
                    "Switch reads to new column.",
                    "Drop old column after verification.",
                ],
                reversible=False,
                may_lock_table=True,
                may_rewrite_table=True,
                confidence="high",
            )
        )
    return findings


def rule_drop_table_or_column(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    ast = stmt.ast

    if isinstance(ast, exp.Drop):
        table_expr = ast.find(exp.Table)
        table = table_expr.name if table_expr else None
        kind = str(ast.args.get("kind", "")).upper()
        if "TABLE" in kind or isinstance(ast.find(exp.Table), exp.Table):
            stats = table_stats(config, table)
            findings.append(
                make_finding(
                    rule_id="PG008",
                    title="Dropping table",
                    severity=RiskLevel.CRITICAL,
                    stmt=stmt,
                    table=table,
                    why_it_matters=(
                        "Irreversible without backup and may break deployed application versions."
                    ),
                    safer_alternative="Stop reads, deploy compatibility code, verify unused, backup, then drop.",
                    rollout_steps=[
                        "Stop reads from the table.",
                        "Deploy compatibility code removing references.",
                        "Verify table is unused in logs/metrics.",
                        "Take backup before physical drop.",
                        "Drop table during maintenance window.",
                    ],
                    reversible=False,
                    may_lock_table=True,
                    confidence="high",
                )
            )
        return findings

    if isinstance(ast, exp.Alter):
        table = get_table_from_ast(ast)
        for action in _alter_actions(stmt):
            if isinstance(action, exp.Drop):
                col = action.find(exp.Column)
                col_name = col.name if col else None
                if "DROP COLUMN" in stmt.sql.upper() or col_name:
                    stats = table_stats(config, table)
                    findings.append(
                        make_finding(
                            rule_id="PG008",
                            title="Dropping column",
                            severity=RiskLevel.CRITICAL if is_critical_table(stats, config) else RiskLevel.HIGH,
                            stmt=stmt,
                            table=table,
                            column=col_name,
                            why_it_matters=(
                                "Irreversible without backup and may break deployed app versions."
                            ),
                            safer_alternative=(
                                "Deploy code that no longer reads/writes column; "
                                "delay physical drop; backup first."
                            ),
                            rollout_steps=[
                                "Deploy application without column references.",
                                "Verify no queries use the column.",
                                "Backup before drop.",
                                "Drop column in maintenance window.",
                            ],
                            reversible=False,
                            may_lock_table=True,
                            confidence="high",
                        )
                    )
    return findings


def rule_rename(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    sql_upper = stmt.sql.upper()
    if "RENAME" not in sql_upper:
        return findings

    table = get_table_from_ast(stmt.ast) if stmt.ast else None
    if not table:
        match = re.search(r"ALTER\s+TABLE\s+(\w+)", stmt.sql, re.I)
        table = match.group(1) if match else None

    is_table_rename = "RENAME TO" in sql_upper and "COLUMN" not in sql_upper
    is_col_rename = "RENAME COLUMN" in sql_upper

    if not is_table_rename and not is_col_rename:
        return findings

    stats = table_stats(config, table)
    title = "Renaming table" if is_table_rename else "Renaming column"
    findings.append(
        make_finding(
            rule_id="PG009",
            title=title,
            severity=bump_severity(RiskLevel.HIGH, stats, config),
            stmt=stmt,
            table=table,
            why_it_matters="Breaks old application versions unless deployed carefully.",
            safer_alternative=(
                "Add new column/table alias, dual-read/write, deploy app transition, remove old name later."
            ),
            rollout_steps=[
                "Introduce new name alongside old name (view or alias column).",
                "Deploy application to use new name.",
                "Remove old name after all instances updated.",
            ],
            reversible=False,
            confidence="high",
        )
    )
    return findings


def rule_full_table_dml(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    ast = stmt.ast

    if isinstance(ast, exp.Delete):
        table = get_table_from_ast(ast)
        where = ast.find(exp.Where)
        if where is None:
            stats = table_stats(config, table)
            findings.append(
                make_finding(
                    rule_id="PG010",
                    title="DELETE without WHERE clause",
                    severity=RiskLevel.CRITICAL if is_large_table(stats, config) else RiskLevel.HIGH,
                    stmt=stmt,
                    table=table,
                    why_it_matters="May lock and delete entire table, generating huge WAL.",
                    safer_alternative="Add WHERE clause; batch deletes by primary key ranges.",
                    rollout_steps=[
                        "Add selective WHERE clause.",
                        "Batch deletes by primary key ranges.",
                        "Monitor replication lag between batches.",
                    ],
                    reversible=False,
                    may_lock_table=True,
                    confidence="high",
                )
            )

    if isinstance(ast, exp.Update):
        table = get_table_from_ast(ast)
        where = ast.find(exp.Where)
        if where is None:
            stats = table_stats(config, table)
            findings.append(
                make_finding(
                    rule_id="PG010",
                    title="UPDATE without WHERE clause",
                    severity=RiskLevel.CRITICAL if is_large_table(stats, config) else RiskLevel.HIGH,
                    stmt=stmt,
                    table=table,
                    why_it_matters="May lock and update entire table, generating huge WAL.",
                    safer_alternative="Add WHERE clause; batch updates by primary key ranges.",
                    rollout_steps=[
                        "Add selective WHERE clause.",
                        "Batch updates by primary key ranges.",
                        "Sleep between batches; monitor replication lag.",
                    ],
                    reversible=False,
                    may_lock_table=True,
                    confidence="high",
                )
            )
    return findings


def rule_backfill_without_batching(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    migration_sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    ast = stmt.ast
    if not isinstance(ast, exp.Update):
        return findings

    where = ast.find(exp.Where)
    if where is None:
        return findings

    where_sql = where.sql(dialect="postgres").upper()
    # Detect backfill pattern: SET col = ... WHERE col IS NULL
    if "IS NULL" not in where_sql:
        return findings

    # Skip if migration mentions batching
    if re.search(r"\b(batch|limit|sleep|chunk)\b", migration_sql, re.I):
        return findings

    table = get_table_from_ast(ast)
    stats = table_stats(config, table)
    if not is_large_table(stats, config) and stats.estimated_rows == 0:
        return findings

    findings.append(
        make_finding(
            rule_id="PG011",
            title="Backfill without batching",
            severity=bump_severity(RiskLevel.MEDIUM, stats, config),
            stmt=stmt,
            table=table,
            why_it_matters=(
                "Large backfills can lock rows, create WAL spikes, and cause replication lag."
            ),
            safer_alternative="Batch by primary key with LIMIT and sleep between batches.",
            rollout_steps=[
                "Batch updates by primary key ranges.",
                "Limit rows per batch (e.g. 1000-10000).",
                "Sleep between batches.",
                "Track progress in a control table.",
            ],
            may_lock_table=True,
            confidence="medium" if stats.estimated_rows == 0 else "high",
        )
    )
    return findings


def rule_concurrent_index_in_transaction(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if not re.search(r"CREATE\s+INDEX\s+CONCURRENTLY", stmt.sql, re.I):
        return findings
    if not stmt.in_transaction:
        return findings

    table = get_table_from_ast(stmt.ast) if stmt.ast else None
    findings.append(
        make_finding(
            rule_id="PG012",
            title="CREATE INDEX CONCURRENTLY inside transaction block",
            severity=RiskLevel.HIGH,
            stmt=stmt,
            table=table,
            why_it_matters=(
                "Postgres does not allow CREATE INDEX CONCURRENTLY inside a transaction block."
            ),
            safer_alternative="Run CREATE INDEX CONCURRENTLY outside BEGIN/COMMIT.",
            rollout_steps=[
                "Remove CONCURRENTLY index from transactional migration.",
                "Run as standalone statement outside transaction.",
            ],
            confidence="high",
        )
    )
    return findings


def rule_missing_rollback_note(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    all_stmts: list[ParsedStatement],
    migration_sql: str,
) -> list[Finding]:
    """Only run once on last statement - handled via rule registry wrapper."""
    return []


def check_missing_rollback(
    statements: list[ParsedStatement],
    migration_sql: str,
) -> list[Finding]:
    destructive_patterns = [
        r"\bDROP\s+TABLE\b",
        r"\bDROP\s+COLUMN\b",
        r"\bALTER\s+COLUMN\b.*\bTYPE\b",
        r"\bDELETE\s+FROM\b",
        r"\bUPDATE\b",
        r"\bRENAME\b",
    ]
    has_destructive = any(
        re.search(p, strip_sql_comments(s.sql), re.I)
        for s in statements
        for p in destructive_patterns
    )
    if not has_destructive:
        return []
    if migration_has_rollback_comment(migration_sql):
        return []

    return [
        Finding(
            rule_id="PG013",
            title="Missing rollback note for irreversible operations",
            severity=RiskLevel.MEDIUM,
            why_it_matters=(
                "Destructive migrations should document rollback/backout/backup steps."
            ),
            evidence="Migration contains destructive operations without rollback comments.",
            safer_alternative=(
                "Add SQL comments describing rollback steps, backup requirements, and verification."
            ),
            rollout_steps=[
                RolloutStep(order=1, description="Document rollback procedure in migration comments."),
                RolloutStep(order=2, description="Ensure backup exists before running."),
            ],
            reversible=False,
            confidence="medium",
        )
    ]


def rule_lock_heavy_alter(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(stmt.ast, exp.Alter):
        return findings

    sql_upper = stmt.sql.upper()
    # Skip rules already covered
    skip_keywords = ("ADD COLUMN", "DROP COLUMN", "RENAME", "TYPE", "UNIQUE", "FOREIGN KEY", "NOT NULL")
    if any(k in sql_upper for k in skip_keywords):
        return findings

    table = get_table_from_ast(stmt.ast)
    stats = table_stats(config, table)
    if not is_large_table(stats, config):
        return findings

    findings.append(
        make_finding(
            rule_id="PG014",
            title="Lock-heavy ALTER TABLE on large table",
            severity=bump_severity(RiskLevel.MEDIUM, stats, config),
            stmt=stmt,
            table=table,
            why_it_matters="ALTER TABLE on large tables may acquire exclusive locks for extended periods.",
            safer_alternative="Review lock mode; consider online migration patterns or maintenance window.",
            rollout_steps=[
                "Test lock duration in staging with production-like data volume.",
                "Schedule during low-traffic window.",
                "Monitor pg_locks during execution.",
            ],
            may_lock_table=True,
            confidence="medium",
        )
    )
    return findings


def rule_constraint_validation(
    stmt: ParsedStatement,
    config: AnalysisConfig,
    _schema: ParsedSchema,
    _all: list[ParsedStatement],
    _sql: str,
) -> list[Finding]:
    findings: list[Finding] = []
    sql_upper = stmt.sql.upper()

    check_patterns = ("ADD CONSTRAINT", "VALIDATE CONSTRAINT", "CHECK", "NOT NULL")
    if not any(p in sql_upper for p in check_patterns):
        return findings
    if "NOT VALID" in sql_upper:
        return findings

    # FK and unique covered elsewhere
    if "FOREIGN KEY" in sql_upper or "UNIQUE" in sql_upper:
        return findings

    table = get_table_from_ast(stmt.ast) if stmt.ast else None
    stats = table_stats(config, table)
    if not is_large_table(stats, config) and stats.estimated_rows == 0:
        return findings

    findings.append(
        make_finding(
            rule_id="PG015",
            title="Constraint validation risk on large table",
            severity=bump_severity(RiskLevel.MEDIUM, stats, config),
            stmt=stmt,
            table=table,
            why_it_matters=(
                "Adding CHECK/NOT NULL constraints validates all existing rows and may lock the table."
            ),
            safer_alternative="Use NOT VALID where supported; VALIDATE CONSTRAINT during low traffic.",
            rollout_steps=[
                "Add constraint with NOT VALID if supported.",
                "Validate constraint separately during low-traffic window.",
            ],
            may_lock_table=True,
            confidence="medium",
        )
    )
    return findings


POSTGRES_RULES: list[RuleFunc] = [
    rule_not_null_without_backfill,
    rule_add_column_with_default,
    rule_create_index_without_concurrently,
    rule_unique_constraint,
    rule_foreign_key_without_not_valid,
    rule_column_type_change,
    rule_drop_table_or_column,
    rule_rename,
    rule_full_table_dml,
    rule_backfill_without_batching,
    rule_concurrent_index_in_transaction,
    rule_lock_heavy_alter,
    rule_constraint_validation,
]
