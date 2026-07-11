"""SQL and schema parsing using sqlglot."""

from __future__ import annotations

import json
import re
from pathlib import Path

import sqlglot
from sqlglot import exp

from migrate_risk.models import (
    AnalysisConfig,
    ParsedSchema,
    ParsedStatement,
    SchemaColumn,
    SchemaForeignKey,
    SchemaIndex,
    SchemaTable,
)


def load_migration(path: Path) -> str:
    """Read migration SQL from disk."""
    return path.read_text(encoding="utf-8")


def load_config(path: Path | None) -> AnalysisConfig:
    """Load optional analysis config from JSON."""
    if path is None:
        return AnalysisConfig()
    data = json.loads(path.read_text(encoding="utf-8"))
    return AnalysisConfig.model_validate(data)


def _line_number_for_offset(sql: str, offset: int) -> int:
    return sql[:offset].count("\n") + 1


def parse_migration(sql: str) -> list[ParsedStatement]:
    """Split migration SQL into statements with transaction context."""
    statements: list[ParsedStatement] = []
    in_transaction = False
    index = 0

    for raw in sqlglot.parse(sql, read="postgres"):
        if raw is None:
            continue
        sql_text = raw.sql(dialect="postgres")
        offset = sql.find(sql_text)
        line = _line_number_for_offset(sql, offset) if offset >= 0 else 1

        if isinstance(raw, exp.Transaction):
            in_transaction = True
        elif isinstance(raw, (exp.Commit, exp.Rollback)):
            in_transaction = False

        statements.append(
            ParsedStatement(
                index=index,
                sql=sql_text,
                line_number=line,
                in_transaction=in_transaction,
                ast=raw,
            )
        )
        index += 1

    return statements


def _extract_column_def(col_exp: exp.ColumnDef) -> SchemaColumn:
    name = col_exp.name
    data_type = ""
    nullable = True
    default = None

    for constraint in col_exp.find_all(exp.ColumnConstraint):
        kind = constraint.kind
        if isinstance(kind, exp.NotNullColumnConstraint):
            nullable = False
        elif isinstance(kind, exp.DefaultColumnConstraint):
            default_expr = kind.this
            default = default_expr.sql(dialect="postgres") if default_expr else None

    kind = col_exp.kind
    if kind:
        data_type = kind.sql(dialect="postgres")

    return SchemaColumn(name=name, data_type=data_type, nullable=nullable, default=default)


def parse_schema(sql: str) -> ParsedSchema:
    """Parse schema.sql into table/column/constraint metadata."""
    schema = ParsedSchema()
    current_table: SchemaTable | None = None

    try:
        statements = sqlglot.parse(sql, read="postgres")
    except Exception as exc:
        schema.warnings.append(f"Schema parse error: {exc}")
        return schema

    for stmt in statements:
        if stmt is None:
            continue
        try:
            if isinstance(stmt, exp.Create) and str(stmt.args.get("kind", "")).upper() == "TABLE":
                schema_expr = stmt.this
                if isinstance(schema_expr, exp.Schema):
                    table_name = schema_expr.this.name if schema_expr.this else ""
                else:
                    table_expr = stmt.find(exp.Table)
                    table_name = table_expr.name if table_expr else ""
                if not table_name:
                    continue

                current_table = SchemaTable(name=table_name)

                column_defs = list(schema_expr.find_all(exp.ColumnDef)) if isinstance(
                    schema_expr, exp.Schema
                ) else list(stmt.find_all(exp.ColumnDef))
                for col in column_defs:
                    col_def = _extract_column_def(col)
                    current_table.columns[col_def.name] = col_def

                for pk in stmt.find_all(exp.PrimaryKey):
                    cols = [c.name for c in pk.find_all(exp.Column)]
                    current_table.primary_key = cols

                for idx in stmt.find_all(exp.Index):
                    idx_name = idx.name or ""
                    cols = [c.name for c in idx.find_all(exp.Column)]
                    unique = any(
                        isinstance(c, exp.UniqueColumnConstraint)
                        for c in stmt.find_all(exp.UniqueColumnConstraint)
                    )
                    current_table.indexes.append(
                        SchemaIndex(name=idx_name, columns=cols, unique=unique)
                    )

                for fk in stmt.find_all(exp.ForeignKey):
                    ref_table = fk.find(exp.Table)
                    fk_cols = [c.name for c in fk.find_all(exp.Column)]
                    ref_cols = []
                    if ref_table:
                        ref_cols = [c.name for c in ref_table.find_all(exp.Column)]
                    current_table.foreign_keys.append(
                        SchemaForeignKey(
                            name=fk.name,
                            columns=fk_cols,
                            referenced_table=ref_table.name if ref_table else "",
                            referenced_columns=ref_cols,
                        )
                    )

                schema.tables[table_name] = current_table

            elif isinstance(stmt, exp.Alter) and current_table:
                _apply_alter_to_schema(stmt, schema)
        except Exception as exc:
            schema.warnings.append(f"Partial schema parse failure: {exc}")

    # Fallback: regex extraction for simple CREATE TABLE blocks
    if not schema.tables:
        schema = _parse_schema_regex(sql)

    return schema


def _apply_alter_to_schema(stmt: exp.Alter, schema: ParsedSchema) -> None:
    table_expr = stmt.find(exp.Table)
    if not table_expr:
        return
    table = schema.tables.get(table_expr.name)
    if not table:
        return
    for action in stmt.args.get("actions") or stmt.expressions or []:
        if isinstance(action, exp.ColumnDef):
            table.columns[action.name] = _extract_column_def(action)


def _parse_schema_regex(sql: str) -> ParsedSchema:
    """Best-effort schema extraction when AST parsing is incomplete."""
    schema = ParsedSchema()
    create_pattern = re.compile(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\((.*?)\);",
        re.IGNORECASE | re.DOTALL,
    )
    for match in create_pattern.finditer(sql):
        table_name = match.group(1)
        body = match.group(2)
        table = SchemaTable(name=table_name)
        for line in body.split(","):
            line = line.strip()
            if not line or line.upper().startswith(("PRIMARY", "UNIQUE", "FOREIGN", "CONSTRAINT", "CHECK")):
                continue
            parts = line.split()
            if parts:
                col_name = parts[0]
                nullable = "NOT NULL" not in line.upper()
                data_type = parts[1] if len(parts) > 1 else ""
                table.columns[col_name] = SchemaColumn(
                    name=col_name, data_type=data_type, nullable=nullable
                )
        schema.tables[table_name] = table
    return schema


def get_table_from_ast(node: exp.Expression) -> str | None:
    """Extract primary table name from a statement AST."""
    table = node.find(exp.Table)
    return table.name if table else None


def strip_sql_comments(sql: str) -> str:
    """Remove SQL line and block comments for static pattern matching."""
    without_block = re.sub(r"/\*.*?\*/", "", sql, flags=re.DOTALL)
    return re.sub(r"--.*?$", "", without_block, flags=re.MULTILINE)


def migration_has_rollback_comment(sql: str) -> bool:
    """Check if migration mentions rollback/backout/backup."""
    pattern = re.compile(r"\b(rollback|backout|backup|revert)\b", re.IGNORECASE)
    return bool(pattern.search(sql))
