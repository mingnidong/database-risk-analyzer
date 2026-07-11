"""Tests for PostgreSQL migration rules."""

from pathlib import Path

import pytest

from migrate_risk.analyzer import analyze_migration
from migrate_risk.models import AnalysisConfig, RiskLevel
from migrate_risk.parser import parse_migration
from migrate_risk.rules.postgres import (
    rule_column_type_change,
    rule_create_index_without_concurrently,
    rule_drop_table_or_column,
    rule_foreign_key_without_not_valid,
    rule_full_table_dml,
    rule_not_null_without_backfill,
)


@pytest.fixture
def config(examples_dir: Path) -> AnalysisConfig:
    from migrate_risk.parser import load_config
    return load_config(examples_dir / "config.json")


def _stmt(sql: str, index: int = 0):
    statements = parse_migration(sql)
    return statements[index]


def test_detect_not_null_column(config):
    sql = "ALTER TABLE users ADD COLUMN age INTEGER NOT NULL;"
    findings = rule_not_null_without_backfill(_stmt(sql), config, None, [], sql)
    assert len(findings) >= 1
    assert findings[0].rule_id == "PG001"
    assert findings[0].table == "users"
    assert findings[0].severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_detect_create_index_without_concurrently(config):
    sql = "CREATE INDEX idx_events_user_id ON events(user_id);"
    findings = rule_create_index_without_concurrently(_stmt(sql), config, None, [], sql)
    assert len(findings) == 1
    assert findings[0].rule_id == "PG004"
    assert findings[0].severity in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_concurrent_index_not_flagged_same_risk(config):
    sql = "CREATE INDEX CONCURRENTLY idx_events_user_id ON events(user_id);"
    findings = rule_create_index_without_concurrently(_stmt(sql), config, None, [], sql)
    assert len(findings) == 0


def test_detect_drop_table(config):
    sql = "DROP TABLE users;"
    findings = rule_drop_table_or_column(_stmt(sql), config, None, [], sql)
    assert any(f.title == "Dropping table" for f in findings)
    assert findings[0].severity == RiskLevel.CRITICAL


def test_detect_drop_column(config):
    sql = "ALTER TABLE users DROP COLUMN email;"
    findings = rule_drop_table_or_column(_stmt(sql), config, None, [], sql)
    assert any("Dropping column" in f.title for f in findings)


def test_detect_fk_without_not_valid(config):
    sql = (
        "ALTER TABLE orders ADD CONSTRAINT fk_user "
        "FOREIGN KEY(user_id) REFERENCES users(id);"
    )
    findings = rule_foreign_key_without_not_valid(_stmt(sql), config, None, [], sql)
    assert len(findings) == 1
    assert findings[0].rule_id == "PG006"


def test_fk_with_not_valid_not_flagged(config):
    sql = (
        "ALTER TABLE orders ADD CONSTRAINT fk_user "
        "FOREIGN KEY(user_id) REFERENCES users(id) NOT VALID;"
    )
    findings = rule_foreign_key_without_not_valid(_stmt(sql), config, None, [], sql)
    assert len(findings) == 0


def test_detect_type_change(config):
    sql = "ALTER TABLE users ALTER COLUMN status TYPE INTEGER USING status::integer;"
    findings = rule_column_type_change(_stmt(sql), config, None, [], sql)
    assert len(findings) >= 1
    assert findings[0].rule_id == "PG007"


def test_detect_full_table_delete(config):
    sql = "DELETE FROM events;"
    findings = rule_full_table_dml(_stmt(sql), config, None, [], sql)
    assert len(findings) == 1
    assert findings[0].severity == RiskLevel.CRITICAL


def test_detect_full_table_update(config):
    sql = "UPDATE users SET status = 'inactive';"
    findings = rule_full_table_dml(_stmt(sql), config, None, [], sql)
    assert len(findings) == 1


def test_safe_migration_no_false_rollback_from_comments(examples_dir: Path):
    result = analyze_migration(examples_dir / "safe_migration.sql")
    rollback_findings = [f for f in result.findings if f.rule_id == "PG013"]
    assert rollback_findings == []


def test_risky_migration_has_findings(examples_dir: Path, config):
    result = analyze_migration(
        examples_dir / "risky_migration.sql",
        config_path=examples_dir / "config.json",
        schema_path=examples_dir / "schema.sql",
    )
    assert len(result.findings) >= 5
    assert result.risk_score > 25
