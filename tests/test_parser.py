"""Tests for SQL parsing."""

from pathlib import Path

from migrate_risk.parser import load_config, parse_migration, parse_schema, strip_sql_comments


def test_parse_alter_table_add_column():
    sql = "ALTER TABLE users ADD COLUMN age INTEGER;"
    statements = parse_migration(sql)
    assert len(statements) == 1
    assert "users" in statements[0].sql
    assert statements[0].index == 0


def test_parse_multiple_statements():
    sql = """
    ALTER TABLE users ADD COLUMN a INT;
    ALTER TABLE users ADD COLUMN b INT;
    """
    statements = parse_migration(sql)
    assert len(statements) == 2


def test_parse_schema_tables(examples_dir: Path):
    schema = parse_schema((examples_dir / "schema.sql").read_text())
    assert "users" in schema.tables
    assert "events" in schema.tables
    assert "email" in schema.tables["users"].columns


def test_load_config(examples_dir: Path):
    config = load_config(examples_dir / "config.json")
    assert config.tables["events"].estimated_rows == 80_000_000
    assert config.settings.large_table_row_threshold == 1_000_000


def test_transaction_tracking():
    sql = """
    BEGIN;
    CREATE INDEX CONCURRENTLY idx ON users(email);
    COMMIT;
    """
    statements = parse_migration(sql)
    index_stmt = next(s for s in statements if "CREATE INDEX" in s.sql)
    assert index_stmt.in_transaction is True


def test_strip_sql_comments():
    sql = "SELECT 1; -- comment\n/* block */ UPDATE users SET x=1;"
    stripped = strip_sql_comments(sql)
    assert "comment" not in stripped
    assert "block" not in stripped
    assert "UPDATE" in stripped
