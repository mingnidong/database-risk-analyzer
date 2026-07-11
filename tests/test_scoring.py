"""Tests for risk scoring."""

from pathlib import Path

from migrate_risk.analyzer import analyze_migration
from migrate_risk.models import AnalysisConfig, Finding, RiskLevel
from migrate_risk.scoring import compute_overall_score, overall_risk_level, score_finding


def test_score_increases_with_table_size(examples_dir: Path):
    config_small = AnalysisConfig()
    config_large = AnalysisConfig(
        tables={
            "events": {
                "estimated_rows": 80_000_000,
                "write_qps": 400,
                "criticality": "critical",
            }
        }
    )
    finding = Finding(
        rule_id="PG004",
        title="CREATE INDEX without CONCURRENTLY",
        severity=RiskLevel.HIGH,
        table="events",
        why_it_matters="test",
        evidence="CREATE INDEX idx ON events(x)",
    )
    small_score = score_finding(finding, config_small)
    large_score = score_finding(finding, config_large)
    assert large_score > small_score


def test_overall_risk_levels():
    assert overall_risk_level(10) == RiskLevel.LOW
    assert overall_risk_level(30) == RiskLevel.MEDIUM
    assert overall_risk_level(60) == RiskLevel.HIGH
    assert overall_risk_level(80) == RiskLevel.CRITICAL


def test_empty_findings_score_zero():
    assert compute_overall_score([], AnalysisConfig()) == 0


def test_safe_migration_lower_than_risky(examples_dir: Path):
    risky = analyze_migration(
        examples_dir / "risky_migration.sql",
        config_path=examples_dir / "config.json",
    )
    safe = analyze_migration(
        examples_dir / "safe_migration.sql",
        config_path=examples_dir / "config.json",
    )
    assert safe.risk_score < risky.risk_score
