"""Tests for rollout plan generation."""

from migrate_risk.models import Finding, RiskLevel, RolloutStep
from migrate_risk.rollout import build_rollout_plan


def test_build_rollout_plan_deduplicates():
    findings = [
        Finding(
            rule_id="A",
            title="Test",
            severity=RiskLevel.HIGH,
            why_it_matters="x",
            evidence="sql1",
            rollout_steps=[
                RolloutStep(order=1, description="Step one"),
                RolloutStep(order=2, description="Step two"),
            ],
        ),
        Finding(
            rule_id="B",
            title="Test 2",
            severity=RiskLevel.MEDIUM,
            why_it_matters="y",
            evidence="sql2",
            rollout_steps=[
                RolloutStep(order=1, description="Step one"),
            ],
        ),
    ]
    plan = build_rollout_plan(findings)
    descriptions = [s.description for s in plan]
    assert descriptions.count("Step one") == 1
    assert len(plan) == 2


def test_rollout_plan_from_risky_migration(examples_dir):
    from migrate_risk.analyzer import analyze_migration

    result = analyze_migration(examples_dir / "risky_migration.sql")
    assert len(result.rollout_plan) >= 1
