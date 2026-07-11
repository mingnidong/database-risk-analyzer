"""Rollout plan aggregation from findings."""

from __future__ import annotations

from migrate_risk.models import Finding, RolloutStep


def build_rollout_plan(findings: list[Finding]) -> list[RolloutStep]:
    """Merge rollout steps from all findings into a deduplicated ordered plan."""
    seen: set[str] = set()
    steps: list[RolloutStep] = []
    order = 1

    for finding in sorted(findings, key=lambda f: f.severity.severity_weight(), reverse=True):
        for step in finding.rollout_steps:
            key = step.description.strip().lower()
            if key in seen:
                continue
            seen.add(key)
            steps.append(RolloutStep(order=order, description=step.description))
            order += 1

    if not steps and findings:
        steps.append(
            RolloutStep(
                order=1,
                description="Review all findings and test migration in staging before production.",
            )
        )

    return steps
