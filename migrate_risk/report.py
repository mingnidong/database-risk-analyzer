"""Report generation: text, JSON, and HTML output."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from jinja2 import Template
from rich.console import Console
from rich.panel import Panel

from migrate_risk.models import MigrationAnalysis, RiskLevel

RISK_COLORS = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bold red",
}


HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Migration Risk Report — {{ analysis.migration_file }}</title>
  <style>
    :root {
      --bg: #0f1419;
      --card: #1a2332;
      --text: #e6edf3;
      --muted: #8b949e;
      --low: #3fb950;
      --medium: #d29922;
      --high: #f85149;
      --critical: #ff6b6b;
      --accent: #58a6ff;
      --border: #30363d;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
      max-width: 960px;
      margin: 0 auto;
    }
    h1 { font-size: 1.75rem; margin-bottom: 0.25rem; }
    .tagline { color: var(--muted); margin-bottom: 2rem; }
    .summary-card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 1rem;
      align-items: center;
    }
    .risk-badge {
      font-size: 1.5rem;
      font-weight: 700;
      padding: 0.5rem 1rem;
      border-radius: 8px;
      text-transform: uppercase;
    }
    .risk-low { background: rgba(63,185,80,0.2); color: var(--low); }
    .risk-medium { background: rgba(210,153,34,0.2); color: var(--medium); }
    .risk-high { background: rgba(248,81,73,0.2); color: var(--high); }
    .risk-critical { background: rgba(255,107,107,0.25); color: var(--critical); }
    .score { font-size: 2.5rem; font-weight: 700; color: var(--accent); }
    .section { margin-bottom: 2rem; }
    .section h2 {
      font-size: 1.25rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }
    .finding {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
    }
    .finding h3 { font-size: 1rem; margin-bottom: 0.5rem; }
    .meta { color: var(--muted); font-size: 0.875rem; margin-bottom: 0.75rem; }
    .label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
    pre {
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.75rem;
      overflow-x: auto;
      font-size: 0.8rem;
      margin: 0.5rem 0;
    }
    ol { padding-left: 1.25rem; }
    li { margin-bottom: 0.35rem; }
    .warnings {
      background: rgba(210,153,34,0.1);
      border: 1px solid var(--medium);
      border-radius: 8px;
      padding: 1rem;
    }
    .tags { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.5rem; }
    .tag {
      font-size: 0.7rem;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      background: #21262d;
      color: var(--muted);
    }
    footer { color: var(--muted); font-size: 0.8rem; margin-top: 3rem; text-align: center; }
  </style>
</head>
<body>
  <h1>Migration Risk Report</h1>
  <p class="tagline">Find dangerous database migrations before they lock production.</p>

  <div class="summary-card">
    <div>
      <p class="label">Migration file</p>
      <p>{{ analysis.migration_file }}</p>
      <p class="meta">{{ analysis.statement_count }} statements · {{ analysis.findings|length }} findings</p>
      {% if analysis.affected_tables %}
      <p class="meta">Affected tables: {{ analysis.affected_tables|join(', ') }}</p>
      {% endif %}
    </div>
    <div style="text-align: right;">
      <p class="label">Overall risk</p>
      <div class="risk-badge risk-{{ analysis.overall_risk.value }}">{{ analysis.overall_risk.value }}</div>
      <p class="score">{{ analysis.risk_score }}/100</p>
    </div>
  </div>

  {% if analysis.rollout_plan %}
  <div class="section">
    <h2>Recommended Rollout Plan</h2>
    <ol>
      {% for step in analysis.rollout_plan %}
      <li>{{ step.description }}</li>
      {% endfor %}
    </ol>
  </div>
  {% endif %}

  <div class="section">
    <h2>Findings</h2>
    {% for finding in analysis.findings %}
    <div class="finding">
      <h3>{{ loop.index }}. {{ finding.title }}</h3>
      <p class="meta">
        Severity: <strong>{{ finding.severity.value|upper }}</strong>
        {% if finding.table %} · Table: {{ finding.table }}{% endif %}
        {% if finding.column %} · Column: {{ finding.column }}{% endif %}
        · Confidence: {{ finding.confidence }}
      </p>
      <p><span class="label">Why it matters</span><br>{{ finding.why_it_matters }}</p>
      <p class="label" style="margin-top:0.75rem">Evidence</p>
      <pre>{{ finding.evidence }}</pre>
      {% if finding.safer_alternative %}
      <p><span class="label">Safer alternative</span><br>{{ finding.safer_alternative }}</p>
      {% endif %}
      {% if finding.rollout_steps %}
      <p class="label" style="margin-top:0.75rem">Rollout</p>
      <ol>
        {% for step in finding.rollout_steps %}
        <li>{{ step.description }}</li>
        {% endfor %}
      </ol>
      {% endif %}
      <div class="tags">
        <span class="tag">{{ 'Reversible' if finding.reversible else 'Irreversible' }}</span>
        {% if finding.may_lock_table %}<span class="tag">May lock table</span>{% endif %}
        {% if finding.may_rewrite_table %}<span class="tag">May rewrite table</span>{% endif %}
      </div>
    </div>
    {% else %}
    <p>No risky patterns detected.</p>
    {% endfor %}
  </div>

  {% if analysis.warnings %}
  <div class="section warnings">
    <h2>Warnings &amp; Limitations</h2>
    <ul>
      {% for w in analysis.warnings %}
      <li>{{ w }}</li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  <footer>
    Generated by migrate-risk · Static analysis only — not a substitute for staging/production testing.
  </footer>
</body>
</html>
""")


def render_text(analysis: MigrationAnalysis, console: Console | None = None) -> str:
    """Render a rich text report and return as string."""
    # Record to a buffer only; printing to stdout would duplicate CLI output.
    con = Console(record=True, file=StringIO(), width=100)
    risk_color = RISK_COLORS.get(analysis.overall_risk, "white")

    con.print()
    con.print(Panel.fit("[bold]Migration Risk Report[/bold]", border_style="blue"))
    con.print(
        f"File: [cyan]{analysis.migration_file}[/cyan]  "
        f"({analysis.statement_count} statements)"
    )
    con.print(
        f"Overall Risk: [{risk_color} bold]{analysis.overall_risk.value.upper()}[/] "
        f"([{risk_color}]{analysis.risk_score}/100[/])"
    )

    if analysis.affected_tables:
        con.print(f"Affected tables: [dim]{', '.join(analysis.affected_tables)}[/dim]")

    if analysis.rollout_plan:
        con.print("\n[bold]Recommended Rollout Plan[/bold]")
        for step in analysis.rollout_plan:
            con.print(f"  {step.order}. {step.description}")

    for i, finding in enumerate(analysis.findings, 1):
        sev_color = RISK_COLORS.get(finding.severity, "white")
        con.print()
        con.print(f"[bold]Finding {i}:[/bold] {finding.title}")
        if finding.table:
            con.print(f"  Table: [cyan]{finding.table}[/cyan]")
        if finding.column:
            con.print(f"  Column: [cyan]{finding.column}[/cyan]")
        con.print(f"  Severity: [{sev_color}]{finding.severity.value.upper()}[/]")
        con.print(f"  Why it matters: {finding.why_it_matters}")
        con.print(f"  Evidence: [dim]{finding.evidence}[/dim]")
        if finding.safer_alternative:
            con.print(f"  Safer alternative: [green]{finding.safer_alternative}[/green]")
        if finding.rollout_steps:
            con.print("  Rollout:")
            for step in finding.rollout_steps:
                con.print(f"    {step.order}. {step.description}")
        tags = []
        tags.append("reversible" if finding.reversible else "irreversible")
        if finding.may_lock_table:
            tags.append("may lock table")
        if finding.may_rewrite_table:
            tags.append("may rewrite table")
        con.print(f"  Tags: [dim]{', '.join(tags)}[/dim] (confidence: {finding.confidence})")

    if analysis.warnings:
        con.print("\n[yellow bold]Warnings[/yellow bold]")
        for w in analysis.warnings:
            con.print(f"  • {w}")

    if not analysis.findings:
        con.print("\n[green]No risky patterns detected.[/green]")

    con.print()
    return con.export_text()


def render_json(analysis: MigrationAnalysis) -> str:
    """Serialize analysis to JSON."""
    data = analysis.model_dump(mode="json")
    return json.dumps(data, indent=2)


def render_html(analysis: MigrationAnalysis) -> str:
    """Render standalone HTML report."""
    return HTML_TEMPLATE.render(analysis=analysis)


def write_report(
    analysis: MigrationAnalysis,
    fmt: str,
    output_path: Path | None = None,
    console: Console | None = None,
) -> str:
    """Generate report in requested format, optionally writing to file."""
    if fmt == "json":
        content = render_json(analysis)
    elif fmt == "html":
        content = render_html(analysis)
    else:
        content = render_text(analysis, console)

    if output_path:
        output_path.write_text(content, encoding="utf-8")

    return content
