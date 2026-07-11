# migrate-risk

**Find dangerous database migrations before they lock production.**

A Python static analyzer that finds risky PostgreSQL migrations and generates safer rollout plans.

---

## Why migration risk matters

Database migrations are one of the few changes that can take down production without a code deploy. A single `CREATE INDEX` without `CONCURRENTLY`, an `ALTER TABLE ... ADD COLUMN ... NOT NULL`, or an unbatched `UPDATE` on a large table can lock writes, spike WAL, and cause replication lag — sometimes for hours.

**migrate-risk** analyzes migration SQL *statically* (no database connection required) and flags dangerous patterns before they reach production, with explanations, safer alternatives, and rollout plans.

> **This is static analysis, not a substitute for staging or production testing.** Always validate migrations against realistic data volumes in a non-production environment.

---

## What it detects

| Pattern | Risk |
|---------|------|
| `NOT NULL` column without safe backfill | High / Critical |
| Column with `DEFAULT` on large tables | Medium / High |
| Volatile defaults (`now()`, `gen_random_uuid()`, etc.) | Medium / High |
| `CREATE INDEX` without `CONCURRENTLY` | High |
| `UNIQUE` constraint on large tables | High |
| Foreign key without `NOT VALID` | High |
| Column type changes | High / Critical |
| `DROP TABLE` / `DROP COLUMN` | Critical |
| Table/column renames | High |
| `DELETE` / `UPDATE` without `WHERE` | Critical |
| Unbatched backfills | Medium / High |
| `CREATE INDEX CONCURRENTLY` inside transaction | High |
| Missing rollback notes for destructive ops | Medium |
| Lock-heavy `ALTER TABLE` on large tables | Medium / High |
| Constraint validation on large tables | Medium / High |

---

## What it does not do

- Connect to a live database (no credentials needed)
- Execute or simulate migrations against real data
- Guarantee zero-downtime — it recommends patterns, not proofs
- Support non-PostgreSQL dialects yet (MySQL planned)
- Parse every edge case of dynamic SQL or ORM-generated migrations

---

## Installation

Requires **Python 3.11+**.

```bash
git clone <repo-url>
cd database_migration_analyzer
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

---

## CLI usage

```bash
# Basic analysis
migrate-risk analyze examples/risky_migration.sql

# With schema and table-size config for better estimates
migrate-risk analyze examples/risky_migration.sql \
  --schema examples/schema.sql \
  --config examples/config.json

# JSON output
migrate-risk analyze examples/risky_migration.sql --format json

# HTML report
migrate-risk analyze examples/risky_migration.sql --format html --output report.html

# Exit nonzero on high+ risk (for CI)
migrate-risk analyze examples/risky_migration.sql --strict

# Custom fail threshold
migrate-risk analyze examples/risky_migration.sql --fail-on medium
```

### Options

| Option | Description |
|--------|-------------|
| `--schema` | Optional `schema.sql` for table/column metadata |
| `--config` | Optional `config.json` with row counts and criticality |
| `--format` | `text` (default), `json`, or `html` |
| `--output` | Write report to file |
| `--strict` | Exit 1 on high or critical risk |
| `--fail-on` | Exit 1 at `medium`, `high`, or `critical` |
| `--database` | Dialect (default: `postgres`) |

---

## Examples

```bash
# Risky migration — many findings, high score
migrate-risk analyze examples/risky_migration.sql \
  --schema examples/schema.sql --config examples/config.json

# Safe migration — nullable columns, CONCURRENTLY, NOT VALID FK
migrate-risk analyze examples/safe_migration.sql

# Expand/contract multi-step pattern
migrate-risk analyze examples/multi_step_migration.sql
```

---

## Config format

`config.json` supplies table statistics to refine severity and scoring:

```json
{
  "database": "postgres",
  "tables": {
    "users": {
      "estimated_rows": 5000000,
      "write_qps": 120,
      "criticality": "high"
    },
    "events": {
      "estimated_rows": 80000000,
      "write_qps": 400,
      "criticality": "critical"
    }
  },
  "settings": {
    "large_table_row_threshold": 1000000,
    "critical_table_row_threshold": 10000000
  }
}
```

Without config, rules still run but table-size-aware severity uses defaults (unknown size).

---

## Risk scoring model

Each finding has a severity: `low`, `medium`, `high`, or `critical`.

**Overall score (0–100)** combines:

1. **Max finding score** — base severity score adjusted by:
   - Table row count (large / critical thresholds)
   - Write QPS
   - Table criticality
   - Irreversibility
   - Lock / rewrite risk
   - Confidence level
2. **Extra findings penalty** — +3 per additional finding (capped at +15)

**Risk levels:**

| Score | Level |
|-------|-------|
| 0–24 | Low |
| 25–49 | Medium |
| 50–74 | High |
| 75–100 | Critical |

Scoring is deterministic: same input always produces the same score.

---

## Postgres-specific rules

Rules live in `migrate_risk/rules/postgres.py` and are easy to extend. Each rule returns structured `Finding` objects with:

- Evidence (source SQL)
- Why it matters in production
- Safer alternative SQL or pattern
- Step-by-step rollout plan
- Reversibility and lock/rewrite flags
- Confidence level

`CREATE INDEX CONCURRENTLY` cannot run inside `BEGIN`/`COMMIT` — migrate-risk detects that hazard when migrations are wrapped in transactions.

---

## Sample output

```
Migration Risk Report
Overall Risk: HIGH (72/100)

Finding 1: CREATE INDEX without CONCURRENTLY
Table: events
Severity: HIGH
Why it matters: Creating a normal index on a large write-heavy table can block writes.
Evidence: CREATE INDEX idx_events_type ON events(event_type)
Safer alternative: CREATE INDEX CONCURRENTLY idx_events_type ON events(event_type)
Rollout:
  1. Run CREATE INDEX CONCURRENTLY outside a transaction.
  2. Monitor lock waits and replication lag.
  3. Retry safely if interrupted.
```

---

## Limitations

- Parses SQL with [sqlglot](https://github.com/tobymao/sqlglot); unusual syntax may be missed
- Schema parsing is best-effort, not a full DDL engine
- Row counts come from config, not live metadata
- Cannot detect application-level coupling (e.g. code still reading dropped columns)
- Transaction context detection is line-based on parsed statements

---

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check migrate_risk tests
```

---

## Roadmap

- [ ] Live database metadata adapter
- [ ] GitHub Actions integration
- [ ] Alembic / Django / Rails migration support
- [ ] PR comment bot
- [ ] Postgres lock simulation
- [ ] MySQL support
- [ ] Table-size inference from statistics
- [ ] Migration dependency graph
- [ ] Automatic safer migration rewrite suggestions

---

## License

MIT
