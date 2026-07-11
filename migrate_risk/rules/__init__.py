"""Rule registry for migration analysis."""

from migrate_risk.rules.postgres import POSTGRES_RULES

__all__ = ["POSTGRES_RULES", "get_rules"]


def get_rules(database: str):
    """Return rule list for the given database dialect."""
    if database.lower() in ("postgres", "postgresql"):
        return POSTGRES_RULES
    return POSTGRES_RULES
