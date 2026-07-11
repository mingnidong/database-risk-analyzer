"""Pydantic data models for migration risk analysis."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        if score <= 24:
            return cls.LOW
        if score <= 49:
            return cls.MEDIUM
        if score <= 74:
            return cls.HIGH
        return cls.CRITICAL

    def severity_weight(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class TableStats(BaseModel):
    """Per-table metadata used to refine risk estimates."""

    estimated_rows: int = 0
    write_qps: float = 0.0
    criticality: str = "medium"  # low | medium | high | critical


class AnalysisSettings(BaseModel):
    large_table_row_threshold: int = 1_000_000
    critical_table_row_threshold: int = 10_000_000


class AnalysisConfig(BaseModel):
    """Configuration loaded from config.json."""

    database: str = "postgres"
    tables: dict[str, TableStats] = Field(default_factory=dict)
    settings: AnalysisSettings = Field(default_factory=AnalysisSettings)


class RolloutStep(BaseModel):
    order: int
    description: str


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: RiskLevel
    table: str | None = None
    column: str | None = None
    why_it_matters: str
    evidence: str
    safer_alternative: str | None = None
    rollout_steps: list[RolloutStep] = Field(default_factory=list)
    reversible: bool = True
    may_lock_table: bool = False
    may_rewrite_table: bool = False
    confidence: str = "medium"  # low | medium | high
    line_number: int | None = None
    statement_index: int | None = None


class RuleResult(BaseModel):
    """Output from a single rule evaluation."""

    findings: list[Finding] = Field(default_factory=list)


class SchemaColumn(BaseModel):
    name: str
    data_type: str = ""
    nullable: bool = True
    default: str | None = None


class SchemaIndex(BaseModel):
    name: str
    columns: list[str] = Field(default_factory=list)
    unique: bool = False


class SchemaForeignKey(BaseModel):
    name: str | None = None
    columns: list[str] = Field(default_factory=list)
    referenced_table: str = ""
    referenced_columns: list[str] = Field(default_factory=list)


class SchemaTable(BaseModel):
    name: str
    columns: dict[str, SchemaColumn] = Field(default_factory=dict)
    primary_key: list[str] = Field(default_factory=list)
    indexes: list[SchemaIndex] = Field(default_factory=list)
    foreign_keys: list[SchemaForeignKey] = Field(default_factory=list)


class ParsedSchema(BaseModel):
    tables: dict[str, SchemaTable] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class ParsedStatement(BaseModel):
    index: int
    sql: str
    line_number: int
    in_transaction: bool = False
    ast: Any = None  # sqlglot Expression; excluded from serialization


class MigrationAnalysis(BaseModel):
    migration_file: str
    database: str = "postgres"
    overall_risk: RiskLevel
    risk_score: int
    findings: list[Finding] = Field(default_factory=list)
    affected_tables: list[str] = Field(default_factory=list)
    affected_columns: list[str] = Field(default_factory=list)
    rollout_plan: list[RolloutStep] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    statement_count: int = 0

    model_config = {"arbitrary_types_allowed": True}
