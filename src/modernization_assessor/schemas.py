from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=240)
    content: str = Field(min_length=1, max_length=20_000)

    @field_validator("path")
    @classmethod
    def trim_path(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("path must not be blank")
        return value


class AssessmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    project_name: str = Field(min_length=1, max_length=120)
    files: list[SourceFile] = Field(min_length=1, max_length=30)

    @field_validator("project_name")
    @classmethod
    def trim_project_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("project_name must not be blank")
        return value


class Finding(BaseModel):
    finding_id: str
    category: str
    severity: Literal["low", "medium", "high"]
    file: str
    evidence: str
    rationale: str


class MigrationWave(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    goal: str = Field(min_length=8, max_length=400)
    finding_ids: list[str] = Field(max_length=180)
    checks: list[str] = Field(min_length=1, max_length=5)


class RiskItem(BaseModel):
    risk: str = Field(min_length=5, max_length=300)
    finding_ids: list[str] = Field(min_length=1, max_length=180)
    mitigation: str = Field(min_length=8, max_length=400)


class ModernizationPlan(BaseModel):
    executive_summary: str = Field(min_length=20, max_length=1000)
    suggested_target: str = Field(min_length=2, max_length=100)
    migration_waves: list[MigrationWave] = Field(min_length=1, max_length=5)
    risks: list[RiskItem] = Field(max_length=8)
    assumptions: list[str] = Field(max_length=8)


class Dependency(BaseModel):
    file: str
    kind: Literal["package", "project", "assembly"]
    name: str
    version: str | None = None
    conditional: bool = False
    unresolved: bool = False


class AssessmentResponse(BaseModel):
    project_name: str
    analysis_mode: Literal["google_cloud_gemini", "deterministic_fallback"]
    detected_target_frameworks: list[str]
    findings: list[Finding]
    plan: ModernizationPlan
    files_analyzed: int

    scanner_version: str = "0.2.0"
    input_sha256: str
    build_validation: Literal["not_evaluated"] = "not_evaluated"
    deployment_readiness: Literal["not_evaluated"] = "not_evaluated"
    dependency_inventory: list[Dependency] = Field(default_factory=list)
    dependency_analysis: Literal["static_declared_references_only"] = (
        "static_declared_references_only"
    )
    fallback_reason: (
        Literal["model_disabled", "timeout", "invalid_output", "provider_error"] | None
    ) = None
