from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


class SourceFile(BaseModel):
    path: str = Field(min_length=1, max_length=240)
    content: str = Field(min_length=1, max_length=20_000)


class AssessmentRequest(BaseModel):
    project_name: str = Field(min_length=1, max_length=120)
    files: list[SourceFile] = Field(min_length=1, max_length=30)


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
    finding_ids: list[str] = Field(max_length=20)
    checks: list[str] = Field(min_length=1, max_length=5)


class RiskItem(BaseModel):
    risk: str = Field(min_length=5, max_length=300)
    finding_ids: list[str] = Field(min_length=1, max_length=20)
    mitigation: str = Field(min_length=8, max_length=400)


class ModernizationPlan(BaseModel):
    executive_summary: str = Field(min_length=20, max_length=1000)
    suggested_target: str = Field(min_length=2, max_length=100)
    migration_waves: list[MigrationWave] = Field(min_length=1, max_length=5)
    risks: list[RiskItem] = Field(max_length=8)
    assumptions: list[str] = Field(max_length=8)


class AssessmentResponse(BaseModel):
    project_name: str
    analysis_mode: Literal["vertex_gemini", "deterministic_fallback"]
    detected_target_frameworks: list[str]
    findings: list[Finding]
    plan: ModernizationPlan
    files_analyzed: int
