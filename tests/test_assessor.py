import json
import pytest

from modernization_assessor.planner import assess
from modernization_assessor.scanner import scan
from modernization_assessor.schemas import AssessmentRequest, SourceFile


class FakeProvider:
    def __init__(self, payload):
        self.payload = payload
        self.prompt = ""
    def plan(self, prompt):
        self.prompt = prompt
        return json.dumps(self.payload)


def request(files=None):
    return AssessmentRequest(project_name="Legacy Checkout", files=files or [
        SourceFile(path="src/Checkout.cs", content="using System.Web;\nvar formatter = new BinaryFormatter();"),
        SourceFile(path="Checkout.csproj", content="<Project><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup></Project>")])


def test_scanner_extracts_framework_and_grounded_findings():
    frameworks, findings = scan(request())
    assert frameworks == ["net48"]
    assert {f.category for f in findings} == {"system_web", "binaryformatter"}
    assert all(f.evidence and f.finding_id.startswith("finding-") for f in findings)


def test_model_plan_uses_scanner_finding_ids():
    base = assess(request())
    first_id = base.findings[0].finding_id
    provider = FakeProvider({"executive_summary":"Modernize the supplied legacy checkout sample incrementally.",
        "suggested_target":".NET 10 LTS candidate","migration_waves":[{"name":"Replace legacy web layer",
        "goal":"Move web-specific behavior behind a testable application boundary.","finding_ids":[first_id],
        "checks":["Run compatibility tests."]}],"risks":[],"assumptions":["This is a bounded source sample."]})
    result = assess(request(), provider)
    assert result.analysis_mode == "vertex_gemini"
    assert first_id in provider.prompt


def test_unknown_model_references_fall_back_safely():
    provider = FakeProvider({"executive_summary":"Modernize the supplied legacy checkout sample incrementally.",
        "suggested_target":".NET 10 LTS candidate","migration_waves":[{"name":"Replace old layer",
        "goal":"Move the old behavior behind a testable boundary.","finding_ids":["invented-finding"],
        "checks":["Run compatibility tests."]}],"risks":[],"assumptions":[]})
    result = assess(request(), provider)
    assert result.analysis_mode == "deterministic_fallback"
    assert all(ref in {f.finding_id for f in result.findings} for wave in result.plan.migration_waves for ref in wave.finding_ids)


@pytest.mark.parametrize("path", ["../secrets.cs", "/etc/passwd.cs", "notes.txt"])
def test_scanner_rejects_unsafe_or_unsupported_paths(path):
    with pytest.raises(ValueError):
        scan(AssessmentRequest(project_name="x", files=[SourceFile(path=path, content="class C {}")]))


def test_scanner_rejects_dtd_and_duplicate_paths():
    with pytest.raises(ValueError):
        scan(AssessmentRequest(project_name="x", files=[SourceFile(path="x.csproj", content="<!DOCTYPE Project [<!ENTITY x 'a'>]><Project/>")]))
    with pytest.raises(ValueError):
        scan(AssessmentRequest(project_name="x", files=[SourceFile(path="x.cs", content="a"),SourceFile(path="x.cs", content="b")]))


def test_api_bounds_and_fallback(monkeypatch):
    from fastapi.testclient import TestClient
    from modernization_assessor.app import app
    monkeypatch.setenv("GEMINI_ENABLED", "false")
    client = TestClient(app)
    response = client.post("/assess", json={"project_name":"Legacy Checkout","files":[{"path":"x.cs","content":"using System.Web;"}]})
    assert response.status_code == 200
    assert response.json()["analysis_mode"] == "deterministic_fallback"
    assert client.get("/health").status_code == 200
    assert client.post("/assess", json={"project_name":"x","files":[]}).status_code == 422
