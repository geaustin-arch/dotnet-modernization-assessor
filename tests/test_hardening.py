import json
import logging
import pytest
from modernization_assessor.planner import assess, _prompt
from modernization_assessor.schemas import AssessmentRequest, SourceFile


def sample():
    return AssessmentRequest(
        project_name="secret-project-canary",
        files=[
            SourceFile(
                path="secret-path-canary.cs",
                content="using System.Web; // apiKey=secret-source-canary",
            ),
            SourceFile(
                path="x.csproj",
                content="""<Project><PropertyGroup><TargetFrameworks>net48;apiKey=secret-framework-canary</TargetFrameworks></PropertyGroup><ItemGroup Condition="'$(Configuration)'=='Release'"><PackageReference Include="Example" Version="$(PackageVersion)"/><ProjectReference Include="../Core/Core.csproj"/></ItemGroup></Project>""",
            ),
        ],
    )


def test_model_egress_contains_no_caller_text_or_malformed_frameworks():
    from modernization_assessor.scanner import scan

    req = sample()
    frameworks, findings = scan(req)
    prompt = _prompt(req, frameworks, findings)
    assert "canary" not in prompt
    assert "System.Web" in prompt  # scanner-owned rationale remains useful
    assert json.loads(prompt)["target_frameworks"] == ["net48"]


def test_declared_dependencies_are_marked_unresolved_and_no_readiness_is_claimed():
    result = assess(sample())
    assert result.build_validation == "not_evaluated"
    assert result.deployment_readiness == "not_evaluated"
    assert len(result.input_sha256) == 64
    assert result.scanner_version == "0.2.0"
    assert len(result.dependency_inventory) == 2
    assert all(d.conditional and d.unresolved for d in result.dependency_inventory)
    assert result.fallback_reason == "model_disabled"
    assert result.input_sha256 == assess(sample()).input_sha256


@pytest.mark.parametrize(
    "error,reason",
    [
        (TimeoutError("secret-canary"), "timeout"),
        (RuntimeError("secret-canary"), "provider_error"),
        (ValueError("secret-canary"), "invalid_output"),
    ],
)
def test_provider_failure_has_safe_observable_fallback(error, reason, caplog):
    class FailedProvider:
        def plan(self, prompt):
            raise error

    with caplog.at_level(logging.WARNING):
        result = assess(sample(), FailedProvider())
    assert result.analysis_mode == "deterministic_fallback"
    assert result.fallback_reason == reason
    assert "secret-canary" not in caplog.text


def test_deep_dependency_xml_is_bounded():
    content = "<Project>" + "<Group>" * 40 + "</Group>" * 40 + "</Project>"
    with pytest.raises(ValueError, match="nesting"):
        assess(
            AssessmentRequest(
                project_name="x", files=[SourceFile(path="x.csproj", content=content)]
            )
        )


def test_per_file_limit_counts_utf8_bytes():
    with pytest.raises(ValueError, match="20 KB"):
        assess(
            AssessmentRequest(
                project_name="x", files=[SourceFile(path="x.cs", content="é" * 11_000)]
            )
        )
