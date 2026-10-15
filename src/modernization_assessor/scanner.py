"""Bounded, non-executing scanner for common legacy .NET migration signals."""

from __future__ import annotations

import re
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from pathlib import PurePosixPath

from .schemas import AssessmentRequest, Dependency, Finding

TOTAL_BYTES_LIMIT = 200_000
PATTERNS = (
    (
        "binaryformatter",
        "high",
        re.compile(r"\bBinaryFormatter\b", re.I),
        "BinaryFormatter is unsafe for untrusted data and should be removed.",
    ),
    (
        "thread_abort",
        "high",
        re.compile(r"\bThread\s*\.\s*Abort\s*\(", re.I),
        "Thread.Abort is unsupported or unsafe in modern .NET and needs cancellation-based control flow.",
    ),
    (
        "system_web",
        "high",
        re.compile(r"\bSystem\.Web\b|\bHttpContext\.Current\b"),
        "System.Web is tied to classic ASP.NET and requires an ASP.NET Core boundary redesign.",
    ),
    (
        "legacy_http_client",
        "medium",
        re.compile(r"\bHttpWebRequest\b|\bWebClient\b"),
        "Legacy HTTP APIs should be reviewed for migration to HttpClient and managed lifetimes.",
    ),
    (
        "configuration_manager",
        "medium",
        re.compile(r"\bConfigurationManager\b"),
        "ConfigurationManager usage should be mapped to modern configuration and secret providers.",
    ),
    (
        "remoting",
        "high",
        re.compile(r"\b(?:MarshalByRefObject|RemotingConfiguration)\b"),
        ".NET Remoting patterns need replacement with an explicit supported communication boundary.",
    ),
)
SUPPORTED_SUFFIXES = {".cs", ".csproj", ".config"}


def _safe_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    parsed = PurePosixPath(normalized)
    if (
        parsed.is_absolute()
        or re.match(r"^[A-Za-z]:", normalized)
        or ".." in parsed.parts
        or parsed.suffix.lower() not in SUPPORTED_SUFFIXES
    ):
        raise ValueError(f"Unsupported or unsafe source path: {path}")
    canonical = parsed.as_posix()
    if canonical in {"", "."}:
        raise ValueError("Source path must name a supported file")
    return canonical


def scan(request: AssessmentRequest) -> tuple[list[str], list[Finding]]:
    total = 0
    frameworks: list[str] = []
    findings: list[Finding] = []
    seen_paths: set[str] = set()
    for item in request.files:
        path = _safe_path(item.path)
        path_key = path.casefold()
        if path_key in seen_paths:
            raise ValueError(f"Duplicate source path: {path}")
        seen_paths.add(path_key)
        item_bytes = len(item.content.encode("utf-8"))
        if item_bytes > 20_000:
            raise ValueError("Source file exceeds the 20 KB limit")
        total += item_bytes
        if total > TOTAL_BYTES_LIMIT:
            raise ValueError("Combined source content exceeds the 200 KB demo limit")
        if path.lower().endswith(".csproj"):
            if (
                "<!DOCTYPE" in item.content.upper()
                or "<!ENTITY" in item.content.upper()
            ):
                raise ValueError(
                    "Project manifests with DTD or entity declarations are not accepted"
                )
            try:
                root = ET.fromstring(
                    item.content,
                    forbid_dtd=True,
                    forbid_entities=True,
                    forbid_external=True,
                )
            except DefusedXmlException:
                raise ValueError("Unsafe project XML") from None
            except ET.ParseError:
                findings.append(
                    Finding(
                        finding_id=f"finding-{len(findings) + 1:02d}",
                        category="invalid_project_manifest",
                        severity="high",
                        file=path,
                        evidence="Project XML could not be parsed",
                        rationale="Resolve project-file errors before planning framework migration.",
                    )
                )
                continue
            for node in root.iter():
                if (
                    node.tag.split("}")[-1] in {"TargetFramework", "TargetFrameworks"}
                    and node.text
                ):
                    frameworks.extend(
                        value.strip() for value in node.text.split(";") if value.strip()
                    )
        if path.lower().endswith(".cs"):
            for category, severity, pattern, rationale in PATTERNS:
                match = pattern.search(item.content)
                if match:
                    start, end = (
                        max(0, match.start() - 60),
                        min(len(item.content), match.end() + 100),
                    )
                    snippet = " ".join(item.content[start:end].split())
                    findings.append(
                        Finding(
                            finding_id=f"finding-{len(findings) + 1:02d}",
                            category=category,
                            severity=severity,
                            file=path,
                            evidence=snippet[:220],
                            rationale=rationale,
                        )
                    )
    return sorted(set(frameworks)), findings


def dependency_inventory(request: AssessmentRequest) -> list[Dependency]:
    """Read declarations only; do not evaluate MSBuild, resolve packages, or execute restore.

    Conditions and property expressions are marked unresolved. Transitive packages,
    imported build files and external references remain outside this bounded inventory.
    """
    records = []
    for item in request.files:
        if not item.path.lower().endswith(".csproj"):
            continue
        path = _safe_path(item.path)
        if "<!DOCTYPE" in item.content.upper() or "<!ENTITY" in item.content.upper():
            raise ValueError("DTD/entity declarations are not accepted")
        try:
            root = ET.fromstring(
                item.content,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            )
        except DefusedXmlException:
            raise ValueError("Unsafe project XML") from None
        except ET.ParseError:
            continue
        kinds = {
            "PackageReference": "package",
            "ProjectReference": "project",
            "Reference": "assembly",
        }

        def visit(node, conditional=False, depth=0):
            if depth > 32:
                raise ValueError("Project XML nesting limit exceeded")
            conditional = conditional or bool(node.attrib.get("Condition"))
            name = node.tag.split("}")[-1]
            if name in kinds:
                reference = node.attrib.get("Include") or node.attrib.get("Update")
                version = node.attrib.get("Version")
                for child in node:
                    if child.tag.split("}")[-1] == "Version" and child.text:
                        version = child.text.strip()
                if reference:
                    records.append(
                        Dependency(
                            file=path,
                            kind=kinds[name],
                            name=reference[:500],
                            version=version[:200] if version else None,
                            conditional=conditional,
                            unresolved=conditional
                            or "$(" in reference
                            or bool(version and "$(" in version)
                            or (name == "PackageReference" and not version),
                        )
                    )
            for child in node:
                visit(child, conditional, depth + 1)

        visit(root)
    return records
