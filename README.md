# AI .NET Modernization Assessor

An API prototype that combines a bounded, non-executing scanner for common legacy .NET signals with a Gemini-generated incremental migration plan. Static findings are produced first; model risks and migration waves must reference those finding IDs. When the model is disabled or produces invalid output, the app returns a deterministic plan.

## What it demonstrates

- A narrow HTTP API and typed request/response contracts for C# source samples.
- Safe handling of source snippets: no code is built or executed, file paths are checked, project XML DTD/entity declarations are rejected, and input size is bounded.
- Deterministic detection for classic `System.Web`, `BinaryFormatter`, `Thread.Abort`, legacy HTTP APIs, `ConfigurationManager`, and .NET Remoting markers.
- `.csproj` target framework extraction without loading project dependencies.
- Gemini structured output on Vertex AI grounded in scanner findings rather than raw, arbitrary model guesses.
- Reference validation that rejects plans which cite findings the scanner did not return.
- Mocked model tests and offline fallback behavior; no cloud credentials are needed for CI.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
pytest -q
uvicorn modernization_assessor.app:app --reload
```

Open `http://127.0.0.1:8000/docs`. The deterministic assessment works without Google Cloud credentials.

## Enable Gemini on Vertex AI

Install the optional SDK extra and configure ADC. The project needs billing, the Vertex AI API, and the `roles/aiplatform.user` permission.

```bash
pip install -e '.[vertex]'
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="global"
export GEMINI_ENABLED="true"
export GEMINI_MODEL="gemini-2.5-flash"
uvicorn modernization_assessor.app:app --reload
```

On PowerShell, use `$env:GOOGLE_CLOUD_PROJECT="your-project-id"` syntax. Vertex calls may incur charges. Never submit proprietary source or secrets unless your organization has approved that data flow.

## Example request

```json
{
  "project_name": "Legacy Checkout",
  "files": [
    {"path": "src/CheckoutController.cs", "content": "using System.Web;\npublic class CheckoutController { }"},
    {"path": "Checkout.csproj", "content": "<Project><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup></Project>"}
  ]
}
```

Send it to `POST /assess`. The response shows detected frameworks, evidence-backed findings, an incremental plan, risks, assumptions, and whether Gemini or the fallback produced the plan.

## Design limits

The scanner is a small pattern-based sample, not a Roslyn analyzer and not a complete inventory of a repository. It accepts at most 30 files, 20 KB per file, and 200 KB total. Results should start a technical discovery and characterization-testing process; they do not replace dependency analysis, build validation, architecture review, security assessment, or deployment planning.
