# AI .NET Modernization Assessor

An API prototype that combines a bounded, non-executing scanner for common legacy .NET signals with a Gemini-generated incremental migration plan. Static findings are produced first; model risks and migration waves must reference every finding ID. When the model is disabled or produces invalid output, the app returns a deterministic plan.

## What it demonstrates

- A narrow HTTP API and typed request/response contracts for C# source samples.
- Safe handling of source snippets: no code is built or executed, paths are canonicalized and checked, project XML DTD/entity declarations are rejected, and input size is bounded.
- Deterministic detection for classic `System.Web`, `BinaryFormatter`, `Thread.Abort`, legacy HTTP APIs, `ConfigurationManager`, and .NET Remoting markers.
- `.csproj` target framework extraction without loading project dependencies.
- Gemini structured output on Google Cloud grounded in scanner findings rather than raw, arbitrary model guesses.
- Model data minimization excludes caller source excerpts, paths, and project names entirely.
- Plan validation that rejects unknown references and plans that fail to account for any detected finding.
- Mocked model tests and offline fallback behavior; no cloud credentials are needed for CI.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
pip install --no-deps -e .
pytest -q
uvicorn modernization_assessor.app:app --host 127.0.0.1
```

Set `AUTH_PUBLIC_KEY` (RSA PEM), `AUTH_ISSUER`, and `AUTH_AUDIENCE` from your
identity provider. Send its token in `Authorization: Bearer <token>` with
`assessments:run` permission. Tokens require `sub`, `tenant_id`, `iat`, `exp`,
`iss`, `aud`, and `permissions`. Missing configuration fails closed; no anonymous
bypass exists. `/health` is public, and interactive docs are disabled. Deterministic
assessment needs no cloud credentials. See [SECURITY.md](SECURITY.md).

## Enable Gemini on Google Cloud

Install the optional SDK extra and configure Application Default Credentials (ADC). The Google Cloud project needs billing, the Gemini Enterprise Agent Platform API (`aiplatform.googleapis.com`), and permission to invoke models, such as `roles/aiplatform.user`.

```bash
pip install -e '.[google-cloud]'
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT="your-project-id"
export GOOGLE_CLOUD_LOCATION="global"
export GEMINI_ENABLED="true"
export GEMINI_MODEL="gemini-3.8-flash"
uvicorn modernization_assessor.app:app --host 127.0.0.1
```

On PowerShell, use `$env:GOOGLE_CLOUD_PROJECT="your-project-id"` syntax. Model calls may incur charges. Model calls receive only scanner-owned categories/rationales, finding IDs, and
validated framework names. Caller project names, paths, source excerpts, and
package names are excluded. Treat model use as an approved data flow; findings
can still reveal technical characteristics. Calls have a 10-second SDK timeout,
one attempt, and a 4,096-token output cap. Invalid output and provider failures
return a deterministic plan with a sanitized `fallback_reason`.

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

## Evidence and dependency inventory

Responses include `scanner_version`, `input_sha256`, `dependency_inventory`,
`build_validation: "not_evaluated"`, and `deployment_readiness: "not_evaluated"`.
Declared package/project/assembly references are read without evaluating MSBuild.
Conditions, property expressions, and missing package versions are marked
unresolved. Imported files, central package versions, transitive dependencies,
and runtime compatibility require further analysis; inventory is not resolution.
Project XML uses defusedxml with DTD/entities/external access forbidden. UTF-8
per-file and aggregate byte limits apply before analysis.

No source is persisted by this service. Keep request bodies and generated
responses out of gateway/APM logs. Source is returned only in response to its
own authenticated assessment request. The input digest is for provenance, not
an independent claim of correctness or a stable semantic code fingerprint.

## Safe validation and deployment sequence

1. Inventory the complete solution, imports, central package files, dependencies,
   deployment topology, integrations, data migration, and business constraints.
2. Add characterization tests and record baseline compatibility/performance.
3. If build validation is introduced, run restore/build/tests in a separate
   disposable sandbox. MSBuild and restore can execute untrusted code. Give it
   no production credentials, no host socket, no general network access, and
   strict CPU/memory/time limits. Do not execute builds inside this HTTP API.
4. Use successful baseline/target build and test results as evidence; keep
   unresolved failures explicit. Approve each migration wave through architecture review.
5. Deploy an immutable image to a canary, verify health/error/latency and data
   compatibility, and use a documented rollback gate before increasing traffic.

Required deployment controls include gateway TLS/fleet quotas, managed identity,
provider budgets, required CI checks, and monitoring for fallback/error rates.
Dependency resolution, an isolated build worker, semantic/Roslyn analysis, and
runtime deployment discovery remain explicit future work; this service does
not claim to perform them. Rich reports and automated remediation PRs are
optional after that evidence pipeline exists.

## Local Docker validation

Requires Docker Engine/Desktop with the Compose v2 plugin. From this repository:

```bash
docker compose config --quiet
docker compose up --build --wait --wait-timeout 120
python3 scripts/docker_smoke.py
docker compose down
```

The API binds only to `127.0.0.1:8011`. The default configuration deliberately
has no identity credentials: `/health` succeeds, docs return 404, and protected
requests return 503. The smoke script expects this unconfigured baseline;
it does not prove authenticated business operations or storage recovery.
Existing application tests cover those paths. The `Local Docker` workflow builds
and runs the actual image with the same Compose settings.

For authenticated local requests, provide `AUTH_ISSUER`, `AUTH_AUDIENCE`, and
`AUTH_PUBLIC_KEY` (the full RSA PEM) through your shell or a private `.env` file,
then recreate the container. Use tokens from your configured identity provider.
Never commit credentials. Model calls remain disabled in this local configuration.
The container runs as UID 65532 with a read-only root filesystem, a temporary
`/tmp`, dropped capabilities, and CPU/memory/process limits.
