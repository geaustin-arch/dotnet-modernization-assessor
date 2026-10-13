from fastapi import FastAPI, HTTPException
from .planner import assess
from .schemas import AssessmentRequest, AssessmentResponse

app = FastAPI(title="AI .NET Modernization Assessor", version="0.1.0")


@app.get("/health")
def health():
    import os
    return {"status": "ok", "model_enabled": os.getenv("GEMINI_ENABLED", "false").lower() == "true"}


@app.post("/assess", response_model=AssessmentResponse)
def assess_project(body: AssessmentRequest):
    try:
        return assess(body)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
