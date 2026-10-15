from fastapi import Depends, FastAPI, HTTPException
from .security import Principal, require, secure_app
from .planner import assess
from .schemas import AssessmentRequest, AssessmentResponse

app = FastAPI(
    title="AI .NET Modernization Assessor",
    version="0.2.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
secure_app(app)


@app.get("/health")
def health():
    import os

    return {
        "status": "ok",
        "model_enabled": os.getenv("GEMINI_ENABLED", "false").lower() == "true",
    }


@app.post("/assess", response_model=AssessmentResponse)
def assess_project(
    body: AssessmentRequest, principal: Principal = Depends(require("assessments:run"))
):
    try:
        return assess(body)
    except ValueError:
        raise HTTPException(422, "Invalid source sample") from None
