"""AgentShield — Runtime security for AI agents."""

import os
from datetime import datetime, timezone

from fastapi import FastAPI
from pydantic import BaseModel

from src.detectors.prompt_injection import detect_prompt_injection

app = FastAPI(
    title="AgentShield",
    description="Runtime security proxy for AI agents",
    version="0.1.0",
)


# ── Request/Response models ──

class ScanRequest(BaseModel):
    text: str
    agent_id: str | None = None
    context: str | None = None


class ScanResponse(BaseModel):
    is_injection: bool
    risk_level: str
    score: float
    matched_patterns: list[str]
    explanation: str
    action: str  # "allow", "block", "flag"
    scanned_at: str


# ── Endpoints ──

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "0.1.0",
        "environment": os.getenv("APP_ENV", "development"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/")
async def root():
    return {"message": "AgentShield API", "docs": "/docs"}


@app.post("/scan", response_model=ScanResponse)
async def scan_text(request: ScanRequest):
    """Scan text for prompt injection attacks."""
    result = detect_prompt_injection(request.text)

    # Determine action based on risk level
    if result.risk_level in ("critical", "high"):
        action = "block"
    elif result.risk_level == "medium":
        action = "flag"
    else:
        action = "allow"

    return ScanResponse(
        is_injection=result.is_injection,
        risk_level=result.risk_level,
        score=result.score,
        matched_patterns=result.matched_patterns,
        explanation=result.explanation,
        action=action,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/scan/batch")
async def scan_batch(requests: list[ScanRequest]):
    """Scan multiple texts for prompt injection attacks."""
    results = []
    for req in requests:
        result = detect_prompt_injection(req.text)
        action = "block" if result.risk_level in ("critical", "high") else (
            "flag" if result.risk_level == "medium" else "allow"
        )
        results.append(ScanResponse(
            is_injection=result.is_injection,
            risk_level=result.risk_level,
            score=result.score,
            matched_patterns=result.matched_patterns,
            explanation=result.explanation,
            action=action,
            scanned_at=datetime.now(timezone.utc).isoformat(),
        ))
    return {"results": results, "total": len(results), "blocked": sum(1 for r in results if r.action == "block")}
