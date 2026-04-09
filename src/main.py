"""AgentShield — Runtime security for AI agents."""

import os
from datetime import datetime, timezone

from fastapi import FastAPI

app = FastAPI(
    title="AgentShield",
    description="Runtime security proxy for AI agents",
    version="0.1.0",
)


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
