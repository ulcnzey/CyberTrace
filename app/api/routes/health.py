"""Liveness check for the API process and the database."""

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.persistence.database import get_db

router = APIRouter(tags=["health"])


@router.get("/health", response_model=None)
def health(db: Session = Depends(get_db)) -> JSONResponse:
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "application": settings.app_name,
                "database": "unavailable",
            },
        )
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "application": settings.app_name,
            "database": "ok",
        },
    )
