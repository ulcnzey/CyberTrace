"""CyberTrace application entry point."""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.hub import hub
from app.api.routes.analyses import router as analyses_router
from app.api.routes.health import router as health_router
from app.api.routes.live import router as live_router
from app.api.routes.reports import router as reports_router
from app.api.websocket import router as websocket_router
from app.config import settings
from app.persistence.database import init_db
from app.services.live_monitor import live_monitor


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    hub.set_loop(asyncio.get_running_loop())
    yield
    live_monitor.stop()


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )
    application.include_router(health_router)
    application.include_router(analyses_router)
    application.include_router(reports_router)
    application.include_router(live_router)
    application.include_router(websocket_router)

    web_dir = settings.web_dir
    application.mount("/static", StaticFiles(directory=web_dir), name="static")

    @application.get("/")
    def index() -> FileResponse:
        return FileResponse(web_dir / "index.html")

    return application


app = create_app()
