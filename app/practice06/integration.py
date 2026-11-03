"""Fail-closed integration into the same app; never silently retain legacy routes."""
from pathlib import Path
from fastapi import FastAPI
from app.db.connection import DB_PATH
from .config import SecuritySettings, get_settings
from .router import router
from .service import DeanService


def install_practice06(app: FastAPI, *, database_path: Path = DB_PATH,
                       settings: SecuritySettings | None = None) -> None:
    allowed = {"/health", "/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"}
    if any(getattr(route, "path", None) not in allowed for route in app.routes):
        raise RuntimeError("remove legacy router registrations before installing practical 6")
    if getattr(app.state, "practice06_installed", False):
        raise RuntimeError("practical 6 is already installed")
    app.state.practice06_settings = settings if settings is not None else get_settings()
    app.state.practice06_service = DeanService(database_path)
    app.include_router(router)
    app.version = "0.6.0"
    app.openapi_schema = None
    app.state.practice06_installed = True
