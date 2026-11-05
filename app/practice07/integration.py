"""Student task: extend the SAME integrated P6 app and preserve its lifecycle."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from .filelog import EventSink
from .settings import LogSettings, get_log_settings
from .middleware import SecurityLogMiddleware


def install_practice07(app: FastAPI, *, log_settings: LogSettings | None = None,
                       sink: EventSink | None = None) -> None:
    """Require P6 installed; reject duplicate P7 installation before side effects.

    Install only middleware, state.practice07_sink and version0.7.0. Preserve
    every registered P6 business path/permission and the old lifespan context.
    State flag practice07_installed=True. Set openapi_schema=None.
    Lifespan must emit app.started successfully before serving, and emit
    app.stopped/close sink in finally. No background HTTP server, new app,
    audit HTTP routes or automatic schema/data modification at startup.
    Middleware sink_provider reads app.state.practice07_sink; lifecycle reads
    the same state on entry. Default sink uses get_log_settings(); tests can
    inject a separate sink without another application or runtime log path.
    """
    raise NotImplementedError("TODO: safe lifecycle and middleware integration")
