"""Student task: install into the actual existing application before startup."""
from fastapi import FastAPI
from .limiter import FixedWindowLimiter
from .settings import LimitSettings, get_limit_settings


def install_practice08(app: FastAPI, *, settings: LimitSettings | None = None,
                       clock=None) -> None:
    """Require completed P7, no previous P8 and middleware_stack is None.

    Reject invalid/duplicate setup BEFORE side effects. Require exactly one
    P7 SecurityLogMiddleware in app.user_middleware. Register the limit catalog
    entry, create ONE limiter in app.state.practice08_limiter, insert Starlette
    Middleware(LoginThrottleMiddleware,limiter_provider=...) immediately AFTER
    that P7 entry. The provider reads app.state, enabling independent test
    policies; do not cache a different instance or create one per request.
    app.add_middleware alone would put the gate OUTSIDE P7; do not do that.
    Preserve every route, dependency, exception adapter and lifespan. No new app,
    new HTTP endpoint, automatic migration, database cleanup or account change.
    Add the 429 response/headers to the existing POST login OpenAPI operation,
    version0.8.0, invalidate openapi_schema; flag practice08_installed=True.
    Separately adapt the existing P7 safe route resolver to use the fixed marker
    only when its value equals LOGIN_PATH (never use raw client path/query).
    """
    raise NotImplementedError("TODO: integrate the same P7 app safely")
