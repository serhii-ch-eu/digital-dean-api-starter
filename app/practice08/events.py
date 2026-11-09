"""Student task: extend, not bypass, the P7 event catalog and field allowlist."""
from app.practice07.context import require_context
from app.practice07.events import Event, EVENT_LEVELS
from app.practice07.filelog import safe_emit
from .settings import LOGIN_PATH

LIMIT_EVENT = "auth.login_limited"


def register_limit_event() -> None:
    """Add LIMIT_EVENT=WARNING idempotently. Refuse a conflicting old level.

    Preserve all old entries, Event validation and formatter. No runtime monkey
    patch of Event.__post_init__, no arbitrary **extra or free-form payload.
    """
    raise NotImplementedError("TODO: extend the validated event catalog")


def emit_limit_event() -> bool:
    """Provided safe event; no authentication was performed for this request."""
    context = require_context()
    return safe_emit(context.sink, Event(
        LIMIT_EVENT, "denied", request_id=context.request_id,
        action="login.limit", method="POST", route=LOGIN_PATH, status=429,
    ))
