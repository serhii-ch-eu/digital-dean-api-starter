"""Provided trusted identity and event helpers; students wire actual P6 operations."""
import hashlib
import jwt
from app.practice06.tokens import read_access_token, BadToken
from .context import require_context
from .events import Event
from .filelog import safe_emit


def verified_access_context(token, settings) -> tuple[int, str]:
    """Preserve ALL P6 checks before extracting the random jti for correlation."""
    user_id = read_access_token(token, settings)
    try:
        claims = jwt.decode(token, settings.key, algorithms=["HS256"],
                            issuer=settings.issuer, audience=settings.audience,
                            leeway=0, options={"require": ["jti"], "strict_aud": True})
        reference = hashlib.sha256(claims["jti"].encode("ascii")).hexdigest()
    except (jwt.InvalidTokenError, KeyError, TypeError, ValueError, UnicodeError):
        raise BadToken("invalid access token") from None
    return user_id, reference


def bind_identity(principal, session_ref: str) -> None:
    """Call ONLY after principal() checked the current DB status and single role."""
    current = require_context()
    probe = Event("http.completed", "success", actor_id=principal.id,
                  role=principal.role.value, session_ref=session_ref)
    current.actor_id, current.role = probe.actor_id, probe.role
    current.session_ref = probe.session_ref


def bind_login(user_id: int, session_ref: str) -> None:
    """Correct active password login can have no assigned role; do not invent one."""
    current = require_context()
    probe = Event("auth.login_succeeded", "success", actor_id=user_id, session_ref=session_ref)
    current.actor_id, current.session_ref = probe.actor_id, probe.session_ref
    current.role = None


def emit_current(sink, event: str, outcome: str, **fields) -> bool:
    current = require_context()
    return safe_emit(sink, Event(event, outcome, request_id=current.request_id,
        actor_id=current.actor_id, role=current.role, session_ref=current.session_ref, **fields))


def emit_domain(event: str, outcome: str, **fields) -> bool:
    """The request's sink avoids a new global logger/service constructor contract."""
    current = require_context()
    if current.sink is None:
        raise RuntimeError("request event sink is not installed")
    return emit_current(current.sink, event, outcome, **fields)
