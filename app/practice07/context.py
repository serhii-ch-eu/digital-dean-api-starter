"""One request object per ASGI scope; never a shared global connection/actor."""
from contextvars import ContextVar
from dataclasses import dataclass, field
from uuid import uuid4
from .events import canonical_request_id


@dataclass
class RequestContext:
    request_id: str
    actor_id: int | None = None
    role: str | None = None
    session_ref: str | None = None
    action: str | None = None
    sink: object | None = field(default=None, repr=False)


CURRENT: ContextVar[RequestContext | None] = ContextVar("p07_request", default=None)


@dataclass(frozen=True)
class AuditContext:
    actor_id: int
    request_id: str

    def __post_init__(self):
        if type(self.actor_id) is not int or not 0 < self.actor_id <= 2**63 - 1:
            raise ValueError("trusted actor id required")
        if not canonical_request_id(self.request_id):
            raise ValueError("server UUID4 request id required")


def new_request_context() -> RequestContext:
    return RequestContext(str(uuid4()))


def require_context() -> RequestContext:
    value = CURRENT.get()
    if value is None:
        raise RuntimeError("request context is not installed")
    return value


def audit_for_actor(actor_id: int) -> AuditContext:
    current = require_context()
    if current.actor_id != actor_id:
        raise RuntimeError("actor must match the authenticated request")
    return AuditContext(actor_id, current.request_id)
