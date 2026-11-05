"""Provided event vocabulary and field allowlist; no free-form payload/body."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re
from uuid import UUID

EVENT_LEVELS = {
    "app.started": "INFO", "app.stopped": "INFO",
    "http.completed": "INFO", "http.failed": "ERROR",
    "auth.login_succeeded": "INFO", "auth.login_failed": "WARNING",
    "auth.token_issued": "INFO", "auth.token_rejected": "WARNING",
    "access.denied": "WARNING", "input.rejected": "WARNING",
    "grade.read": "INFO", "grade.created": "INFO", "grade.updated": "INFO",
    "grade.unchanged": "INFO", "operation.succeeded": "INFO",
    "operation.failed": "WARNING", "database.failed": "ERROR",
}
ROLES = {"admin", "manager", "teacher", "student"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_request_id(value: str) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value and UUID(value).version == 4
    except (ValueError, AttributeError):
        return False


@dataclass(frozen=True)
class Event:
    event: str
    outcome: str
    request_id: str | None = None
    actor_id: int | None = None
    role: str | None = None
    session_ref: str | None = None
    action: str | None = None
    method: str | None = None
    route: str | None = None
    status: int | None = None
    elapsed_ms: float | None = None
    course_id: int | None = None
    student_id: int | None = None
    target_id: int | None = None
    returned_count: int | None = None
    committed: bool | None = None
    occurred_at: str = field(default_factory=utc_now, init=False)

    def __post_init__(self):
        if self.event not in EVENT_LEVELS:
            raise ValueError("unknown event")
        if self.outcome not in {"success", "failure", "denied", "unchanged"}:
            raise ValueError("unknown outcome")
        if self.request_id is not None and not canonical_request_id(self.request_id):
            raise ValueError("invalid request id")
        if self.role is not None and self.role not in ROLES:
            raise ValueError("invalid role")
        if self.session_ref is not None and not re.fullmatch(r"[0-9a-f]{64}", self.session_ref):
            raise ValueError("invalid session reference")
        for name in ("actor_id", "course_id", "student_id", "target_id"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or not 0 < value <= 2**63 - 1):
                raise ValueError("invalid object id")
        if self.returned_count is not None:
            if type(self.returned_count) is not int or self.returned_count < 0:
                raise ValueError("invalid count")
        if self.status is not None and (type(self.status) is not int or not 100 <= self.status <= 599):
            raise ValueError("invalid HTTP status")
        if self.elapsed_ms is not None:
            if type(self.elapsed_ms) not in (float, int) or not math.isfinite(self.elapsed_ms) or self.elapsed_ms < 0:
                raise ValueError("invalid duration")
        for name, bound in (("action", 64), ("method", 16), ("route", 256)):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or len(value) > bound):
                raise ValueError("invalid bounded text")
        if self.committed is not None and type(self.committed) is not bool:
            raise ValueError("invalid commit flag")
