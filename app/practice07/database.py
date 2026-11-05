"""Provided per-connection functions; immutable identity is not supplied by JSON."""
from contextlib import contextmanager
import json
from pathlib import Path
from app.db.connection import open_database
from .context import AuditContext
from .events import utc_now


def snapshot(student_id, teacher_id, course_id, grade) -> str:
    return json.dumps(dict(student_id=student_id, teacher_id=teacher_id,
                           course_id=course_id, grade=grade),
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


@contextmanager
def open_audited_database(path: Path, context: AuditContext):
    """Still recheck P6 role/status/object permission inside the write transaction.

    Helpers are connection-local, non-deterministic by default; do not register
    these as global callbacks returning the most recently seen HTTP user.
    This function establishes attribution, NOT authorization.
    """
    if not isinstance(context, AuditContext):
        raise TypeError("trusted AuditContext required")
    with open_database(path) as con:
        con.create_function("p07_actor_id", 0, lambda: context.actor_id)
        con.create_function("p07_request_id", 0, lambda: context.request_id)
        con.create_function("p07_now", 0, utc_now)
        con.create_function("p07_snapshot", 4, snapshot)
        yield con
