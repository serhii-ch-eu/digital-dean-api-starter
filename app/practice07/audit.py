"""Student task: atomic additive migration and all five audit triggers."""
from pathlib import Path
from app.db.connection import DB_PATH

TABLE_SQL = """CREATE TABLE IF NOT EXISTS grade_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER NOT NULL CHECK(actor_id > 0),
    occurred_at TEXT NOT NULL,
    operation TEXT NOT NULL CHECK(operation IN ('INSERT','UPDATE','DELETE')),
    request_id TEXT NOT NULL,
    old_values TEXT,
    new_values TEXT,
    CHECK((operation='INSERT' AND old_values IS NULL AND new_values IS NOT NULL)
       OR (operation='UPDATE' AND old_values IS NOT NULL AND new_values IS NOT NULL)
       OR (operation='DELETE' AND old_values IS NOT NULL AND new_values IS NULL))
)"""
TRIGGER_NAMES = {
    "p07_grade_insert", "p07_grade_update", "p07_grade_delete",
    "p07_audit_no_update", "p07_audit_no_delete",
}


def trigger_statements() -> tuple[str, ...]:
    """Return five CREATE TRIGGER IF NOT EXISTS statements.

    grade AFTER INSERT/UPDATE/DELETE: require active existing p07_actor_id(),
    use p07_request_id()/p07_now(), and before/after p07_snapshot() values.
    UPDATE compares all four OLD/NEW fields with IS NOT, not UPDATE OF.
    Identical full-row UPDATE creates no history. INSERT/DELETE always do.
    grade_audit BEFORE UPDATE/DELETE: RAISE(ABORT,'audit history is append only').
    No REPLACE or manual audit insertion from an HTTP handler.
    """
    raise NotImplementedError("TODO: transactional row audit triggers")


def migrate_database(path: Path = DB_PATH) -> None:
    """Require complete P6 schema and clean FKs; one explicit write transaction.

    Create TABLE_SQL, triggers and index ix_p07_audit_request(request_id).
    Verify expected audit columns, trigger definitions and index on rerun;
    reject conflicting pre-existing objects without removing/replacing them.
    Preserve users, password records, enrollments and grades, with no backfill
    of invented past events. Failure rolls back DDL and all changes.
    """
    raise NotImplementedError("TODO: idempotent audited schema migration")


if __name__ == "__main__":
    migrate_database()
    print("Practical 7 audit migration completed")
