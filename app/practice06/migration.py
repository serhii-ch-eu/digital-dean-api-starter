"""Student task: additive and atomic migration of the completed practice 5 DB."""
from pathlib import Path
from app.db.connection import DB_PATH, open_database, write_transaction

STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS course_teacher (
        course_id INTEGER NOT NULL,
        teacher_id INTEGER NOT NULL,
        PRIMARY KEY (course_id,teacher_id),
        FOREIGN KEY (course_id) REFERENCES course(id) ON DELETE CASCADE,
        FOREIGN KEY (teacher_id) REFERENCES "user"(id) ON DELETE RESTRICT
    )""",
    """CREATE TABLE IF NOT EXISTS course_student (
        course_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        PRIMARY KEY (course_id,student_id),
        FOREIGN KEY (course_id) REFERENCES course(id) ON DELETE CASCADE,
        FOREIGN KEY (student_id) REFERENCES "user"(id) ON DELETE RESTRICT
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_p06_user_one_role ON user_role(user_id)",
    "CREATE INDEX IF NOT EXISTS ix_p06_teacher ON course_teacher(teacher_id)",
    "CREATE INDEX IF NOT EXISTS ix_p06_student ON course_student(student_id)",
)


def migrate_database(path: Path = DB_PATH) -> None:
    """Require the six P5 tables, exact lookups, no FK violations or duplicate roles.

    One write_transaction: validate, execute STATEMENTS, recheck, commit.
    No DROP, REPLACE, DELETE of existing data, automatic enrollment or new admin.
    A failure must roll back newly created tables/indexes as well.
    """
    raise NotImplementedError("TODO: atomic additive migration")


if __name__ == "__main__":
    migrate_database()
    print("Practical 6 migration completed")
