"""Student task: persistent account operations on separate short connections."""
from pathlib import Path
import sqlite3

from app.db.connection import open_database, write_transaction
from app.schemas.user_account import UserCreate, UserPublic
from app.security.passwords import make_password_record, verify_password


class UserNotFound(Exception):
    """No account with the requested id."""


class UserConflict(Exception):
    """The canonical login or email is already used."""


class UserReferenced(Exception):
    """Academic records prohibit physical deletion."""


class UserRepository:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)

    def register_user(self, data: UserCreate) -> UserPublic:
        """Create a password-protected account and return its public fields."""
        password_record, salt = make_password_record(data.password.get_secret_value())
        try:
            with open_database(self.database_path) as connection:
                with write_transaction(connection):
                    cursor = connection.execute(
                        'INSERT INTO "user" (name, email, login, password, salt, status_id) '
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (data.name, str(data.email), data.login, password_record, salt,
                         data.status_id),
                    )
                    user_id = cursor.lastrowid
                    row = connection.execute(
                        'SELECT id, name, email, login, status_id FROM "user" WHERE id = ?',
                        (user_id,),
                    ).fetchone()
                    return UserPublic.model_validate(dict(row))
        except sqlite3.IntegrityError as exc:
            message = str(exc)
            if (getattr(exc, "sqlite_errorname", None) == "SQLITE_CONSTRAINT_UNIQUE"
                    and ("user.login" in message or "user.email" in message)):
                raise UserConflict from None
            raise

    def delete_user(self, user_id: int) -> None:
        """Physically delete an unreferenced user; preserve referenced data."""
        with open_database(self.database_path) as connection:
            with write_transaction(connection):
                exists = connection.execute(
                    'SELECT 1 FROM "user" WHERE id = ?', (user_id,)
                ).fetchone()
                if exists is None:
                    raise UserNotFound

                referenced = connection.execute(
                    "SELECT 1 FROM grade "
                    "WHERE student_id = ? OR teacher_id = ? LIMIT 1",
                    (user_id, user_id),
                ).fetchone()
                if referenced is not None:
                    raise UserReferenced

                try:
                    connection.execute('DELETE FROM "user" WHERE id = ?', (user_id,))
                except sqlite3.IntegrityError as exc:
                    if getattr(exc, "sqlite_errorname", "").startswith("SQLITE_CONSTRAINT_FOREIGNKEY"):
                        raise UserReferenced from None
                    raise

    def block_user(self, user_id: int) -> UserPublic:
        """Set blocked status without changing the account's other fields."""
        with open_database(self.database_path) as connection:
            with write_transaction(connection):
                cursor = connection.execute(
                    'UPDATE "user" SET status_id = ? WHERE id = ?', (2, user_id)
                )
                if cursor.rowcount == 0:
                    raise UserNotFound
                row = connection.execute(
                    'SELECT id, name, email, login, status_id FROM "user" WHERE id = ?',
                    (user_id,),
                ).fetchone()
                return UserPublic.model_validate(dict(row))

    def login(self, login: str, password: str) -> bool:
        """Return whether these credentials belong to an active account."""
        with open_database(self.database_path) as connection:
            row = connection.execute(
                'SELECT password, salt, status_id FROM "user" WHERE login = ?',
                (login,),
            ).fetchone()
        if row is None:
            return False
        password_matches = verify_password(password, row["password"], row["salt"])
        return row["status_id"] == 1 and password_matches
