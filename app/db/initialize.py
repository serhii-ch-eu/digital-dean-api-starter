"""Student task: atomic, repeatable schema creation and lookup initialization."""
from pathlib import Path

from app.db.connection import DB_PATH, open_database, write_transaction
from app.db.schema import DDL_STATEMENTS, ROLE_ROWS, STATUS_ROWS


def initialize_database(path: Path = DB_PATH) -> None:
    """Create parent directory and all tables; preserve users on repeat runs.

    Create the schema and immutable lookup rows atomically. Existing user data
    is preserved, and conflicting lookup contents abort the transaction.
    """
    database_path = Path(path)
    database_path.parent.mkdir(parents=True, exist_ok=True)

    with open_database(database_path) as connection:
        with write_transaction(connection):
            for statement in DDL_STATEMENTS:
                connection.execute(statement)

            expected_lookups = (
                ("status", STATUS_ROWS),
                ("role", ROLE_ROWS),
            )
            for table, expected_rows in expected_lookups:
                existing_rows = tuple(
                    tuple(row)
                    for row in connection.execute(
                        f"SELECT id, name FROM {table} ORDER BY id"
                    ).fetchall()
                )
                if any(row not in expected_rows for row in existing_rows):
                    raise ValueError(f"unexpected rows in {table} lookup")

                for row in expected_rows:
                    if row not in existing_rows:
                        connection.execute(
                            f"INSERT INTO {table} (id, name) VALUES (?, ?)", row
                        )

                actual_rows = tuple(
                    tuple(row)
                    for row in connection.execute(
                        f"SELECT id, name FROM {table} ORDER BY id"
                    ).fetchall()
                )
                if actual_rows != expected_rows:
                    raise ValueError(f"{table} lookup does not match expected rows")


if __name__ == "__main__":
    initialize_database()
    print("Database initialized; no default accounts created.")
