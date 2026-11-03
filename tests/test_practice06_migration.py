"""Additive migration, durable records and role constraints."""
import sqlite3
import pytest
from app.db.initialize import initialize_database
from app.db.connection import open_database, write_transaction
from app.db.schema import DDL_STATEMENTS
from app.repositories.user_repository import UserRepository
from app.schemas.user_account import UserCreate
from app.practice06.migration import migrate_database


def test_migration_keeps_existing_records(tmp_path):
    path = tmp_path/"prior.sqlite3"; initialize_database(path)
    user = UserRepository(path).register_user(UserCreate(name="Prior",email="prior@example.com",
        login="prior_user",password="Learning only 06!",status_id=1))
    with open_database(path) as con, write_transaction(con):
        con.execute("INSERT INTO course(id,name) VALUES (?,?)", (77,"Prior course"))
        con.execute("INSERT INTO grade VALUES (?,?,?,?)", (user.id,user.id,77,55))
        before = tuple(con.execute('SELECT * FROM "user" WHERE id=?',(user.id,)).fetchone())
    migrate_database(path); migrate_database(path)
    with open_database(path) as con:
        assert tuple(con.execute('SELECT * FROM "user" WHERE id=?',(user.id,)).fetchone()) == before
        assert con.execute("SELECT grade FROM grade WHERE course_id=77").fetchone()[0] == 55
        assert con.execute("SELECT count(*) FROM course_student").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM course_teacher").fetchone()[0] == 0
        assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert not con.execute("PRAGMA foreign_key_check").fetchall()


def test_duplicate_legacy_roles_roll_back(tmp_path):
    path = tmp_path/"roles.sqlite3"; initialize_database(path)
    user = UserRepository(path).register_user(UserCreate(name="Prior",email="roles@example.com",
        login="prior_roles",password="Learning only 06!",status_id=1))
    with open_database(path) as con, write_transaction(con):
        con.executemany("INSERT INTO user_role VALUES (?,?)", [(user.id,1),(user.id,2)])
    with pytest.raises((ValueError,sqlite3.IntegrityError)): migrate_database(path)
    with open_database(path) as con:
        assert con.execute("SELECT count(*) FROM user_role").fetchone()[0] == 2
        assert con.execute("SELECT count(*) FROM sqlite_master WHERE name='course_student'").fetchone()[0] == 0


def test_empty_database_not_silently_initialized(tmp_path):
    path = tmp_path/"empty.sqlite3"
    with pytest.raises((ValueError,sqlite3.Error)): migrate_database(path)


def test_foreign_keys_and_one_role(p06_lab):
    path, ids = p06_lab[1:3]
    with open_database(path) as con:
        with pytest.raises(sqlite3.IntegrityError):
            with write_transaction(con): con.execute("INSERT INTO user_role VALUES (?,?)",(ids["admin"],2))
        with pytest.raises(sqlite3.IntegrityError):
            with write_transaction(con): con.execute("INSERT INTO course_student VALUES (?,?)",(11,999999))
        assert not con.execute("PRAGMA foreign_key_check").fetchall()


# Shared fixtures are imported explicitly, not hidden in the student's older conftest.
from tests.practice06_support import p06_settings, p06_seed, p06_lab
