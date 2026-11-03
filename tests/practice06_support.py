"""Independent synthetic database per test; never the application's runtime DB."""
import importlib
import secrets
import sqlite3
import pytest
from fastapi.testclient import TestClient
from app.db.initialize import initialize_database
from app.db.connection import open_database, write_transaction
from app.repositories.user_repository import UserRepository
from app.schemas.user_account import UserCreate
from app.practice06.bootstrap import create_local_account
from app.practice06.config import SecuritySettings
from app.practice06.migration import migrate_database
from app.practice06.models import Role
from app.practice06.service import DeanService

PASSWORD = "Learning only 06!"
ACCOUNTS = {"admin": Role.ADMIN, "manager": Role.MANAGER,
    "teacher_a": Role.TEACHER, "teacher_b": Role.TEACHER,
    "student_a": Role.STUDENT, "student_b": Role.STUDENT, "student_c": Role.STUDENT}


@pytest.fixture(scope="session")
def p06_settings():
    return SecuritySettings(secrets.token_bytes(32))


@pytest.fixture(scope="session")
def p06_seed(tmp_path_factory):
    path = tmp_path_factory.mktemp("p06-template") / "seed.sqlite3"
    initialize_database(path)
    migrate_database(path)
    ids = {}
    for login, role in ACCOUNTS.items():
        data = UserCreate(name="Synthetic " + login, email=login + "@example.com",
                          login=login, password=PASSWORD, status_id=1)
        ids[login] = create_local_account(path, data, role).id
    ids["no_role"] = UserRepository(path).register_user(UserCreate(
        name="No role", email="no_role@example.com", login="no_role",
        password=PASSWORD, status_id=1)).id
    with open_database(path) as con, write_transaction(con):
        con.executemany("INSERT INTO course(id,name) VALUES (?,?)",
                        [(11,"Alpha"),(12,"Beta"),(13,"Empty")])
        con.executemany("INSERT INTO course_teacher(course_id,teacher_id) VALUES (?,?)",
            [(11,ids["teacher_a"]),(11,ids["teacher_b"]),(12,ids["teacher_b"])])
        con.executemany("INSERT INTO course_student(course_id,student_id) VALUES (?,?)",
            [(11,ids["student_a"]),(11,ids["student_b"]),(12,ids["student_c"])])
        con.executemany("INSERT INTO grade(student_id,teacher_id,course_id,grade) VALUES (?,?,?,?)",
            [(ids["student_a"],ids["teacher_a"],11,80),
             (ids["student_b"],ids["teacher_b"],11,70),
             (ids["student_c"],ids["teacher_b"],12,60)])
    return path, ids


@pytest.fixture
def p06_lab(tmp_path, monkeypatch, p06_seed, p06_settings):
    path = tmp_path / "isolated.sqlite3"
    source, ids = p06_seed
    with sqlite3.connect(source) as src, sqlite3.connect(path) as dst:
        src.backup(dst)
    monkeypatch.setenv("DEAN_JWT_SECRET_HEX", p06_settings.key.hex())
    # The student's actual existing application must be integrated, not a replacement test app.
    app = importlib.import_module("app.main").app
    from app.practice06.router import get_service, get_security_settings
    app.dependency_overrides[get_service] = lambda: DeanService(path)
    app.dependency_overrides[get_security_settings] = lambda: p06_settings
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            yield client, path, dict(ids), p06_settings
    finally:
        app.dependency_overrides.pop(get_service, None)
        app.dependency_overrides.pop(get_security_settings, None)


def headers(lab, login):
    client = lab[0]
    result = client.post("/api/v1/auth/login", json={"login":login,"password":PASSWORD})
    assert result.status_code == 200, result.text
    body = result.json()
    assert set(body) == {"access_token", "token_type", "expires_in"}
    assert body["token_type"] == "bearer" and body["expires_in"] == 900
    return {"Authorization":"Bearer " + body["access_token"]}
