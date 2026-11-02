"""Моделі та HTTP-контракт; усі записи вигадані."""

import json
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.repositories import student_repository
from app.repositories.secure_note_repository import repository as note_repository
from app.schemas.secure_note import NoteCreate
from app.schemas.student import StudentCreate
from app.security import keys


@pytest.mark.parametrize("text", ("x" * 4096, "я" * 2048, "  текст  "))
def test_accepted_text_is_preserved(text):
    assert NoteCreate(text=text).text == text


@pytest.mark.parametrize(
    "payload",
    (
        {"text": ""},
        {"text": " "},
        {"text": "x" * 4097},
        {"text": "я" * 2049},
        {"text": 42},
        {"text": "demo", "key": "do-not-accept"},
    ),
)
def test_invalid_note_input(payload):
    with pytest.raises(ValidationError):
        NoteCreate(**payload)


def test_unknown_student_is_not_found():
    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/students/{uuid4()}/secure-notes/{uuid4()}"
        )
    assert response.status_code == 404


@pytest.fixture
def note_test_env():
    """Фікстура: наявний студент, чисте сховище, ізольований ключ на час тесту."""
    student_repository.clear_db()
    note_repository.clear()

    # Створюємо студента відповідно до схеми StudentCreate (Робота 1)
    student_in = StudentCreate(
        full_name="Олександр Шевченко",
        email="o.shevchenko@example.com",
        group_code="ІП-11",
        study_program="Комп'ютерні науки",
    )
    student = student_repository.create(student_in)

    old_key = keys.PROCESS_KEY
    keys.PROCESS_KEY = keys.create_process_key(limit=1_000_000)
    try:
        yield student
    finally:
        keys.PROCESS_KEY = old_key
        note_repository.clear()

def test_note_api_and_internal_storage(note_test_env):
    student = note_test_env
    student_id = student.id

    with TestClient(app) as client:
        # POST 201 без text/key/конверта
        post_res = client.post(
            f"/api/v1/students/{student_id}/secure-notes",
            json={"text": "Таємна примітка"},
        )
        assert post_res.status_code == 201
        data = post_res.json()
        assert "id" in data
        assert data["student_id"] == str(student_id)
        assert "text" not in data
        assert "key" not in data
        assert "ciphertext" not in data

        note_id = data["id"]

        # GET 200 із точним текстом
        get_res = client.get(f"/api/v1/students/{student_id}/secure-notes/{note_id}")
        assert get_res.status_code == 200
        get_data = get_res.json()
        assert get_data["text"] == "Таємна примітка"

    # У внутрішньому EncryptedNote немає text/key; nonce=12, tag=16
    stored = note_repository.get(student.id, UUID(note_id))
    assert not hasattr(stored, "text")
    assert not hasattr(stored, "key")
    assert len(stored.nonce) == 12
    assert len(stored.tag) == 16
    assert stored.ciphertext != "Таємна примітка".encode("utf-8")


def test_damaged_note_is_rejected_without_plaintext(note_test_env):
    student = note_test_env

    with TestClient(app) as client:
        res = client.post(
            f"/api/v1/students/{student.id}/secure-notes",
            json={"text": "Важливі дані"},
        )
        note_id = res.json()["id"]

        # Змінюємо конверт лише в тестовій підготовці, не через HTTP-маршрут
        from dataclasses import replace
        stored = note_repository.get(student.id, UUID(note_id))
        damaged_ct = bytearray(stored.ciphertext)
        damaged_ct[0] ^= 0xFF
        damaged_note = replace(stored, ciphertext=bytes(damaged_ct))
        note_repository._items[UUID(note_id)] = damaged_note

        # 500 i detail="Protected note unavailable", без секретів і траси
        get_res = client.get(f"/api/v1/students/{student.id}/secure-notes/{note_id}")
        assert get_res.status_code == 500
        assert get_res.json() == {"detail": "Protected note unavailable"}


def test_nonce_limit_rejects_only_new_writes(note_test_env):
    student = note_test_env

    # Імпортуємо безпосередньо модуль secure_notes для підміни PROCESS_KEY в роутері
    from app.api import secure_notes
    
    # Створюємо новий ProcessKey із лімітом 2
    limited_key = keys.create_process_key(limit=2)
    
    # Підміняємо ключ у модулі secure_notes та keys
    old_router_key = secure_notes.PROCESS_KEY
    secure_notes.PROCESS_KEY = limited_key
    keys.PROCESS_KEY = limited_key

    try:
        with TestClient(app) as client:
            # 1-й POST (успішний, використання 1/2)
            res1 = client.post(
                f"/api/v1/students/{student.id}/secure-notes",
                json={"text": "Перша примітка"},
            )
            assert res1.status_code == 201
            note1_id = res1.json()["id"]

            # 2-й POST (успішний, використання 2/2 — ліміт вичерпано)
            res2 = client.post(
                f"/api/v1/students/{student.id}/secure-notes",
                json={"text": "Друга примітка"},
            )
            assert res2.status_code == 201

            # 3-й POST (перевищення ліміту -> 503)
            res3 = client.post(
                f"/api/v1/students/{student.id}/secure-notes",
                json={"text": "Третя примітка"},
            )
            assert res3.status_code == 503
            assert res3.json() == {"detail": "Protected note unavailable"}

            # Раніше створені примітки успішно читаються (200 OK)
            res_get = client.get(f"/api/v1/students/{student.id}/secure-notes/{note1_id}")
            assert res_get.status_code == 200
            assert res_get.json()["text"] == "Перша примітка"
    finally:
        secure_notes.PROCESS_KEY = old_router_key

def test_benchmark_report_reader(monkeypatch, tmp_path):
    # Підміна конфігурації шляху до файлу звіту
    test_report_file = tmp_path / "crypto_report.json"
    from app.api import crypto_lab
    monkeypatch.setattr(crypto_lab, "DEFAULT_REPORT_PATH", test_report_file)

    with TestClient(app) as client:
        # 1. Запит до відсутнього файлу (404)
        res_404 = client.get("/api/v1/crypto-lab/report")
        assert res_404.status_code == 404
        assert res_404.json() == {"detail": "Benchmark report not found"}

        # 2. Запит до пошкодженого файлу (500)
        test_report_file.write_text("invalid json content {{{", encoding="utf-8")
        res_500 = client.get("/api/v1/crypto-lab/report")
        assert res_500.status_code == 500
        assert res_500.json() == {"detail": "Error reading benchmark report"}

        # 3. Запит до коректного файлу (200)
        valid_data = {"test_metric": 100.5}
        test_report_file.write_text(json.dumps(valid_data), encoding="utf-8")
        res_200 = client.get("/api/v1/crypto-lab/report")
        assert res_200.status_code == 200
        assert res_200.json() == valid_data