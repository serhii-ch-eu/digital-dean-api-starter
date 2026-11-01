
def test_note_api_and_internal_storage():
    from uuid import UUID, uuid4
    from fastapi.testclient import TestClient
    from app.main import app
    from app.repositories.secure_note_repository import repository

    with TestClient(app) as client:
        student = client.post(
            "/api/v1/students",
            json={
                "full_name": "Test Student",
                "email": f"test_{uuid4().hex}@example.com",
                "group_code": "KH-31",
                "study_program": "Cybersecurity",
            },
        )

        assert student.status_code == 201
        student_id = student.json()["id"]

        original = "Secret student note"

        created = client.post(
            f"/api/v1/students/{student_id}/secure-notes",
            json={"text": original},
        )

        assert created.status_code == 201
        assert "text" not in created.json()
        assert "key" not in created.json()

        note_id = created.json()["id"]

        stored = repository.get(
            UUID(student_id),
            UUID(note_id),
        )

        assert len(stored.nonce) == 12
        assert len(stored.tag) == 16
        assert stored.ciphertext != original.encode("utf-8")
        assert stored.key_id == app.state.process_key.key_id

        response = client.get(
            f"/api/v1/students/{student_id}/secure-notes/{note_id}"
        )

        assert response.status_code == 200
        assert response.json()["text"] == original
        assert response.json()["id"] == note_id
        assert response.json()["student_id"] == student_id


def test_damaged_note_is_rejected_without_plaintext(monkeypatch):
    from dataclasses import replace
    from uuid import UUID, uuid4
    from fastapi.testclient import TestClient

    from app.main import app
    from app.repositories.secure_note_repository import repository

    with TestClient(app) as client:
        student = client.post(
            "/api/v1/students",
            json={
                "full_name": "Test Student",
                "email": f"damage_{uuid4().hex}@example.com",
                "group_code": "KH-31",
                "study_program": "Cybersecurity",
            },
        )
        assert student.status_code == 201
        sid = student.json()["id"]

        secret = "Confidential student information"

        created = client.post(
            f"/api/v1/students/{sid}/secure-notes",
            json={"text": secret},
        )
        assert created.status_code == 201

        nid = created.json()["id"]
        stored = repository.get(UUID(sid), UUID(nid))

        damaged_tag = bytes([stored.tag[0] ^ 1]) + stored.tag[1:]

        monkeypatch.setitem(
            repository._items,
            UUID(nid),
            replace(stored, tag=damaged_tag),
        )

        response = client.get(
            f"/api/v1/students/{sid}/secure-notes/{nid}"
        )

        assert response.status_code == 500
        assert response.json() == {
            "detail": "Protected note unavailable"
        }
        assert secret not in response.text



def test_nonce_limit_rejects_only_new_writes(monkeypatch):
    from uuid import uuid4
    from fastapi.testclient import TestClient

    from app.main import app
    from app.security.keys import create_process_key
    from app.repositories.secure_note_repository import repository

    repository.clear()
    monkeypatch.setattr(
        app.state, "process_key", create_process_key(limit=2)
    )

    try:
        with TestClient(app) as client:
            student = client.post(
                "/api/v1/students",
                json={
                    "full_name": "Test Student",
                    "email": f"limit_{uuid4().hex}@example.com",
                    "group_code": "KH-31",
                    "study_program": "Cybersecurity",
                },
            )
            assert student.status_code == 201
            sid = student.json()["id"]

            note_ids = []

            for i in range(2):
                response = client.post(
                    f"/api/v1/students/{sid}/secure-notes",
                    json={"text": f"Secret note {i}"},
                )
                assert response.status_code == 201
                note_ids.append(response.json()["id"])

            third = client.post(
                f"/api/v1/students/{sid}/secure-notes",
                json={"text": "Third note"},
            )

            assert third.status_code == 503
            assert third.json() == {
                "detail": "Protected note unavailable"
            }

            for i, nid in enumerate(note_ids):
                response = client.get(
                    f"/api/v1/students/{sid}/secure-notes/{nid}"
                )
                assert response.status_code == 200
                assert response.json()["text"] == f"Secret note {i}"

    finally:
        repository.clear()


def test_benchmark_report_reader(tmp_path, monkeypatch):
    import json
    from pathlib import Path
    from fastapi.testclient import TestClient

    from app.main import app
    from app.api import crypto_lab

    source = Path("results/practice-02/report.json")

    report = json.loads(
        source.read_text(encoding="utf-8")
    )

    test_file = tmp_path / "report.json"

    test_file.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        crypto_lab,
        "REPORT_PATH",
        test_file,
    )

    url = "/api/v1/lab/crypto/benchmark-results"

    with TestClient(app) as client:
        response = client.get(url)

        assert response.status_code == 200
        assert response.json()["schema_version"] == 1
        assert len(response.json()["results"]) == 36

        # Missing report must return 404.
        test_file.unlink()

        missing = client.get(url)

        assert missing.status_code == 404
        assert missing.json() == {
            "detail": "Benchmark results unavailable"
        }

        # Invalid report must return 500.
        test_file.write_text(
            '{"schema_version":1,"results":[]}',
            encoding="utf-8",
        )

        damaged = client.get(url)

        assert damaged.status_code == 500
        assert damaged.json() == {
            "detail": "Benchmark results unavailable"
        }

        # Invalid JSON must also return 500.
        test_file.write_text(
            '{"broken":',
            encoding="utf-8",
        )

        invalid_json = client.get(url)

        assert invalid_json.status_code == 500

def test_patch_secure_note_variant_8():
    from uuid import UUID, uuid4
    from fastapi.testclient import TestClient
    from app.main import app
    from app.repositories.secure_note_repository import repository

    with TestClient(app) as client:
        student = client.post(
            "/api/v1/students",
            json={
                "full_name": "Test Student",
                "email": f"patch_{uuid4().hex}@example.com",
                "group_code": "KH-31",
                "study_program": "Cybersecurity",
            },
        )
        assert student.status_code == 201
        sid = student.json()["id"]

        created = client.post(
            f"/api/v1/students/{sid}/secure-notes",
            json={"text": "Original secret"},
        )
        assert created.status_code == 201
        nid = created.json()["id"]

        before = repository.get(UUID(sid), UUID(nid))

        updated = client.patch(
            f"/api/v1/students/{sid}/secure-notes/{nid}",
            json={"text": "Updated secret"},
        )

        assert updated.status_code == 200
        assert updated.json()["text"] == "Updated secret"
        assert updated.json()["id"] == nid
        assert updated.json()["student_id"] == sid

        after = repository.get(UUID(sid), UUID(nid))

        assert before.nonce != after.nonce
        assert before.key_id == after.key_id

        response = client.get(
            f"/api/v1/students/{sid}/secure-notes/{nid}"
        )
        assert response.status_code == 200
        assert response.json()["text"] == "Updated secret"

        invalid = client.patch(
            f"/api/v1/students/{sid}/secure-notes/{nid}",
            json={"text": "Test", "is_admin": True},
        )
        assert invalid.status_code == 422

# TODO: регресійні тести всіх маршрутів роботи 1 і тест свого варіанта роботи 2.
