import pytest
from fastapi.testclient import TestClient
from uuid import uuid4
from app.main import app
from app.repositories.student_repository import clear_db

client = TestClient(app)

@pytest.fixture(autouse=True)
def run_around_tests():
    clear_db()
    yield

def get_valid_payload():
    return {
        "full_name": "Іван Франко",
        "email": "ivan.franko@example.com",
        "group_code": "КН-31",
        "study_program": "Computer Science"
    }

def test_create_student():
    response = client.post("/api/v1/students", json=get_valid_payload())
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["study_program"] == "Computer Science"

def test_invalid_email():
    payload = get_valid_payload()
    payload["email"] = "invalid-email"
    response = client.post("/api/v1/students", json=payload)
    assert response.status_code == 422

def test_list_students():
    client.post("/api/v1/students", json=get_valid_payload())
    response = client.get("/api/v1/students")
    assert response.status_code == 200
    assert len(response.json()) == 1

def test_get_student_success():
    created = client.post("/api/v1/students", json=get_valid_payload()).json()
    response = client.get(f"/api/v1/students/{created['id']}")
    assert response.status_code == 200
    assert response.json()["id"] == created["id"]

def test_get_student_not_found():
    response = client.get(f"/api/v1/students/{uuid4()}")
    assert response.status_code == 404

def test_partial_update():
    created = client.post("/api/v1/students", json=get_valid_payload()).json()
    response = client.patch(f"/api/v1/students/{created['id']}", json={"group_code": "ПІ-41"})
    assert response.status_code == 200
    data = response.json()
    assert data["group_code"] == "ПІ-41"
    assert data["full_name"] == created["full_name"]

def test_update_unknown_field():
    created = client.post("/api/v1/students", json=get_valid_payload()).json()
    response = client.patch(f"/api/v1/students/{created['id']}", json={"is_admin": True})
    assert response.status_code == 422

def test_variant_filtering():
    client.post("/api/v1/students", json=get_valid_payload())
    payload2 = get_valid_payload()
    payload2["email"] = "second@example.com"
    payload2["study_program"] = "Software Engineering"
    client.post("/api/v1/students", json=payload2)
    
    response = client.get("/api/v1/students?study_program=Computer Science")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["study_program"] == "Computer Science"

def test_variant_boundary_short():
    payload = get_valid_payload()
    payload["study_program"] = "C"
    response = client.post("/api/v1/students", json=payload)
    assert response.status_code == 422

def test_variant_boundary_long():
    payload = get_valid_payload()
    payload["study_program"] = "C" * 101
    response = client.post("/api/v1/students", json=payload)
    assert response.status_code == 422