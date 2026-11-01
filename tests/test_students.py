
import pytest
from uuid import uuid4
from fastapi.testclient import TestClient

from app.main import app
from app.repositories.student_repository import student_repository


client = TestClient(app)

BASE_URL = "/api/v1/students"


@pytest.fixture(autouse=True)
def clear_repository():
    """Очищення даних перед кожним тестом."""
    student_repository.clear()
    yield
    student_repository.clear()


def student_data(
    email="ivan.petrenko@example.com",
    study_program="Кібербезпека",
):
    return {
        "full_name": "Іван Петренко",
        "email": email,
        "group_code": "КН-31",
        "study_program": study_program,
    }


def create_student(**kwargs):
    return client.post(
        BASE_URL,
        json=student_data(**kwargs),
    )


def test_create_student():
    """Перевірка створення студента."""
    response = create_student()

    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert data["full_name"] == "Іван Петренко"
    assert data["email"] == "ivan.petrenko@example.com"
    assert data["group_code"] == "КН-31"
    assert data["study_program"] == "Кібербезпека"


def test_invalid_email():
    """Відхилення некоректної електронної адреси."""
    payload = student_data()
    payload["email"] = "wrong-email"

    response = client.post(BASE_URL, json=payload)

    assert response.status_code == 422
    assert client.get(BASE_URL).json() == []


def test_list_students():
    """Отримання списку студентів."""
    create_student()

    create_student(
        email="olena.koval@example.com"
    )

    response = client.get(BASE_URL)

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_get_existing_student():
    """Отримання студента за UUID."""
    created = create_student().json()

    response = client.get(
        f"{BASE_URL}/{created['id']}"
    )

    assert response.status_code == 200
    assert response.json() == created


def test_get_missing_student():
    """Перевірка відповіді 404."""
    missing_id = str(uuid4())

    response = client.get(
        f"{BASE_URL}/{missing_id}"
    )

    assert response.status_code == 404
    assert "detail" in response.json()


def test_partial_update():
    """Оновлення лише переданого поля."""
    created = create_student().json()

    response = client.patch(
        f"{BASE_URL}/{created['id']}",
        json={"group_code": "КН-32"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["group_code"] == "КН-32"
    assert data["full_name"] == created["full_name"]
    assert data["email"] == created["email"]
    assert data["study_program"] == created["study_program"]
    assert data["id"] == created["id"]


def test_unknown_field():
    """Заборона невідомих полів."""
    created = create_student().json()

    response = client.patch(
        f"{BASE_URL}/{created['id']}",
        json={"is_admin": True},
    )

    assert response.status_code == 422


def test_filter_study_program():
    """Фільтрація за освітньою програмою."""
    create_student()

    create_student(
        email="olena.koval@example.com",
        study_program="Комп'ютерні науки",
    )

    response = client.get(
        BASE_URL,
        params={"study_program": "Кібербезпека"},
    )

    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["study_program"] == "Кібербезпека"


def test_study_program_min_length():
    """Допустима мінімальна довжина поля."""
    response = create_student(
        study_program="ІТ"
    )

    assert response.status_code == 201
    assert response.json()["study_program"] == "ІТ"


def test_study_program_too_short():
    """Відхилення надто короткої назви."""
    response = create_student(
        study_program="І"
    )

    assert response.status_code == 422


def test_study_program_too_long():
    """Відхилення назви понад 100 символів."""
    response = create_student(
        study_program="А" * 101
    )

    assert response.status_code == 422


def test_empty_patch():
    """Заборона порожнього оновлення."""
    created = create_student().json()

    response = client.patch(
        f"{BASE_URL}/{created['id']}",
        json={},
    )

    assert response.status_code == 422


def test_duplicate_email():
    """Перевірка унікальності email."""
    create_student()

    response = create_student(
        email="IVAN.PETRENKO@example.com"
    )

    assert response.status_code == 409


def test_duplicate_email_on_update():
    """Заборона повторного email під час PATCH."""
    create_student()

    second = create_student(
        email="olena.koval@example.com"
    ).json()

    response = client.patch(
        f"{BASE_URL}/{second['id']}",
        json={
            "email": "IVAN.PETRENKO@example.com"
        },
    )

    assert response.status_code == 409


def test_cannot_change_student_id():
    """Заборона зміни ідентифікатора."""
    created = create_student().json()

    response = client.patch(
        f"{BASE_URL}/{created['id']}",
        json={"id": str(uuid4())},
    )

    assert response.status_code == 422
