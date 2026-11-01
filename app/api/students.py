
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.student import (
    StudentCreate,
    StudentRead,
    StudentUpdate,
)

from app.repositories.student_repository import (
    DuplicateEmailError,
    StudentNotFoundError,
    student_repository,
)


router = APIRouter(
    prefix="/api/v1/students",
    tags=["students"],
)


@router.post(
    "",
    response_model=StudentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_student(payload: StudentCreate) -> StudentRead:
    """Створення нового запису студента."""

    try:
        return student_repository.create(payload)
    except DuplicateEmailError:
        raise HTTPException(
            status_code=409,
            detail="Електронна адреса вже використовується",
        )


@router.get(
    "",
    response_model=list[StudentRead],
)
def list_students(
    study_program: str | None = Query(default=None),
) -> list[StudentRead]:
    """Отримання списку студентів із фільтрацією."""

    return student_repository.list(
        variant_filter=study_program
    )


@router.get(
    "/{student_id}",
    response_model=StudentRead,
)
def get_student(student_id: UUID) -> StudentRead:
    """Отримання студента за UUID."""

    try:
        return student_repository.get(student_id)
    except StudentNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Студента не знайдено",
        )


@router.patch(
    "/{student_id}",
    response_model=StudentRead,
)
def update_student(
    student_id: UUID,
    payload: StudentUpdate,
) -> StudentRead:
    """Часткове оновлення запису студента."""

    try:
        return student_repository.update(
            student_id,
            payload,
        )

    except StudentNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Студента не знайдено",
        )

    except DuplicateEmailError:
        raise HTTPException(
            status_code=409,
            detail="Електронна адреса вже використовується",
        )

    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="Некоректні дані оновлення",
        )
