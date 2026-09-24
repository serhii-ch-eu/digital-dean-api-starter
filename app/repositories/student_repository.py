from uuid import UUID

from app.schemas.student import StudentCreate, StudentRead, StudentUpdate


class StudentNotFoundError(KeyError):
    """Запис студента не знайдено."""


class DuplicateEmailError(ValueError):
    """Електронна адреса вже використовується."""


class InMemoryStudentRepository:
    def __init__(self) -> None:
        self._students: dict[UUID, StudentRead] = {}

    def create(self, payload: StudentCreate) -> StudentRead:
        raise NotImplementedError

    def list(self, *, variant_filter: str | None = None) -> list[StudentRead]:
        raise NotImplementedError

    def get(self, student_id: UUID) -> StudentRead:
        raise NotImplementedError

    def update(self, student_id: UUID, payload: StudentUpdate) -> StudentRead:
        raise NotImplementedError

    def clear(self) -> None:
        self._students.clear()


student_repository = InMemoryStudentRepository()
