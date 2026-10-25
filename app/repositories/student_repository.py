
from uuid import UUID, uuid4

from app.schemas.student import (
    StudentCreate,
    StudentRead,
    StudentUpdate,
)


class StudentNotFoundError(KeyError):
    """Запис студента не знайдено."""


class DuplicateEmailError(ValueError):
    """Електронна адреса вже використовується."""


class InMemoryStudentRepository:
    def __init__(self) -> None:
        self._students: dict[UUID, StudentRead] = {}

    def _check_email(
        self,
        email: str,
        exclude_id: UUID | None = None,
    ) -> None:
        """Перевірка унікальності електронної адреси."""

        for student in self._students.values():
            if exclude_id is not None and student.id == exclude_id:
                continue

            if student.email.casefold() == email.casefold():
                raise DuplicateEmailError(
                    "Електронна адреса вже використовується"
                )

    def create(self, payload: StudentCreate) -> StudentRead:
        """Створення нового студента."""

        self._check_email(str(payload.email))

        student = StudentRead(
            id=uuid4(),
            **payload.model_dump(),
        )

        self._students[student.id] = student
        return student

    def list(
        self,
        *,
        variant_filter: str | None = None,
    ) -> list[StudentRead]:
        """Отримання списку студентів із фільтрацією."""

        students = list(self._students.values())

        if variant_filter is not None:
            students = [
                student
                for student in students
                if student.study_program == variant_filter
            ]

        return students

    def get(self, student_id: UUID) -> StudentRead:
        """Пошук студента за ідентифікатором."""

        student = self._students.get(student_id)

        if student is None:
            raise StudentNotFoundError(
                "Студента не знайдено"
            )

        return student

    def update(
        self,
        student_id: UUID,
        payload: StudentUpdate,
    ) -> StudentRead:
        """Часткове оновлення даних студента."""

        student = self.get(student_id)

        update_data = payload.model_dump(
            exclude_unset=True
        )

        if not update_data:
            raise ValueError(
                "Порожнє оновлення заборонено"
            )

        if "email" in update_data:
            self._check_email(
                str(update_data["email"]),
                exclude_id=student_id,
            )

        updated_student = student.model_copy(
            update=update_data
        )

        self._students[student_id] = updated_student

        return updated_student

    def clear(self) -> None:
        """Очищення сховища перед тестами."""

        self._students.clear()


student_repository = InMemoryStudentRepository()
