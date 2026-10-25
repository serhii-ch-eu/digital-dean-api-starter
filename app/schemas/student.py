
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    model_validator,
)


class StrictModel(BaseModel):
    """Базова модель із забороною невідомих полів."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


class StudentCreate(StrictModel):
    """Дані для створення студента."""

    full_name: str = Field(
        min_length=5,
        max_length=120,
    )
    email: EmailStr
    group_code: str = Field(
        pattern=r"^[A-ZА-ЯІЇЄҐ0-9]+-[0-9]{2}$",
    )
    study_program: str = Field(
        min_length=2,
        max_length=100,
    )


class StudentRead(StudentCreate):
    """Дані студента у відповіді API."""

    id: UUID


class StudentUpdate(StrictModel):
    """Дані для часткового оновлення студента."""

    full_name: str | None = Field(
        default=None,
        min_length=5,
        max_length=120,
    )
    email: EmailStr | None = None
    group_code: str | None = Field(
        default=None,
        pattern=r"^[A-ZА-ЯІЇЄҐ0-9]+-[0-9]{2}$",
    )
    study_program: str | None = Field(
        default=None,
        min_length=2,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_update(self):
        """Заборонити порожнє оновлення та null."""

        if not self.model_fields_set:
            raise ValueError("Порожнє оновлення заборонено")

        for field in self.model_fields_set:
            if getattr(self, field) is None:
                raise ValueError(
                    f"Поле {field} не може бути null"
                )

        return self
