"""Explicit public fields and strict write inputs; no client role/author fields."""
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

Id = Annotated[StrictInt, Field(gt=0, le=9_223_372_036_854_775_807)]
GradeValue = Annotated[StrictInt, Field(ge=0, le=100)]


class Role(StrEnum):
    ADMIN = "admin"
    MANAGER = "manager"
    TEACHER = "teacher"
    STUDENT = "student"


@dataclass(frozen=True)
class Principal:
    id: int
    role: Role


class Message(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class TokenResponse(Message):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: Literal[900] = 900


class Me(Message):
    id: Id
    login: str
    role: Role
    status_id: Literal[1] = 1


class StatusChange(Message):
    status_id: Annotated[StrictInt, Field(ge=0, le=2)]


class CourseInput(Message):
    name: Annotated[str, Field(min_length=1, max_length=120)]

    @field_validator("name")
    @classmethod
    def clean_name(cls, value):
        value = value.strip()
        if not value or "\x00" in value:
            raise ValueError("invalid course name")
        return value


class CoursePublic(CourseInput):
    id: Id


class GradeCreate(Message):
    student_id: Id
    grade: GradeValue


class GradeChange(Message):
    grade: GradeValue


class GradePublic(GradeCreate):
    teacher_id: Id
    course_id: Id


class EnrollmentPublic(Message):
    course_id: Id
    user_id: Id
    role: Literal["teacher", "student"]
