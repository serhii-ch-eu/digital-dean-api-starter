from pydantic import BaseModel, ConfigDict, EmailStr, Field
from typing import Optional
from uuid import UUID

class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

class StudentCreate(StrictModel):
    full_name: str = Field(min_length=5, max_length=120)
    email: EmailStr
    group_code: str = Field(pattern=r"^[A-ZА-ЯІЇЄҐ0-9]+-\d{2}$")
    study_program: str = Field(min_length=2, max_length=100)

class StudentUpdate(StrictModel):
    full_name: Optional[str] = Field(default=None, min_length=5, max_length=120)
    email: Optional[EmailStr] = None
    group_code: Optional[str] = Field(default=None, pattern=r"^[A-ZА-ЯІЇЄҐ0-9]+-\d{2}$")
    study_program: Optional[str] = Field(default=None, min_length=2, max_length=100)

class StudentRead(BaseModel):
    id: UUID
    full_name: str
    email: EmailStr
    group_code: str
    study_program: str