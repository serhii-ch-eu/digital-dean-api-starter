from fastapi import APIRouter, HTTPException, status, Query
from uuid import UUID
from typing import List, Optional
from app.schemas.student import StudentCreate, StudentRead, StudentUpdate
from app.repositories import student_repository

router = APIRouter(prefix="/api/v1/students", tags=["students"])

@router.post("", response_model=StudentRead, status_code=status.HTTP_201_CREATED)
def create_student(student: StudentCreate):
    created = student_repository.create(student)
    if not created:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email conflict")
    return created

@router.get("", response_model=List[StudentRead])
def get_students(study_program: Optional[str] = Query(None)):
    return student_repository.get_all(study_program=study_program)

@router.get("/{student_id}", response_model=StudentRead)
def get_student(student_id: UUID):
    student = student_repository.get_by_id(student_id)
    if not student:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found")
    return student

@router.patch("/{student_id}", response_model=StudentRead)
def update_student(student_id: UUID, student_update: StudentUpdate):
    if not student_update.model_dump(exclude_unset=True):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Empty update body")
        
    try:
        updated = student_repository.update(student_id, student_update)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email conflict")
        
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found")
    return updated