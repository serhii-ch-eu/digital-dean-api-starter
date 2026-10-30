from uuid import UUID, uuid4
from typing import List, Optional
from app.schemas.student import StudentCreate, StudentUpdate, StudentRead

_db: dict[UUID, StudentRead] = {}

def clear_db() -> None:
    _db.clear()

def _email_exists(email: str, exclude_id: Optional[UUID] = None) -> bool:
    email_lower = email.lower()
    for student in _db.values():
        if student.email.lower() == email_lower and student.id != exclude_id:
            return True
    return False

def create(student_in: StudentCreate) -> Optional[StudentRead]:
    if _email_exists(student_in.email):
        return None
    new_id = uuid4()
    student = StudentRead(id=new_id, **student_in.model_dump())
    _db[new_id] = student
    return student

def get_all(study_program: Optional[str] = None) -> List[StudentRead]:
    students = list(_db.values())
    if study_program:
        students = [s for s in students if s.study_program == study_program]
    return students

def get_by_id(student_id: UUID) -> Optional[StudentRead]:
    return _db.get(student_id)

def update(student_id: UUID, update_data: StudentUpdate) -> Optional[StudentRead]:
    student = _db.get(student_id)
    if not student:
        return None
    
    update_dict = update_data.model_dump(exclude_unset=True)
    if "email" in update_dict and _email_exists(update_dict["email"], exclude_id=student_id):
        raise ValueError("Email already in use")
        
    updated_student = student.model_copy(update=update_dict)
    _db[student_id] = updated_student
    return updated_student