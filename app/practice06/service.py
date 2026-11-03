"""Student business logic; all writes recheck the actor INSIDE their transaction."""
from pathlib import Path
from app.schemas.user_account import UserCreate, UserPublic
from .models import (
    Principal, Me, CourseInput, CoursePublic, GradeCreate, GradeChange,
    GradePublic, EnrollmentPublic,
)


class DeanService:
    def __init__(self, database_path: Path):
        self.database_path = Path(database_path)

    def authenticate(self, login: str, password: str) -> int:
        """Correct existing P5 verifier AND active status; else AuthenticationRequired.
        Return id, NOT a token. Missing role does not make a password incorrect.
        """
        raise NotImplementedError("TODO: active credential verification")

    def principal(self, user_id: int) -> Principal:
        """Current active user + exactly one known DB role.
        Missing/inactive -> AuthenticationRequired; no/multiple/unknown role -> Forbidden.
        """
        raise NotImplementedError("TODO: current database identity")

    def me(self, actor_id: int) -> Me:
        raise NotImplementedError("TODO: safe current identity")

    def list_users(self, actor_id: int, limit: int, offset: int) -> list[UserPublic]:
        raise NotImplementedError("TODO: admin only, safe fields")

    def get_user(self, actor_id: int, user_id: int) -> UserPublic:
        raise NotImplementedError("TODO: admin only, safe fields or NotFound")

    def create_user(self, actor_id: int, data: UserCreate) -> UserPublic:
        """Admin only; keep P5 hash/salt; no automatic role. Duplicate -> Conflict.
        Compute password outside write lock, then recheck admin and insert atomically.
        """
        raise NotImplementedError("TODO: guarded registration")

    def set_status(self, actor_id: int, user_id: int, status_id: int) -> UserPublic:
        raise NotImplementedError("TODO: admin only; only status changes")

    def list_courses(self, actor_id: int, limit: int, offset: int) -> list[CoursePublic]:
        """Manager all; teacher assigned; student enrolled; admin Forbidden."""
        raise NotImplementedError("TODO: scoped query, not client-side filtering")

    def get_course(self, actor_id: int, course_id: int) -> CoursePublic:
        raise NotImplementedError("TODO: visible course or NotFound")

    def create_course(self, actor_id: int, data: CourseInput) -> CoursePublic:
        raise NotImplementedError("TODO: manager only")

    def update_course(self, actor_id: int, course_id: int, data: CourseInput) -> CoursePublic:
        raise NotImplementedError("TODO: manager only; course name")

    def delete_course(self, actor_id: int, course_id: int) -> None:
        """Manager; grade references -> Conflict with FULL rollback. No grades -> delete."""
        raise NotImplementedError("TODO: guarded course deletion")

    def assign_teacher(self, actor_id: int, course_id: int, user_id: int) -> EnrollmentPublic:
        """Manager; target must have exactly teacher role; repeat -> same200 result."""
        raise NotImplementedError("TODO: parameterized idempotent assignment")

    def remove_teacher(self, actor_id: int, course_id: int, user_id: int) -> None:
        """Manager; missing course404; absent link204; historical grades stay."""
        raise NotImplementedError("TODO: remove assignment, NOT grades")

    def enroll_student(self, actor_id: int, course_id: int, user_id: int) -> EnrollmentPublic:
        """Manager OR assigned teacher; target student role. Repeat -> same200 result."""
        raise NotImplementedError("TODO: role plus current course relationship")

    def withdraw_student(self, actor_id: int, course_id: int, user_id: int) -> None:
        """Manager only; absent link204; preserve all grades."""
        raise NotImplementedError("TODO: enrollment removal only")

    def list_grades(self, actor_id: int, course_id: int, limit: int,
                    offset: int) -> list[GradePublic]:
        """Manager all for course; assigned teacher ONLY self-authored grades."""
        raise NotImplementedError("TODO: scope in SQL, preserve ownership")

    def create_grade(self, actor_id: int, course_id: int, data: GradeCreate) -> GradePublic:
        """Assigned teacher + enrolled target with student role. Author=actor_id.
        Duplicate student/course -> Conflict, NEVER overwrite another author.
        """
        raise NotImplementedError("TODO: guarded grade insertion")

    def update_grade(self, actor_id: int, course_id: int, student_id: int,
                     data: GradeChange) -> GradePublic:
        """Assigned teacher + enrolled student + self-authored existing grade.
        Invisible/other author's grade -> NotFound. No author change or upsert.
        """
        raise NotImplementedError("TODO: current assignment AND authorship")

    def own_grades(self, actor_id: int, limit: int, offset: int) -> list[GradePublic]:
        """Student only; filter student_id=actor_id, including withdrawn courses."""
        raise NotImplementedError("TODO: historical personal grade query")
