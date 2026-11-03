"""The agreed FUNCTION-level matrix. Object checks belong in the service too."""
from enum import StrEnum
from .models import Role


class Action(StrEnum):
    USER_READ = "user.read"
    USER_CREATE = "user.create"
    USER_STATUS = "user.status"
    COURSE_READ = "course.read"
    COURSE_WRITE = "course.write"
    TEACHER_ASSIGN = "teacher.assign"
    STUDENT_ENROLL = "student.enroll"
    STUDENT_WITHDRAW = "student.withdraw"
    GRADE_READ = "grade.read"
    GRADE_WRITE = "grade.write"
    OWN_GRADES = "grade.own"


ROLE_ACTIONS = {
    Role.ADMIN: frozenset({Action.USER_READ, Action.USER_CREATE, Action.USER_STATUS}),
    Role.MANAGER: frozenset({Action.COURSE_READ, Action.COURSE_WRITE,
        Action.TEACHER_ASSIGN, Action.STUDENT_ENROLL, Action.STUDENT_WITHDRAW,
        Action.GRADE_READ}),
    Role.TEACHER: frozenset({Action.COURSE_READ, Action.STUDENT_ENROLL,
        Action.GRADE_READ, Action.GRADE_WRITE}),
    Role.STUDENT: frozenset({Action.COURSE_READ, Action.OWN_GRADES}),
}


class AuthenticationRequired(Exception):
    pass


class Forbidden(Exception):
    pass


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def role_allows(role: Role, action: Action) -> bool:
    """Exact allowlist; admin is NOT a superuser; unknown -> False."""
    raise NotImplementedError("TODO: deny-by-default role predicate")
