"""Provided HTTP adapter. Implement tokens, policy and transactional service logic."""
from typing import Annotated
import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.api.account_validation import SensitiveRoute
from app.schemas.user_account import LoginRequest, UserCreate, UserPublic
from .config import SecuritySettings
from .models import (
    Principal, TokenResponse, Me, StatusChange, CourseInput, CoursePublic,
    GradeCreate, GradeChange, GradePublic, EnrollmentPublic,
)
from .policy import Action, AuthenticationRequired, Forbidden, NotFound, Conflict, role_allows
from .service import DeanService
from .tokens import BadToken, issue_access_token, read_access_token

router = APIRouter(prefix="/api/v1", route_class=SensitiveRoute)
bearer = HTTPBearer(auto_error=False)
PathId = Annotated[int, Path(gt=0, le=9_223_372_036_854_775_807)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0)]


def invoke(operation):
    try:
        return operation()
    except AuthenticationRequired:
        raise HTTPException(401, "authentication required",
                            headers={"WWW-Authenticate": "Bearer"}) from None
    except Forbidden:
        raise HTTPException(403, "operation forbidden") from None
    except NotFound:
        raise HTTPException(404, "resource not found") from None
    except Conflict:
        raise HTTPException(409, "operation conflicts with current state") from None
    except sqlite3.Error:
        raise HTTPException(500, "database unavailable") from None


def get_service(request: Request) -> DeanService:
    return request.app.state.practice06_service


def get_security_settings(request: Request) -> SecuritySettings:
    return request.app.state.practice06_settings


Service = Annotated[DeanService, Depends(get_service)]
Settings = Annotated[SecuritySettings, Depends(get_security_settings)]
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


def authentication_error() -> HTTPException:
    return HTTPException(401, "authentication required",
                         headers={"WWW-Authenticate": "Bearer"})


def current_actor(credentials: Credentials, settings: Settings, service: Service) -> Principal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise authentication_error()
    try:
        user_id = read_access_token(credentials.credentials, settings)
    except BadToken:
        raise authentication_error() from None
    return invoke(lambda: service.principal(user_id))


Actor = Annotated[Principal, Depends(current_actor)]


def permitted(action: Action):
    def guard(actor: Actor) -> Principal:
        if not role_allows(actor.role, action):
            raise HTTPException(403, "operation forbidden")
        return actor
    return guard


@router.post("/auth/login", response_model=TokenResponse, tags=["auth"])
def login(data: LoginRequest, response: Response, service: Service, settings: Settings):
    user_id = invoke(lambda: service.authenticate(data.login, data.password.get_secret_value()))
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return TokenResponse(access_token=issue_access_token(user_id, settings))


@router.get("/auth/me", response_model=Me, tags=["auth"])
def me(actor: Actor, service: Service):
    return invoke(lambda: service.me(actor.id))


@router.get("/users", response_model=list[UserPublic], tags=["users"])
def list_users(service: Service, actor: Annotated[Principal, Depends(permitted(Action.USER_READ))],
               limit: Limit = 100, offset: Offset = 0):
    return invoke(lambda: service.list_users(actor.id, limit, offset))


@router.get("/users/{user_id}", response_model=UserPublic, tags=["users"])
def get_user(user_id: PathId, service: Service,
             actor: Annotated[Principal, Depends(permitted(Action.USER_READ))]):
    return invoke(lambda: service.get_user(actor.id, user_id))


@router.post("/users", response_model=UserPublic, status_code=201, tags=["users"])
def register_user(data: UserCreate, service: Service,
                  actor: Annotated[Principal, Depends(permitted(Action.USER_CREATE))]):
    return invoke(lambda: service.create_user(actor.id, data))


@router.patch("/users/{user_id}/status", response_model=UserPublic, tags=["users"])
def set_status(user_id: PathId, data: StatusChange, service: Service,
               actor: Annotated[Principal, Depends(permitted(Action.USER_STATUS))]):
    return invoke(lambda: service.set_status(actor.id, user_id, data.status_id))


@router.patch("/users/{user_id}/block", response_model=UserPublic, tags=["users"])
def block_user(user_id: PathId, service: Service,
               actor: Annotated[Principal, Depends(permitted(Action.USER_STATUS))]):
    return invoke(lambda: service.set_status(actor.id, user_id, 2))


@router.get("/courses", response_model=list[CoursePublic], tags=["courses"])
def list_courses(service: Service,
                 actor: Annotated[Principal, Depends(permitted(Action.COURSE_READ))],
                 limit: Limit = 100, offset: Offset = 0):
    return invoke(lambda: service.list_courses(actor.id, limit, offset))


@router.get("/courses/{course_id}", response_model=CoursePublic, tags=["courses"])
def get_course(course_id: PathId, service: Service,
                actor: Annotated[Principal, Depends(permitted(Action.COURSE_READ))]):
    return invoke(lambda: service.get_course(actor.id, course_id))


@router.post("/courses", response_model=CoursePublic, status_code=201, tags=["courses"])
def create_course(data: CourseInput, service: Service,
                   actor: Annotated[Principal, Depends(permitted(Action.COURSE_WRITE))]):
    return invoke(lambda: service.create_course(actor.id, data))


@router.patch("/courses/{course_id}", response_model=CoursePublic, tags=["courses"])
def update_course(course_id: PathId, data: CourseInput, service: Service,
                   actor: Annotated[Principal, Depends(permitted(Action.COURSE_WRITE))]):
    return invoke(lambda: service.update_course(actor.id, course_id, data))


@router.delete("/courses/{course_id}", status_code=204, response_class=Response, tags=["courses"])
def delete_course(course_id: PathId, service: Service,
                   actor: Annotated[Principal, Depends(permitted(Action.COURSE_WRITE))]):
    invoke(lambda: service.delete_course(actor.id, course_id))
    return Response(status_code=204)


@router.put("/courses/{course_id}/teachers/{user_id}", response_model=EnrollmentPublic,
            tags=["enrollments"])
def assign_teacher(course_id: PathId, user_id: PathId, service: Service,
                    actor: Annotated[Principal, Depends(permitted(Action.TEACHER_ASSIGN))]):
    return invoke(lambda: service.assign_teacher(actor.id, course_id, user_id))


@router.delete("/courses/{course_id}/teachers/{user_id}", status_code=204,
               response_class=Response, tags=["enrollments"])
def remove_teacher(course_id: PathId, user_id: PathId, service: Service,
                    actor: Annotated[Principal, Depends(permitted(Action.TEACHER_ASSIGN))]):
    invoke(lambda: service.remove_teacher(actor.id, course_id, user_id))
    return Response(status_code=204)


@router.put("/courses/{course_id}/students/{user_id}", response_model=EnrollmentPublic,
            tags=["enrollments"])
def enroll_student(course_id: PathId, user_id: PathId, service: Service,
                    actor: Annotated[Principal, Depends(permitted(Action.STUDENT_ENROLL))]):
    return invoke(lambda: service.enroll_student(actor.id, course_id, user_id))


@router.delete("/courses/{course_id}/students/{user_id}", status_code=204,
               response_class=Response, tags=["enrollments"])
def withdraw_student(course_id: PathId, user_id: PathId, service: Service,
                      actor: Annotated[Principal, Depends(permitted(Action.STUDENT_WITHDRAW))]):
    invoke(lambda: service.withdraw_student(actor.id, course_id, user_id))
    return Response(status_code=204)


@router.get("/courses/{course_id}/grades", response_model=list[GradePublic], tags=["grades"])
def list_grades(course_id: PathId, service: Service,
                actor: Annotated[Principal, Depends(permitted(Action.GRADE_READ))],
                limit: Limit = 100, offset: Offset = 0):
    return invoke(lambda: service.list_grades(actor.id, course_id, limit, offset))


@router.post("/courses/{course_id}/grades", response_model=GradePublic, status_code=201,
             tags=["grades"])
def create_grade(course_id: PathId, data: GradeCreate, service: Service,
                   actor: Annotated[Principal, Depends(permitted(Action.GRADE_WRITE))]):
    return invoke(lambda: service.create_grade(actor.id, course_id, data))


@router.patch("/courses/{course_id}/grades/{student_id}", response_model=GradePublic,
              tags=["grades"])
def update_grade(course_id: PathId, student_id: PathId, data: GradeChange, service: Service,
                   actor: Annotated[Principal, Depends(permitted(Action.GRADE_WRITE))]):
    return invoke(lambda: service.update_grade(actor.id, course_id, student_id, data))


@router.get("/me/grades", response_model=list[GradePublic], tags=["grades"])
def own_grades(service: Service,
                actor: Annotated[Principal, Depends(permitted(Action.OWN_GRADES))],
                limit: Limit = 100, offset: Offset = 0):
    return invoke(lambda: service.own_grades(actor.id, limit, offset))
