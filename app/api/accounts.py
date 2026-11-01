"""Student task: register these four functions on the SAME existing app."""
from typing import Annotated
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Path, Response

from app.api.account_validation import SensitiveRoute
from app.db.connection import DB_PATH
from app.repositories.user_repository import (
    UserConflict, UserNotFound, UserReferenced, UserRepository,
)
from app.schemas.user_account import LoginRequest, UserCreate, UserPublic

router = APIRouter(tags=["accounts"], route_class=SensitiveRoute)


def get_user_repository() -> UserRepository:
    return UserRepository(DB_PATH)


Repository = Annotated[UserRepository, Depends(get_user_repository)]
UserId = Annotated[int, Path(gt=0, le=9_223_372_036_854_775_807)]


@router.post("/api/v1/users", response_model=UserPublic, status_code=201)
def register_user(data: UserCreate, repository: Repository) -> UserPublic:
    try:
        return repository.register_user(data)
    except UserConflict:
        raise HTTPException(status_code=409, detail="user already exists") from None
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="database unavailable") from None


@router.delete("/api/v1/users/{user_id}", status_code=204)
def delete_user(user_id: UserId, repository: Repository) -> Response:
    try:
        repository.delete_user(user_id)
    except UserNotFound:
        raise HTTPException(status_code=404, detail="user not found") from None
    except UserReferenced:
        raise HTTPException(status_code=409, detail="user has grade references") from None
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="database unavailable") from None
    return Response(status_code=204)


@router.patch("/api/v1/users/{user_id}/block", response_model=UserPublic)
def block_user(user_id: UserId, repository: Repository) -> UserPublic:
    try:
        return repository.block_user(user_id)
    except UserNotFound:
        raise HTTPException(status_code=404, detail="user not found") from None
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="database unavailable") from None


@router.post("/api/v1/auth/login", response_model=bool)
def login(data: LoginRequest, repository: Repository) -> bool:
    try:
        return repository.login(data.login, data.password.get_secret_value())
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="database unavailable") from None
