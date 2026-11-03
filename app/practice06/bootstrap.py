"""Trusted LOCAL provisioning utility for synthetic lab accounts, never an HTTP API."""
import argparse
from getpass import getpass
from pathlib import Path
from app.db.connection import DB_PATH
from app.schemas.user_account import UserCreate, UserPublic
from .models import Role


def create_local_account(path: Path, data: UserCreate, role: Role) -> UserPublic:
    """Hash using completed P5 implementation; one transaction inserts user AND role.
    Require active status for this explicit local provisioning operation.
    No default password or admin, no output of password/hash/salt.
    """
    raise NotImplementedError("TODO: atomic trusted local provisioning")


def assign_local_role(path: Path, user_id: int, role: Role) -> None:
    """One trusted local transaction replaces only this user's role association.
    Do not delete users, enrollments or grades. No HTTP role-grant route.
    """
    raise NotImplementedError("TODO: local single-role assignment")


def main():
    parser = argparse.ArgumentParser(description="LOCAL synthetic-account provisioning")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--login", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--email", required=True)
    create.add_argument("--role", required=True, choices=[r.value for r in Role])
    assign = commands.add_parser("assign-role")
    assign.add_argument("--user-id", type=int, required=True)
    assign.add_argument("--role", required=True, choices=[r.value for r in Role])
    args = parser.parse_args()
    if args.command == "create":
        password = getpass("Synthetic account password: ")
        if password != getpass("Repeat password: "):
            parser.error("password confirmation mismatch")
        data = UserCreate(name=args.name, email=args.email, login=args.login,
                          password=password, status_id=1)
        result = create_local_account(DB_PATH, data, Role(args.role))
        print(f"Created synthetic account id={result.id}")
    else:
        if args.user_id <= 0:
            parser.error("user id must be positive")
        assign_local_role(DB_PATH, args.user_id, Role(args.role))
        print("Local role assignment completed")


if __name__ == "__main__":
    main()
