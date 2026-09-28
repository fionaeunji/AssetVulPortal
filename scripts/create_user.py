"""로컬 사용자 생성 (비밀번호는 대화형 입력, 명령행 인자/로그에 남기지 않음).

사용: python -m scripts.create_user --username admin --role admin
"""
from __future__ import annotations

import argparse
import getpass
import re
import sys

from sqlalchemy import select

from app.db import session_scope
from app.models import User
from app.models.enums import Role
from app.security.passwords import WeakPasswordError, hash_password, validate_password_strength
from app.services import audit

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--role", required=True, choices=[r.value for r in Role])
    args = parser.parse_args()

    if not USERNAME_RE.fullmatch(args.username):
        print("username 형식 오류 (영문/숫자/_.- 3~64자)", file=sys.stderr)
        return 2
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Password (again): "):
        print("비밀번호가 일치하지 않습니다.", file=sys.stderr)
        return 2
    try:
        validate_password_strength(pw)
    except WeakPasswordError as e:
        print(f"비밀번호 정책 위반: {e}", file=sys.stderr)
        return 2

    with session_scope() as s:
        if s.execute(select(User).where(User.username == args.username)).scalar_one_or_none():
            print("이미 존재하는 사용자입니다.", file=sys.stderr)
            return 1
        s.add(User(username=args.username, password_hash=hash_password(pw), role=Role(args.role)))
        audit.record(s, actor="cli", action=audit.AuditAction.USER_CHANGE, target_type="user",
                     target_id=args.username, after={"username": args.username, "role": args.role,
                                                     "op": "create"})
    print(f"사용자 생성 완료: {args.username} ({args.role})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
