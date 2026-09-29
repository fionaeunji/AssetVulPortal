"""DB 기반 Lease Lock — Web 프로세스와 Scheduler 프로세스 간 중복 실행 방지."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, insert, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.models import JobLock
from app.models.types import utcnow


def acquire(factory: sessionmaker[Session], name: str, holder: str, ttl: timedelta) -> bool:
    """원자적으로 Lock 획득. 이미 유효한 Lock이 있으면 False. 만료된 Lock은 인수."""
    now = utcnow()
    with factory() as s:
        try:
            s.execute(insert(JobLock).values(name=name, holder=holder, acquired_at=now,
                                             expires_at=now + ttl))
            s.commit()
            return True
        except IntegrityError:
            s.rollback()
        res = s.execute(
            update(JobLock)
            .where(JobLock.name == name, JobLock.expires_at < now)
            .values(holder=holder, acquired_at=now, expires_at=now + ttl)
        )
        s.commit()
        return res.rowcount == 1


def release(factory: sessionmaker[Session], name: str, holder: str) -> None:
    with factory() as s:
        s.execute(delete(JobLock).where(JobLock.name == name, JobLock.holder == holder))
        s.commit()
