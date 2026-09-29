"""DB 레벨 무결성 보호 (Defense in depth).

- Append-only 테이블: audit_logs, vulnerability_assessments, status_history → UPDATE/DELETE 금지
- 불변 컬럼: vulnerabilities.epss_initial*, asset_vulnerabilities.initial_due_at,
  policy_versions 내용
애플리케이션 버그나 직접 SQL로도 과거 증적을 덮어쓰지 못하게 한다.
"""
from __future__ import annotations

from sqlalchemy import event
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session

APPEND_ONLY_TABLES = ("audit_logs", "vulnerability_assessments", "status_history")

_SQLITE: list[str] = []
for _t in APPEND_ONLY_TABLES:
    _SQLITE += [
        f"CREATE TRIGGER IF NOT EXISTS trg_{_t}_no_update BEFORE UPDATE ON {_t} "
        f"BEGIN SELECT RAISE(ABORT, '{_t} is append-only'); END;",
        f"CREATE TRIGGER IF NOT EXISTS trg_{_t}_no_delete BEFORE DELETE ON {_t} "
        f"BEGIN SELECT RAISE(ABORT, '{_t} is append-only'); END;",
    ]
_SQLITE += [
    """CREATE TRIGGER IF NOT EXISTS trg_vuln_epss_initial_immutable
       BEFORE UPDATE OF epss_initial, epss_initial_date, epss_first_seen_at ON vulnerabilities
       WHEN OLD.epss_initial IS NOT NULL AND (
            NEW.epss_initial IS NOT OLD.epss_initial
         OR NEW.epss_initial_date IS NOT OLD.epss_initial_date
         OR NEW.epss_first_seen_at IS NOT OLD.epss_first_seen_at)
       BEGIN SELECT RAISE(ABORT, 'epss_initial is immutable'); END;""",
    """CREATE TRIGGER IF NOT EXISTS trg_av_initial_due_immutable
       BEFORE UPDATE OF initial_due_at ON asset_vulnerabilities
       WHEN OLD.initial_due_at IS NOT NULL AND NEW.initial_due_at IS NOT OLD.initial_due_at
       BEGIN SELECT RAISE(ABORT, 'initial_due_at is immutable'); END;""",
    """CREATE TRIGGER IF NOT EXISTS trg_policy_content_immutable
       BEFORE UPDATE OF version, content_yaml, content_sha256 ON policy_versions
       BEGIN SELECT RAISE(ABORT, 'policy version content is immutable'); END;""",
    """CREATE TRIGGER IF NOT EXISTS trg_policy_no_delete BEFORE DELETE ON policy_versions
       BEGIN SELECT RAISE(ABORT, 'policy versions cannot be deleted'); END;""",
]

_POSTGRES: list[str] = [
    """CREATE OR REPLACE FUNCTION vp_forbid_change() RETURNS trigger AS $$
       BEGIN RAISE EXCEPTION '% is append-only', TG_TABLE_NAME; END; $$ LANGUAGE plpgsql;""",
    """CREATE OR REPLACE FUNCTION vp_epss_initial_immutable() RETURNS trigger AS $$
       BEGIN
         IF OLD.epss_initial IS NOT NULL AND (
              NEW.epss_initial IS DISTINCT FROM OLD.epss_initial
           OR NEW.epss_initial_date IS DISTINCT FROM OLD.epss_initial_date
           OR NEW.epss_first_seen_at IS DISTINCT FROM OLD.epss_first_seen_at) THEN
           RAISE EXCEPTION 'epss_initial is immutable';
         END IF;
         RETURN NEW;
       END; $$ LANGUAGE plpgsql;""",
    """CREATE OR REPLACE FUNCTION vp_initial_due_immutable() RETURNS trigger AS $$
       BEGIN
         IF OLD.initial_due_at IS NOT NULL
            AND NEW.initial_due_at IS DISTINCT FROM OLD.initial_due_at THEN
           RAISE EXCEPTION 'initial_due_at is immutable';
         END IF;
         RETURN NEW;
       END; $$ LANGUAGE plpgsql;""",
    """CREATE OR REPLACE FUNCTION vp_policy_immutable() RETURNS trigger AS $$
       BEGIN
         IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'policy versions cannot be deleted'; END IF;
         IF NEW.version IS DISTINCT FROM OLD.version
            OR NEW.content_yaml IS DISTINCT FROM OLD.content_yaml
            OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256 THEN
           RAISE EXCEPTION 'policy version content is immutable';
         END IF;
         RETURN NEW;
       END; $$ LANGUAGE plpgsql;""",
]
for _t in APPEND_ONLY_TABLES:
    _POSTGRES.append(
        f"CREATE TRIGGER trg_{_t}_append_only BEFORE UPDATE OR DELETE ON {_t} "
        f"FOR EACH ROW EXECUTE FUNCTION vp_forbid_change();"
    )
_POSTGRES += [
    "CREATE TRIGGER trg_vuln_epss_initial_immutable BEFORE UPDATE ON vulnerabilities "
    "FOR EACH ROW EXECUTE FUNCTION vp_epss_initial_immutable();",
    "CREATE TRIGGER trg_av_initial_due_immutable BEFORE UPDATE ON asset_vulnerabilities "
    "FOR EACH ROW EXECUTE FUNCTION vp_initial_due_immutable();",
    "CREATE TRIGGER trg_policy_immutable BEFORE UPDATE OR DELETE ON policy_versions "
    "FOR EACH ROW EXECUTE FUNCTION vp_policy_immutable();",
]


def guard_statements(dialect_name: str) -> list[str]:
    if dialect_name == "sqlite":
        return list(_SQLITE)
    if dialect_name == "postgresql":
        return list(_POSTGRES)
    raise NotImplementedError(f"DB guards not defined for dialect: {dialect_name}")


def install_db_guards(conn: Connection) -> None:
    for stmt in guard_statements(conn.dialect.name):
        conn.exec_driver_sql(stmt)


# ---- ORM 레벨 보호 ----
class AppendOnlyViolation(RuntimeError):
    pass


def _register_orm_guard() -> None:
    from app.models import AuditLog, StatusHistory, VulnerabilityAssessment

    protected = (AuditLog, StatusHistory, VulnerabilityAssessment)

    @event.listens_for(Session, "before_flush")
    def _block_append_only_changes(session, _ctx, _instances):
        for obj in list(session.dirty) + list(session.deleted):
            if isinstance(obj, protected) and (
                obj in session.deleted or session.is_modified(obj, include_collections=False)
            ):
                raise AppendOnlyViolation(f"{type(obj).__tablename__} is append-only")


_register_orm_guard()
