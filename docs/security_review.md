# Secure Coding 검토 결과 (Phase 9)

- 검토일: 2026-09-28
- 대상: `app/`, `scripts/` (Python 5.3천 행), 템플릿, 설정, 의존성
- 방법: 정적 분석(Bandit), 의존성 취약점 조회(pip-audit), 위험 패턴 전수 검색, 수동 코드 검토, 자동화 테스트

## 1. 도구 결과

| 도구 | 버전 | 결과 |
|---|---|---|
| Bandit (`bandit -r app scripts`) | 1.9.4 | 최초 Low 4건 → **0건**. `assert` 사용 2건은 명시적 예외로 교체, B105 2건은 오탐(정규식 상수·점수 규칙명)으로 사유 주석 `# nosec B105` 처리 |
| pip-audit (`pip-audit -r requirements.txt`) | 2.10.1 | **알려진 취약점 없음** (조회 시점 기준) |
| 위험 패턴 검색 | — | 동적 SQL 조합·`\|safe`·`Markup`·`innerHTML`·`eval/exec`·`yaml.load`·`pickle/subprocess`·`verify=False`·하드코딩 Secret **0건**. `exec_driver_sql` 은 고정 DDL(Trigger) 상수만 실행 |

위험 패턴 검색은 `tests/security/test_hardening.py::test_forbidden_patterns_absent` 로 자동화하여, 이후 코드 변경 시 회귀를 막는다.

## 2. 이번 Phase에서 보완한 사항

| # | 발견 내용 | 위험 | 조치 | 테스트 |
|---|---|---|---|---|
| 1 | `Content-Length` 없는 POST(chunked 전송)는 폼 크기 제한을 우회 가능 | 메모리/디스크 고갈(DoS) | 모든 POST에 `Content-Length` 필수(411), 초과 시 413 | `test_post_without_content_length_rejected`, `test_large_form_rejected` |
| 2 | 계정 잠금은 계정 단위라 여러 계정에 대한 대입 공격(Password spraying)에는 효과 제한 | 무차별 대입 | IP 단위 실패 제한(10분 20회, 초과 시 429) + 감사로그 `rate_limited` | `test_ip_rate_limit_blocks_even_correct_password`, `test_rate_limiter_window_and_reset` |
| 3 | 로그인 실패 감사로그에 공격자 입력 사용자명이 그대로 저장 | 로그 위조(제어문자/방향 전환 문자) | `clean_text` 로 제어문자 제거·길이 제한 | `test_failed_login_username_sanitized_in_audit` |
| 4 | HSTS 헤더 없음 | 운영 HTTPS 다운그레이드 | `APP_ENV=prod` 에서 `Strict-Transport-Security` 추가 | `test_hsts_only_in_prod` |
| 5 | `assert` 로 상태 검증 (`python -O` 시 제거됨) | 검증 누락 | 명시적 `RuntimeError` | Bandit 0건 |

## 3. Secure Coding Checklist 결과

| 분류 | 요구 | 구현 | 검증 테스트 |
|---|---|---|---|
| File Upload | `.xlsx`만 허용, `.xls/.xlsm/.exe/.js/.html/zip` 거부 | 확장자 allowlist + ZIP 서명 + OOXML Content-Type(매크로·VBA·ActiveX·외부연결·포함개체 거부) | `tests/security/test_upload.py` (28건) |
| | 단순 확장자 검사 금지 | 서명·구조·XML(defusedxml) 검증, Zip bomb(총 해제크기·압축비), 내부 경로 조작 검사 | `test_zip_bomb_rejected`, `test_xxe_rejected`, `test_xml_entity_expansion_rejected` |
| | 크기 제한 | 기본 5MB + 요청 본문 제한 | `test_size_limit_and_empty`, `test_oversized_request_rejected` |
| | 원본 파일명 미사용 / Path Traversal 방지 / Web Root 밖 저장 | UUID 파일명, 경로 검증, `data/uploads` (static 외부), 덮어쓰기 금지 | `test_path_traversal_filename_cannot_escape_upload_dir`, `test_display_name_sanitized` |
| Input Validation | Server side, allowlist | Pydantic/전용 검증기, Enum allowlist(자산구분·중요도·상태·역할) | `test_invalid_rows_rejected_without_db_change`, `test_invalid_query_params_do_not_error` |
| | IP / CVE / CVSS / EPSS 형식·범위 | `ipaddress`, 정규식, 0–10 / 0–1, NaN·Inf 거부 + DB CHECK 제약 | `test_invalid_ip`, `test_invalid_cve_id`, `test_invalid_cvss`, `test_invalid_epss`, `test_cvss_and_epss_range_check` |
| SQL Injection | ORM / 바인드 파라미터만 | SQLAlchemy ORM, LIKE 검색은 `autoescape=True` | `test_sql_injection_in_search_is_harmless` |
| XSS | 외부 CVE 설명·Excel 값 비신뢰 | Jinja2 autoescape, `\|safe` 미사용, JS 미사용, CSP `script-src 'self'`(인라인 금지) | `test_xss_from_excel_and_cve_description_is_escaped`, `test_forbidden_patterns_absent` |
| CSRF | — | Synchronizer Token(모든 POST, 로그인 포함) + `SameSite=Strict` | `test_status_change_requires_csrf`, `test_login_without_csrf_rejected` |
| SSRF | 사용자 URL 요청 금지, Endpoint Allowlist | `app/config/endpoints.py` 상수만, 요청 직전 Host 재검증, Redirect는 Allowlist 대상만 최대 3회 | `test_ssrf_allowlist`, `test_http_client_blocks_non_allowlisted_destination`, `test_redirect_followed_only_to_allowlisted_host` |
| Secrets | 소스 미포함, `.env` 제외, 로그 미기록 | `.env`(gitignore) + `.env.example`, `SecretStr`, 로그 Redaction 필터, API Key는 헤더로만 | `test_env_not_tracked_and_example_has_no_secret`, `test_log_redaction`, `test_nvd_non_retryable_error_raises_without_secret` |
| Authentication | 인증 구조, 사내 인증 연동 대비 | `AuthProvider` 인터페이스(Local 구현), scrypt, 5회 실패 계정 잠금, IP 제한, 세션 유휴 만료, 로그인 시 세션 재생성 | `test_login_lockout`, `test_login_failure_audited_and_generic_message` |
| Authorization | Viewer / Operator / Administrator | 의존성 주입 RBAC, 권한은 매 요청 DB 기준 | `test_viewer_cannot_change_status`, `test_admin_pages_rbac`, `test_deactivated_user_loses_access` |
| Error Handling | Stack trace 비노출, 상세는 서버 로그 | 전역 예외 처리 → 오류 ID만 표시 | `test_no_stack_trace_exposed`, `test_404_page_has_no_internal_details` |
| Audit Log | 필수 이벤트 기록, 일반 사용자 수정·삭제 불가 | ORM Guard + DB Trigger + SHA-256 Hash chain, 수정·삭제 경로 없음 | `test_required_audit_events_recorded_and_immutable`, `test_audit_sql_update_and_delete_blocked`, `test_audit_tamper_detected` |
| Export | Formula Injection 방어 | `= + - @`·탭/CR/LF·전각 문자 → `'` 접두 + 문자열 타입 강제 | `tests/security/test_export.py`, `test_export_neutralizes_formula_injection_from_excel_and_nvd` |
| 외부 데이터 | 대용량/비정상 응답 | 스트리밍 크기 제한, Pydantic 스키마 검증, gzip 해제 상한, TLS 검증 유지(OS 저장소) | `test_oversized_response_rejected`, `test_nvd_invalid_schema_raises`, `test_ssl_context_verifies_certificates` |
| 보안 헤더 | — | CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, no-store, (prod) HSTS | `test_security_headers`, `test_hsts_only_in_prod` |

## 4. 요구사항 필수 테스트 대응표 (요구사항 §18)

| 요구 테스트 | 테스트 |
|---|---|
| CVSS 9.8 + EPSS 0.40 → 긴급 / 0.20 → 우선 / 0.05 → 주의, CVSS 7.5 → 주의, 6.9 → 관리대상 아님 | `tests/unit/test_policy.py::test_required_severity_cases` (+ 경계값 `test_boundaries`) |
| CPE Exact Match | `test_matching.py::test_cpe_exact_match`, `test_update_field_exact_match` |
| Version Range Match | `test_matching.py::test_version_range_match`, `test_version_range_vulnerable`, `test_in_range_boundaries` |
| Version Range 제외 | `test_matching.py::test_version_range_excluded`, `test_mapping_flow.py::test_patched_versions_not_mapped` |
| 잘못된 CPE | `test_cpe_and_validators.py::test_invalid_cpe`, `test_asset_import.py::test_import_sample`(MAIL-001) |
| CPE 없는 자산 | `test_mapping_flow.py::test_no_cpe_assets_never_auto_vulnerable`, `test_level2_candidates_created_with_rule_scores` |
| 중복 CVE 수집 | `test_collection.py::test_recollection_is_idempotent_and_preserves_initial_epss`, `test_schema.py::test_duplicate_cve_rejected` |
| EPSS 업데이트 | `test_collection.py::test_recollection_is_idempotent_and_preserves_initial_epss`, `test_older_epss_does_not_overwrite_current` |
| Initial EPSS 보존 | 위 테스트 + `test_schema.py::test_epss_initial_is_immutable_at_db_level`, `test_epss_missing_then_first_seen_becomes_initial` |
| 악성 Excel 업로드 | `tests/security/test_upload.py`, `test_asset_import.py::test_malicious_upload_rejected_and_audited`, `test_web.py::test_web_upload_rejects_malicious_and_viewer` |
| Formula Injection | `tests/security/test_export.py`, `test_export_web.py::test_export_neutralizes_formula_injection_from_excel_and_nvd`, `test_asset_import.py::test_formula_cell_rejected` |
| Path Traversal | `test_upload.py::test_path_traversal_filename_cannot_escape_upload_dir`, `test_zip_path_traversal_entry_rejected`, `test_display_name_sanitized` |
| 잘못된 CVE ID / CVSS / EPSS | `test_cpe_and_validators.py::test_invalid_cve_id` / `test_invalid_cvss` / `test_invalid_epss`, `test_schema.py::test_cvss_and_epss_range_check`, `test_normalize_rejected_and_invalid` |

전체 자동화 테스트: **368건 통과** (`python -m pytest`).

## 5. 잔여 위험 및 운영 전환 권고

| 항목 | 현재(PoC) | 운영 권고 |
|---|---|---|
| 인증 | 로컬 계정 + scrypt | `AuthProvider` 를 사내 SSO(SAML/OIDC)로 교체, MFA |
| 전송 구간 | `127.0.0.1` 바인딩, HTTP | 사내 인증서로 HTTPS(리버스 프록시) + `APP_ENV=prod`(Secure 쿠키·HSTS) |
| 로그인 IP 제한 | 프로세스 메모리 | 다중 인스턴스 시 공용 저장소(Redis 등) 또는 WAF |
| 클라이언트 IP | 직접 접속 IP | 리버스 프록시 사용 시 신뢰 프록시 설정 후 `X-Forwarded-For` 반영 |
| 감사로그 Hash chain | 단일 Writer(SQLite) 기준 | PostgreSQL 다중 Writer 시 advisory lock, 외부 로그(SIEM) 전송 |
| DB 파일 | SQLite 파일 | PostgreSQL 전환 + 계정 최소권한(`audit_logs` UPDATE/DELETE REVOKE) |
| Bundle 무결성 | SHA-256 + 선택적 HMAC | VDI 반입 시 `BUNDLE_HMAC_KEY` 필수 설정, 가능하면 전자서명 |
| 의존성 | 버전 고정 | 반입 전 `pip-audit` 재실행, 내부 패키지 저장소 사용 |
