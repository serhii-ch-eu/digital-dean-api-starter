"""The actual app: early rejection, log evidence and retained security controls."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
from types import SimpleNamespace
import pytest
from app.db.connection import open_database
from app.practice07.events import canonical_request_id
from app.practice07.context import CURRENT, new_request_context
from app.practice08.middleware import LoginThrottleMiddleware, LIMIT_DETAIL
from app.practice08.integration import install_practice08
from app.practice08.limiter import FixedWindowLimiter
from app.practice08.settings import LimitSettings, LOGIN_PATH
from tests.practice08_support import (
    p08_lab, p07_lab, p07_db, p06_seed, p06_settings,
    ManualClock, auth, login, events, rows, PASSWORD,
)


def exhaust(lab):
    for _ in range(2):
        assert login(lab, "absent", "wrong").status_code == 401


def test_429_contract_and_recovery(p08_lab):
    lab = p08_lab; exhaust(lab)
    result = login(lab)
    assert result.status_code == 429 and result.json() == {"detail": LIMIT_DETAIL}
    assert result.headers["Retry-After"] == "10"
    assert result.headers["Cache-Control"] == "no-store"
    assert "WWW-Authenticate" not in result.headers
    assert canonical_request_id(result.headers["X-Request-ID"])
    lab.clock.advance(10)
    assert login(lab).status_code == 200


def test_success_and_invalid_json_both_consume_slots(p08_lab):
    lab = p08_lab
    assert login(lab).status_code == 200
    assert lab.client.post(LOGIN_PATH, content="{").status_code == 422
    assert login(lab).status_code == 429


def test_health_protected_access_and_other_methods_do_not_consume(p08_lab):
    lab = p08_lab; token = auth(lab)
    for _ in range(4):
        assert lab.client.get("/health").status_code == 200
        assert lab.client.get("/api/v1/auth/me", headers=token).status_code == 200
        assert lab.client.get(LOGIN_PATH).status_code == 405
    assert login(lab).status_code == 200
    assert login(lab).status_code == 429


def test_headers_and_alternate_login_do_not_create_quota(p08_lab):
    lab = p08_lab; exhaust(lab)
    result = login(lab, "another", headers={
        "X-Forwarded-For": "203.0.113.99", "Forwarded": "for=203.0.113.100",
        "X-Request-ID": "CLIENT_SECRET_REQUEST_ID",
    })
    assert result.status_code == 429
    assert result.headers["X-Request-ID"] != "CLIENT_SECRET_REQUEST_ID"


def test_logs_correlate_without_fake_authentication(p08_lab):
    lab = p08_lab; exhaust(lab)
    result = login(lab, "SECRET_LOGIN_08", "SECRET_PASSWORD_08",
                   headers={"Authorization": "Bearer SECRET_TOKEN_08"})
    found = [e for e in events(lab.prior[4])
             if e["request_id"] == result.headers["X-Request-ID"]]
    assert len([e for e in found if e["event"] == "auth.login_limited"]) == 1
    assert len([e for e in found if e["event"] == "http.completed"]) == 1
    assert all(e["route"] == LOGIN_PATH and e["status"] == 429 for e in found)
    assert all(e["actor_id"] is e["role"] is e["session_ref"] is None for e in found)
    assert not any(e["event"] in {"auth.login_failed", "auth.token_issued"} for e in found)
    assert not any(value in lab.prior[4].read_text() for value in
                   ("SECRET_LOGIN_08", "SECRET_PASSWORD_08", "SECRET_TOKEN_08"))
    assert CURRENT.get() is None


def test_no_user_status_or_grade_history_changes_on_rejection(p08_lab):
    lab = p08_lab
    with open_database(lab.prior[1]) as con:
        before = con.execute('SELECT id,status_id FROM "user" ORDER BY id').fetchall()
    exhaust(lab)
    assert login(lab).status_code == 429
    with open_database(lab.prior[1]) as con:
        assert con.execute('SELECT id,status_id FROM "user" ORDER BY id').fetchall() == before
    assert rows(lab.prior[1]) == []


def test_parallel_http_does_not_overadmit(p08_lab):
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: login(p08_lab, "missing", "wrong"), range(8)))
    assert sorted(r.status_code for r in results) == [401, 401] + [429]*6
    assert len({r.headers["X-Request-ID"] for r in results}) == 8


def test_denial_reads_no_body_or_downstream():
    from app.practice08.events import register_limit_event
    register_limit_event()
    limiter = FixedWindowLimiter(LimitSettings(1, 10), ManualClock())
    assert limiter.admit().allowed
    async def forbidden(*args):
        raise AssertionError("body or downstream was accessed")
    class Sink:
        def __init__(self): self.items = []
        def emit(self, event): self.items.append(event); return True
    context = new_request_context(); context.sink = Sink()
    marker = CURRENT.set(context); messages = []
    async def send(message): messages.append(message)
    scope = dict(type="http", path=LOGIN_PATH, method="POST", headers=[])
    try:
        asyncio.run(LoginThrottleMiddleware(forbidden, lambda: limiter)(scope, forbidden, send))
    finally:
        CURRENT.reset(marker)
    assert messages[0]["status"] == 429
    assert len(context.sink.items) == 1


def test_non_http_scope_is_unchanged():
    seen = []
    async def downstream(scope, receive, send): seen.append(scope)
    def forbidden(): raise AssertionError("non-HTTP admission")
    scope = {"type": "lifespan"}
    asyncio.run(LoginThrottleMiddleware(downstream, forbidden)(scope, None, None))
    assert seen == [scope]


def test_catalog_and_21_operations_remain(p08_lab):
    schema = p08_lab.client.get("/openapi.json").json()
    assert schema["info"]["version"] == "0.8.0"
    operations = [(p, m) for p, v in schema["paths"].items()
                  for m in v if m in {"get", "post", "put", "patch", "delete"}]
    assert len(operations) == 21
    assert "429" in schema["paths"][LOGIN_PATH]["post"]["responses"]
    for route in ("/api/v1/students", "/api/v1/audit", "/api/v1/auth/reset-limit"):
        assert p08_lab.client.get(route).status_code == 404


def test_duplicate_install_does_not_change_state(p08_lab):
    lab = p08_lab; old = lab.app.state.practice08_limiter
    with pytest.raises(RuntimeError): install_practice08(lab.app)
    assert lab.app.state.practice08_limiter is old


@pytest.mark.parametrize("role,target,expected", [
    ("admin", "student_a", 403), ("manager", "student_a", 403),
    ("student_a", "student_a", 403), ("teacher_a", "student_b", 404),
])
def test_previous_rbac_and_authorship_survive(p08_lab, role, target, expected):
    lab = p08_lab
    result = lab.client.patch(
        f'/api/v1/courses/11/grades/{lab.prior[2][target]}',
        headers=auth(lab, role), json={"grade": 99},
    )
    assert result.status_code == expected and rows(lab.prior[1]) == []


def test_grade_audit_survives_and_422_has_no_write(p08_lab):
    lab = p08_lab; token = auth(lab)
    url = f'/api/v1/courses/11/grades/{lab.prior[2]["student_a"]}'
    rejected = lab.client.patch(url, headers=token, json={"grade": 99, "teacher_id": 1})
    assert rejected.status_code == 422 and rows(lab.prior[1]) == []
    accepted = lab.client.patch(url, headers=token, json={"grade": 81})
    history = rows(lab.prior[1])
    assert accepted.status_code == 200 and len(history) == 1
    assert history[0]["actor_id"] == lab.prior[2]["teacher_a"]
    assert history[0]["request_id"] == accepted.headers["X-Request-ID"]


def test_limited_login_does_not_disable_old_token(p08_lab):
    lab = p08_lab; token = auth(lab)
    assert login(lab, "absent", "wrong").status_code == 401
    assert login(lab).status_code == 429
    assert lab.client.get("/api/v1/auth/me", headers=token).status_code == 200
    assert lab.client.get("/api/v1/auth/me", headers={"Authorization": "Bearer forged"}).status_code == 401
