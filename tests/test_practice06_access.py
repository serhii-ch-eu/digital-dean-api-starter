"""Positive/negative HTTP and object-level policy acceptance tests."""
import sqlite3
import pytest
from app.db.connection import open_database, write_transaction
from app.practice06.models import Role
from tests.practice06_support import p06_settings, p06_seed, p06_lab, headers, PASSWORD


@pytest.mark.parametrize("login", ["admin","manager","teacher_a","student_a"])
def test_login_and_safe_me(p06_lab, login):
    h = headers(p06_lab,login); r = p06_lab[0].get("/api/v1/auth/me",headers=h)
    assert r.status_code == 200
    assert set(r.json()) == {"id","login","role","status_id"}
    assert r.json()["id"] == p06_lab[2][login]


@pytest.mark.parametrize("login,password", [("missing","wrong"),("admin","wrong")])
def test_wrong_credentials_generic(p06_lab, login, password):
    r = p06_lab[0].post("/api/v1/auth/login",json={"login":login,"password":password})
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer"
    assert r.json() == {"detail":"authentication required"}


@pytest.mark.parametrize("auth", [None,"Basic xyz","Bearer bad.token.value"])
def test_missing_or_invalid_bearer(p06_lab, auth):
    r = p06_lab[0].get("/api/v1/courses",headers={} if auth is None else {"Authorization":auth})
    assert r.status_code == 401 and r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.parametrize("login,expected", [("admin",403),("manager",200),
    ("teacher_a",200),("student_a",200)])
def test_course_visibility_by_role(p06_lab, login, expected):
    r = p06_lab[0].get("/api/v1/courses",headers=headers(p06_lab,login))
    assert r.status_code == expected
    if login in {"teacher_a","student_a"}: assert [x["id"] for x in r.json()] == [11]
    if login == "manager": assert [x["id"] for x in r.json()] == [11,12,13]


@pytest.mark.parametrize("login", ["manager","teacher_a","student_a"])
def test_user_management_denied_outside_admin(p06_lab, login):
    assert p06_lab[0].get("/api/v1/users",headers=headers(p06_lab,login)).status_code == 403


def test_admin_registration_and_no_privilege_fields(p06_lab):
    client, _, ids, _ = p06_lab; h = headers(p06_lab,"admin")
    data = dict(name="New synthetic",email="new@example.com",login="new_student",password=PASSWORD)
    r = client.post("/api/v1/users",headers=h,json=data)
    assert r.status_code == 201 and r.json()["status_id"] == 0
    assert set(r.json()) == {"id","name","email","login","status_id"}
    assert client.post("/api/v1/users",headers=h,json=data).status_code == 409
    data["role_id"] = 1
    r = client.post("/api/v1/users",headers=h,json=data)
    assert r.status_code == 422 and PASSWORD not in r.text and '"input"' not in r.text
    target = r.json()  # only sanitized error content, no returned input values
    assert isinstance(target,dict)


def test_block_and_unblock_current_state(p06_lab):
    client, path, ids, _ = p06_lab
    student = headers(p06_lab,"student_a"); admin = headers(p06_lab,"admin")
    with open_database(path) as con:
        old = tuple(con.execute('SELECT password,salt FROM "user" WHERE id=?',(ids["student_a"],)).fetchone())
    url = f'/api/v1/users/{ids["student_a"]}/block'
    assert client.patch(url,headers=admin).status_code == 200
    assert client.patch(url,headers=admin).status_code == 200
    assert client.get("/api/v1/me/grades",headers=student).status_code == 401
    assert client.post("/api/v1/auth/login",json={"login":"student_a","password":PASSWORD}).status_code == 401
    assert client.patch(f'/api/v1/users/{ids["student_a"]}/status',headers=admin,
                        json={"status_id":1}).status_code == 200
    assert client.get("/api/v1/me/grades",headers=student).status_code == 200
    with open_database(path) as con:
        assert tuple(con.execute('SELECT password,salt FROM "user" WHERE id=?',(ids["student_a"],)).fetchone()) == old


def test_no_role_has_no_protected_access(p06_lab):
    h = headers(p06_lab,"no_role")
    assert p06_lab[0].get("/api/v1/auth/me",headers=h).status_code == 403


def test_role_changes_are_not_cached_in_token(p06_lab):
    client,path,ids,_ = p06_lab; h = headers(p06_lab,"manager")
    assert client.get("/api/v1/courses",headers=h).status_code == 200
    with open_database(path) as con, write_transaction(con):
        con.execute("UPDATE user_role SET role_id=1 WHERE user_id=?",(ids["manager"],))
    assert client.get("/api/v1/courses",headers=h).status_code == 403
    assert client.get("/api/v1/users",headers=h).status_code == 200


def test_current_course_assignment(p06_lab):
    client,_,ids,_ = p06_lab; teacher=headers(p06_lab,"teacher_a")
    assert client.get("/api/v1/courses/12",headers=teacher).status_code == 404
    assert client.get("/api/v1/courses/11/grades",headers=teacher).status_code == 200
    assert client.delete(f'/api/v1/courses/11/teachers/{ids["teacher_a"]}',
                         headers=headers(p06_lab,"manager")).status_code == 204
    assert client.get("/api/v1/courses/11/grades",headers=teacher).status_code == 404


def test_teacher_sees_only_authored_grades(p06_lab):
    r = p06_lab[0].get("/api/v1/courses/11/grades",headers=headers(p06_lab,"teacher_a"))
    assert r.status_code == 200 and len(r.json()) == 1
    assert r.json()[0]["teacher_id"] == p06_lab[2]["teacher_a"]


def test_teacher_cannot_edit_other_author(p06_lab):
    client,_,ids,_ = p06_lab; h = headers(p06_lab,"teacher_a")
    r = client.patch(f'/api/v1/courses/11/grades/{ids["student_b"]}',headers=h,json={"grade":99})
    assert r.status_code == 404
    r = client.post("/api/v1/courses/11/grades",headers=h,
                    json={"student_id":ids["student_b"],"grade":99})
    assert r.status_code == 409


def test_teacher_enrolls_only_own_course_and_cannot_withdraw(p06_lab):
    client,_,ids,_ = p06_lab; h = headers(p06_lab,"teacher_a")
    own = f'/api/v1/courses/11/students/{ids["student_c"]}'
    assert client.put(own,headers=h).status_code == 200
    assert client.put(own,headers=h).status_code == 200
    assert client.delete(own,headers=h).status_code == 403
    assert client.put(f'/api/v1/courses/12/students/{ids["student_a"]}',headers=h).status_code == 404


def test_create_update_grade_derives_author(p06_lab):
    client,_,ids,_ = p06_lab; h = headers(p06_lab,"teacher_a")
    assert client.put(f'/api/v1/courses/11/students/{ids["student_c"]}',headers=h).status_code == 200
    r = client.post("/api/v1/courses/11/grades",headers=h,
                    json={"student_id":ids["student_c"],"grade":88})
    assert r.status_code == 201 and r.json()["teacher_id"] == ids["teacher_a"]
    r = client.patch(f'/api/v1/courses/11/grades/{ids["student_c"]}',headers=h,json={"grade":89})
    assert r.status_code == 200 and r.json()["grade"] == 89


@pytest.mark.parametrize("extra", ["teacher_id","role_id","is_admin"])
def test_client_privileged_fields_rejected(p06_lab, extra):
    client,_,ids,_ = p06_lab
    data = {"student_id":ids["student_c"],"grade":88,extra:ids["teacher_b"]}
    assert client.post("/api/v1/courses/11/grades",headers=headers(p06_lab,"teacher_a"),
                       json=data).status_code == 422


@pytest.mark.parametrize("value", [-1,101,True,99.5,"99",None])
def test_strict_grade_range(p06_lab, value):
    client,_,ids,_ = p06_lab
    assert client.patch(f'/api/v1/courses/11/grades/{ids["student_a"]}',
        headers=headers(p06_lab,"teacher_a"),json={"grade":value}).status_code == 422


def test_unenrolled_grade_target_denied(p06_lab):
    client,_,ids,_ = p06_lab
    r = client.post("/api/v1/courses/11/grades",headers=headers(p06_lab,"teacher_a"),
                    json={"student_id":ids["student_c"],"grade":88})
    assert r.status_code == 409


def test_manager_can_read_but_not_write_grades(p06_lab):
    client,_,ids,_ = p06_lab; h = headers(p06_lab,"manager")
    r = client.get("/api/v1/courses/11/grades",headers=h)
    assert r.status_code == 200 and len(r.json()) == 2
    assert client.patch(f'/api/v1/courses/11/grades/{ids["student_a"]}',headers=h,
                        json={"grade":99}).status_code == 403


def test_student_personal_historical_grades(p06_lab):
    client,_,ids,_ = p06_lab; student=headers(p06_lab,"student_a")
    r = client.get("/api/v1/me/grades",headers=student)
    assert r.status_code == 200 and all(x["student_id"] == ids["student_a"] for x in r.json())
    assert client.get("/api/v1/courses/11/grades",headers=student).status_code == 403
    assert client.delete(f'/api/v1/courses/11/students/{ids["student_a"]}',
                         headers=headers(p06_lab,"manager")).status_code == 204
    assert client.get("/api/v1/courses",headers=student).json() == []
    assert client.get("/api/v1/me/grades",headers=student).json() == r.json()


def test_course_delete_conflict_preserves_everything(p06_lab):
    client,path,_,_ = p06_lab; h = headers(p06_lab,"manager")
    assert client.delete("/api/v1/courses/11",headers=h).status_code == 409
    with open_database(path) as con:
        assert con.execute("SELECT count(*) FROM course_student WHERE course_id=11").fetchone()[0] == 2
        assert con.execute("SELECT count(*) FROM course_teacher WHERE course_id=11").fetchone()[0] == 2
        assert con.execute("SELECT count(*) FROM grade WHERE course_id=11").fetchone()[0] == 2


def test_course_crud_and_target_roles(p06_lab):
    client,_,ids,_ = p06_lab; h = headers(p06_lab,"manager")
    r = client.post("/api/v1/courses",headers=h,json={"name":"New course"})
    assert r.status_code == 201; course=r.json()["id"]
    assert client.patch(f"/api/v1/courses/{course}",headers=h,json={"name":"Renamed"}).status_code == 200
    assert client.put(f'/api/v1/courses/{course}/teachers/{ids["student_a"]}',headers=h).status_code == 409
    assert client.put(f'/api/v1/courses/{course}/teachers/{ids["teacher_a"]}',headers=h).status_code == 200
    assert client.put(f'/api/v1/courses/{course}/students/{ids["student_a"]}',headers=h).status_code == 200
    r = client.delete(f"/api/v1/courses/{course}",headers=h)
    assert r.status_code == 204 and r.content == b""
    assert client.get(f"/api/v1/courses/{course}",headers=h).status_code == 404


def test_no_legacy_bypass_or_user_delete(p06_lab):
    client,_,ids,_ = p06_lab; h = headers(p06_lab,"admin")
    assert client.delete(f'/api/v1/users/{ids["student_a"]}',headers=h).status_code in {404,405}
    for path in ("/api/v1/students","/api/v1/crypto/hash-benchmark-results",
                 "/api/v1/hash-benchmark-results"):
        assert client.get(path).status_code == 404
    schema = client.get("/openapi.json").json()
    assert schema["info"]["version"] == "0.6.0"
    assert schema["paths"]["/api/v1/courses"]["get"]["security"]
    assert client.get("/health").json() == {"status":"ok"}
