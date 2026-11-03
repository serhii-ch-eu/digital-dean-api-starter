"""Codec/profile and complete coarse permission-matrix acceptance tests."""
from datetime import datetime, timezone
import secrets
import jwt
import pytest
from app.practice06.config import SecuritySettings, get_settings
from app.practice06.models import Role
from app.practice06.policy import Action, ROLE_ACTIONS, role_allows
from app.practice06.tokens import REQUIRED, BadToken, issue_access_token, read_access_token


def claims():
    now = int(datetime.now(timezone.utc).timestamp())
    return dict(sub="7", iss="digital-dean-api", aud="digital-dean-api:access",
                iat=now, nbf=now, exp=now+900, jti=secrets.token_hex(16), token_use="access")


def test_round_trip_and_minimal_claims():
    settings = SecuritySettings(secrets.token_bytes(32))
    token = issue_access_token(7, settings)
    assert read_access_token(token, settings) == 7
    payload = jwt.decode(token, settings.key, algorithms=["HS256"],
                         issuer=settings.issuer, audience=settings.audience)
    assert set(payload) == set(REQUIRED)
    assert payload["sub"] == "7" and payload["token_use"] == "access"
    assert payload["iat"] == payload["nbf"] and payload["exp"]-payload["iat"] == 900
    assert len(payload["jti"]) == 32
    assert jwt.get_unverified_header(token) == {"alg":"HS256","typ":"JWT"}
    assert issue_access_token(7, settings) != token


@pytest.mark.parametrize("field", REQUIRED)
def test_missing_claim_rejected(field):
    settings = SecuritySettings(secrets.token_bytes(32)); data = claims(); data.pop(field)
    token = jwt.encode(data, settings.key, algorithm="HS256")
    with pytest.raises(BadToken): read_access_token(token, settings)


@pytest.mark.parametrize("field,value", [
    ("sub",7),("sub","0"),("sub","07"),("sub","-1"),("sub","9223372036854775808"),
    ("iss","other"),("aud","other"),("aud",["digital-dean-api:access"]),
    ("token_use","refresh"),("iat",True),("iat",1.5),("jti","bad"),
    ("exp",0),("exp","9999999999"),("nbf",9999999999),
])
def test_invalid_claim_rejected(field, value):
    settings = SecuritySettings(secrets.token_bytes(32)); data = claims(); data[field] = value
    token = jwt.encode(data, settings.key, algorithm="HS256")
    with pytest.raises(BadToken): read_access_token(token, settings)


@pytest.mark.parametrize("mode", ["none","HS384","wrong-key","wrong-typ","kid",
    "extra-role","long-lifetime","different-nbf","expired","future"])
def test_token_substitution_and_profile(mode):
    settings = SecuritySettings(secrets.token_bytes(32)); data = claims()
    algorithm, key, head = "HS256", settings.key, {"typ":"JWT"}
    if mode == "none": algorithm, key = "none", None
    elif mode == "HS384": algorithm, key = "HS384", secrets.token_bytes(64)
    elif mode == "wrong-key": key = secrets.token_bytes(32)
    elif mode == "wrong-typ": head["typ"] = "refresh"
    elif mode == "kid": head["kid"] = "untrusted"
    elif mode == "extra-role": data["role"] = "admin"
    elif mode == "long-lifetime": data["exp"] += 1
    elif mode == "different-nbf": data["nbf"] -= 1
    elif mode == "expired":
        for f in ("iat","nbf","exp"): data[f] -= 1800
    elif mode == "future":
        for f in ("iat","nbf","exp"): data[f] += 1800
    token = jwt.encode(data, key, algorithm=algorithm, headers=head)
    with pytest.raises(BadToken): read_access_token(token, settings)


@pytest.mark.parametrize("token", ["", "not-a-token", "a.b.c", "x"*4097],
                         ids=["empty","text","malformed","oversized"])
def test_bad_serialization_rejected(token):
    with pytest.raises(BadToken):
        read_access_token(token, SecuritySettings(secrets.token_bytes(32)))


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("action", list(Action))
def test_complete_role_matrix(role, action):
    assert role_allows(role, action) is (action in ROLE_ACTIONS[role])


def test_unknown_role_and_action_denied():
    assert role_allows("root", Action.COURSE_READ) is False
    assert role_allows(Role.ADMIN, "everything") is False


@pytest.mark.parametrize("value", [None,"","secret","00"*31,"zz"*32])
def test_missing_or_invalid_config(monkeypatch, value):
    get_settings.cache_clear()
    if value is None: monkeypatch.delenv("DEAN_JWT_SECRET_HEX", raising=False)
    else: monkeypatch.setenv("DEAN_JWT_SECRET_HEX", value)
    try:
        with pytest.raises(ValueError): get_settings()
    finally: get_settings.cache_clear()
