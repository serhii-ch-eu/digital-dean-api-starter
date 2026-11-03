"""Working isolated JWT example. No server, DB, persistent key or token output."""
from datetime import datetime, timezone
import secrets
import jwt


def main():
    # Ephemeral example key, NOT the application's configuration or a password.
    key = secrets.token_bytes(32)
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {"sub": "7", "iss": "digital-dean-api", "aud": "digital-dean-api:access",
              "iat": now, "nbf": now, "exp": now + 900,
              "jti": secrets.token_hex(16), "token_use": "access"}
    token = jwt.encode(claims, key, algorithm="HS256", headers={"typ": "JWT"})
    checked = jwt.decode(token, key, algorithms=["HS256"],
        issuer="digital-dean-api", audience="digital-dean-api:access",
        options={"require": list(claims), "strict_aud": True})
    assert checked == claims
    # This example demonstrates library verification, NOT the full local codec
    # profile, current DB status, single-role enforcement or course ownership.
    try:
        jwt.decode(token, secrets.token_bytes(32), algorithms=["HS256"],
                   issuer="digital-dean-api", audience="digital-dean-api:access")
    except jwt.InvalidTokenError:
        pass
    else:
        raise AssertionError("wrong key must fail")
    print("JWT example passed; no tokens or keys printed")


if __name__ == "__main__":
    main()
