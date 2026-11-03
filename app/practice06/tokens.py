"""Student JWT codec. See the working isolated example, not an auth server."""
from .config import SecuritySettings

REQUIRED = ("sub", "iss", "aud", "iat", "nbf", "exp", "jti", "token_use")


class BadToken(ValueError):
    """Never expose the original library error or token to HTTP clients."""


def issue_access_token(user_id: int, settings: SecuritySettings) -> str:
    """HS256; typ JWT; sub canonical positive decimal string; UTC integer dates.

    iat=nbf=now, exp=now+900, random 32-lowercase-hex jti, token_use=access.
    Only REQUIRED payload fields, fixed issuer/audience, no password or role.
    """
    raise NotImplementedError("TODO: issue bounded-profile access token")


def read_access_token(token: str, settings: SecuritySettings) -> int:
    """Return verified user id or raise BadToken.

    Max4096 chars; only HS256, typ JWT and no other header keys. Verify MAC,
    required claims and fixed issuer/audience. Strict integer NumericDates,
    iat=nbf, exp-iat=900, no leeway. Canonical sub in SQLite positive-id range,
    jti exactly32 lowercase hex and token_use=access. Reject extra claims.
    Never select key/algorithm from untrusted header or disable verification.
    """
    raise NotImplementedError("TODO: cryptographic and semantic validation")
