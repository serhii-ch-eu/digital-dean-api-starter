"""Fixed local JWT profile; never provide a default signing secret."""
from dataclasses import dataclass, field
from functools import lru_cache
import os
import re

ISSUER = "digital-dean-api"
AUDIENCE = "digital-dean-api:access"
LIFETIME_SECONDS = 900
MAX_TOKEN_CHARS = 4096


@dataclass(frozen=True)
class SecuritySettings:
    key: bytes = field(repr=False)
    issuer: str = ISSUER
    audience: str = AUDIENCE

    def __post_init__(self):
        if type(self.key) is not bytes or not 32 <= len(self.key) <= 128:
            raise ValueError("JWT key must contain 32..128 bytes")
        if self.issuer != ISSUER or self.audience != AUDIENCE:
            raise ValueError("unsupported local JWT profile")


@lru_cache(maxsize=1)
def get_settings() -> SecuritySettings:
    value = os.environ.get("DEAN_JWT_SECRET_HEX", "")
    if not re.fullmatch(r"(?:[0-9a-f]{2}){32,128}", value):
        raise ValueError("set DEAN_JWT_SECRET_HEX to a locally generated random key")
    return SecuritySettings(bytes.fromhex(value))
