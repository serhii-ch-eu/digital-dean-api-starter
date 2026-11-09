"""Provided strict local demonstration policy, not a universal security standard."""
from dataclasses import dataclass
import os
import re

LOGIN_PATH = "/api/v1/auth/login"


@dataclass(frozen=True)
class LimitSettings:
    max_attempts: int = 5
    window_seconds: int = 60

    def __post_init__(self):
        for value, upper in ((self.max_attempts, 1000), (self.window_seconds, 3600)):
            if type(value) is not int or not 1 <= value <= upper:
                raise ValueError("invalid local admission policy")


def get_limit_settings() -> LimitSettings:
    def read(name, default):
        value = os.environ.get(name, str(default))
        if re.fullmatch(r"[1-9][0-9]*", value) is None or len(value) > 4:
            raise ValueError("invalid local admission configuration")
        return int(value)
    return LimitSettings(read("DEAN_LOGIN_MAX_ATTEMPTS", 5),
                         read("DEAN_LOGIN_WINDOW_SECONDS", 60))
