"""Provided isolated fixtures; tests exercise the student's actual existing app."""
from dataclasses import dataclass
from threading import RLock
import pytest
from app.practice08.limiter import FixedWindowLimiter
from app.practice08.settings import LimitSettings, LOGIN_PATH
from tests.practice07_support import (
    p07_lab, p07_db, p06_seed, p06_settings, PASSWORD, events, rows,
)


class ManualClock:
    def __init__(self, value=0.0):
        self.value, self.lock = float(value), RLock()

    def __call__(self):
        with self.lock:
            return self.value

    def advance(self, seconds):
        if type(seconds) not in (int, float) or seconds < 0:
            raise ValueError("nonnegative advance required")
        with self.lock:
            self.value += seconds


@dataclass
class Lab:
    prior: tuple
    app: object
    clock: ManualClock
    limiter: FixedWindowLimiter

    @property
    def client(self):
        return self.prior[0]


@pytest.fixture
def p08_lab(p07_lab):
    from app.main import app
    assert getattr(app.state, "practice08_installed", False), "integrate the actual P7 app"
    previous = app.state.practice08_limiter
    clock = ManualClock()
    limiter = FixedWindowLimiter(LimitSettings(2, 10), clock)
    app.state.practice08_limiter = limiter
    try:
        yield Lab(p07_lab, app, clock, limiter)
    finally:
        app.state.practice08_limiter = previous


def login(lab, name="teacher_a", password=PASSWORD, **kwargs):
    return lab.client.post(LOGIN_PATH, json={"login": name, "password": password}, **kwargs)


def auth(lab, name="teacher_a"):
    result = login(lab, name)
    assert result.status_code == 200, result.text
    return {"Authorization": "Bearer " + result.json()["access_token"]}
