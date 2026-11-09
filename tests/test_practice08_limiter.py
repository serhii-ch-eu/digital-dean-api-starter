"""Admission mathematics, atomicity and strict local configuration; no sleep."""
from concurrent.futures import ThreadPoolExecutor
import math
import pytest
from app.practice08.limiter import FixedWindowLimiter, Decision
from app.practice08.settings import LimitSettings, get_limit_settings
from app.practice08.events import register_limit_event, LIMIT_EVENT
from app.practice07.events import Event, EVENT_LEVELS
from tests.practice08_support import ManualClock


@pytest.mark.parametrize("count", [1, 2, 5])
def test_exact_threshold(count):
    limiter = FixedWindowLimiter(LimitSettings(count, 10), ManualClock())
    assert all(limiter.admit() == Decision(True) for _ in range(count))
    assert limiter.admit() == Decision(False, 10)


def test_first_call_not_object_creation_starts_window():
    clock = ManualClock(); limiter = FixedWindowLimiter(LimitSettings(1, 10), clock)
    clock.advance(100)
    assert limiter.admit().allowed
    assert limiter.admit().retry_after == 10


def test_boundary_rounding_and_denial_does_not_extend():
    clock = ManualClock(); limiter = FixedWindowLimiter(LimitSettings(1, 10), clock)
    assert limiter.admit().allowed
    clock.advance(9.1)
    assert limiter.admit() == Decision(False, 1)
    clock.advance(0.9)
    assert limiter.admit() == Decision(True)
    assert limiter.admit() == Decision(False, 10)


def test_long_idle_renews_only_once():
    clock = ManualClock(); limiter = FixedWindowLimiter(LimitSettings(2, 10), clock)
    assert limiter.admit().allowed
    clock.advance(1000)
    assert [limiter.admit().allowed for _ in range(3)] == [True, True, False]


def test_instances_do_not_share_state():
    clock = ManualClock()
    first = FixedWindowLimiter(LimitSettings(1, 10), clock)
    second = FixedWindowLimiter(LimitSettings(1, 10), clock)
    assert first.admit().allowed and not first.admit().allowed
    assert second.admit().allowed


def test_parallel_admission_exactly_n():
    limiter = FixedWindowLimiter(LimitSettings(3, 10), ManualClock())
    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(lambda _: limiter.admit(), range(24)))
    assert sum(d.allowed for d in decisions) == 3
    assert all(d.retry_after == 10 for d in decisions if not d.allowed)


@pytest.mark.parametrize("maximum,window", [
    (0, 60), (-1, 60), (1001, 60), (True, 60), (1.0, 60),
    (5, 0), (5, 3601), (5, False), (5, "60"),
])
def test_policy_rejects_invalid_types_and_bounds(maximum, window):
    with pytest.raises(ValueError):
        LimitSettings(maximum, window)


@pytest.mark.parametrize("value", ["0", "-1", "5.0", " 5", "05", "NaN", "1001"])
def test_environment_is_strict(monkeypatch, value):
    monkeypatch.setenv("DEAN_LOGIN_MAX_ATTEMPTS", value)
    with pytest.raises(ValueError):
        get_limit_settings()


def test_environment_defaults_and_valid_override(monkeypatch):
    for key in ("DEAN_LOGIN_MAX_ATTEMPTS", "DEAN_LOGIN_WINDOW_SECONDS"):
        monkeypatch.delenv(key, raising=False)
    assert get_limit_settings() == LimitSettings(5, 60)
    monkeypatch.setenv("DEAN_LOGIN_MAX_ATTEMPTS", "7")
    monkeypatch.setenv("DEAN_LOGIN_WINDOW_SECONDS", "20")
    assert get_limit_settings() == LimitSettings(7, 20)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1, True, "1"])
def test_bad_clock_is_not_a_reset(value):
    limiter = FixedWindowLimiter(LimitSettings(1, 10), lambda: value)
    with pytest.raises(ValueError):
        limiter.admit()


def test_backward_clock_does_not_grant_new_quota():
    clock = ManualClock(10); limiter = FixedWindowLimiter(LimitSettings(1, 10), clock)
    assert limiter.admit().allowed
    clock.value = 9
    with pytest.raises(ValueError):
        limiter.admit()
    clock.value = 10
    assert not limiter.admit().allowed


def test_catalog_extension_preserves_validation():
    before = dict(EVENT_LEVELS)
    register_limit_event(); register_limit_event()
    assert EVENT_LEVELS[LIMIT_EVENT] == "WARNING"
    assert all(EVENT_LEVELS[key] == level for key, level in before.items())
    assert Event(LIMIT_EVENT, "denied").actor_id is None
    with pytest.raises(ValueError):
        Event("unapproved.event", "denied")


def test_catalog_conflict_is_not_silently_replaced(monkeypatch):
    monkeypatch.setitem(EVENT_LEVELS, LIMIT_EVENT, "INFO")
    with pytest.raises(RuntimeError):
        register_limit_event()
    assert EVENT_LEVELS[LIMIT_EVENT] == "INFO"
