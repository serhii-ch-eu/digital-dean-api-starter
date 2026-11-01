"""Структура звіту; змістову перевірку validate_report реалізує студент."""
from datetime import datetime, timezone
from math import isclose, isfinite
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, StrictInt
from app.security.hashing.profiles import (AlgorithmID, CHECK_NAMES, PAYLOAD_SIZES,
                                           PROFILES, Mode)


def _exact_int(value):
    if type(value) is not int:
        raise ValueError("integer required; bool/float/string is not an integer")
    return value


Version = Annotated[Literal[1], BeforeValidator(_exact_int)]
Int5 = Annotated[Literal[5], BeforeValidator(_exact_int)]
Int10 = Annotated[Literal[10], BeforeValidator(_exact_int)]
Int100 = Annotated[Literal[100], BeforeValidator(_exact_int)]
Int1000 = Annotated[Literal[1000], BeforeValidator(_exact_int)]
Int1024 = Annotated[Literal[1024], BeforeValidator(_exact_int)]
Int16384 = Annotated[Literal[16384], BeforeValidator(_exact_int)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
NonnegativeInt = Annotated[StrictInt, Field(ge=0)]
Positive = Annotated[float, Field(gt=0)]
Nonnegative = Annotated[float, Field(ge=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)


class Parameters(StrictModel):
    sizes: list[PositiveInt] = Field(min_length=4, max_length=4)
    chunk_bytes: Int16384
    warmup: Int10
    series: Int5
    repeats_small: Int1000
    repeats_large: Int100
    avalanche_trials: Int100
    avalanche_bytes: Int1024


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=160)
    openssl_ssl: str = Field(min_length=1, max_length=160)
    os: str = Field(min_length=1, max_length=240)
    cpu: str = Field(min_length=1, max_length=160)
    architecture: str = Field(min_length=1, max_length=80)


class AlgorithmStatus(StrictModel):
    algorithm: AlgorithmID
    available: bool
    reason: Literal["not_available_in_environment"] | None
    implementation: str | None = Field(max_length=160)


class PerformanceResult(StrictModel):
    algorithm: AlgorithmID
    mode: Mode
    payload_bytes: PositiveInt
    digest_bytes: PositiveInt
    repeats: PositiveInt
    median_ns: Positive
    iqr_ns: Nonnegative
    throughput_mib_s: Positive


class AvalancheResult(StrictModel):
    algorithm: AlgorithmID
    input_bytes: Int1024
    trials: Int100
    digest_bits: PositiveInt
    min_flipped_bits: NonnegativeInt
    max_flipped_bits: NonnegativeInt
    mean_flipped_bits: Nonnegative
    mean_fraction: float = Field(ge=0, le=1)


class CorrectnessCheck(StrictModel):
    algorithm: AlgorithmID
    name: Literal["known-abc", "known-empty", "unicode-utf8", "determinism",
                  "digest-length", "stream-equivalence"]
    passed: bool


class Summary(StrictModel):
    algorithms_count: PositiveInt
    available_count: PositiveInt
    results_count: NonnegativeInt
    checks_count: NonnegativeInt
    all_checks_passed: bool


class HashReport(StrictModel):
    schema_version: Version
    created_at: str = Field(min_length=20, max_length=40)
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    parameters: Parameters
    environment: Environment
    algorithms: list[AlgorithmStatus] = Field(min_length=7, max_length=7)
    results: list[PerformanceResult] = Field(min_length=40, max_length=56)
    avalanche: list[AvalancheResult] = Field(min_length=5, max_length=7)
    checks: list[CorrectnessCheck] = Field(min_length=30, max_length=42)


class HashResponse(HashReport):
    # Filtering may return fewer results; full disk report must stay complete.
    results: list[PerformanceResult] = Field(max_length=56)
    summary: Summary | None = None


def validate_report(data: object) -> HashReport:
    report = HashReport.model_validate(data)

    try:
        created = datetime.fromisoformat(report.created_at.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise ValueError("created_at must be a valid timezone-aware timestamp") from None
    if created.tzinfo is None or created.utcoffset() is None:
        raise ValueError("created_at must include a timezone")
    if created.utcoffset().total_seconds() != 0:
        raise ValueError("created_at must be UTC")

    if report.parameters.sizes != list(PAYLOAD_SIZES):
        raise ValueError("parameters.sizes must match the fixed payload sizes")

    algorithms = {row.algorithm: row for row in report.algorithms}
    if len(algorithms) != len(PROFILES) or set(algorithms) != set(PROFILES):
        raise ValueError("algorithms must contain every profile exactly once")
    for algorithm, status in algorithms.items():
        if status.available:
            if status.reason is not None or not status.implementation:
                raise ValueError("available profiles require implementation and no reason")
        elif not PROFILES[algorithm].legacy:
            raise ValueError("required profiles cannot be unavailable")
        elif status.reason != "not_available_in_environment" or status.implementation is not None:
            raise ValueError("unavailable legacy profiles require the explicit unavailable state")

    available = {name for name, status in algorithms.items() if status.available}
    expected_results = {(a, size, mode) for a in available for size in PAYLOAD_SIZES
                        for mode in ("whole", "chunked")}
    result_keys = [(r.algorithm, r.payload_bytes, r.mode) for r in report.results]
    if len(result_keys) != len(set(result_keys)) or set(result_keys) != expected_results:
        raise ValueError("results must cover each available profile, size, and mode exactly once")
    for result in report.results:
        profile = PROFILES[result.algorithm]
        if result.digest_bytes != profile.digest_bytes:
            raise ValueError("result digest length does not match its profile")
        expected_repeats = 100 if result.payload_bytes == 1048576 else 1000
        if result.repeats != expected_repeats:
            raise ValueError("result repeats do not match the fixed experiment")
        expected_rate = result.payload_bytes * 1e9 / (result.median_ns * (2**20))
        if not isclose(result.throughput_mib_s, expected_rate, rel_tol=1e-6, abs_tol=1e-12):
            raise ValueError("throughput is inconsistent with payload size and median")

    avalanche_keys = [row.algorithm for row in report.avalanche]
    if len(avalanche_keys) != len(set(avalanche_keys)) or set(avalanche_keys) != available:
        raise ValueError("avalanche must contain each available profile exactly once")
    for row in report.avalanche:
        bits = PROFILES[row.algorithm].digest_bytes * 8
        if row.digest_bits != bits or row.input_bytes != 1024 or row.trials != 100:
            raise ValueError("avalanche parameters do not match the fixed experiment")
        if row.min_flipped_bits > row.max_flipped_bits or row.max_flipped_bits > bits:
            raise ValueError("avalanche bit bounds are inconsistent")
        if not row.min_flipped_bits <= row.mean_flipped_bits <= row.max_flipped_bits:
            raise ValueError("avalanche mean is outside observed bounds")
        if not isfinite(row.mean_fraction) or not isclose(
                row.mean_fraction, row.mean_flipped_bits / bits, rel_tol=1e-9, abs_tol=1e-12):
            raise ValueError("avalanche fraction is inconsistent with its mean")

    check_keys = [(row.algorithm, row.name) for row in report.checks]
    expected_checks = {(a, name) for a in available for name in CHECK_NAMES}
    if len(check_keys) != len(set(check_keys)) or set(check_keys) != expected_checks:
        raise ValueError("checks must cover every available profile and check exactly once")
    return report
