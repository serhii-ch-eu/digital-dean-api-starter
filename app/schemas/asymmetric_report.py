"""Strict saved-report schema and semantic checks for Practice 03."""

from datetime import datetime, timedelta
from math import isclose
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from app.security.asymmetric.profiles import (
    DIRECT_SIZE,
    HYBRID_SIZES,
    KEY_PROFILES,
    PROFILES,
    expected_ciphertext_bytes,
)


def _exact_integer(value: object) -> int:
    if type(value) is not int:
        raise ValueError("an exact integer is required")
    return value


One = Annotated[Literal[1], BeforeValidator(_exact_integer)]
Five = Annotated[Literal[5], BeforeValidator(_exact_integer)]
Ten = Annotated[Literal[10], BeforeValidator(_exact_integer)]
Twenty = Annotated[Literal[20], BeforeValidator(_exact_integer)]
SixtyFour = Annotated[Literal[64], BeforeValidator(_exact_integer)]
ProfileId = Literal[
    "rsa2048-oaep", "rsa3072-oaep", "rsa3072-oaep-aes256gcm",
    "hpke-x25519-aes256gcm", "hpke-p256-aes256gcm",
]
KeyId = Literal["rsa-2048", "rsa-3072", "x25519", "p256"]
PositiveFloat = Annotated[float, Field(gt=0, allow_inf_nan=False)]
NonNegativeFloat = Annotated[float, Field(ge=0, allow_inf_nan=False)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Experiment(StrictModel):
    series: Five
    operations_per_series: Twenty
    warmup: Ten
    keygen_runs: Five
    direct_payload_bytes: SixtyFour
    hybrid_sizes_bytes: list[int]
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    created_at_utc: str = Field(min_length=20, max_length=40)


class Environment(StrictModel):
    python: str = Field(min_length=1, max_length=100)
    cryptography: Literal["48.0.1"]
    openssl: str = Field(min_length=1, max_length=150)
    os: str = Field(min_length=1, max_length=150)
    cpu: str = Field(min_length=1, max_length=200)


class KeyGeneration(StrictModel):
    key_profile: KeyId
    runs: Five
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    public_key_der_bytes: int = Field(gt=0, le=4096)


class Result(StrictModel):
    profile: ProfileId
    group: Literal["direct", "hybrid"]
    operation: Literal["encrypt", "decrypt"]
    payload_bytes: int = Field(gt=0, le=1048576)
    series: Five
    operations_per_series: Twenty
    median_ns: PositiveFloat
    iqr_ns: NonNegativeFloat
    ciphertext_bytes: int = Field(gt=0, le=1048988)
    throughput_mib_s: PositiveFloat | None


class Check(StrictModel):
    profile: ProfileId
    name: Literal[
        "roundtrip", "wrong_key", "tamper", "wrong_context", "oaep_boundary"
    ]
    passed: bool


class BenchmarkReport(StrictModel):
    schema_version: One
    experiment: Experiment
    environment: Environment
    key_generation: list[KeyGeneration] = Field(min_length=4, max_length=4)
    results: list[Result] = Field(min_length=22, max_length=22)
    checks: list[Check] = Field(min_length=22, max_length=22)


class BenchmarkResponse(BenchmarkReport):
    # The full saved file is verified before filtering any results.
    results: list[Result] = Field(max_length=22)


def validate_complete_report(data: object) -> BenchmarkReport:
    """Reject missing, duplicate or internally contradictory benchmark data."""
    report = BenchmarkReport.model_validate(data)
    experiment = report.experiment

    sizes = experiment.hybrid_sizes_bytes
    if any(type(size) is not int for size in sizes) or sizes != list(HYBRID_SIZES):
        raise ValueError("invalid hybrid payload sizes")

    if experiment.direct_payload_bytes != DIRECT_SIZE:
        raise ValueError("invalid direct payload size")

    try:
        when = datetime.fromisoformat(
            experiment.created_at_utc.replace("Z", "+00:00")
        )
    except ValueError as exc:
        raise ValueError("invalid experiment timestamp") from exc
    if when.tzinfo is None or when.utcoffset() != timedelta(0):
        raise ValueError("experiment timestamp must be UTC")

    expected_keys = set(KEY_PROFILES)
    actual_keys = [item.key_profile for item in report.key_generation]
    if len(actual_keys) != len(set(actual_keys)) or set(actual_keys) != expected_keys:
        raise ValueError("incomplete or duplicate key generation coverage")

    required_results = {
        (profile, operation, payload)
        for profile, spec in PROFILES.items()
        for payload in spec.sizes
        for operation in ("encrypt", "decrypt")
    }
    actual_results = [
        (item.profile, item.operation, item.payload_bytes)
        for item in report.results
    ]
    if (
        len(actual_results) != len(set(actual_results))
        or set(actual_results) != required_results
    ):
        raise ValueError("incomplete or duplicate result coverage")

    for item in report.results:
        spec = PROFILES[item.profile]
        if item.group != spec.group:
            raise ValueError("inconsistent profile group")
        if item.ciphertext_bytes != expected_ciphertext_bytes(
            item.profile, item.payload_bytes
        ):
            raise ValueError("inconsistent ciphertext size")
        if spec.group == "direct":
            if item.throughput_mib_s is not None:
                raise ValueError("throughput is not defined for direct RSA")
        else:
            expected_throughput = (
                item.payload_bytes * 1e9 / (1024 * 1024 * item.median_ns)
            )
            if item.throughput_mib_s is None or not isclose(
                item.throughput_mib_s, expected_throughput, rel_tol=1e-6
            ):
                raise ValueError("inconsistent throughput")

    required_checks = {
        (profile, check)
        for profile in PROFILES
        for check in ("roundtrip", "wrong_key", "tamper", "wrong_context")
    } | {
        ("rsa2048-oaep", "oaep_boundary"),
        ("rsa3072-oaep", "oaep_boundary"),
    }
    actual_checks = [(item.profile, item.name) for item in report.checks]
    if len(actual_checks) != len(set(actual_checks)) or set(actual_checks) != required_checks:
        raise ValueError("incomplete or duplicate correctness checks")

    # A failed check must stay in the report, rather than being omitted.
    return report
