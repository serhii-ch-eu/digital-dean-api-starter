"""Структура базового звіту; допишіть семантичний валідатор."""
from typing import Annotated, Literal
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field


def _exact_integer(value: object) -> int:
    # Numeric Literal comparisons alone can accept True or 5.0 as integers.
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
    name: Literal["roundtrip", "wrong_key", "tamper", "wrong_context", "oaep_boundary"]
    passed: bool


class BenchmarkReport(StrictModel):
    schema_version: One
    experiment: Experiment
    environment: Environment
    key_generation: list[KeyGeneration] = Field(min_length=4, max_length=4)
    results: list[Result] = Field(min_length=22, max_length=22)
    checks: list[Check] = Field(min_length=22, max_length=22)


class BenchmarkResponse(BenchmarkReport):
    # First validate the complete saved report, then filter only results.
    # Keep key_generation and checks complete. An empty filtered list is valid.
    results: list[Result] = Field(max_length=22)


def validate_complete_report(data: object) -> BenchmarkReport:
    report = BenchmarkReport.model_validate(data)
    
    # 1. Перевірка формату часу (UTC)
    if not (report.experiment.created_at_utc.endswith("Z") or "+00:00" in report.experiment.created_at_utc):
        raise ValueError("created_at_utc має бути у форматі UTC (ISO 8601)")

    # 2. Повнота та унікальність генерації ключів (4 унікальні профілі)
    key_profiles = {k.key_profile for k in report.key_generation}
    if len(key_profiles) != 4:
        raise ValueError("key_generation має містити рівно 4 унікальні профілі ключів")

    # 3. Перевірка комбінацій результатів (22 унікальні комбінації)
    result_keys = {(r.profile, r.operation, r.payload_bytes) for r in report.results}
    if len(result_keys) != 22:
        raise ValueError("results має містити рівно 22 унікальні комбінації (profile, operation, payload_bytes)")

    # 4. Семантика результатів: розміри конвертів та розрахунок пропускної здатності
    for r in report.results:
        # Очікувані розміри згідно з Таблицею 2
        expected_bytes = 0
        if r.profile == "rsa2048-oaep":
            expected_bytes = 256
        elif r.profile == "rsa3072-oaep":
            expected_bytes = 384
        elif r.profile == "rsa3072-oaep-aes256gcm":
            expected_bytes = r.payload_bytes + 412
        elif r.profile == "hpke-x25519-aes256gcm":
            expected_bytes = r.payload_bytes + 48
        elif r.profile == "hpke-p256-aes256gcm":
            expected_bytes = r.payload_bytes + 81
            
        if r.ciphertext_bytes != expected_bytes:
            raise ValueError(
                f"Некоректний ciphertext_bytes для {r.profile} з payload_bytes={r.payload_bytes}. "
                f"Очікується {expected_bytes}, отримано {r.ciphertext_bytes}"
            )

        # Перевірка throughput_mib_s
        if r.group == "direct":
            if r.throughput_mib_s is not None:
                raise ValueError(f"throughput_mib_s має бути null для direct профілю {r.profile}")
        else:
            if r.throughput_mib_s is None:
                raise ValueError(f"throughput_mib_s обов'язковий для гібридного профілю {r.profile}")
            
            # v = (S * 10^9) / (2^20 * t_m) згідно з Формулою 3
            expected_throughput = (r.payload_bytes * 10**9) / ((1 << 20) * r.median_ns)
            # Допускаємо невелику похибку округлення для чисел із рухомою комою
            if abs(r.throughput_mib_s - expected_throughput) > 0.01:
                raise ValueError(
                    f"Помилка розрахунку пропускної здатності для {r.profile}. "
                    f"Очікується {expected_throughput:.2f}, отримано {r.throughput_mib_s}"
                )

    # 5. Унікальність перевірок (22 унікальні комбінації)
    check_keys = {(c.profile, c.name) for c in report.checks}
    if len(check_keys) != 22:
        raise ValueError("checks має містити рівно 22 унікальні комбінації перевірок")

    return report