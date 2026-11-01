"""Offline asymmetric-encryption benchmark. Never run this from an HTTP route."""

import csv
import json
import os
import platform
import secrets
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from time import perf_counter_ns

from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from app.schemas.asymmetric_report import validate_complete_report
from app.security.asymmetric.adapters import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import (
    CONTEXT,
    DIRECT_SIZE,
    HYBRID_SIZES,
    KEY_PROFILES,
    PROFILES,
    expected_ciphertext_bytes,
    oaep_max_bytes,
)

SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5
CSV_COLUMNS = (
    "group", "profile", "operation", "payload_bytes", "series_index",
    "operations", "elapsed_ns", "ns_per_operation", "ciphertext_bytes",
)
ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "practice-03"


def measure_batch(operation, count: int = OPERATIONS) -> tuple[int, float]:
    if count < 1:
        raise ValueError("count must be positive")
    started = perf_counter_ns()
    for _ in range(count):
        operation()
    elapsed = perf_counter_ns() - started
    return elapsed, elapsed / count


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != SERIES:
        raise ValueError("five series required")
    q1, _, q3 = statistics.quantiles(samples, n=4, method="inclusive")
    return float(statistics.median(samples)), float(q3 - q1)


def _source_commit() -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    )
    return result.stdout.strip()


def _rejects(operation) -> bool:
    try:
        operation()
    except (DecryptionError, ValueError):
        return True
    return False


def _correctness_checks(keys: dict) -> list[dict]:
    checks = []
    for profile, spec in PROFILES.items():
        private, public = keys[spec.key_profile]
        message = secrets.token_bytes(spec.sizes[0])
        envelope = encrypt(profile, public, message, context=CONTEXT)

        checks.append({
            "profile": profile,
            "name": "roundtrip",
            "passed": (
                len(envelope) == expected_ciphertext_bytes(profile, len(message))
                and decrypt(profile, private, envelope, context=CONTEXT) == message
            ),
        })

        wrong_private, _ = generate_keypair(spec.key_profile)
        checks.append({
            "profile": profile,
            "name": "wrong_key",
            "passed": _rejects(
                lambda: decrypt(profile, wrong_private, envelope, context=CONTEXT)
            ),
        })

        tampered = envelope[:-1] + bytes([envelope[-1] ^ 1])
        checks.append({
            "profile": profile,
            "name": "tamper",
            "passed": _rejects(
                lambda: decrypt(profile, private, tampered, context=CONTEXT)
            ),
        })

        checks.append({
            "profile": profile,
            "name": "wrong_context",
            "passed": _rejects(
                lambda: decrypt(
                    profile, private, envelope, context=CONTEXT + b":different"
                )
            ),
        })

        if spec.group == "direct":
            bits = public.key_size
            limit = oaep_max_bytes(bits)
            boundary_message = secrets.token_bytes(limit)
            boundary_envelope = encrypt(profile, public, boundary_message)
            boundary_works = (
                decrypt(profile, private, boundary_envelope) == boundary_message
            )
            oversize_rejected = _rejects(
                lambda: encrypt(profile, public, secrets.token_bytes(limit + 1))
            )
            checks.append({
                "profile": profile,
                "name": "oaep_boundary",
                "passed": boundary_works and oversize_rejected,
            })

    return checks


def _environment() -> dict:
    cpu = (
        platform.processor()
        or os.environ.get("PROCESSOR_IDENTIFIER")
        or platform.machine()
        or "unavailable"
    )
    return {
        "python": platform.python_version(),
        "cryptography": version("cryptography"),
        "openssl": backend.openssl_version_text(),
        "os": f"{platform.system()} {platform.release()} {platform.version()}",
        "cpu": cpu[:200],
    }


def run_experiment() -> None:
    source_commit = _source_commit()

    # Key generation is measured independently (one new pair per run).
    rows = []
    key_generation = []
    for key_profile in KEY_PROFILES:
        samples = []
        public_der_bytes = None
        for series_index in range(1, KEYGEN_RUNS + 1):
            started = perf_counter_ns()
            _, public = generate_keypair(key_profile)
            elapsed = perf_counter_ns() - started
            samples.append(float(elapsed))
            public_der_bytes = len(public.public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ))
            rows.append({
                "group": "keygen", "profile": key_profile,
                "operation": "keygen", "payload_bytes": 0,
                "series_index": series_index, "operations": 1,
                "elapsed_ns": elapsed, "ns_per_operation": float(elapsed),
                "ciphertext_bytes": 0,
            })
        median_ns, iqr_ns = summarize(samples)
        key_generation.append({
            "key_profile": key_profile, "runs": KEYGEN_RUNS,
            "median_ns": median_ns, "iqr_ns": iqr_ns,
            "public_key_der_bytes": public_der_bytes,
        })

    # Recipient keys and synthetic data are prepared outside all timers.
    keys = {name: generate_keypair(name) for name in KEY_PROFILES}
    work = {}
    samples = {}
    for profile, spec in PROFILES.items():
        private, public = keys[spec.key_profile]
        for payload_bytes in spec.sizes:
            message = secrets.token_bytes(payload_bytes)
            envelope = encrypt(profile, public, message, context=CONTEXT)
            expected = expected_ciphertext_bytes(profile, payload_bytes)
            if len(envelope) != expected:
                raise RuntimeError(f"wrong envelope size: {profile}")
            if decrypt(profile, private, envelope, context=CONTEXT) != message:
                raise RuntimeError(f"roundtrip failed: {profile}")

            # Warm up both measured operations ten times.
            for _ in range(WARMUP):
                encrypt(profile, public, message, context=CONTEXT)
            for _ in range(WARMUP):
                decrypt(profile, private, envelope, context=CONTEXT)

            work[profile, payload_bytes] = (message, envelope, expected)
            for operation in ("encrypt", "decrypt"):
                samples[profile, payload_bytes, operation] = []

    # Rotate the profile order on each series to reduce order bias.
    profiles = list(PROFILES)
    for series_index in range(1, SERIES + 1):
        shift = (series_index - 1) % len(profiles)
        rotated = profiles[shift:] + profiles[:shift]
        for profile in rotated:
            spec = PROFILES[profile]
            private, public = keys[spec.key_profile]
            for payload_bytes in spec.sizes:
                message, envelope, expected = work[profile, payload_bytes]
                for operation in ("encrypt", "decrypt"):
                    if operation == "encrypt":
                        def measured():
                            return encrypt(profile, public, message, context=CONTEXT)
                    else:
                        def measured():
                            return decrypt(profile, private, envelope, context=CONTEXT)

                    elapsed, ns_per_operation = measure_batch(measured)
                    samples[profile, payload_bytes, operation].append(ns_per_operation)
                    rows.append({
                        "group": spec.group, "profile": profile,
                        "operation": operation, "payload_bytes": payload_bytes,
                        "series_index": series_index, "operations": OPERATIONS,
                        "elapsed_ns": elapsed,
                        "ns_per_operation": ns_per_operation,
                        "ciphertext_bytes": expected,
                    })

    results = []
    for profile, spec in PROFILES.items():
        for payload_bytes in spec.sizes:
            for operation in ("encrypt", "decrypt"):
                median_ns, iqr_ns = summarize(
                    samples[profile, payload_bytes, operation]
                )
                throughput = (
                    payload_bytes * 1e9 / (1024 * 1024 * median_ns)
                    if spec.group == "hybrid" else None
                )
                results.append({
                    "profile": profile, "group": spec.group,
                    "operation": operation, "payload_bytes": payload_bytes,
                    "series": SERIES, "operations_per_series": OPERATIONS,
                    "median_ns": median_ns, "iqr_ns": iqr_ns,
                    "ciphertext_bytes": expected_ciphertext_bytes(
                        profile, payload_bytes
                    ),
                    "throughput_mib_s": throughput,
                })

    checks = _correctness_checks(keys)
    report = {
        "schema_version": 1,
        "experiment": {
            "series": SERIES, "operations_per_series": OPERATIONS,
            "warmup": WARMUP, "keygen_runs": KEYGEN_RUNS,
            "direct_payload_bytes": DIRECT_SIZE,
            "hybrid_sizes_bytes": list(HYBRID_SIZES),
            "source_commit": source_commit,
            "created_at_utc": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
        },
        "environment": _environment(),
        "key_generation": key_generation,
        "results": results,
        "checks": checks,
    }

    if len(rows) != 130 or len(results) != 22 or len(checks) != 22:
        raise RuntimeError("unexpected experiment row counts")
    validate_complete_report(report)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with (OUTPUT_DIR / "raw.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    with (OUTPUT_DIR / "report.json").open("w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")

    passed = sum(check["passed"] for check in checks)
    print(f"Source commit: {source_commit}")
    print(f"Raw measurements: {len(rows)}")
    print(f"Key generation aggregates: {len(key_generation)}")
    print(f"Encrypt/decrypt aggregates: {len(results)}")
    print(f"Correctness checks: {passed}/{len(checks)} passed")
    print(f"CSV: {OUTPUT_DIR / 'raw.csv'}")
    print(f"JSON: {OUTPUT_DIR / 'report.json'}")


def main() -> int:
    run_experiment()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
