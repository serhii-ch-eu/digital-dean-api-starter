"""Локальний експеримент з хешуванням; HTTP-запити його не запускають."""
import csv
import json
import platform
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median, quantiles
from time import perf_counter_ns

from app.schemas.hash_report import validate_report
from app.security.hashing.adapters import hash_bytes, hamming_bits, prepare_operation
from app.security.hashing.profiles import (
    AVALANCHE_BYTES,
    AVALANCHE_TRIALS,
    CHECK_NAMES,
    CHUNK_BYTES,
    PAYLOAD_SIZES,
    PROFILES,
    SERIES,
    WARMUP,
    make_hasher,
    probe_profiles,
    repeat_count,
    synthetic_payload,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "results" / "practice-04"
ALGORITHMS = tuple(PROFILES)
MODES = ("whole", "chunked")
KNOWN_VECTORS = {
    "sha256": (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    ),
    "sha512": (
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    ),
    "sha3-256": (
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    ),
    "blake2b-256": (
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    ),
    "blake2s-256": (
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    ),
    "md5": (
        "d41d8cd98f00b204e9800998ecf8427e",
        "900150983cd24fb0d6963f7d28e17f72",
    ),
    "sha1": (
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
    ),
}


def measure_batch(operation, repeats: int) -> tuple[int, float]:
    """Return total elapsed nanoseconds and the per-operation mean."""
    if type(repeats) is not int or repeats <= 0:
        raise ValueError("positive repeat count required")
    start = perf_counter_ns()
    for _ in range(repeats):
        operation()
    elapsed_ns = perf_counter_ns() - start
    return elapsed_ns, elapsed_ns / repeats


def summarize(samples: list[float]) -> tuple[float, float]:
    if len(samples) != SERIES:
        raise ValueError(f"exactly {SERIES} series required")
    q1, _, q3 = quantiles(samples, n=4, method="inclusive")
    return median(samples), q3 - q1


def _source_commit() -> str:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status.strip():
        raise RuntimeError("working tree must be clean before the experiment")
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _correctness_checks(available: list[str]) -> list[dict]:
    checks = []
    unicode_message = "Відомість Цифрового деканату — тест UTF-8".encode("utf-8")
    for algorithm in available:
        expected_empty, expected_abc = KNOWN_VECTORS[algorithm]
        check_results = {
            "known-abc": hash_bytes(algorithm, b"abc").hex() == expected_abc,
            "known-empty": hash_bytes(algorithm, b"").hex() == expected_empty,
        }

        unicode_hasher = make_hasher(algorithm)
        unicode_hasher.update(unicode_message)
        check_results["unicode-utf8"] = (
            hash_bytes(algorithm, unicode_message) == unicode_hasher.digest()
        )

        first = hash_bytes(algorithm, unicode_message)
        check_results["determinism"] = first == hash_bytes(algorithm, unicode_message)
        check_results["digest-length"] = len(first) == PROFILES[algorithm].digest_bytes
        check_results["stream-equivalence"] = (
            hash_bytes(algorithm, unicode_message, "whole")
            == hash_bytes(algorithm, unicode_message, "chunked")
        )
        checks.extend(
            {"algorithm": algorithm, "name": name, "passed": check_results[name]}
            for name in CHECK_NAMES
        )
    return checks


def _measure(available: list[str]) -> tuple[list[dict], list[dict]]:
    raw_rows = []
    aggregate_rows = []
    for algorithm in available:
        for payload_bytes in PAYLOAD_SIZES:
            payload = synthetic_payload(payload_bytes)
            repeats = repeat_count(payload_bytes)
            for mode in MODES:
                operation = prepare_operation(algorithm, payload, mode)
                for _ in range(WARMUP):
                    operation()

                series_ns = []
                per_operation_ns = []
                for series_index in range(1, SERIES + 1):
                    elapsed_ns, ns_per_op = measure_batch(operation, repeats)
                    series_ns.append(elapsed_ns)
                    per_operation_ns.append(ns_per_op)
                    raw_rows.append({
                        "algorithm": algorithm,
                        "mode": mode,
                        "payload_bytes": payload_bytes,
                        "series": series_index,
                        "repeats": repeats,
                        "elapsed_ns": elapsed_ns,
                        "ns_per_op": ns_per_op,
                    })

                median_ns, iqr_ns = summarize(per_operation_ns)
                aggregate_rows.append({
                    "algorithm": algorithm,
                    "mode": mode,
                    "payload_bytes": payload_bytes,
                    "digest_bytes": PROFILES[algorithm].digest_bytes,
                    "repeats": repeats,
                    "median_ns": median_ns,
                    "iqr_ns": iqr_ns,
                    "throughput_mib_s": payload_bytes * 1e9 / (median_ns * 2**20),
                })
    return raw_rows, aggregate_rows


def _avalanche(available: list[str]) -> tuple[list[dict], list[dict]]:
    original = synthetic_payload(AVALANCHE_BYTES)
    aggregate_rows = []
    raw_rows = []
    for algorithm in available:
        baseline = hash_bytes(algorithm, original)
        distances = []
        digest_bits = PROFILES[algorithm].digest_bytes * 8
        for bit_index in range(AVALANCHE_TRIALS):
            mutated = bytearray(original)
            mutated[bit_index // 8] ^= 1 << (bit_index % 8)
            changed_digest = hash_bytes(algorithm, bytes(mutated))
            flipped_bits = hamming_bits(baseline, changed_digest)
            distances.append(flipped_bits)
            raw_rows.append({
                "algorithm": algorithm,
                "trial": bit_index + 1,
                "bit_index": bit_index,
                "digest_bits": digest_bits,
                "flipped_bits": flipped_bits,
                "fraction": flipped_bits / digest_bits,
            })

        average = mean(distances)
        aggregate_rows.append({
            "algorithm": algorithm,
            "input_bytes": AVALANCHE_BYTES,
            "trials": AVALANCHE_TRIALS,
            "digest_bits": digest_bits,
            "min_flipped_bits": min(distances),
            "max_flipped_bits": max(distances),
            "mean_flipped_bits": average,
            "mean_fraction": average / digest_bits,
        })
    return aggregate_rows, raw_rows


def _environment() -> dict:
    cpu = platform.processor() or platform.machine() or "unknown"
    return {
        "python": sys.version.split()[0],
        "openssl_ssl": ssl.OPENSSL_VERSION,
        "os": platform.platform(),
        "cpu": cpu,
        "architecture": platform.machine() or "unknown",
    }


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_experiment() -> None:
    # Capture the exact source revision before doing any checks or measurements.
    source_commit = _source_commit()
    statuses = probe_profiles()
    available = [row["algorithm"] for row in statuses if row["available"]]

    checks = _correctness_checks(available)
    raw_rows, results = _measure(available)
    avalanche, avalanche_rows = _avalanche(available)
    report_data = {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_commit": source_commit,
        "parameters": {
            "sizes": list(PAYLOAD_SIZES),
            "chunk_bytes": CHUNK_BYTES,
            "warmup": WARMUP,
            "series": SERIES,
            "repeats_small": 1000,
            "repeats_large": 100,
            "avalanche_trials": AVALANCHE_TRIALS,
            "avalanche_bytes": AVALANCHE_BYTES,
        },
        "environment": _environment(),
        "algorithms": statuses,
        "results": results,
        "avalanche": avalanche,
        "checks": checks,
    }
    report = validate_report(report_data)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    _write_csv(
        OUTPUT_DIR / "raw.csv",
        raw_rows,
        ["algorithm", "mode", "payload_bytes", "series", "repeats", "elapsed_ns", "ns_per_op"],
    )
    _write_csv(
        OUTPUT_DIR / "avalanche.csv",
        avalanche_rows,
        ["algorithm", "trial", "bit_index", "digest_bits", "flipped_bits", "fraction"],
    )
    with (OUTPUT_DIR / "report.json").open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(report.model_dump(mode="json"), stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")

    failed = [check for check in checks if not check["passed"]]
    print({
        "source_commit": source_commit,
        "available_algorithms": len(available),
        "results": len(results),
        "raw_rows": len(raw_rows),
        "avalanche_rows": len(avalanche_rows),
        "checks": len(checks),
        "failed_checks": len(failed),
        "report": str(OUTPUT_DIR / "report.json"),
    })
    if failed:
        raise SystemExit("one or more hash correctness checks failed")


if __name__ == "__main__":
    run_experiment()
