
"""Practice 02: reproducible symmetric-encryption benchmarks."""

import argparse
import csv
import json
import os
import platform
import random
import secrets
import ssl
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from statistics import median, quantiles
from time import get_clock_info, perf_counter_ns
from uuid import uuid4

import cryptography
from Crypto import __version__ as pycryptodome_version

from app.security.adapters import open_bytes, seal_bytes
from app.security.nonce import NonceSequence


SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100

BENCHMARK_AAD = (
    b"digital-dean-practice-02-benchmark"
    .ljust(64, b".")
)

BACKENDS = (
    "cryptography",
    "pycryptodome",
)

ALGORITHMS = {
    "AES-128-GCM": 16,
    "AES-256-GCM": 32,
    "ChaCha20-Poly1305": 32,
}


def measure_batch(operation, arguments) -> float:
    """Mean nanoseconds per operation in one batch."""
    if not arguments:
        raise ValueError("Empty batch")

    started = perf_counter_ns()

    for args in arguments:
        operation(*args)

    elapsed = perf_counter_ns() - started

    if elapsed <= 0:
        raise RuntimeError("Invalid elapsed time")

    return elapsed / len(arguments)


def summarize(series_mean_ns, size_bytes) -> dict:
    """Calculate median, inclusive IQR and throughput."""
    if len(series_mean_ns) != SERIES:
        raise ValueError("Five series required")

    if size_bytes <= 0:
        raise ValueError("Invalid message size")

    q1, _, q3 = quantiles(
        series_mean_ns,
        n=4,
        method="inclusive",
    )

    typical = median(series_mean_ns)

    if typical <= 0:
        raise ValueError("Time must be positive")

    return {
        "median_ns": typical,
        "iqr_ns": q3 - q1,
        "throughput_mib_s": (
            size_bytes * 1e9 / (2**20 * typical)
        ),
    }


def _git_commit() -> str:
    """Get the current Git commit before benchmarking."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        return result.stdout.strip()

    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
    ):
        return "unknown"


def _environment() -> dict:
    """Collect available environment information."""
    try:
        from cryptography.hazmat.backends.openssl.backend import (
            backend,
        )
        crypto_openssl = backend.openssl_version_text()

    except (ImportError, AttributeError):
        crypto_openssl = "unknown"

    return {
        "processor": (
            platform.processor()
            or os.environ.get("PROCESSOR_IDENTIFIER", "unknown")
        ),
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "cryptography_version": cryptography.__version__,
        "pycryptodome_version": pycryptodome_version,
        "cryptography_openssl": crypto_openssl,
        "python_ssl": ssl.OPENSSL_VERSION,
        "hardware_acceleration": "not_verified",
        "timer": "perf_counter_ns",
        "timer_resolution_seconds": (
            get_clock_info("perf_counter").resolution
        ),
    }


def run_benchmark(output_dir: Path) -> None:
    """Run 36 cases and save 180 measured series."""

    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )

    # Same data for every algorithm and library.
    messages = {
        size: secrets.token_bytes(size)
        for size in SIZES_BYTES
    }

    # Separate key and nonce counter for each combination.
    credentials = {
        (backend, algorithm): (
            secrets.token_bytes(key_size),
            NonceSequence(),
        )
        for backend in BACKENDS
        for algorithm, key_size in ALGORITHMS.items()
    }

    tasks = []

    # Prepare all experiment configurations.
    for size, message in messages.items():
        for (backend, algorithm), (key, nonces) in (
            credentials.items()
        ):
            nonce_for_read = nonces.next()

            ciphertext, tag = seal_bytes(
                backend,
                algorithm,
                key,
                nonce_for_read,
                message,
                BENCHMARK_AAD,
            )

            decrypted = open_bytes(
                backend,
                algorithm,
                key,
                nonce_for_read,
                ciphertext,
                tag,
                BENCHMARK_AAD,
            )

            if decrypted != message:
                raise RuntimeError(
                    f"Round-trip failed: "
                    f"{backend} {algorithm} {size}"
                )

            common = {
                "backend": backend,
                "algorithm": algorithm,
                "size_bytes": size,
                "key": key,
                "nonces": nonces,
                "message": message,
                "decrypt_args": (
                    backend,
                    algorithm,
                    key,
                    nonce_for_read,
                    ciphertext,
                    tag,
                    BENCHMARK_AAD,
                ),
            }

            tasks.append({
                **common,
                "operation": "encrypt",
            })

            tasks.append({
                **common,
                "operation": "decrypt",
            })

    # Warmup is excluded from timing statistics.
    for task in tasks:
        if task["operation"] == "encrypt":
            arguments = [
                (
                    task["backend"],
                    task["algorithm"],
                    task["key"],
                    task["nonces"].next(),
                    task["message"],
                    BENCHMARK_AAD,
                )
                for _ in range(WARMUP)
            ]

            for args in arguments:
                seal_bytes(*args)

        else:
            for _ in range(WARMUP):
                result = open_bytes(*task["decrypt_args"])

                if result != task["message"]:
                    raise RuntimeError(
                        "Decryption warmup failed"
                    )

    raw_rows = []

    series_by_task = {
        (
            task["backend"],
            task["algorithm"],
            task["size_bytes"],
            task["operation"],
        ): []
        for task in tasks
    }

    # Fixed seed controls ordering, not cryptographic values.
    order_rng = random.Random(2026)

    for series_index in range(1, SERIES + 1):
        shuffled = tasks.copy()
        order_rng.shuffle(shuffled)

        for task in shuffled:
            if task["operation"] == "encrypt":
                # Reserve nonces before starting the timer.
                arguments = [
                    (
                        task["backend"],
                        task["algorithm"],
                        task["key"],
                        task["nonces"].next(),
                        task["message"],
                        BENCHMARK_AAD,
                    )
                    for _ in range(OPERATIONS_PER_SERIES)
                ]

                operation = seal_bytes

            else:
                # Repeating decryption is permitted.
                arguments = (
                    [task["decrypt_args"]]
                    * OPERATIONS_PER_SERIES
                )

                operation = open_bytes

            mean_ns = measure_batch(
                operation,
                arguments,
            )

            total_ns = round(
                mean_ns * len(arguments)
            )

            key = (
                task["backend"],
                task["algorithm"],
                task["size_bytes"],
                task["operation"],
            )

            series_by_task[key].append(mean_ns)

            raw_rows.append({
                "run_id": run_id,
                "backend": task["backend"],
                "algorithm": task["algorithm"],
                "size_bytes": task["size_bytes"],
                "operation": task["operation"],
                "series_index": series_index,
                "operations": len(arguments),
                "total_ns": total_ns,
                "mean_ns": mean_ns,
            })

    # Build aggregate results.
    results = []

    for (
        backend,
        algorithm,
        size,
        operation,
    ), samples in sorted(series_by_task.items()):

        results.append({
            "backend": backend,
            "algorithm": algorithm,
            "size_bytes": size,
            "operation": operation,
            "series_mean_ns": samples,
            **summarize(samples, size),
        })

    if len(raw_rows) != 180 or len(results) != 36:
        raise RuntimeError(
            "Unexpected number of benchmark rows"
        )

    # Create report with measured values.
    report = {
        "schema_version": 1,
        "run_id": run_id,
        "timestamp_utc": (
            datetime.now(timezone.utc).isoformat()
        ),
        "source_commit_before_benchmark": _git_commit(),
        "environment": _environment(),
        "parameters": {
            "sizes_bytes": list(SIZES_BYTES),
            "warmup": WARMUP,
            "series": SERIES,
            "operations_per_series": OPERATIONS_PER_SERIES,
            "aad_length_bytes": len(BENCHMARK_AAD),
            "includes_cipher_object_creation": True,
            "excludes_key_nonce_and_input_preparation": True,
            "ordering_seed": 2026,
        },
        "results": results,
    }

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    fields = (
        "run_id",
        "backend",
        "algorithm",
        "size_bytes",
        "operation",
        "series_index",
        "operations",
        "total_ns",
        "mean_ns",
    )

    # Save individual timing series.
    with (output_dir / "raw.csv").open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
        )

        writer.writeheader()
        writer.writerows(raw_rows)

    # Save aggregate statistics.
    (output_dir / "report.json").write_text(
        json.dumps(
            report,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )

    print(
        f"Benchmark completed: "
        f"{len(raw_rows)} series, "
        f"{len(results)} results"
    )

    print(
        f"Saved: {output_dir / 'raw.csv'} "
        f"and {output_dir / 'report.json'}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Practice 2 symmetric benchmark"
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
    )

    args = parser.parse_args()
    run_benchmark(args.output_dir)


if __name__ == "__main__":
    main()
