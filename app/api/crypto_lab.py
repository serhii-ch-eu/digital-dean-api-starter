
import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter(
    prefix="/api/v1/lab/crypto",
    tags=["crypto-lab"],
)

REPORT_PATH = (
    Path(__file__).resolve().parents[2]
    / "results/practice-02/report.json"
)

ERROR = "Benchmark results unavailable"


def load_benchmark_report(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(report, dict):
        raise ValueError("Invalid report")

    if report.get("schema_version") != 1:
        raise ValueError("Invalid schema version")

    if not isinstance(report.get("run_id"), str):
        raise ValueError("Invalid run ID")

    if not isinstance(report.get("environment"), dict):
        raise ValueError("Invalid environment")

    if not isinstance(report.get("parameters"), dict):
        raise ValueError("Invalid parameters")

    results = report.get("results")

    if not isinstance(results, list) or len(results) != 36:
        raise ValueError("Invalid results")

    expected = {
        (backend, algorithm, size, operation)
        for backend in ("cryptography", "pycryptodome")
        for algorithm in (
            "AES-128-GCM",
            "AES-256-GCM",
            "ChaCha20-Poly1305",
        )
        for size in (1024, 65536, 1048576)
        for operation in ("encrypt", "decrypt")
    }

    actual = set()

    for row in results:
        if not isinstance(row, dict):
            raise ValueError("Invalid result row")

        identity = (
            row.get("backend"),
            row.get("algorithm"),
            row.get("size_bytes"),
            row.get("operation"),
        )

        if identity not in expected or identity in actual:
            raise ValueError("Invalid combination")

        actual.add(identity)

        samples = row.get("series_mean_ns")

        if not isinstance(samples, list) or len(samples) != 5:
            raise ValueError("Invalid series")

        if any(
            type(value) not in (int, float) or value <= 0
            for value in samples
        ):
            raise ValueError("Invalid measurement")

        for field in (
            "median_ns",
            "iqr_ns",
            "throughput_mib_s",
        ):
            value = row.get(field)

            if type(value) not in (int, float):
                raise ValueError("Invalid metric")

            if value < 0 or (
                field != "iqr_ns" and value == 0
            ):
                raise ValueError("Invalid metric")

    if actual != expected:
        raise ValueError("Incomplete report")

    return report


@router.get("/benchmark-results")
def benchmark_results():
    try:
        return load_benchmark_report(REPORT_PATH)
    except FileNotFoundError:
        raise HTTPException(404, ERROR)
    except (OSError, ValueError, TypeError, UnicodeError):
        raise HTTPException(500, ERROR)
