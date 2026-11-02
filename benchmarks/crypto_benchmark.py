"""Заповніть функції за методикою практичної роботи, не вигадуйте результати."""

import argparse
import csv
import json
import statistics
import time
from pathlib import Path
from secrets import token_bytes

from app.security.adapters import open_bytes, seal_bytes
from app.security.nonce import NonceSequence
from app.security.profiles import KEY_BYTES

SIZES_BYTES = (1024, 65536, 1048576)
WARMUP = 10
SERIES = 5
OPERATIONS_PER_SERIES = 100
BENCHMARK_AAD = b"digital-dean-practice-02-benchmark".ljust(64, b".")

COMBINATIONS = [
    ("cryptography", "AES-128-GCM"),
    ("cryptography", "AES-256-GCM"),
    ("cryptography", "ChaCha20-Poly1305"),
    ("pycryptodome", "AES-128-GCM"),
    ("pycryptodome", "AES-256-GCM"),
    ("pycryptodome", "ChaCha20-Poly1305"),
]


def measure_batch(operation, arguments) -> float:
    """perf_counter_ns, середній час серії; аргументи вже підготовлені."""
    start_ns = time.perf_counter_ns()
    for args in arguments:
        operation(*args)
    end_ns = time.perf_counter_ns()
    total_ns = end_ns - start_ns
    return total_ns / len(arguments)


def _calc_inclusive_iqr(data: list[float]) -> float:
    """Розрахунок inclusive IQR (метод Тьюкі/inclusive)."""
    sorted_data = sorted(data)
    n = len(sorted_data)
    if n == 1:
        return 0.0

    def quantile(p: float) -> float:
        idx = p * (n - 1)
        i = int(idx)
        fraction = idx - i
        if i + 1 < n:
            return sorted_data[i] + fraction * (sorted_data[i + 1] - sorted_data[i])
        return float(sorted_data[i])

    q1 = quantile(0.25)
    q3 = quantile(0.75)
    return q3 - q1


def summarize(series_mean_ns: list[float], size_bytes: int) -> dict:
    """Медіана 5 середніх, inclusive IQR і МіБ/с за початковими байтами."""
    median_ns = statistics.median(series_mean_ns)
    iqr_ns = _calc_inclusive_iqr(series_mean_ns)

    # Переведення часу на операцію в секунди
    seconds_per_op = median_ns / 1e9
    mib_per_sec = (size_bytes / (1024 * 1024)) / seconds_per_op if seconds_per_op > 0 else 0.0

    return {
        "median_ns": round(median_ns, 2),
        "iqr_ns": round(iqr_ns, 2),
        "mib_per_sec": round(mib_per_sec, 2),
    }


def run_benchmark(output_dir: Path) -> None:
    """Шість комбінацій, 3 розміри, 2 операції; 180 серій, 36 агрегатів."""
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_csv_path = output_dir / "raw.csv"
    report_json_path = output_dir / "report.json"

    raw_records = []
    aggregates = {}

    for backend, algorithm in COMBINATIONS:
        # Окремий ключ на кожну комбінацію
        key = token_bytes(KEY_BYTES[algorithm])
        # Лічильник nonce
        nonce_seq = NonceSequence(limit=1_000_000)

        for size_bytes in SIZES_BYTES:
            plaintext = token_bytes(size_bytes)

            for op_type in ("seal", "open"):
                series_means = []

                # --- Прогрівання (Warmup) ---
                warmup_args = []
                for _ in range(WARMUP):
                    nonce = nonce_seq.next()
                    if op_type == "seal":
                        warmup_args.append((backend, algorithm, key, nonce, plaintext, BENCHMARK_AAD))
                    else:
                        ct, tag = seal_bytes(backend, algorithm, key, nonce, plaintext, BENCHMARK_AAD)
                        warmup_args.append((backend, algorithm, key, nonce, ct, tag, BENCHMARK_AAD))

                target_func = seal_bytes if op_type == "seal" else open_bytes
                for args in warmup_args:
                    target_func(*args)

                # --- Основне вимірювання (5 серій по 100 операцій) ---
                for series_idx in range(SERIES):
                    series_args = []
                    for _ in range(OPERATIONS_PER_SERIES):
                        nonce = nonce_seq.next()
                        if op_type == "seal":
                            series_args.append((backend, algorithm, key, nonce, plaintext, BENCHMARK_AAD))
                        else:
                            ct, tag = seal_bytes(backend, algorithm, key, nonce, plaintext, BENCHMARK_AAD)
                            series_args.append((backend, algorithm, key, nonce, ct, tag, BENCHMARK_AAD))

                    mean_ns = measure_batch(target_func, series_args)
                    series_means.append(mean_ns)

                    raw_records.append({
                        "backend": backend,
                        "algorithm": algorithm,
                        "size_bytes": size_bytes,
                        "operation": op_type,
                        "series_index": series_idx,
                        "mean_ns": mean_ns,
                    })

                # Агрегація статистики
                summary = summarize(series_means, size_bytes)
                key_name = f"{backend}_{algorithm}_{size_bytes}_{op_type}"
                aggregates[key_name] = {
                    "backend": backend,
                    "algorithm": algorithm,
                    "size_bytes": size_bytes,
                    "operation": op_type,
                    **summary,
                }

    # Запис raw.csv
    with open(raw_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["backend", "algorithm", "size_bytes", "operation", "series_index", "mean_ns"],
        )
        writer.writeheader()
        writer.writerows(raw_records)

    # Запис report.json
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(aggregates, f, indent=2, ensure_ascii=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Practice 2 symmetric benchmark")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        run_benchmark(args.output_dir)
    except NotImplementedError as exc:
        parser.exit(2, f"Практична 2: модуль вимірювань ще не реалізовано: {exc}\n")


if __name__ == "__main__":
    main()