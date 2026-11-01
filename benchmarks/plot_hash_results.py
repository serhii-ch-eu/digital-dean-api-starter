"""Побудова графіків за фактичними результатами практичної роботи 4."""
import csv
import json
from collections import Counter, defaultdict
from math import isclose
from pathlib import Path
from statistics import median, quantiles

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter


ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "results" / "practice-04"
REPORT_PATH = RESULTS_DIR / "report.json"
RAW_PATH = RESULTS_DIR / "raw.csv"
AVALANCHE_PATH = RESULTS_DIR / "avalanche.csv"
ALGORITHMS = (
    "sha256", "sha512", "sha3-256", "blake2b-256", "blake2s-256", "md5", "sha1"
)
ALGORITHM_LABELS = {
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "sha3-256": "SHA3-256",
    "blake2b-256": "BLAKE2b-256",
    "blake2s-256": "BLAKE2s-256",
    "md5": "MD5",
    "sha1": "SHA-1",
}


def _load_inputs() -> tuple[dict, list[dict], list[dict]]:
    with REPORT_PATH.open("r", encoding="utf-8") as stream:
        report = json.load(stream)
    with RAW_PATH.open("r", newline="", encoding="utf-8") as stream:
        raw_rows = list(csv.DictReader(stream))
    with AVALANCHE_PATH.open("r", newline="", encoding="utf-8") as stream:
        avalanche_rows = list(csv.DictReader(stream))

    available = [row["algorithm"] for row in report["algorithms"] if row["available"]]
    if available != list(ALGORITHMS):
        raise ValueError("Звіт має містити сім доступних алгоритмів у визначеному порядку")
    if len(report["results"]) != 56 or len(raw_rows) != 280:
        raise ValueError("Кількість агрегованих або сирих вимірювань не відповідає експерименту")
    if len(report["avalanche"]) != 7 or len(avalanche_rows) != 700:
        raise ValueError("Кількість результатів лавинного експерименту не відповідає очікуваній")

    raw_groups = defaultdict(list)
    for row in raw_rows:
        key = (row["algorithm"], row["mode"], int(row["payload_bytes"]))
        raw_groups[key].append(float(row["ns_per_op"]))
    for result in report["results"]:
        key = (result["algorithm"], result["mode"], result["payload_bytes"])
        if key not in raw_groups or len(raw_groups[key]) != 5:
            raise ValueError("Сирі вимірювання не покривають усі п'ять серій")
        q1, _, q3 = quantiles(raw_groups[key], n=4, method="inclusive")
        if not isclose(result["median_ns"], median(raw_groups[key]), rel_tol=1e-9):
            raise ValueError("Медіана звіту не відповідає сирим вимірюванням")
        if not isclose(result["iqr_ns"], q3 - q1, rel_tol=1e-9, abs_tol=1e-9):
            raise ValueError("IQR звіту не відповідає сирим вимірюванням")

    avalanche_counts = Counter(row["algorithm"] for row in avalanche_rows)
    if any(avalanche_counts[name] != 100 for name in ALGORITHMS):
        raise ValueError("Для кожного алгоритму мають бути 100 лавинних випробувань")
    avalanche_by_algorithm = {row["algorithm"]: row for row in report["avalanche"]}
    for name in ALGORITHMS:
        raw_mean = sum(float(row["fraction"]) for row in avalanche_rows
                       if row["algorithm"] == name) / 100
        summary = avalanche_by_algorithm[name]
        if summary["trials"] != 100 or not isclose(
                summary["mean_fraction"], raw_mean, rel_tol=1e-9, abs_tol=1e-12):
            raise ValueError("Середня частка у звіті не відповідає лавинним випробуванням")

    return report, raw_rows, avalanche_rows


def _plot_performance(report: dict) -> Path:
    results = [row for row in report["results"] if row["payload_bytes"] == 1048576]
    by_key = {(row["algorithm"], row["mode"]): row for row in results}
    if len(results) != 14 or len(by_key) != 14:
        raise ValueError("Для графіка швидкодії потрібні 14 агрегатів для повідомлення 1 МіБ")

    labels = [ALGORITHM_LABELS[name] for name in ALGORITHMS]
    whole = [by_key[(name, "whole")]["throughput_mib_s"] for name in ALGORITHMS]
    chunked = [by_key[(name, "chunked")]["throughput_mib_s"] for name in ALGORITHMS]
    positions = list(range(len(ALGORITHMS)))
    width = 0.38

    fig, ax = plt.subplots(figsize=(12, 6.5))
    ax.bar([position - width / 2 for position in positions], whole, width,
           label="Цілим повідомленням (whole)", color="#2563eb")
    ax.bar([position + width / 2 for position in positions], chunked, width,
           label="Блоками (chunked)", color="#f97316")
    ax.set_title("Пропускна здатність алгоритмів для повідомлення 1 МіБ")
    ax.set_xlabel("Алгоритм хешування")
    ax.set_ylabel("Пропускна здатність, МіБ/с")
    ax.set_xticks(positions, labels)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.set_axisbelow(True)
    ax.legend(title="Режим обробки")
    fig.tight_layout()
    destination = RESULTS_DIR / "hash_performance.png"
    fig.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return destination


def _plot_avalanche(report: dict) -> Path:
    by_algorithm = {row["algorithm"]: row for row in report["avalanche"]}
    if set(by_algorithm) != set(ALGORITHMS):
        raise ValueError("Звіт має містити лавинний результат для кожного алгоритму")
    fractions = [by_algorithm[name]["mean_fraction"] for name in ALGORITHMS]
    labels = [ALGORITHM_LABELS[name] for name in ALGORITHMS]
    positions = list(range(len(ALGORITHMS)))

    fig, ax = plt.subplots(figsize=(11, 6.5))
    bars = ax.bar(positions, fractions, color="#0f766e", width=0.68,
                  label="Середня частка змінених бітів")
    ax.axhline(0.5, color="#dc2626", linestyle="--", linewidth=1.7,
               label="Орієнтир 0,5")
    ax.set_title("Середня частка змінених бітів у лавинному досліді")
    ax.set_xlabel("Алгоритм хешування")
    ax.set_ylabel("Частка змінених бітів у хеші")
    ax.set_ylim(0, 1)
    ax.set_xticks(positions, labels)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:g}".replace(".", ",")))
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    ax.set_axisbelow(True)
    ax.legend()
    for bar, fraction in zip(bars, fractions):
        ax.annotate(f"{fraction:.4f}".replace(".", ","),
                    (bar.get_x() + bar.get_width() / 2, fraction),
                    xytext=(0, 5), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8)
    fig.text(
        0.5, 0.015,
        "100 одно-бітних змін на алгоритм. Результати не є оцінкою криптографічної стійкості.",
        ha="center", va="bottom", fontsize=9,
    )
    fig.tight_layout(rect=(0, 0.055, 1, 1))
    destination = RESULTS_DIR / "hash_avalanche.png"
    fig.savefig(destination, dpi=180, bbox_inches="tight")
    plt.close(fig)
    return destination


def main() -> None:
    report, _raw_rows, _avalanche_rows = _load_inputs()
    created = (_plot_performance(report), _plot_avalanche(report))
    for path in created:
        print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
