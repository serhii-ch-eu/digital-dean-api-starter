
import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt

folder = Path("results/practice-02")
report = json.loads(
    (folder / "report.json").read_text(encoding="utf-8")
)

results = report["results"]
sizes = [1024, 65536, 1048576]

for operation in ("encrypt", "decrypt"):
    fig, ax = plt.subplots(figsize=(11, 6))

    for backend in ("cryptography", "pycryptodome"):
        for algorithm in (
            "AES-128-GCM",
            "AES-256-GCM",
            "ChaCha20-Poly1305",
        ):
            rows = [
                row for row in results
                if row["backend"] == backend
                and row["algorithm"] == algorithm
                and row["operation"] == operation
            ]

            rows.sort(key=lambda row: row["size_bytes"])

            assert len(rows) == 3

            speeds = [
                row["throughput_mib_s"]
                for row in rows
            ]

            ax.plot(
                sizes,
                speeds,
                marker="o",
                label=f"{backend} / {algorithm}",
            )

    ax.set_xscale("log", base=2)
    ax.set_xticks(sizes)
    ax.set_xticklabels(["1 KiB", "64 KiB", "1 MiB"])
    ax.set_xlabel("Message size")
    ax.set_ylabel("Throughput (MiB/s)")

    title = (
        "Encryption throughput"
        if operation == "encrypt"
        else "Authenticated decryption throughput"
    )

    ax.set_title(title + " - median of 5 series")
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8)

    fig.tight_layout()
    fig.savefig(
        folder / f"{operation}_throughput.png",
        dpi=180,
    )
    plt.close(fig)

fields = [
    "backend",
    "algorithm",
    "size_bytes",
    "operation",
    "median_ns",
    "iqr_ns",
    "throughput_mib_s",
]

with (folder / "summary.csv").open(
    "w", newline="", encoding="utf-8"
) as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()

    for row in results:
        writer.writerow({
            field: row[field] for field in fields
        })

print("Created 2 graphs and summary.csv")
