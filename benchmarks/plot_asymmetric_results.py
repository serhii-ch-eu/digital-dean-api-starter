
import json
from pathlib import Path

import matplotlib.pyplot as plt


root = Path(__file__).resolve().parents[1]
folder = root / "results" / "practice-03"

with (folder / "report.json").open(encoding="utf-8") as f:
    report = json.load(f)


# Graph 1. Key generation time
key_data = report["key_generation"]

labels = [item["key_profile"] for item in key_data]
times = [item["median_ns"] / 1_000_000 for item in key_data]

plt.figure(figsize=(10, 6))
plt.bar(labels, times)
plt.yscale("log")
plt.ylabel("Час генерації, мс (логарифмічна шкала)")
plt.title("Порівняння часу генерації ключів")
plt.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(folder / "key_generation.png", dpi=180)
plt.close()


# Graph 2. Hybrid encryption throughput
profiles = {
    "rsa3072-oaep-aes256gcm": "RSA-3072 + AES-GCM",
    "hpke-x25519-aes256gcm": "HPKE X25519",
    "hpke-p256-aes256gcm": "HPKE P-256",
}

plt.figure(figsize=(10, 6))

for profile, label in profiles.items():
    rows = sorted(
        (
            item["payload_bytes"] // 1024,
            item["throughput_mib_s"],
        )
        for item in report["results"]
        if item["profile"] == profile
        and item["operation"] == "encrypt"
    )

    if len(rows) != 3:
        raise ValueError(f"Missing measurements for {profile}")

    sizes, speeds = zip(*rows)
    plt.plot(sizes, speeds, marker="o", label=label)

plt.xscale("log", base=2)
plt.xticks([1, 64, 1024], ["1 KiB", "64 KiB", "1024 KiB"])
plt.xlabel("Розмір повідомлення")
plt.ylabel("Пропускна здатність, MiB/s")
plt.title("Швидкість гібридного шифрування")
plt.grid(alpha=0.3)
plt.legend()
plt.tight_layout()
plt.savefig(folder / "hybrid_throughput.png", dpi=180)
plt.close()

print("Created:", folder / "key_generation.png")
print("Created:", folder / "hybrid_throughput.png")
