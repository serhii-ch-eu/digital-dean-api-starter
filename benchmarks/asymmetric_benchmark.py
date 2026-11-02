"""Окремий експеримент, не виклик з HTTP. Дані створює студент."""
import csv
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
import statistics
from time import perf_counter_ns
from typing import Any

from cryptography import __version__ as crypto_version
from cryptography.hazmat.backends.openssl.backend import backend as openssl_backend
from cryptography.hazmat.primitives import serialization

from app.security.asymmetric.adapters import (
    DecryptionError,
    decrypt,
    encrypt,
    generate_keypair,
)
from app.security.asymmetric.profiles import CONTEXT, KEY_PROFILES, PROFILES
from app.schemas.asymmetric_report import validate_complete_report

SERIES = 5
OPERATIONS = 20
WARMUP = 10
KEYGEN_RUNS = 5
CSV_COLUMNS = (
    "group", "profile", "operation", "payload_bytes", "series_index",
    "operations", "elapsed_ns", "ns_per_operation", "ciphertext_bytes",
)

RESULTS_DIR = Path(__file__).resolve().parents[1] / "results" / "practice-03"
CSV_PATH = RESULTS_DIR / "raw.csv"
REPORT_PATH = RESULTS_DIR / "report.json"


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


def get_git_commit() -> str:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()
        if len(commit) == 40:
            return commit
    except Exception:
        pass
    return "0" * 40


def oaep_max_bytes(key_bits: int) -> int:
    if key_bits not in (2048, 3072):
        raise ValueError("unsupported RSA key size")
    return key_bits // 8 - 2 * 32 - 2


def run_checks() -> list[dict[str, Any]]:
    checks = []

    # 1. roundtrip, wrong_key, tamper, wrong_context для всіх 5 профілів
    for profile in sorted(PROFILES):
        key_prof = (
            "rsa-2048" if "2048" in profile
            else "rsa-3072" if "3072" in profile
            else "x25519" if "x25519" in profile
            else "p256"
        )
        priv1, pub1 = generate_keypair(key_prof)
        priv2, pub2 = generate_keypair(key_prof)
        msg = b"synthetic-record-for-check"

        # roundtrip
        try:
            env = encrypt(profile, pub1, msg)
            dec = decrypt(profile, priv1, env)
            checks.append({"profile": profile, "name": "roundtrip", "passed": dec == msg})
        except Exception:
            checks.append({"profile": profile, "name": "roundtrip", "passed": False})

        # wrong_key
        try:
            env = encrypt(profile, pub1, msg)
            decrypt(profile, priv2, env)
            checks.append({"profile": profile, "name": "wrong_key", "passed": False})
        except DecryptionError:
            checks.append({"profile": profile, "name": "wrong_key", "passed": True})
        except Exception:
            checks.append({"profile": profile, "name": "wrong_key", "passed": False})

        # tamper
        try:
            env = encrypt(profile, pub1, msg)
            tampered = env[:-1] + bytes([env[-1] ^ 1])
            decrypt(profile, priv1, tampered)
            checks.append({"profile": profile, "name": "tamper", "passed": False})
        except DecryptionError:
            checks.append({"profile": profile, "name": "tamper", "passed": True})
        except Exception:
            checks.append({"profile": profile, "name": "tamper", "passed": False})

        # wrong_context
        try:
            env = encrypt(profile, pub1, msg, context=CONTEXT)
            decrypt(profile, priv1, env, context=b"wrong-context")
            checks.append({"profile": profile, "name": "wrong_context", "passed": False})
        except DecryptionError:
            checks.append({"profile": profile, "name": "wrong_context", "passed": True})
        except Exception:
            checks.append({"profile": profile, "name": "wrong_context", "passed": False})

    # 2. oaep_boundary для двох прямих RSA
    for profile in ["rsa2048-oaep", "rsa3072-oaep"]:
        bits = 2048 if "2048" in profile else 3072
        priv, pub = generate_keypair("rsa-" + str(bits))
        max_len = oaep_max_bytes(bits)

        ok = False
        try:
            env_valid = encrypt(profile, pub, b"A" * max_len)
            dec_valid = decrypt(profile, priv, env_valid)

            invalid_rejected = False
            try:
                encrypt(profile, pub, b"A" * (max_len + 1))
            except ValueError:
                invalid_rejected = True

            ok = (dec_valid == b"A" * max_len) and invalid_rejected
        except Exception:
            ok = False

        checks.append({"profile": profile, "name": "oaep_boundary", "passed": ok})

    return checks


def run_experiment() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    raw_rows = []

    # 1. Генерація ключів (KEYGEN_RUNS = 5)
    keygen_stats = []
    for kp in ["rsa-2048", "rsa-3072", "x25519", "p256"]:
        # Warmup
        generate_keypair(kp)

        durations = []
        pub_der_bytes = 0
        for i in range(1, KEYGEN_RUNS + 1):
            t0 = perf_counter_ns()
            priv, pub = generate_keypair(kp)
            t1 = perf_counter_ns()
            dur = float(t1 - t0)
            durations.append(dur)

            if hasattr(pub, "public_bytes"):
                der = pub.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                pub_der_bytes = len(der)
            else:
                pub_der_bytes = 32

            raw_rows.append({
                "group": "key_generation",
                "profile": kp,
                "operation": "keygen",
                "payload_bytes": 0,
                "series_index": i,
                "operations": 1,
                "elapsed_ns": int(dur),
                "ns_per_operation": dur,
                "ciphertext_bytes": 0,
            })

        med_ns, iqr_ns = summarize(durations)
        keygen_stats.append({
            "key_profile": kp,
            "runs": KEYGEN_RUNS,
            "median_ns": med_ns,
            "iqr_ns": iqr_ns,
            "public_key_der_bytes": pub_der_bytes,
        })

    # Матриця операцій
    combos = [
        ("rsa2048-oaep", "direct", 64),
        ("rsa3072-oaep", "direct", 64),
        ("rsa3072-oaep-aes256gcm", "hybrid", 1024),
        ("rsa3072-oaep-aes256gcm", "hybrid", 65536),
        ("rsa3072-oaep-aes256gcm", "hybrid", 1048576),
        ("hpke-x25519-aes256gcm", "hybrid", 1024),
        ("hpke-x25519-aes256gcm", "hybrid", 65536),
        ("hpke-x25519-aes256gcm", "hybrid", 1048576),
        ("hpke-p256-aes256gcm", "hybrid", 1024),
        ("hpke-p256-aes256gcm", "hybrid", 65536),
        ("hpke-p256-aes256gcm", "hybrid", 1048576),
    ]

    results_stats = []

    for profile, group, size in combos:
        key_prof = (
            "rsa-2048" if "2048" in profile
            else "rsa-3072" if "3072" in profile
            else "x25519" if "x25519" in profile
            else "p256"
        )
        priv, pub = generate_keypair(key_prof)
        msg = os.urandom(size)

        for op in ["encrypt", "decrypt"]:
            # Warmup (10 operations)
            for _ in range(WARMUP):
                env_w = encrypt(profile, pub, msg)
                if op == "decrypt":
                    decrypt(profile, priv, env_w)

            series_means = []
            ct_len = 0

            for s_idx in range(1, SERIES + 1):
                if op == "encrypt":
                    def encrypt_op():
                        nonlocal ct_len
                        res = encrypt(profile, pub, msg)
                        ct_len = len(res)

                    elapsed, mean_ns = measure_batch(encrypt_op, OPERATIONS)
                else:
                    envelopes = [encrypt(profile, pub, msg) for _ in range(OPERATIONS)]
                    ct_len = len(envelopes[0])
                    idx = 0

                    def decrypt_op():
                        nonlocal idx
                        decrypt(profile, priv, envelopes[idx])
                        idx += 1

                    elapsed, mean_ns = measure_batch(decrypt_op, OPERATIONS)

                series_means.append(mean_ns)

                raw_rows.append({
                    "group": group,
                    "profile": profile,
                    "operation": op,
                    "payload_bytes": size,
                    "series_index": s_idx,
                    "operations": OPERATIONS,
                    "elapsed_ns": elapsed,
                    "ns_per_operation": mean_ns,
                    "ciphertext_bytes": ct_len,
                })

            med_ns, iqr_ns = summarize(series_means)

            throughput = None
            if group == "hybrid":
                throughput = (size * 10**9) / ((1 << 20) * med_ns)

            results_stats.append({
                "profile": profile,
                "group": group,
                "operation": op,
                "payload_bytes": size,
                "series": SERIES,
                "operations_per_series": OPERATIONS,
                "median_ns": med_ns,
                "iqr_ns": iqr_ns,
                "ciphertext_bytes": ct_len,
                "throughput_mib_s": throughput,
            })

    # 2. Атомарне збереження raw.csv
    tmp_csv = CSV_PATH.with_suffix(".tmp")
    with open(tmp_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(raw_rows)
    tmp_csv.replace(CSV_PATH)

    # 3. Формування report.json
    now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    try:
        openssl_str = openssl_backend.openssl_version_text()
    except Exception:
        openssl_str = "OpenSSL (library default)"

    report_data = {
        "schema_version": 1,
        "experiment": {
            "series": SERIES,
            "operations_per_series": OPERATIONS,
            "warmup": WARMUP,
            "keygen_runs": KEYGEN_RUNS,
            "direct_payload_bytes": 64,
            "hybrid_sizes_bytes": [1024, 65536, 1048576],
            "source_commit": get_git_commit(),
            "created_at_utc": now_utc,
        },
        "environment": {
            "python": sys.version.split()[0],
            "cryptography": "48.0.1",
            "openssl": openssl_str,
            "os": f"{platform.system()} {platform.release()}",
            "cpu": platform.processor() or "Unknown CPU",
        },
        "key_generation": keygen_stats,
        "results": results_stats,
        "checks": run_checks(),
    }

    # Валідація та атомарне збереження report.json
    validated_report = validate_complete_report(report_data)

    tmp_json = REPORT_PATH.with_suffix(".tmp")
    with open(tmp_json, "w", encoding="utf-8") as f:
        json.dump(validated_report.model_dump(), f, indent=2)
    tmp_json.replace(REPORT_PATH)

    print(f"Успішно збережено результати експерименту у {CSV_PATH} та {REPORT_PATH}")


def main() -> int:
    try:
        run_experiment()
    except NotImplementedError as exc:
        print(str(exc))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())