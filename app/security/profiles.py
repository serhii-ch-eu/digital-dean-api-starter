"""Параметри визначеного навчального профілю, не універсальні межі схем."""

KEY_BYTES = {
    "AES-128-GCM": 16,
    "AES-256-GCM": 32,
    "ChaCha20-Poly1305": 32,
}
BACKENDS = ("cryptography", "pycryptodome")
NONCE_BYTES = 12
TAG_BYTES = 16


def validate_profile(algorithm: str, key: bytes, nonce: bytes) -> None:
    expected_size = KEY_BYTES.get(algorithm)

    if expected_size is None:
        raise ValueError("Unsupported algorithm")

    if len(key) != expected_size:
        raise ValueError("Invalid key length")

    if len(nonce) != NONCE_BYTES:
        raise ValueError("Invalid nonce length")

