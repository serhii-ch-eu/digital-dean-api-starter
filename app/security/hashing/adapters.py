"""Реалізуйте бібліотечне хешування; не пишіть власних криптопримітивів."""
from app.security.hashing.profiles import CHUNK_BYTES, PROFILES, make_hasher


def prepare_operation(algorithm: str, data: bytes, mode: str = "whole"):
    """Prepare reusable input chunks and return a fresh-hasher operation."""
    if not isinstance(algorithm, str):
        raise TypeError("algorithm must be a string")
    if algorithm not in PROFILES:
        raise ValueError("unknown hash profile")
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if mode not in ("whole", "chunked"):
        raise ValueError("mode must be 'whole' or 'chunked'")

    if mode == "whole":
        chunks = (data,)
    else:
        chunks = tuple(data[offset:offset + CHUNK_BYTES]
                       for offset in range(0, len(data), CHUNK_BYTES))

    def operation() -> bytes:
        hasher = make_hasher(algorithm)
        for chunk in chunks:
            hasher.update(chunk)
        return hasher.digest()

    return operation


def hash_bytes(algorithm: str, data: bytes, mode: str = "whole") -> bytes:
    return prepare_operation(algorithm, data, mode)()


def hamming_bits(left: bytes, right: bytes) -> int:
    if not isinstance(left, bytes) or not isinstance(right, bytes):
        raise TypeError("hashes must be bytes")
    if not left or not right:
        raise ValueError("hashes must be non-empty")
    if len(left) != len(right):
        raise ValueError("hashes must have equal lengths")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))
