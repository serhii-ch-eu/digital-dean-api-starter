"""Спільний контракт для cryptography та PyCryptodome без відкритого fallback."""

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM, ChaCha20Poly1305,
)
from Crypto.Cipher import AES, ChaCha20_Poly1305
from cryptography.exceptions import InvalidTag
from app.security.profiles import validate_profile


class CiphertextError(Exception):
    """Повідомлення не пройшло перевірку автентичності."""
    pass


def seal_bytes(backend: str, algorithm: str, key: bytes, nonce: bytes, data: bytes, aad: bytes):
    """Повернути (ciphertext, tag); перевірити профіль і бібліотеку."""
    validate_profile(algorithm, key, nonce)
    is_aes = algorithm.startswith("AES-")
    
    if backend == "cryptography":
        factory = AESGCM if is_aes else ChaCha20Poly1305
        combined = factory(key).encrypt(nonce, data, aad)
        return combined[:-16], combined[-16:]
        
    if backend == "pycryptodome":
        cipher = (
            AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
            if is_aes else
            ChaCha20_Poly1305.new(key=key, nonce=nonce)
        )
        cipher.update(aad)
        return cipher.encrypt_and_digest(data)
        
    raise ValueError("Unsupported backend")


def open_bytes(backend: str, algorithm: str, key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes) -> bytes:
    """Видати байти тільки після успішної перевірки повного тега."""
    validate_profile(algorithm, key, nonce)
    if backend not in {"cryptography", "pycryptodome"}:
        raise ValueError("Unsupported backend")
    if len(tag) != 16:
        raise CiphertextError("Verification failed")
        
    is_aes = algorithm.startswith("AES-")
    try:
        if backend == "cryptography":
            factory = AESGCM if is_aes else ChaCha20Poly1305
            return factory(key).decrypt(nonce, ct + tag, aad)
            
        cipher = (
            AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
            if is_aes else
            ChaCha20_Poly1305.new(key=key, nonce=nonce)
        )
        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)
    except (InvalidTag, ValueError) as exc:
        raise CiphertextError("Verification failed") from exc