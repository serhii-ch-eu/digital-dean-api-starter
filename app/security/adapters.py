
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    ChaCha20Poly1305,
)
from Crypto.Cipher import AES, ChaCha20_Poly1305

from app.security.profiles import validate_profile


class CiphertextError(Exception):
    pass


def seal_bytes(backend, algorithm, key, nonce, data, aad):
    validate_profile(algorithm, key, nonce)
    is_aes = algorithm.startswith("AES-")

    if backend == "cryptography":
        factory = AESGCM if is_aes else ChaCha20Poly1305
        combined = factory(key).encrypt(nonce, data, aad)
        return combined[:-16], combined[-16:]

    if backend == "pycryptodome":
        if is_aes:
            cipher = AES.new(
                key, AES.MODE_GCM, nonce=nonce, mac_len=16
            )
        else:
            cipher = ChaCha20_Poly1305.new(
                key=key, nonce=nonce
            )

        cipher.update(aad)
        return cipher.encrypt_and_digest(data)

    raise ValueError("Unsupported backend")


def open_bytes(backend, algorithm, key, nonce, ct, tag, aad):
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

        if is_aes:
            cipher = AES.new(
                key, AES.MODE_GCM, nonce=nonce, mac_len=16
            )
        else:
            cipher = ChaCha20_Poly1305.new(
                key=key, nonce=nonce
            )

        cipher.update(aad)
        return cipher.decrypt_and_verify(ct, tag)

    except (InvalidTag, ValueError) as exc:
        raise CiphertextError("Verification failed") from exc
