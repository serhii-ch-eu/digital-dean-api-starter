"""Реалізуйте криптографічні адаптери без власних примітивів.

generate_keypair повертає (private, public). encrypt/decrypt приймають
profile, об'єкт відповідного ключа, bytes і keyword-only context.
Контекст: label для OAEP, label та AAD для RSA/AES, info для HPKE.
RSA/AES envelope: wrapped_key[384] || nonce[12] || ct_with_tag.
HPKE envelope: повернений Suite.encrypt enc || ct без перекодування.
"""
import secrets
from typing import Any

from cryptography.exceptions import InvalidKey, InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import AEAD, KDF, KEM, Suite

from app.security.asymmetric.profiles import CONTEXT, KEY_PROFILES, PROFILES


class DecryptionError(ValueError):
    """Єдина безпечна помилка відхилення криптографічного повідомлення."""


def _get_oaep_padding(label: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=label,
    )


def generate_keypair(key_profile: str) -> tuple[object, object]:
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")

    if key_profile == "rsa-2048":
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    elif key_profile == "rsa-3072":
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    elif key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()
    elif key_profile == "p256":
        private = ec.generate_private_key(ec.SECP256R1())
    else:
        raise ValueError("unsupported key profile")

    return private, private.public_key()


def _get_hpke_suite(profile: str) -> Suite:
    if profile == "hpke-x25519-aes256gcm":
        return Suite(KEM.X25519, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
    elif profile == "hpke-p256-aes256gcm":
        return Suite(KEM.P256, KDF.HKDF_SHA256, AEAD.AES_256_GCM)
    raise ValueError("unsupported encryption profile")


def encrypt(profile: str, public: object, message: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    if profile in ("rsa2048-oaep", "rsa3072-oaep"):
        expected_size = 2048 if profile == "rsa2048-oaep" else 3072
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size != expected_size:
            raise ValueError("key type or size mismatch for profile")
        
        oaep = _get_oaep_padding(context)
        return public.encrypt(message, oaep)

    elif profile == "rsa3072-oaep-aes256gcm":
        if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 3072:
            raise ValueError("key type or size mismatch for profile")

        aes_key = AESGCM.generate_key(bit_length=256)
        nonce = secrets.token_bytes(12)
        oaep = _get_oaep_padding(context)

        wrapped_key = public.encrypt(aes_key, oaep)
        ciphertext = AESGCM(aes_key).encrypt(nonce, message, context)

        # wrapped_key[384] || nonce[12] || ct_with_tag
        return wrapped_key + nonce + ciphertext

    elif profile in ("hpke-x25519-aes256gcm", "hpke-p256-aes256gcm"):
        suite = _get_hpke_suite(profile)
        return suite.encrypt(message, public, info=context)

    raise ValueError("unsupported encryption profile")


def _decrypt(profile: str, private: object, envelope: bytes, context: bytes) -> bytes:
    if profile in ("rsa2048-oaep", "rsa3072-oaep"):
        expected_size = 2048 if profile == "rsa2048-oaep" else 3072
        if not isinstance(private, rsa.RSAPrivateKey) or private.key_size != expected_size:
            raise ValueError("key type or size mismatch for profile")

        oaep = _get_oaep_padding(context)
        return private.decrypt(envelope, oaep)

    elif profile == "rsa3072-oaep-aes256gcm":
        if not isinstance(private, rsa.RSAPrivateKey) or private.key_size != 3072:
            raise ValueError("key type or size mismatch for profile")

        # wrapped_key[384] + nonce[12] + min AES-GCM tag[16]
        if len(envelope) < 384 + 12 + 16:
            raise ValueError("invalid envelope length")

        wrapped_key = envelope[:384]
        nonce = envelope[384:396]
        ciphertext = envelope[396:]

        oaep = _get_oaep_padding(context)
        aes_key = private.decrypt(wrapped_key, oaep)
        return AESGCM(aes_key).decrypt(nonce, ciphertext, context)

    elif profile in ("hpke-x25519-aes256gcm", "hpke-p256-aes256gcm"):
        suite = _get_hpke_suite(profile)
        return suite.decrypt(envelope, private, info=context)

    raise ValueError("unsupported encryption profile")


def decrypt(profile: str, private: object, envelope: bytes,
            *, context: bytes = CONTEXT) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")
    try:
        return _decrypt(profile, private, envelope, context)
    except (InvalidTag, InvalidKey, InvalidSignature, ValueError, TypeError) as exc:
        if isinstance(exc, DecryptionError):
            raise
        raise DecryptionError("decryption rejected") from exc