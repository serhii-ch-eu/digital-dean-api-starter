
"""Asymmetric and hybrid encryption adapters for Practice 03."""

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    padding,
    rsa,
    x25519,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hpke import (
    Suite,
    KEM,
    KDF,
    AEAD,
)

from app.security.asymmetric.profiles import (
    CONTEXT,
    PROFILES,
    KEY_PROFILES,
)


class DecryptionError(ValueError):
    """Generic error for rejected encrypted messages."""


def generate_keypair(key_profile: str) -> tuple[object, object]:
    if key_profile not in KEY_PROFILES:
        raise ValueError("unsupported key profile")

    if key_profile == "rsa-2048":
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    elif key_profile == "rsa-3072":
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,
        )

    elif key_profile == "x25519":
        private = x25519.X25519PrivateKey.generate()

    elif key_profile == "p256":
        private = ec.generate_private_key(
            ec.SECP256R1()
        )

    else:
        raise ValueError("unsupported key profile")

    return private, private.public_key()


def _check_key(
    profile: str,
    key: object,
    *,
    public: bool,
) -> None:
    key_profile = PROFILES[profile].key_profile

    if key_profile.startswith("rsa-"):
        key_type = (
            rsa.RSAPublicKey
            if public
            else rsa.RSAPrivateKey
        )

        expected_bits = int(key_profile.split("-")[1])

        if not isinstance(key, key_type):
            raise ValueError("incorrect RSA key type")

        if key.key_size != expected_bits:
            raise ValueError("incorrect RSA key size")

    elif key_profile == "x25519":
        key_type = (
            x25519.X25519PublicKey
            if public
            else x25519.X25519PrivateKey
        )

        if not isinstance(key, key_type):
            raise ValueError("incorrect X25519 key")

    elif key_profile == "p256":
        key_type = (
            ec.EllipticCurvePublicKey
            if public
            else ec.EllipticCurvePrivateKey
        )

        if not isinstance(key, key_type):
            raise ValueError("incorrect P-256 key type")

        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("incorrect elliptic curve")


def _oaep(context: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()
        ),
        algorithm=hashes.SHA256(),
        label=context,
    )


def _hpke_suite(profile: str) -> Suite:
    kem = (
        KEM.X25519
        if profile == "hpke-x25519-aes256gcm"
        else KEM.P256
    )

    return Suite(
        kem,
        KDF.HKDF_SHA256,
        AEAD.AES_256_GCM,
    )


def encrypt(
    profile: str,
    public: object,
    message: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    if not isinstance(message, bytes):
        raise ValueError("message must be bytes")

    if not isinstance(context, bytes):
        raise ValueError("context must be bytes")

    _check_key(profile, public, public=True)

    if profile in (
        "rsa2048-oaep",
        "rsa3072-oaep",
    ):
        max_bytes = public.key_size // 8 - 2 * 32 - 2

        if len(message) > max_bytes:
            raise ValueError("RSA OAEP message too large")

        return public.encrypt(
            message,
            _oaep(context),
        )

    if profile == "rsa3072-oaep-aes256gcm":
        aes_key = AESGCM.generate_key(
            bit_length=256
        )

        nonce = secrets.token_bytes(12)

        wrapped_key = public.encrypt(
            aes_key,
            _oaep(context),
        )

        ciphertext = AESGCM(aes_key).encrypt(
            nonce,
            message,
            context,
        )

        return wrapped_key + nonce + ciphertext

    suite = _hpke_suite(profile)

    return suite.encrypt(
        message,
        public,
        info=context,
    )


def _decrypt(
    profile: str,
    private: object,
    envelope: bytes,
    context: bytes,
) -> bytes:
    if not isinstance(envelope, bytes):
        raise ValueError("invalid envelope")

    if not isinstance(context, bytes):
        raise ValueError("invalid context")

    _check_key(profile, private, public=False)

    if profile in (
        "rsa2048-oaep",
        "rsa3072-oaep",
    ):
        expected_length = private.key_size // 8

        if len(envelope) != expected_length:
            raise ValueError(
                "invalid RSA envelope length"
            )

        return private.decrypt(
            envelope,
            _oaep(context),
        )

    if profile == "rsa3072-oaep-aes256gcm":
        wrapped_length = 384
        nonce_length = 12
        tag_length = 16

        minimum_length = (
            wrapped_length
            + nonce_length
            + tag_length
        )

        if len(envelope) < minimum_length:
            raise ValueError(
                "invalid hybrid envelope length"
            )

        wrapped_key = envelope[:wrapped_length]

        nonce = envelope[
            wrapped_length:
            wrapped_length + nonce_length
        ]

        ciphertext = envelope[
            wrapped_length + nonce_length:
        ]

        aes_key = private.decrypt(
            wrapped_key,
            _oaep(context),
        )

        if len(aes_key) != 32:
            raise ValueError(
                "invalid AES key length"
            )

        return AESGCM(aes_key).decrypt(
            nonce,
            ciphertext,
            context,
        )

    encapsulated_length = (
        32
        if profile == "hpke-x25519-aes256gcm"
        else 65
    )

    if len(envelope) < encapsulated_length + 16:
        raise ValueError(
            "invalid HPKE envelope length"
        )

    suite = _hpke_suite(profile)

    return suite.decrypt(
        envelope,
        private,
        info=context,
    )


def decrypt(
    profile: str,
    private: object,
    envelope: bytes,
    *,
    context: bytes = CONTEXT,
) -> bytes:
    if profile not in PROFILES:
        raise ValueError("unsupported encryption profile")

    try:
        return _decrypt(
            profile,
            private,
            envelope,
            context,
        )

    except (InvalidTag, ValueError, TypeError):
        raise DecryptionError(
            "decryption rejected"
        ) from None
