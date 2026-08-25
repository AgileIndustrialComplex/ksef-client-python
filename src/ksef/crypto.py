"""KSeF 2.0 cryptography.

Two protocol-mandated operations, both implemented on top of
``cryptography`` (the package's only runtime dependency):

1. **Token encryption** (auth): the KSeF token is encrypted with the Ministry
   of Finance public key using RSA-OAEP with SHA-256, over the payload
   ``token|timestamp`` (Base64 output).
2. **Invoice encryption** (sessions): each session uses a random AES-256 key
   and IV. Invoice XML is encrypted with AES-256-CBC; the AES key itself is
   RSA-OAEP-SHA256-encrypted with the MoF public key and both values are sent
   Base64-encoded in ``encryption``.
"""

from __future__ import annotations

import os
from base64 import b64decode, b64encode
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import x509

from ksef.models import EncryptionInfo, SessionEncryption


def _load_public_key(public_key_pem: str | bytes) -> rsa.RSAPublicKey:
    if isinstance(public_key_pem, str):
        public_key_pem = public_key_pem.encode("utf-8")
    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("Expected an RSA public key")
    return key


def encrypt_token(token: str, timestamp: str, public_key_pem: str | bytes) -> str:
    """Encrypt ``token|timestamp`` for POST /auth/ksef-token (Base64)."""
    key = _load_public_key(public_key_pem)
    payload = f"{token}|{timestamp}".encode("utf-8")
    encrypted = key.encrypt(
        payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return b64encode(encrypted).decode("ascii")


def new_session_encryption(public_key_pem: str | bytes, *, public_key_id: str | None = None) -> SessionEncryption:
    """Generate a fresh AES-256 key/IV pair and its API representation."""
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    key = _load_public_key(public_key_pem)
    encrypted_key = key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    api_view = EncryptionInfo(
        encrypted_symmetric_key=b64encode(encrypted_key).decode("ascii"),
        initialization_vector=b64encode(iv).decode("ascii"),
        public_key_id=public_key_id,
    )
    return SessionEncryption(aes_key=aes_key, iv=iv, api_view=api_view)


@dataclass(frozen=True, slots=True)
class EncryptedInvoice:
    encrypted_body_b64: str
    sha256_base64: str


def encrypt_invoice(xml_bytes: bytes, encryption: SessionEncryption) -> EncryptedInvoice:
    """AES-256-CBC encrypt invoice XML and compute its SHA-256 hash.

    Per the KSeF spec the hash is computed on the *plaintext* XML and is sent
    Base64-encoded; the ciphertext body is Base64-encoded separately.
    """
    import hashlib

    padder_len = 16 - (len(xml_bytes) % 16)
    padded = xml_bytes + bytes([padder_len]) * padder_len
    cipher = Cipher(algorithms.AES(encryption.aes_key), modes.CBC(encryption.iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    digest = hashlib.sha256(xml_bytes).digest()
    return EncryptedInvoice(
        encrypted_body_b64=b64encode(ct).decode("ascii"),
        sha256_base64=b64encode(digest).decode("ascii"),
    )


def decrypt_invoice(body_b64: str, encryption: SessionEncryption) -> bytes:
    """Inverse of :func:`encrypt_invoice` (used when downloading invoices)."""
    ct = b64decode(body_b64)
    cipher = Cipher(algorithms.AES(encryption.aes_key), modes.CBC(encryption.iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    pad_len = padded[-1]
    if not 1 <= pad_len <= 16 or padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return padded[:-pad_len]


def sign_xades_placeholder() -> None:  # pragma: no cover
    """Reserved: XAdES signing for certificate/profile auth flows."""
    raise NotImplementedError(
        "XAdES signing requires a qualified seal/signature; use token auth."
    )


__all__ = [
    "EncryptedInvoice",
    "decrypt_invoice",
    "encrypt_invoice",
    "encrypt_token",
    "new_session_encryption",
    "pkcs7",
    "x509",
]
