"""Unit tests for the ``ksef-client gen-cert`` CLI generation logic.

Generation is tested in-memory (no disk writes, no network) so the suite stays
hermetic; the disk-write paths are thin wrappers around serialization that the
live/env-integration work covers.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from ksef.cli import (
    _serial_number_oid,
    generate_keypair,
    self_signed_certificate,
)


def test_serial_number_oid_for_pl_prefixes_tinpl():
    assert _serial_number_oid("PL", "5265877635") == "TINPL-5265877635"


def test_serial_number_oid_non_pl_prepends_country():
    assert _serial_number_oid("DE", "12345") == "DE-12345"


def test_generate_keypair_default_size_is_rsa_2048():
    key = generate_keypair(2048)
    assert key.key_size == 2048
    assert key.public_key().key_size == 2048


def test_self_signed_certificate_matches_key_and_subject():
    key = generate_keypair(2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "Test"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, "TINPL-1234567890"),
        ]
    )
    cert = self_signed_certificate(key, name, days=30)

    assert cert.issuer == cert.subject  # self-signed
    assert cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value == "TINPL-1234567890"
    # the public key matches the generated keypair
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    # basicConstraints CA:false
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    # validity window (UTC accessors avoid the naive-datetime deprecation)
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 30


def test_cert_and_key_serialize_to_loadable_pem():
    key = generate_keypair(2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "T")])
    cert = self_signed_certificate(key, name, days=365)

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

    # both load back without error — matches LoadedCertificate.from_pem / CLI write
    re_cert = x509.load_pem_x509_certificate(cert_pem)
    re_key = serialization.load_pem_private_key(key_pem, None)
    assert re_cert.public_key().public_numbers() == re_key.public_key().public_numbers()  # type: ignore[union-attr]