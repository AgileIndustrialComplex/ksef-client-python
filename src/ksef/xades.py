"""Certificate (XAdES) authentication for KSeF 2.0.

Implements the flow documented in CIRFMF/ksef-api ``uwierzytelnianie.md``:

1. ``POST /auth/challenge`` — obtain a challenge (valid 10 minutes).
2. Build the ``AuthTokenRequest`` XML document (auth schema v2.0) containing
   the challenge, the context identifier (NIP / InternalId / NipVatUe), and
   the subject identifier type (``certificateSubject`` or
   ``certificateFingerprint``).
3. Sign the document with XAdES (enveloped signature) using an X.509
   certificate + private key — a qualified personal/seal certificate or a
   KSeF-issued certificate.
4. ``POST /auth/xades-signature`` with the signed XML.
5. Poll ``GET /auth/{referenceNumber}`` until code 200.
6. ``POST /auth/token/redeem`` for the access/refresh token pair.

XAdES signing requires the optional dependency ``signxml``
(``pip install ksef-client[xades]``); everything else is stdlib XML handling.

Self-signed certificates are accepted by KSeF **only** on the test environment.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol
from xml.etree import ElementTree as ET

if TYPE_CHECKING:  # pragma: no cover - typing only
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.x509 import Certificate

AUTH_NS = "http://ksef.mf.gov.pl/auth/token/2.0"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


class SubjectIdentifierType(StrEnum):
    """How the authenticating subject is identified to KSeF."""

    CERTIFICATE_SUBJECT = "certificateSubject"
    CERTIFICATE_FINGERPRINT = "certificateFingerprint"


class ContextIdentifierTypeV2(StrEnum):
    NIP = "nip"
    INTERNAL_ID = "internalId"
    NIP_VAT_UE = "nipVatUe"


class CertificateSource(Protocol):
    """A certificate + private key pair usable for XAdES signing."""

    @property
    def certificate(self) -> "Certificate": ...

    @property
    def private_key(self) -> "RSAPrivateKey": ...


@dataclass(frozen=True, slots=True)
class LoadedCertificate:
    """Simple value holder for a PEM/DER-loaded cert + key pair."""

    certificate: "Certificate"
    private_key: "RSAPrivateKey"

    @classmethod
    def from_pem(
        cls,
        cert_pem: str | bytes,
        key_pem: str | bytes,
        key_password: str | None = None,
    ) -> "LoadedCertificate":
        """Load from PEM strings/bytes (cert may be a PEM chain)."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        if isinstance(cert_pem, str):
            cert_pem = cert_pem.encode()
        if isinstance(key_pem, str):
            key_pem = key_pem.encode()
        password = key_password.encode() if key_password else None
        key = serialization.load_pem_private_key(key_pem, password=password)
        return cls(
            certificate=x509.load_pem_x509_certificate(cert_pem),
            private_key=key,  # type: ignore[arg-type]
        )

    @classmethod
    def generate_self_signed_test(
        cls,
        *,
        common_name: str = "Test User",
        serial_number: str = f"TINPL-{'0000000000'}",
        country: str = "PL",
    ) -> "LoadedCertificate":
        """Generate a self-signed test certificate (test environment only!).

        Mimics the reference clients' test-certificate helpers: serial number
        carries the identifier KSeF reads (e.g. ``TINPL-<NIP>`` for NIP-based
        subject identification).
        """
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
            ]
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        return cls(certificate=cert, private_key=key)

    def certificate_fingerprint(self) -> str:
        """SHA-256 fingerprint of the DER cert, hex without separators."""
        from cryptography.hazmat.primitives import hashes

        return self.certificate.fingerprint(hashes.SHA256()).hex()


def build_auth_token_request(
    challenge: str,
    context_identifier_type: ContextIdentifierTypeV2 | str,
    context_identifier_value: str,
    subject_identifier_type: SubjectIdentifierType | str,
    *,
    authorization_policy_xml: str | None = None,
) -> str:
    """Build the unsigned ``AuthTokenRequest`` XML document (schema v2.0)."""
    ET.register_namespace("", AUTH_NS)
    root = ET.Element(f"{{{AUTH_NS}}}AuthTokenRequest")

    ch = ET.SubElement(root, f"{{{AUTH_NS}}}Challenge")
    ch.text = challenge

    ctx = ET.SubElement(root, f"{{{AUTH_NS}}}ContextIdentifier")
    t = ET.SubElement(ctx, f"{{{AUTH_NS}}}{context_identifier_type}")
    t.text = context_identifier_value

    s = ET.SubElement(root, f"{{{AUTH_NS}}}SubjectIdentifierType")
    s.text = str(subject_identifier_type)

    if authorization_policy_xml:
        # raw passthrough for advanced cases (allowed IPs policy)
        root.append(ET.fromstring(authorization_policy_xml))

    ET.indent(root, space=" ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def sign_xades(
    unsigned_xml: str,
    cert: LoadedCertificate,
    *,
    key_password: str | None = None,
) -> str:
    """Sign ``unsigned_xml`` with an enveloped XAdES signature.

    Uses ``signxml``'s XAdES support (exclusive c14n, RSA-SHA256,
    enveloped signature referencing the whole document).
    """
    try:
        from lxml import etree  # type: ignore[import-untyped]  # signxml requires lxml trees
        from signxml.xades import XAdESSigner  # type: ignore[attr-defined]  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "XAdES signing requires the optional 'signxml' dependency "
            "(pip install ksef-client[xades])"
        ) from exc

    parser = etree.XMLParser(remove_blank_text=False)
    tree = etree.fromstring(unsigned_xml.encode("utf-8"), parser=parser)
    signer = XAdESSigner(
        digest_algorithm="sha256",
        signature_algorithm="rsa-sha256",
    )
    signed = signer.sign(
        data=tree,
        key=cert.private_key,
        cert=[cert.certificate],
        key_name=None,
    )
    from lxml.etree import tostring  # type: ignore[import-untyped]

    result: str = tostring(signed, encoding="unicode")
    return result


__all__ = [
    "AUTH_NS",
    "ContextIdentifierTypeV2",
    "LoadedCertificate",
    "SubjectIdentifierType",
    "build_auth_token_request",
    "sign_xades",
]
