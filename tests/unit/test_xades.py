"""Unit tests: XAdES certificate auth helpers (AuthTokenRequest + signing)."""

from __future__ import annotations

from ksef.xades import (
    AUTH_NS,
    ContextIdentifierTypeV2,
    LoadedCertificate,
    SubjectIdentifierType,
    build_auth_token_request,
)


def test_build_auth_token_request_structure():
    xml = build_auth_token_request(
        challenge="20260825-CR-TEST",
        context_identifier_type=ContextIdentifierTypeV2.NIP,
        context_identifier_value="5265877635",
        subject_identifier_type=SubjectIdentifierType.CERTIFICATE_SUBJECT,
    )
    assert f'xmlns="{AUTH_NS}"' in xml
    assert "<Challenge>20260825-CR-TEST</Challenge>" in xml
    assert "<Nip>5265877635</Nip>" in xml
    assert "<SubjectIdentifierType>certificateSubject</SubjectIdentifierType>" in xml
    assert xml.startswith("<?xml")


def test_build_auth_token_request_fingerprint_variant():
    xml = build_auth_token_request(
        challenge="CH",
        context_identifier_type="internalId",
        context_identifier_value="abc",
        subject_identifier_type=SubjectIdentifierType.CERTIFICATE_FINGERPRINT,
    )
    assert "<internalId>abc</internalId>" in xml
    assert "<SubjectIdentifierType>certificateFingerprint</SubjectIdentifierType>" in xml


def test_self_signed_test_certificate_generation():
    from cryptography.x509.oid import NameOID

    cert = LoadedCertificate.generate_self_signed_test(serial_number="TINPL-5265877635")
    # KSeF requires givenName (2.5.4.42) + surname (2.5.4.4) on signature certs;
    # without them /auth/xades-signature rejects the cert (21115)
    for oid in (NameOID.GIVEN_NAME, NameOID.SURNAME):
        assert cert.certificate.subject.get_attributes_for_oid(oid), f"missing {oid.dotted_string}"
    sn_attr = cert.certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    assert sn_attr and sn_attr[0].value == "TINPL-5265877635"
    fp = cert.certificate_fingerprint()
    assert len(fp) == 64  # sha256 hex
    int(fp, 16)  # valid hex


def test_loaded_certificate_from_pem_roundtrip():
    generated = LoadedCertificate.generate_self_signed_test()
    from cryptography.hazmat.primitives import serialization

    cert_pem = generated.certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = generated.private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    loaded = LoadedCertificate.from_pem(cert_pem, key_pem)
    assert loaded.certificate_fingerprint() == generated.certificate_fingerprint()


def test_sign_xades_produces_enveloped_signature():
    from ksef.xades import sign_xades

    cert = LoadedCertificate.generate_self_signed_test(serial_number="TINPL-1234567890")
    unsigned = build_auth_token_request("CH", "nip", "1234567890", "certificateSubject")
    signed = sign_xades(unsigned, cert)
    # enveloped: original content preserved + Signature element added
    assert "<Challenge>CH</Challenge>" in signed
    assert "Signature" in signed and "ds:" in signed or "<Signature" in signed
