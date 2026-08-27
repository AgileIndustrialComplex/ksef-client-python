"""Unit tests for certificate->NIP binding detection and the client guard."""

from __future__ import annotations

import pytest

from ksef import KSeFClient, KSeFConfig
from ksef.exceptions import KSeFAuthenticationError
from ksef.xades import (
    LoadedCertificate,
    SubjectIdentifierType,
    tax_number_from_certificate,
)


def make_cert(serial_value: str) -> LoadedCertificate:
    return LoadedCertificate.generate_self_signed_test(serial_number=serial_value)


def test_tax_number_from_pl_serial():
    cert = make_cert("TINPL-5265877635")
    assert tax_number_from_certificate(cert) == "5265877635"


def test_tax_number_from_non_pl_serial():
    cert = make_cert("DE-12345")
    assert tax_number_from_certificate(cert) is None


def test_tax_number_from_unrelated_serial():
    cert = make_cert("some-other-id")
    assert tax_number_from_certificate(cert) is None


class _NoopTransport:
    """Transport that must never be reached when the guard raises early."""

    def __init__(self):
        self.requests = []

    def request(self, *a, **k):
        self.requests.append(a)
        raise AssertionError("should not reach the network")


def test_authenticate_certificate_mismatched_nip_fails_fast():
    """A cert bound to NIP-A must not authenticate as NIP-B, without any request."""
    transport = _NoopTransport()
    client = KSeFClient(
        KSeFConfig(base_url="http://x", nip="2222222222"),
        transport=transport,
    )
    cert = make_cert("TINPL-1111111111")  # bound to a different NIP

    with pytest.raises(KSeFAuthenticationError, match="bound to NIP 1111111111"):
        client.authenticate_with_certificate(
            cert,
            nip="2222222222",
            subject_identifier_type=SubjectIdentifierType.CERTIFICATE_SUBJECT,
        )
    assert not transport.requests, "no network request should have been made"


def test_authenticate_certificate_matching_nip_makes_network_call():
    """A matching cert+NIP proceeds to the (mocked) challenge request."""
    from tests.helpers import json_response

    calls = []

    class Recording:
        def request(self, method, url, *, headers=None, body=None, timeout=30.0):
            calls.append(url)
            # default for an auth challenge
            return json_response(
                {
                    "challenge": "20260101-CR-AAAAAAAA-BBBBBBBB-01",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "timestampMs": 0,
                    "clientIp": "127.0.0.1",
                }
            )

    client = KSeFClient(
        KSeFConfig(base_url="http://x", nip="5265877635"),
        transport=Recording(),
    )
    cert = make_cert("TINPL-5265877635")

    # The guard passes; the flow proceeds to POST /auth/challenge (first call).
    # It will then fail parsing the response, but crucially it reached the network.
    with pytest.raises(Exception):
        client.authenticate_with_certificate(
            cert,
            nip="5265877635",
            subject_identifier_type=SubjectIdentifierType.CERTIFICATE_SUBJECT,
        )
    assert calls  # the challenge was requested (match passed the client-side guard)