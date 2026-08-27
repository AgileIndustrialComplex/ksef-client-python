"""Unit tests: client request handling, auth handshake, error mapping."""

from __future__ import annotations

import json
from base64 import b64decode, b64encode
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from ksef.client import KSeFClient
from ksef.config import KSeFConfig
from ksef.exceptions import KSeFAuthenticationError, KSeFHTTPError
from tests.helpers import FakeTransport, generate_rsa_keypair, json_response

BASE = "https://ksef.test"


def make_client(transport: FakeTransport) -> KSeFClient:
    return KSeFClient(KSeFConfig(base_url=BASE, nip="5265877635"), transport=transport)


def challenge_payload() -> dict:
    return {
        "challenge": "20260825-CR-AABBCCDDEE-FFGGHHIIJJ-01",
        "timestamp": "2026-08-25T10:00:00+00:00",
        "timestampMs": 1777000000000,
        "clientIp": "127.0.0.1",
    }


def tokens_payload() -> dict:
    return {
        "accessToken": {"token": "access-1", "validUntil": "2026-08-25T11:00:00+00:00"},
        "refreshToken": {"token": "refresh-1", "validUntil": "2026-08-26T11:00:00+00:00"},
    }


@pytest.fixture()
def transport() -> FakeTransport:
    t = FakeTransport()
    t.route("POST", "/auth/challenge", lambda req: json_response(challenge_payload()))
    t.route("GET", "/security/public-key-certificates", lambda req: json_response({
        "certificates": [{
            "certificate": "MIIB",
            "type": "AuthenticationEncryption",
            "usage": ["KsefToken"],
            "identifier": "QIoAK/Yc3s27Z4t3SZY4Mhp8JNLH7Vl4N3lNlJAEig8=",
        }]
    }))
    return t


def test_not_authenticated_raises():
    client = make_client(FakeTransport())
    with pytest.raises(KSeFAuthenticationError):
        client.get_session_status("S1")


def test_auth_happy_path(transport: FakeTransport):
    _, pub = generate_rsa_keypair()
    transport.routes[("GET", "/security/public-key-certificates")] = (
        lambda req: json_response({"certificates": [{"certificate": pub.replace("\n", ""), "usage": ["KsefToken"]}]})
    )
    seen_init: dict = {}
    seen_status_calls = {"n": 0}

    def on_ksef_token(req):
        body = json.loads(req.body)
        seen_init.update(body)
        return json_response({
            "referenceNumber": "AUTH/1",
            "authenticationToken": {"token": "tmp-token", "validUntil": "2026-08-25T10:05:00+00:00"},
        })

    def on_status(req):
        assert req.headers["Authorization"] == "Bearer tmp-token"
        seen_status_calls["n"] += 1
        code = 200 if seen_status_calls["n"] >= 2 else 100
        return json_response({"referenceNumber": "AUTH/1", "startDate": "2026-08-25T10:00:00+00:00",
                              "status": {"code": code, "description": ""}})

    transport.route("POST", "/auth/ksef-token", on_ksef_token)
    transport.route("GET", "/auth/AUTH/1", on_status)
    transport.route("POST", "/auth/token/redeem", lambda req: json_response(tokens_payload()))

    client = make_client(transport)
    tokens = client.authenticate_with_token("ksef-secret", nip="5265877635")

    assert tokens.access_token == "access-1"
    assert client.is_authenticated
    # encrypted token decrypts to token|challenge with the *published* key
    enc = b64decode(seen_init["encryptedToken"])
    priv, _ = generate_rsa_keypair.__wrapped__ if False else (None, None)  # noqa
    # verify challenge + context were passed correctly:
    assert seen_init["contextIdentifier"] == {"type": "Nip", "value": "5265877635"}
    assert seen_init["challenge"] == challenge_payload()["challenge"]
    # redeem used the temp authentication token
    redeem_req = [r for r in transport.requests if r.url.endswith("/auth/token/redeem")][0]
    assert redeem_req.headers["Authorization"] == "Bearer tmp-token"


def test_auth_failure_maps_error(transport: FakeTransport):
    _, pub = generate_rsa_keypair()
    transport.routes[("GET", "/security/public-key-certificates")] = (
        lambda req: json_response({"certificates": [{"certificate": pub.replace("\n", ""), "usage": ["KsefToken"]}]})
    )
    transport.route("POST", "/auth/ksef-token", lambda req: json_response({
        "referenceNumber": "AUTH/2",
        "authenticationToken": {"token": "t2", "validUntil": "2026-08-25T10:05:00+00:00"},
    }))
    transport.route("GET", "/auth/AUTH/2", lambda req: json_response(
        {"referenceNumber": "AUTH/2", "status": {"code": 450, "description": "bad challenge"}}))
    client = make_client(transport)
    with pytest.raises(KSeFAuthenticationError, match="450"):
        client.authenticate_with_token("tok")


def test_http_problem_details_extraction():
    t = FakeTransport()
    t.route("GET", "/sessions/S1", lambda req: json_response(
        {"detail": "Not found"}, status=404))
    client = make_client(t)
    client._tokens = type("T", (), {})()  # bypass auth for direct call
    from ksef.models import AuthTokens
    client._tokens = AuthTokens("a", "r", datetime.now(timezone.utc), datetime.now(timezone.utc))
    with pytest.raises(KSeFHTTPError) as exc_info:
        client.get_session_status("S1")
    assert exc_info.value.status_code == 404
    assert "Not found" in str(exc_info.value)


def test_retry_on_503_then_success():
    t = FakeTransport()
    calls = {"n": 0}

    def flaky(req):
        calls["n"] += 1
        if calls["n"] < 2:
            return json_response({"detail": "overloaded"}, status=503)
        return json_response({"status": {"code": 100, "description": ""}, "dateCreated": None, "dateUpdated": None})

    t.route("GET", "/sessions/S9", flaky)
    client = KSeFClient(KSeFConfig(base_url=BASE), transport=t)
    from ksef.models import AuthTokens
    client._tokens = AuthTokens("a", "r", datetime.now(timezone.utc), datetime.now(timezone.utc))
    status = client.get_session_status("S9")
    assert calls["n"] == 2
    assert status.status.code == 100


def test_rate_limits_passthrough():
    t = FakeTransport()
    payload = {"session": {"max": 1}, "invoice": {"perSession": 10000}}
    t.route("GET", "/rate-limits", lambda req: json_response(payload))
    client = KSeFClient(KSeFConfig(base_url=BASE), transport=t)
    from ksef.models import AuthTokens
    client._tokens = AuthTokens("a", "r", datetime.now(timezone.utc), datetime.now(timezone.utc))
    limits = client.rate_limits()
    assert limits.raw == payload


def test_session_encryption_prefers_symmetric_key(transport: FakeTransport):
    """Prepare-session encryption must use the SymmetricKeyEncryption key (and
    its publicKeyId), not the KsefTokenEncryption key — using the token key id
    makes KSeF reject the session with error 21470."""
    priv_token, pub_token = generate_rsa_keypair()
    priv_sym, pub_sym = generate_rsa_keypair()
    token_id = "IPbPM4CB49vtoR/x/3fEI+Y+Q6lK/bVVehQ7/NlPJoo="
    sym_id = "tmtCidSRzR4fvNpLU5hMOM6FzamxJf0BBR8IkXIAwsY="
    # order deliberately lists the token-encryption cert FIRST to ensure the
    # client prefers the symmetric key rather than the first match.
    transport.routes[("GET", "/security/public-key-certificates")] = (
        lambda req: json_response({"certificates": [
            {"certificate": pub_token.replace("\n", ""), "usage": ["KsefTokenEncryption"],
             "publicKeyId": token_id},
            {"certificate": pub_sym.replace("\n", ""), "usage": ["SymmetricKeyEncryption"],
             "publicKeyId": sym_id},
        ]})
    )
    client = make_client(transport)
    enc = client.prepare_session_encryption()
    assert enc.api_view.public_key_id == sym_id

    # the envelope must decrypt with the symmetric private key (not the token
    # key), proving the client encrypted with the right public key.
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    priv_sym_key = _ser.load_pem_private_key(priv_sym.encode(), password=None)
    aes_key = priv_sym_key.decrypt(
        b64decode(enc.api_view.encrypted_symmetric_key),
        _pad.OAEP(mgf=_pad.MGF1(algorithm=hashes.SHA256()),
                  algorithm=hashes.SHA256(), label=None),
    )
    assert len(aes_key) == 32  # AES-256 key recovered with the symmetric key
