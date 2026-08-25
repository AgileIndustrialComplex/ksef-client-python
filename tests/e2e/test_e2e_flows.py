"""End-to-end tests against an in-process mock of the KSeF 2.0 API.

The mock implements the real endpoint contract (paths, payloads, status
codes) from CIRFMF/ksef-api, including:

* token auth handshake with real RSA keypair (challenge → encrypted token →
  poll → redeem)
* online session lifecycle (open → send AES-encrypted invoice → poll status →
  close → UPO download), verifying the server can decrypt what the client
  encrypted
"""

from __future__ import annotations

import json
import threading
import time
from base64 import b64decode, b64encode
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from ksef.client import KSeFClient
from ksef.config import KSeFConfig
from ksef.crypto import decrypt_invoice, new_session_encryption
from ksef.exceptions import KSeFAuthenticationError
from ksef.fa3 import InvoiceData, InvoiceLine, Party, build_fa3
from tests.helpers import generate_rsa_keypair


class MockKSeFServer:
    """Stateful fake of the KSeF REST API for e2e testing."""

    def __init__(self) -> None:
        self._priv_pem, self._pub_pem = generate_rsa_keypair()
        self._priv = serialization.load_pem_private_key(self._priv_pem.encode(), password=None)
        self.sessions: dict[str, dict[str, Any]] = {}
        self.auth_sessions: dict[str, dict[str, Any]] = {}
        self.valid_tokens = {"ksef-secret-token"}
        self.auth_should_fail = False
        self.invoice_status_sequence: list[int] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    # -- lifecycle -------------------------------------------------------

    def start(self) -> str:
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def _read_body(self) -> bytes:
                length = int(self.headers.get("Content-Length", 0))
                return self.rfile.read(length) if length else b""

            def _send(self, status: int, payload: Any, content_type="application/json") -> None:
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                server_ref._handle("GET", self.path, dict(self.headers.items()), b"", self._send)

            def do_POST(self):
                server_ref._handle("POST", self.path, dict(self.headers.items()), self._read_body(), self._send)

            do_PUT = do_POST
            do_DELETE = do_POST

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()

    @property
    def public_key_pem(self) -> str:
        return self._pub_pem

    # -- request routing ---------------------------------------------------

    def _handle(self, method: str, path: str, headers: dict, body: bytes, send) -> None:
        data = json.loads(body) if body and "json" in headers.get("Content-Type", "") else None
        now = datetime.now(timezone.utc)

        if method == "POST" and path == "/auth/challenge":
            return send(200, {
                "challenge": f"{now:%Y%m%d}-CR-{'A' * 8}-{'B' * 8}-01",
                "timestamp": now.isoformat(),
                "timestampMs": int(now.timestamp() * 1000),
                "clientIp": "127.0.0.1",
            })

        if method == "POST" and path == "/auth/xades-signature":
            # Mock-level XAdES check: document parses, is an AuthTokenRequest,
            # and carries a Signature element (real verification happens on
            # the MF side with full chain/OCSP checks).
            import xml.etree.ElementTree as ET

            try:
                root = ET.fromstring(body)
            except ET.ParseError:
                return send(400, {"detail": "Invalid XML"})
            if not root.tag.endswith("AuthTokenRequest"):
                return send(400, {"detail": "Wrong document type"})
            if not any(el.tag.endswith("Signature") for el in root.iter()):
                return send(400, {"detail": "Missing XAdES signature"})
            ref = f"XADES-{len(self.auth_sessions) + 1}"
            self.auth_sessions[ref] = {
                "status": 100,
                "tmp_token": f"tmp-{ref}",
                "xades": True,
            }
            return send(200, {
                "referenceNumber": ref,
                "authenticationToken": {"token": f"tmp-{ref}", "validUntil": (now + timedelta(minutes=5)).isoformat()},
            })

        if method == "POST" and path == "/auth/ksef-token":
            assert data is not None
            try:
                plain = self._priv.decrypt(
                    b64decode(data["encryptedToken"]),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                )
            except Exception:
                return send(400, {"detail": "Cannot decrypt token"})
            token, _, challenge = plain.decode().partition("|")
            if self.auth_should_fail or token not in self.valid_tokens:
                ref = "AUTH-FAIL-1"
                self.auth_sessions[ref] = {"status": 450}
            else:
                ref = f"AUTH-{len(self.auth_sessions) + 1}"
                self.auth_sessions[ref] = {
                    "status": 100,
                    "token": token,
                    "challenge": challenge,
                    "context": data["contextIdentifier"],
                    "tmp_token": f"tmp-{ref}",
                }
            return send(200, {
                "referenceNumber": ref,
                "authenticationToken": {"token": f"tmp-{ref}", "validUntil": (now + timedelta(minutes=5)).isoformat()},
            })

        match_path = path.split("/")
        if method == "GET" and len(match_path) >= 3 and match_path[1] == "auth":
            ref = match_path[2]
            state = self.auth_sessions.get(ref)
            if not state:
                return send(404, {"detail": "Unknown authentication session"})
            if state["status"] == 100:
                state["status"] = 200  # succeed on second poll, like the real API
                return send(200, {"referenceNumber": ref, "startDate": now.isoformat(),
                                  "status": {"code": 100, "description": "In progress"}})
            if state["status"] != 200:
                return send(200, {"referenceNumber": ref, "startDate": now.isoformat(),
                                  "status": {"code": state["status"], "description": "Rejected"}})
            return send(200, {"referenceNumber": ref, "startDate": now.isoformat(),
                              "status": {"code": 200, "description": "Authenticated"}})

        if method == "POST" and path == "/auth/token/redeem":
            bearer = headers.get("Authorization", "").removeprefix("Bearer ")
            for ref, st in self.auth_sessions.items():
                if st.get("tmp_token") == bearer and st.get("status") == 200:
                    return send(200, {
                        "accessToken": {"token": f"access-for-{ref}", "validUntil": (now + timedelta(hours=1)).isoformat()},
                        "refreshToken": {"token": f"refresh-for-{ref}", "validUntil": (now + timedelta(days=1)).isoformat()},
                    })
            return send(401, {"detail": "Redeem not allowed"})

        if method == "POST" and path == "/sessions/online":
            if not self._authorized(headers):
                return send(401, {"detail": "Invalid access token"})
            ref = f"SESSION/{len(self.sessions) + 1:05d}"
            enc = data["encryption"]
            try:
                aes_key = self._priv.decrypt(
                    b64decode(enc["encryptedSymmetricKey"]),
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
                )
            except Exception:
                return send(415, {"detail": "Key decryption failed"})
            self.sessions[ref] = {"aes_key": aes_key, "iv": b64decode(enc["initializationVector"]),
                                  "invoices": {}, "closed": False}
            return send(200, {"referenceNumber": ref, "validUntil": (now + timedelta(hours=8)).isoformat()})

        if method == "POST" and "/invoices" in path and path.startswith("/sessions/online/"):
            parts = path.strip("/").split("/")
            session_ref = f"{parts[2]}/{parts[3]}"
            sess = self.sessions.get(session_ref)
            if not sess or sess["closed"]:
                return send(404, {"detail": "No such open session"})
            inv_hash = data["invoiceHash"]
            xml = decrypt_invoice(data["invoiceContent"], type("E", (), {
                "aes_key": sess["aes_key"], "iv": sess["iv"]})())
            inv_ref = f"INV/{len(sess['invoices']) + 1:04d}"
            ksef_number = f"1234567890-20260825-{session_ref[-5:]}{len(sess['invoices']) + 1:06d}-AB"
            sess["invoices"][inv_ref] = {"hash": inv_hash, "xml": xml, "ksef_number": ksef_number, "polls": 0}
            return send(200, {"referenceNumber": inv_ref})

        if method == "GET" and "/invoices/" in path and path.endswith("/upo"):
            parts = path.strip("/").split("/")
            session_ref, inv_ref = f"{parts[1]}/{parts[2]}", f"{parts[4]}/{parts[5]}"
            inv = self.sessions[session_ref]["invoices"][inv_ref]
            upo = f"<UPO><KSeFNumber>{inv['ksef_number']}</KSeFNumber></UPO>"
            return send(200, upo.encode(), content_type="application/xml")

        if method == "GET" and "/invoices/" in path and path.startswith("/sessions/"):
            parts = path.strip("/").split("/")
            session_ref, inv_ref = f"{parts[1]}/{parts[2]}", f"{parts[4]}/{parts[5]}"
            sess = self.sessions.get(session_ref)
            inv = sess["invoices"].get(inv_ref)
            if not inv:
                return send(404, {"detail": "Unknown invoice"})
            inv["polls"] += 1
            code = 200
            if self.invoice_status_sequence:
                idx = min(inv["polls"], len(self.invoice_status_sequence)) - 1
                code = self.invoice_status_sequence[idx]
            payload: dict[str, Any] = {
                "referenceNumber": inv_ref,
                "invoiceHash": inv["hash"],
                "invoicingDate": now.isoformat(),
                "ordinalNumber": len(sess["invoices"]),
                "invoiceNumber": "FV/e2e/1",
                "status": {"code": code, "description": ""},
            }
            if code >= 200:
                payload["ksefNumber"] = inv["ksef_number"]
                payload["acquisitionDate"] = now.isoformat()
            return send(200, payload)

        if method == "GET" and path.startswith("/sessions/") and len(match_path) == 3:
            ref = match_path[2]
            sess = self.sessions.get(ref)
            if not sess:
                return send(404, {"detail": "Unknown session"})
            return send(200, {"referenceNumber": ref,
                              "status": {"code": 170 if sess["closed"] else 100, "description": ""},
                              "dateCreated": now.isoformat(), "dateUpdated": now.isoformat()})

        if method == "POST" and path.startswith("/sessions/online/") and path.endswith("/close"):
            parts = path.strip("/").split("/")
            ref = f"{parts[2]}/{parts[3]}"
            sess = self.sessions.get(ref)
            if not sess:
                return send(404, {"detail": "Unknown session"})
            sess["closed"] = True
            return send(200, {"status": {"code": 170, "description": "Closed"}})

        if method == "GET" and path == "/security/public-key-certificates":
            der_b64 = b64encode(
                serialization.load_pem_public_key(self._pub_pem.encode()).public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            ).decode()
            return send(200, {"certificates": [{"certificate": der_b64, "usage": ["KsefToken"]}]})

        return send(404, {"detail": f"No mock route for {method} {path}"})

    def _authorized(self, headers: dict) -> bool:
        return any(v.startswith("Bearer access-") for v in headers.values())


def make_client(base_url: str) -> KSeFClient:
    return KSeFClient(KSeFConfig(base_url=base_url, nip="5265877635"))


def sample_invoice() -> InvoiceData:
    return InvoiceData(
        issue_number="FV/e2e/1",
        issue_date=datetime.now(timezone.utc).date(),
        seller=Party(nip="5265877635", name="Seller Sp. z o.o.", street="ul. A 1", city="Warszawa", postal_code="00-001"),
        buyer=Party(nip="1234567890", name="Buyer S.A.", street="ul. B 2", city="Kraków", postal_code="30-002"),
        lines=(InvoiceLine(name="Service", quantity=__import__("decimal").Decimal("1"),
                           unit_price_net=__import__("decimal").Decimal("500.00"), vat_rate="23"),),
    )


def test_full_token_auth_flow(mock_server):
    tokens = make_client(mock_server.base_url()).authenticate_with_token("ksef-secret-token")
    assert tokens.access_token.startswith("access-for-AUTH-")


def test_auth_rejected_for_bad_token(mock_server):
    with pytest.raises(KSeFAuthenticationError):
        make_client(mock_server.base_url()).authenticate_with_token("wrong-token")


def test_certificate_xades_auth_flow(mock_server, monkeypatch):
    monkeypatch.setattr(_client_mod.time, "sleep", lambda s: None)
    from ksef import LoadedCertificate, SubjectIdentifierType

    cert = LoadedCertificate.generate_self_signed_test(serial_number="TINPL-5265877635")
    client = make_client(mock_server.base_url())
    tokens = client.authenticate_with_certificate(
        cert, nip="5265877635", subject_identifier_type=SubjectIdentifierType.CERTIFICATE_SUBJECT,
    )
    assert tokens.access_token.startswith("access-for-XADES-")
    assert client.is_authenticated
    # the mock recorded the xades session and the redeem used its temp token
    refs = [r for r in mock_server.auth_sessions if r.startswith("XADES-")]
    assert refs


def test_online_session_lifecycle(mock_server, monkeypatch):
    monkeypatch.setattr(_client_mod.time, "sleep", lambda s: None)  # instant polling
    client = make_client(mock_server.base_url())
    client.authenticate_with_token("ksef-secret-token")

    session, encryption = client.open_online_session()
    sent = client.send_invoice(session.reference_number, sample_invoice(), encryption)
    invoice_status = client.wait_for_invoice(session.reference_number, sent.reference_number)

    assert invoice_status.ksef_number is not None
    stored_inv = mock_server.sessions[session.reference_number]["invoices"][sent.reference_number]
    # server decrypted exactly the XML we built — proves crypto round-trip works
    assert stored_inv["xml"] == build_fa3(sample_invoice())
    assert stored_inv["hash"] == __import__("base64").b64encode(
        __import__("hashlib").sha256(build_fa3(sample_invoice())).digest()).decode()

    closed = client.close_online_session(session.reference_number)
    assert closed.status.code == 170

    upo = client.get_invoice_upo_by_reference(session.reference_number, sent.reference_number)
    assert invoice_status.ksef_number.encode() in upo


def test_wait_for_invoice_times_out_on_stuck_status(mock_server, monkeypatch):
    monkeypatch.setattr(_client_mod.time, "sleep", lambda s: None)
    mock_server.invoice_status_sequence = [100]  # never completes
    from ksef.client import PollOptions
    client = make_client(mock_server.base_url())
    client.authenticate_with_token("ksef-secret-token")
    session, encryption = client.open_online_session()
    sent = client.send_invoice(session.reference_number, sample_invoice(), encryption)
    opts = PollOptions(timeout_seconds=0.05)
    with pytest.raises(_client_mod.KSeFPollingTimeoutError):
        client.wait_for_invoice(session.reference_number, sent.reference_number, opts)


import ksef.client as _client_mod
import pytest  # noqa: E402


@pytest.fixture(scope="module")
def mock_server():
    server = MockKSeFServer()
    server.base_url = server.start
    yield server
    server.stop()