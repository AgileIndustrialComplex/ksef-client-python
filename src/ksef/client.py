"""The KSeF 2.0 client.

Implements the core integration flows against the API contract published at
https://github.com/CIRFMF/ksef-api (mirrored by CIRFMF/ksef-client-csharp and
CIRFMF/ksef-client-java):

* **Auth with KSeF token** — challenge → RSA-OAEP-encrypted ``token|timestamp``
  → poll status → redeem access/refresh tokens.
* **Interactive (online) sessions** — open session with FA(3) form code and
  envelope encryption, send encrypted invoices, poll statuses, close, fetch UPO.
* **Latarnia** — unauthenticated availability/status endpoints.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Sequence

from ksef._http_json import dumps, loads
from ksef.config import HTTPTransport, KSeFConfig
from ksef.crypto import encrypt_invoice, encrypt_token, new_session_encryption
from ksef.exceptions import (
    KSeFAuthenticationError,
    KSeFClientError,
    KSeFHTTPError,
    KSeFPollingTimeoutError,
)
from ksef.fa3 import InvoiceData, build_fa3
from ksef.xades import sign_xades

if TYPE_CHECKING:
    from ksef import xades

from ksef.models import (
    AuthTokens,
    AuthenticationInitResponse,
    AuthenticationStatusResponse,
    ChallengeResponse,
    Environment,
    FormCode,
    InvoiceStatus,
    OpenSessionResponse,
    RateLimits,
    SendInvoiceResponse,
    SessionEncryption,
    SessionStatus,
    StatusInfo,
    TokenInfo,
    parse_dt,
    parse_status,
)

_RETRYABLE = {429, 500, 502, 503, 504}


def _cert_has_usage(cert: dict[str, Any], *tags: str) -> bool:
    """True if any ``usage`` on the cert contains any of ``tags`` (substring).

    The live API reports tags such as ``KsefTokenEncryption`` and
    ``SymmetricKeyEncryption`` (compound values), so compare as substrings,
    not exact equality, and tolerate a string or a list of strings.
    """
    usage = cert.get("usage") or []
    if isinstance(usage, str):
        usage = [usage]
    for value in usage:
        for tag in tags:
            if tag in str(value):
                return True
    return False


def _is_subject_identifier(value: Any, expected: Any) -> bool:
    """True if ``value`` names the given subject-identifier type.

    Tolerates both the enum member and its string value.
    """
    return value == expected or str(value) == str(expected)


@dataclass(frozen=True, slots=True)
class PollOptions:
    interval_seconds: float = 1.0
    timeout_seconds: float = 120.0


class KSeFClient:
    """Typed, minimal-dependency client for the KSeF 2.0 REST API."""

    def __init__(
        self,
        config: KSeFConfig | None = None,
        *,
        transport: HTTPTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config or KSeFConfig()
        self._transport = transport
        self._clock = clock
        self._tokens: AuthTokens | None = None

    # ------------------------------------------------------------------ #
    # low-level HTTP                                                      #
    # ------------------------------------------------------------------ #

    @property
    def base_url(self) -> str:
        return self._config.base_url.rstrip("/")

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        auth: bool = True,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
        accept: str = "application/json",
    ) -> tuple[int, dict[str, str], Any]:
        url = f"{self.base_url}{path}"
        merged: dict[str, str] = {"Accept": accept, **self._config.extra_headers}
        if headers:
            merged.update(headers)
        body: bytes | None = raw_body
        if json_body is not None:
            merged["Content-Type"] = "application/json"
            body = dumps(json_body)
        elif raw_body is not None:
            merged.setdefault("Content-Type", "application/xml")
        if auth:
            self._ensure_access_token()
            assert self._tokens is not None
            merged["Authorization"] = f"Bearer {self._tokens.access_token}"

        retries = self._config.max_retries
        attempt = 0
        while True:
            status, resp_headers, resp_body = self._transport_or_default().request(
                method, url, headers=merged, body=body, timeout=self._config.timeout
            )
            if status in _RETRYABLE and attempt < retries:
                attempt += 1
                time.sleep(0.5 * attempt)
                continue
            break

        payload: Any = None
        content_type = resp_headers.get("Content-Type", "") or resp_headers.get("content-type", "")
        if "json" in content_type and resp_body:
            try:
                payload = loads(resp_body)
            except ValueError:
                payload = None
        elif not resp_body:
            payload = None
        else:
            payload = resp_body

        if status >= 400:
            message = self._extract_problem_message(payload) or resp_body[:300].decode("utf-8", "replace")
            details = payload if isinstance(payload, dict) else None
            raise KSeFHTTPError(status, message, details=details)
        return status, resp_headers, payload

    def _transport_or_default(self) -> HTTPTransport:
        from ksef.config import UrllibTransport, default_transport

        _ = UrllibTransport  # keep import local; default_transport builds one
        if self._transport is None:
            self._transport = default_transport()
        return self._transport

    @staticmethod
    def _extract_problem_message(payload: Any) -> str | None:
        if isinstance(payload, dict):
            for key in ("detail", "description", "message", "title"):
                value = payload.get(key)
                if isinstance(value, str):
                    exc = payload.get("exceptions") or payload.get("errors")
                    if isinstance(exc, list) and exc:
                        first = exc[0]
                        if isinstance(first, dict):
                            inner = first.get("description") or first.get("detail")
                            if isinstance(inner, str):
                                return f"{value}: {inner}"
                    return value
        return None

    def _ensure_access_token(self) -> None:
        if self._tokens is None:
            raise KSeFAuthenticationError(
                "Not authenticated. Call authenticate_with_token() first."
            )

    # ------------------------------------------------------------------ #
    # authentication (KSeF token flow)                                    #
    # ------------------------------------------------------------------ #

    def authenticate_with_token(
        self,
        token: str,
        nip: str | None = None,
        public_key_pem: str | bytes | None = None,
    ) -> AuthTokens:
        """Full KSeF-token authentication handshake.

        1. POST /auth/challenge
        2. Encrypt ``token|timestamp`` with the MoF public key (RSA-OAEP-SHA256)
           and POST /auth/ksef-token
        3. Poll GET /auth/{referenceNumber} until code == 200
        4. POST /auth/token/redeem to obtain access + refresh tokens
        """
        nip = nip or self._config.nip
        if not nip:
            raise KSeFAuthenticationError("No NIP provided for authentication context")

        _, _, ch_data = self._request("POST", "/auth/challenge", json_body={}, auth=False)
        challenge = ChallengeResponse(
            challenge=ch_data["challenge"],
            timestamp=datetime.fromisoformat(ch_data["timestamp"]),
            timestamp_ms=int(ch_data["timestampMs"]),
            client_ip=ch_data["clientIp"],
        )

        if public_key_pem is None:
            public_key_pem = self.fetch_public_encryption_key()

        encrypted = encrypt_token(token, challenge.challenge, public_key_pem)
        _, _, init_data = self._request(
            "POST",
            "/auth/ksef-token",
            json_body={
                "challenge": challenge.challenge,
                "contextIdentifier": {"type": "Nip", "value": nip},
                "encryptedToken": encrypted,
            },
            auth=False,
        )
        auth_token = TokenInfo(
            token=init_data["authenticationToken"]["token"],
            valid_until=parse_dt(init_data["authenticationToken"]["validUntil"])
            or datetime.now(timezone.utc),
        )
        init = AuthenticationInitResponse(
            reference_number=init_data["referenceNumber"],
            authentication_token=auth_token,
        )

        # poll authentication status
        deadline = self._clock() + PollOptions().timeout_seconds
        while True:
            _, _, st_data = self._request(
                "GET", f"/auth/{init.reference_number}", auth=False,
                headers={"Authorization": f"Bearer {init.authentication_token.token}"},
            )
            status = AuthenticationStatusResponse(
                reference_number=st_data.get("referenceNumber"),
                start_date=parse_dt(st_data.get("startDate")),
                status=parse_status(st_data["status"]),
            )
            if status.status.code == 200:
                break
            if status.status.code not in (100,):
                raise KSeFAuthenticationError(
                    f"Authentication failed: {status.status.code} {status.status.description}"
                )
            if self._clock() > deadline:
                raise KSeFPollingTimeoutError("Authentication did not complete in time")
            time.sleep(PollOptions().interval_seconds)

        _, _, tokens_data = self._request(
            "POST", "/auth/token/redeem", json_body={}, auth=False,
            headers={"Authorization": f"Bearer {init.authentication_token.token}"},
        )
        self._tokens = AuthTokens.from_api(tokens_data)
        return self._tokens

    def refresh_access_token(self) -> AuthTokens:
        if self._tokens is None:
            raise KSeFAuthenticationError("No refresh token available")
        _, _, data = self._request(
            "POST", "/auth/token/refresh", json_body={"refreshToken": self._tokens.refresh_token},
            auth=False,
        )
        self._tokens = AuthTokens.from_api(data)
        return self._tokens

    def authenticate_with_certificate(
        self,
        cert: "xades.LoadedCertificate",
        nip: str | None = None,
        subject_identifier_type: "xades.SubjectIdentifierType | str | None" = None,
    ) -> AuthTokens:
        """Full certificate (XAdES) authentication handshake.

        1. POST /auth/challenge
        2. Build the AuthTokenRequest XML and sign it XAdES with ``cert``
        3. POST /auth/xades-signature with the signed XML
        4. Poll GET /auth/{referenceNumber} until code == 200
        5. POST /auth/token/redeem to obtain access + refresh tokens

        Requires the optional ``signxml`` dependency (``ksef-client[xades]``).
        Self-signed certificates are only accepted by KSeF's test environment.
        """
        from ksef import xades as _xades

        if subject_identifier_type is None:
            subject_identifier_type = _xades.SubjectIdentifierType.CERTIFICATE_SUBJECT

        nip = nip or self._config.nip
        if not nip:
            raise KSeFAuthenticationError("No NIP provided for authentication context")

        if _is_subject_identifier(subject_identifier_type, _xades.SubjectIdentifierType.CERTIFICATE_SUBJECT):
            cert_nip = _xades.tax_number_from_certificate(cert)
            if cert_nip is not None and cert_nip != nip:
                raise KSeFAuthenticationError(
                    f"Certificate is bound to NIP {cert_nip} but {nip} was provided; "
                    "use a certificate generated for the authenticating taxpayer."
                )

        _, _, ch_data = self._request("POST", "/auth/challenge", json_body={}, auth=False)

        unsigned = _xades.build_auth_token_request(
            challenge=ch_data["challenge"],
            context_identifier_type=_xades.ContextIdentifierTypeV2.NIP,
            context_identifier_value=nip,
            subject_identifier_type=subject_identifier_type,
        )
        signed_xml = sign_xades(unsigned, cert)

        headers = {"Content-Type": "application/xml"}
        status, resp_headers, resp_body = self._transport_or_default().request(
            "POST",
            f"{self.base_url}/auth/xades-signature",
            headers=headers,
            body=signed_xml.encode("utf-8"),
            timeout=self._config.timeout,
        )
        init_data = loads(resp_body) if resp_body else {}
        if status >= 400:
            message = self._extract_problem_message(init_data) or (
                resp_body[:300].decode("utf-8", "replace")
                if isinstance(resp_body, bytes)
                else "XAdES submission rejected"
            )
            raise KSeFHTTPError(
                status,
                str(message),
                details=init_data if isinstance(init_data, dict) else None,
            )

        init = AuthenticationInitResponse(
            reference_number=init_data["referenceNumber"],
            authentication_token=TokenInfo(
                token=init_data["authenticationToken"]["token"],
                valid_until=parse_dt(init_data["authenticationToken"]["validUntil"])
                or datetime.now(timezone.utc),
            ),
        )

        # poll authentication status (same shape as the token flow)
        deadline = self._clock() + PollOptions().timeout_seconds
        while True:
            _, _, st_data = self._request(
                "GET", f"/auth/{init.reference_number}", auth=False,
                headers={"Authorization": f"Bearer {init.authentication_token.token}"},
            )
            st = parse_status(st_data["status"])
            if st.code == 200:
                break
            if st.code != 100:
                raise KSeFAuthenticationError(f"Authentication failed: {st.code} {st.description}")
            if self._clock() > deadline:
                raise KSeFPollingTimeoutError("Authentication did not complete in time")
            time.sleep(PollOptions().interval_seconds)

        _, _, tokens_data = self._request(
            "POST", "/auth/token/redeem", json_body={}, auth=False,
            headers={"Authorization": f"Bearer {init.authentication_token.token}"},
        )
        self._tokens = AuthTokens.from_api(tokens_data)
        return self._tokens

    @property
    def is_authenticated(self) -> bool:
        return self._tokens is not None

    # ------------------------------------------------------------------ #
    # public keys                                                         #
    # ------------------------------------------------------------------ #

    def fetch_public_key_certificates(self) -> list[dict[str, Any]]:
        _, _, data = self._request(
            "GET", "/security/public-key-certificates", auth=False
        )
        # The live API returns a bare JSON array; some mocks wrap it in a
        # {certificates: [...]} envelope. Accept both.
        if isinstance(data, list):
            return data
        certs = data.get("certificates", []) if isinstance(data, dict) else []
        return certs

    def fetch_public_encryption_key(self) -> str:
        """Return the PEM public key of the MoF encryption certificate.

        Online-session / invoice encryption must use the **SymmetricKeyEncryption**
        key, not the KsefTokenEncryption key (that one encrypts the auth token).
        Accepts both X.509 certificates and bare SubjectPublicKeyInfo blobs, in
        PEM or Base64 DER form.
        """
        certs = self.fetch_public_key_certificates()

        def _usage(cert: dict[str, Any]) -> str:
            usage = cert.get("usage") or ""
            if isinstance(usage, list):
                usage = " ".join(str(u) for u in usage)
            return str(usage)

        # Prefer a cert whose usage names SymmetricKeyEncryption; fall back to
        # any cert carrying KsefToken/Encryption usage.
        ordered = sorted(
            certs,
            key=lambda c: (0 if "SymmetricKeyEncryption" in _usage(c) else
                           1 if (_cert_has_usage(c, "KsefToken") or _cert_has_usage(c, "Encryption")) else 2),
        )
        for cert in ordered:
            if not _cert_has_usage(cert, "KsefToken", "Encryption"):
                continue
            material = cert.get("certificate", "")
            if not material:
                continue
            from cryptography import x509 as _x509
            from cryptography.hazmat.primitives import serialization

            if "-----BEGIN" in material:
                pem_bytes = material.encode()
            else:
                pem_bytes = (
                    "-----BEGIN CERTIFICATE-----\n"
                    + "\n".join(material[i:i + 64] for i in range(0, len(material), 64))
                    + "\n-----END CERTIFICATE-----\n"
                ).encode()

            def pub_to_pem(pub: Any) -> str:
                raw: bytes = pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return raw.decode()

            try:
                parsed = _x509.load_pem_x509_certificate(pem_bytes)
                return pub_to_pem(parsed.public_key())
            except ValueError:
                try:
                    return pub_to_pem(serialization.load_pem_public_key(pem_bytes))
                except ValueError:
                    der = base64.b64decode(material)
                    try:
                        parsed_der = _x509.load_der_x509_certificate(der)
                        return pub_to_pem(parsed_der.public_key())
                    except ValueError:
                        return pub_to_pem(serialization.load_der_public_key(der))
        raise KSeFClientError("No encryption-capable public key certificate found")

    # ------------------------------------------------------------------ #
    # online sessions                                                     #
    # ------------------------------------------------------------------ #

    def prepare_session_encryption(self) -> SessionEncryption:
        public_key_id: str | None = None
        pem = self.fetch_public_encryption_key()
        # Pick the publicKeyId from the SAME cert whose key we encrypt with —
        # the SymmetricKeyEncryption cert — so the envelope key identifier
        # matches the encryption key. Using the KsefToken key id here makes
        # KSeF reject the session with 21470 (unknown/retired key).
        try:
            certs = self.fetch_public_key_certificates()
            for cert in certs:
                usage = cert.get("usage") or ""
                if isinstance(usage, list):
                    usage = " ".join(str(u) for u in usage)
                if "SymmetricKeyEncryption" in str(usage) or _cert_has_usage(cert, "SymmetricKeyEncryption"):
                    public_key_id = cert.get("identifier") or cert.get("publicKeyId")
                    break
        except Exception:
            pass
        return new_session_encryption(pem, public_key_id=public_key_id)

    def open_online_session(
        self,
        form_code: FormCode | None = None,
        encryption: SessionEncryption | None = None,
    ) -> tuple[OpenSessionResponse, SessionEncryption]:
        """POST /sessions/online — opens an interactive FA(3) session."""
        if encryption is None:
            encryption = self.prepare_session_encryption()
        body = {
            "formCode": {
                "systemCode": form_code.system_code if form_code else FormCode.fa3().system_code,
                "schemaVersion": form_code.schema_version if form_code else FormCode.fa3().schema_version,
                "value": form_code.value if form_code else FormCode.fa3().value,
            },
            "encryption": {
                "encryptedSymmetricKey": encryption.api_view.encrypted_symmetric_key,
                "initializationVector": encryption.api_view.initialization_vector,
                **({"publicKeyId": encryption.api_view.public_key_id} if encryption.api_view.public_key_id else {}),
            },
        }
        _, _, data = self._request("POST", "/sessions/online", json_body=body)
        return (
            OpenSessionResponse(
                reference_number=data["referenceNumber"],
                valid_until=datetime.fromisoformat(data["validUntil"]),
            ),
            encryption,
        )

    def send_invoice_xml(
        self,
        session_reference_number: str,
        xml_bytes: bytes,
        encryption: SessionEncryption,
        invoice_number: str | None = None,
    ) -> SendInvoiceResponse:
        """Send pre-built invoice XML inside an open online session."""
        enc = encrypt_invoice(xml_bytes, encryption)
        body: dict[str, Any] = {
            "invoiceHash": enc.sha256_base64,
            "invoiceSize": len(base64.b64decode(enc.encrypted_body_b64)),
            "invoiceContent": enc.encrypted_body_b64,
        }
        if invoice_number:
            body["invoiceNumber"] = invoice_number
        _, _, data = self._request(
            "POST", f"/sessions/online/{session_reference_number}/invoices", json_body=body
        )
        return SendInvoiceResponse(reference_number=data["referenceNumber"])

    def send_invoice(
        self,
        session_reference_number: str,
        invoice: InvoiceData,
        encryption: SessionEncryption,
    ) -> SendInvoiceResponse:
        """Build FA(3) XML from :class:`InvoiceData` and send it."""
        xml = build_fa3(invoice)
        return self.send_invoice_xml(
            session_reference_number, xml, encryption, invoice.issue_number
        )

    def get_session_status(self, reference_number: str) -> SessionStatus:
        _, _, data = self._request("GET", f"/sessions/{reference_number}")
        return SessionStatus(
            reference_number=reference_number,
            status=parse_status(data["status"]),
            date_created=parse_dt(data.get("dateCreated")),
            date_updated=parse_dt(data.get("dateUpdated")),
            valid_until=parse_dt(data.get("validUntil")),
        )

    def get_invoice_status(
        self, session_reference_number: str, invoice_reference_number: str
    ) -> InvoiceStatus:
        _, _, data = self._request(
            "GET", f"/sessions/{session_reference_number}/invoices/{invoice_reference_number}"
        )
        return InvoiceStatus(
            reference_number=data["referenceNumber"],
            invoice_hash=data["invoiceHash"],
            invoicing_date=datetime.fromisoformat(data["invoicingDate"]),
            ordinal_number=data["ordinalNumber"],
            invoice_number=data.get("invoiceNumber"),
            ksef_number=data.get("ksefNumber"),
            acquisition_date=parse_dt(data.get("acquisitionDate")),
            permanent_storage_date=parse_dt(data.get("permanentStorageDate")),
            status=parse_status(data["status"]) if data.get("status") else None,
        )

    def close_online_session(self, reference_number: str) -> SessionStatus:
        _, _, data = self._request(
            "POST", f"/sessions/online/{reference_number}/close", json_body={}
        )
        return SessionStatus(
            reference_number=reference_number,
            status=parse_status(data["status"]) if data and "status" in data else StatusInfo(0, ""),
        )

    def wait_for_invoice(
        self,
        session_reference_number: str,
        invoice_reference_number: str,
        options: PollOptions | None = None,
    ) -> InvoiceStatus:
        """Poll until the invoice acquires a KSeF number (code 200)."""
        opts = options or PollOptions()
        deadline = self._clock() + opts.timeout_seconds
        while True:
            status = self.get_invoice_status(session_reference_number, invoice_reference_number)
            code = status.status.code if status.status else 100
            if code == 200:
                return status
            if code not in (100, 150):
                raise KSeFClientError(f"Invoice processing failed: {code}")
            if self._clock() > deadline:
                raise KSeFPollingTimeoutError("Invoice was not processed in time")
            time.sleep(opts.interval_seconds)

    def get_invoice_upo_by_reference(
        self, session_reference_number: str, invoice_reference_number: str
    ) -> bytes:
        _, _, body = self._request(
            "GET",
            f"/sessions/{session_reference_number}/invoices/{invoice_reference_number}/upo",
            accept="application/xml",
        )
        return body if isinstance(body, bytes) else str(body).encode()

    # ------------------------------------------------------------------ #
    # misc                                                                #
    # ------------------------------------------------------------------ #

    def rate_limits(self) -> RateLimits:
        _, _, data = self._request("GET", "/rate-limits")
        return RateLimits(raw=data if isinstance(data, dict) else {})


__all__ = ["KSeFClient", "PollOptions"]
