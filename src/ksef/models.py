"""Typed models mirroring the KSeF 2.0 API contract (CIRFMF/ksef-api)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Environment(StrEnum):
    """KSeF API environments."""

    TEST = "https://api-test.ksef.mf.gov.pl/v2"
    PRODUCTION = "https://api.ksef.mf.gov.pl/v2"
    # Latarnia (public availability status) endpoints, no auth required.
    LATARNIA_TEST = "https://api-latarnia-test.ksef.mf.gov.pl"
    LATARNIA_PRODUCTION = "https://api-latarnia.ksef.mf.gov.pl"


class ContextIdentifierType(StrEnum):
    NIP = "Nip"
    INTERNAL_ID = "InternalId"


class AuthenticationMethod(StrEnum):
    KSEF_TOKEN = "Token"
    TRUSTED_PROFILE = "TrustedProfile"
    INTERNAL_CERTIFICATE = "InternalCertificate"
    QUALIFIED_SIGNATURE = "QualifiedSignature"
    QUALIFIED_SEAL = "QualifiedSeal"


@dataclass(frozen=True, slots=True)
class ChallengeResponse:
    """POST /auth/challenge response."""

    challenge: str
    timestamp: datetime
    timestamp_ms: int
    client_ip: str


@dataclass(frozen=True, slots=True)
class TokenInfo:
    token: str
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class AuthenticationInitResponse:
    """POST /auth/ksef-token response."""

    reference_number: str
    authentication_token: TokenInfo


@dataclass(frozen=True, slots=True)
class StatusInfo:
    code: int
    description: str
    details: tuple[str, ...] = ()

    @property
    def is_success(self) -> bool:
        return self.code == 200

    @property
    def in_progress(self) -> bool:
        return self.code == 100


@dataclass(frozen=True, slots=True)
class AuthenticationStatusResponse:
    """GET /auth/{referenceNumber} response."""

    reference_number: str | None
    start_date: datetime | None
    status: StatusInfo


@dataclass(frozen=True, slots=True)
class AuthTokens:
    """Access/refresh token pair returned by POST /auth/token/redeem."""

    access_token: str
    refresh_token: str
    access_valid_until: datetime
    refresh_valid_until: datetime

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> AuthTokens:
        access = data["accessToken"]
        refresh = data["refreshToken"]
        return cls(
            access_token=access["token"],
            refresh_token=refresh["token"],
            access_valid_until=datetime.fromisoformat(access["validUntil"]),
            refresh_valid_until=datetime.fromisoformat(refresh["validUntil"]),
        )


@dataclass(frozen=True, slots=True)
class FormCode:
    """Invoice schema identifier for a session."""

    system_code: str
    schema_version: str
    value: str

    @staticmethod
    def fa3() -> FormCode:
        return FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")

    @staticmethod
    def fa2() -> FormCode:
        return FormCode(system_code="FA (2)", schema_version="1-0E", value="FA")


@dataclass(frozen=True, slots=True)
class EncryptionInfo:
    """Symmetric key (RSA-OAEP-SHA256 encrypted) + IV used to encrypt invoices."""

    encrypted_symmetric_key: str
    initialization_vector: str
    public_key_id: str | None = None


@dataclass(frozen=True, slots=True)
class SessionEncryption:
    """Client-side material for encrypting invoice XML before upload."""

    aes_key: bytes
    iv: bytes
    api_view: EncryptionInfo


@dataclass(frozen=True, slots=True)
class OpenSessionResponse:
    reference_number: str
    valid_until: datetime


@dataclass(frozen=True, slots=True)
class SendInvoiceResponse:
    reference_number: str


@dataclass(frozen=True, slots=True)
class SessionStatus:
    reference_number: str
    status: StatusInfo
    date_created: datetime | None = None
    date_updated: datetime | None = None
    valid_until: datetime | None = None


@dataclass(frozen=True, slots=True)
class InvoiceStatus:
    reference_number: str
    invoice_hash: str
    invoicing_date: datetime
    ordinal_number: int
    invoice_number: str | None = None
    ksef_number: str | None = None
    acquisition_date: datetime | None = None
    permanent_storage_date: datetime | None = None
    status: StatusInfo | None = None


@dataclass(frozen=True, slots=True)
class PublicKeyCertificate:
    """Certificate from GET /security/public-key-certificates."""

    certificate: str
    type: str
    usage: tuple[str, ...]
    public_key_id: str | None = field(default=None)


@dataclass(frozen=True, slots=True)
class RateLimits:
    """GET /rate-limits response (subset; unknown keys are preserved)."""

    raw: dict[str, Any]


def parse_status(data: dict[str, Any]) -> StatusInfo:
    return StatusInfo(
        code=data["code"],
        description=data["description"],
        details=tuple(data.get("details") or ()),
    )


def parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None
