"""Minimal-dependency, typed client for Poland's KSeF 2.0 e-invoicing API.

Reference implementations: CIRFMF/ksef-client-csharp, CIRFMF/ksef-client-java.
API contract: https://github.com/CIRFMF/ksef-api (open-api.json).
"""

from ksef.client import KSeFClient, PollOptions
from ksef.config import HTTPTransport, KSeFConfig, UrllibTransport
from ksef.exceptions import (
    KSeFAuthenticationError,
    KSeFClientError,
    KSeFHTTPError,
    KSeFPollingTimeoutError,
)
from ksef.fa3 import FA3_NAMESPACE, InvoiceData, InvoiceLine, Party, build_fa3
from ksef.latarnia import LatarniaClient
from ksef.models import (
    AuthTokens,
    AuthenticationStatusResponse,
    ChallengeResponse,
    EncryptionInfo,
    Environment,
    FormCode,
    InvoiceStatus,
    OpenSessionResponse,
    RateLimits,
    SendInvoiceResponse,
    SessionEncryption,
    SessionStatus,
    StatusInfo,
)

__all__ = [
    "AuthTokens",
    "AuthenticationStatusResponse",
    "ChallengeResponse",
    "EncryptionInfo",
    "Environment",
    "FA3_NAMESPACE",
    "FormCode",
    "HTTPTransport",
    "InvoiceData",
    "InvoiceLine",
    "InvoiceStatus",
    "KSeFClient",
    "KSeFConfig",
    "KSeFAuthenticationError",
    "KSeFClientError",
    "KSeFHTTPError",
    "KSeFPollingTimeoutError",
    "LatarniaClient",
    "OpenSessionResponse",
    "Party",
    "PollOptions",
    "RateLimits",
    "SendInvoiceResponse",
    "SessionEncryption",
    "SessionStatus",
    "StatusInfo",
    "UrllibTransport",
    "build_fa3",
]

__version__ = "0.1.0"
