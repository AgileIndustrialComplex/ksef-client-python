# ksef-client-python

Minimal-dependency, fully typed client for **KSeF 2.0** (Krajowy System
e-Faktur) — Poland's National e-Invoice System — for **Python 3.12+**.

Modelled on the official reference clients
[CIRFMF/ksef-client-csharp](https://github.com/CIRFMF/ksef-client-csharp) and
[CIRFMF/ksef-client-java](https://github.com/CIRFMF/ksef-client-java), against
the API contract published in [CIRFMF/ksef-api](https://github.com/CIRFMF/ksef-api).

## Features

- **KSeF token authentication** — full challenge → RSA-OAEP-SHA256 encrypted
  `token|timestamp` → status polling → token redemption handshake.
- **Certificate (XAdES) authentication** — build `AuthTokenRequest`, sign it
  with an X.509 certificate via `ksef.xades.sign_xades` (optional
  `signxml` dependency: `pip install ksef-client[xades]`), submit, poll,
  redeem. Includes a self-signed test-certificate generator for the test
  environment.
- **Online (interactive) sessions** — open FA(3) session with envelope
  encryption, send AES-256-CBC-encrypted invoices, poll invoice/session
  statuses, close the session, download UPO.
- **FA(3) XML builder** — stdlib-only generation of minimal valid FA(3)
  invoices (`ksef.fa3`).
- **Latarnia** — unauthenticated KSeF availability/status API (`ksef.latarnia`).
- **`ksef-client` CLI** — generate an RSA key pair + self-signed X.509 cert for
  certificate (XAdES) authentication (`gen-cert`).
- **Typed end to end** — ships `py.typed`; strict-mypy clean.

## Dependencies

One: [`cryptography`](https://cryptography.io) — required by the protocol
itself (RSA-OAEP token/key encryption, AES-CBC invoice envelope). HTTP uses
`urllib`, JSON/XML use the standard library. A pluggable transport seam
(`HTTPTransport`) lets you swap in any HTTP stack or a test double.

## Install

```bash
pip install .
# dev/test extras:
pip install -e '.[test]'
# CLI is available after any install:
ksef-client gen-cert --help
```

## Quickstart

```python
from ksef import Environment, FormCode, KSeFClient, KSeFConfig
from ksef.fa3 import InvoiceData, InvoiceLine, Party
from decimal import Decimal

client = KSeFClient(KSeFConfig.for_environment(Environment.TEST).with_nip("5265877635"))
tokens = client.authenticate_with_token("your-ksef-token")

session, encryption = client.open_online_session(FormCode.fa3())

invoice = InvoiceData(
    issue_number="FV/1/08/2026",
    issue_date=date.today(),
    seller=Party(nip="5265877635", name="Seller Sp. z o.o.",
                 street="ul. Główna 1", city="Warszawa", postal_code="00-001"),
    buyer=Party(nip="1234567890", name="Buyer S.A.",
                street="ul. Boczna 2", city="Kraków", postal_code="30-002"),
    lines=(InvoiceLine(name="Usługa konsultingowa", quantity=Decimal("2"),
                       unit_price_net=Decimal("500.00"), vat_rate="23"),),
)

sent = client.send_invoice(session.reference_number, invoice, encryption)
status = client.wait_for_invoice(session.reference_number, sent.reference_number)
print(status.ksef_number)   # the legal 35-char KSeF number

client.close_online_session(session.reference_number)
upo = client.get_invoice_upo_by_reference(session.reference_number, sent.reference_number)
```

Always develop against `Environment.TEST`
(`https://api-test.ksef.mf.gov.pl/v2`) — production submissions have real legal
consequences.

## CLI: generate a certificate + key pair

```bash
ksef-client gen-cert --nip 5265877635 --out-dir ./certs
```

Writes `cert.pem` (self-signed X.509, serial `TINPL-<NIP>`) and `key.pem`
(RSA-2048, PKCS#8) for **KSeF certificate (XAdES) authentication**. Add
`--ask-password` to encrypt the private key, and `--cn/--country/--days/--key-size`
to customise the subject and key.

```python
from ksef.xades import LoadedCertificate
cert = LoadedCertificate.from_pem("./certs/cert.pem", "./certs/key.pem")  # key_password=... if encrypted
```

The test environment accepts self-signed certificates; production requires a
qualified seal.

## Testing

```bash
pytest tests/unit     # crypto, FA(3) builder, client logic (no network)
pytest tests/e2e      # full flows against an in-process mock KSeF server
pytest tests/live     # LIVE integration tests against the real KSeF test env (opt-in)
```

The e2e suite runs a stateful mock implementing the real endpoint contract,
including server-side decryption of client-encrypted invoices to prove the
crypto round-trip.

### Live integration tests (`tests/live`)

These hit the **real** Polish KSeF **test** environment
(`https://api-test.ksef.mf.gov.pl/v2`) and are gated entirely behind
`KSEF_LIVE=1` so a normal `pytest` run stays offline and hermetic:

```bash
# Latarnia + public-key discovery (no credentials needed):
KSEF_LIVE=1 pytest tests/live

# Token-auth, certificate-auth, online-session flow, UPO, rate-limits:
KSEF_LIVE=1 \
  KSEF_TEST_TOKEN="<your-ksef-test-token>" \
  KSEF_TEST_NIP="<your-tin>" \
  pytest tests/live
```

Optional: `KSEF_TEST_BUYER_NIP` (invoice buyer, defaults to the seller's NIP),
`KSEF_TEST_BASE_URL` (defaults to the test environment) and
`KSEF_TEST_TIMEOUT` (per-request timeout). See `tests/live/README.md`.

> These tests keep the whole library's client surface exercised against the
> real contract, but they cannot assert correctness without valid credentials
> and are deliberately not run by CI.

## Status

Pre-1.0; covers the core auth + online-session + UPO flow. Batch sessions,
certificate enrollment, permissions and invoice query/export endpoints are not
yet implemented.

## License

MIT
