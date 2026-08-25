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
- **Online (interactive) sessions** — open FA(3) session with envelope
  encryption, send AES-256-CBC-encrypted invoices, poll invoice/session
  statuses, close the session, download UPO.
- **FA(3) XML builder** — stdlib-only generation of minimal valid FA(3)
  invoices (`ksef.fa3`).
- **Latarnia** — unauthenticated KSeF availability/status API (`ksef.latarnia`).
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
(`api-test.ksef.mf.gov.pl`) — production submissions have real legal
consequences.

## Testing

```bash
pytest tests/unit     # crypto, FA(3) builder, client logic (no network)
pytest tests/e2e      # full flows against an in-process mock KSeF server
```

The e2e suite runs a stateful mock implementing the real endpoint contract,
including server-side decryption of client-encrypted invoices to prove the
crypto round-trip.

## Status

Pre-1.0; covers the core auth + online-session + UPO flow. Batch sessions,
certificate enrollment, permissions and invoice query/export endpoints are not
yet implemented.

## License

MIT
