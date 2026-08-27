# `tests/live` — Live KSeF integration suite

This is an **opt-in** suite that exercises every public API of
`ksef-client-python` against the **real** Polish KSeF **test** environment
(`https://api-test.ksef.mf.gov.pl/v2`). It complements the hermetic unit/e2e
suites (which use an in-process mock) by verifying the client against the live
contract — generating real FA(3) XML, running the real challenge→redeem
handshake, opening real online sessions, and downloading real UPOs.

## Coverage

| Area | Test file | Functionality exercised |
|------|-----------|------------------------|
| Auth (token) | `test_live_auth.py` | `authenticate_with_token`, `is_authenticated` |
| Auth (refresh) | `test_live_auth.py` | `refresh_access_token` |
| Auth (XAdES cert) | `test_live_auth.py` | `authenticate_with_certificate` (self-signed test cert) |
| Public keys | `test_live_public_keys.py` | `fetch_public_key_certificates`, `fetch_public_encryption_key` |
| Online session | `test_live_session_flow.py` | `open_online_session`, `send_invoice`, `wait_for_invoice`, `get_invoice_status`, `get_session_status`, `close_online_session`, `get_invoice_upo_by_reference` |
| Raw XML send | `test_live_session_flow.py` | `send_invoice_xml` (FA(3) passthrough) |
| Misc | `test_live_misc.py` | `rate_limits` |
| Latarnia | `test_live_latarnia.py` | `LatarniaClient.status`, `LatarniaClient.messages` (no auth) |

## Requirements

- A **KSeF test token** for a taxpayer NIP, provisioned on the MF test
  environment (obtain it from the test `Aplikacja Podatnika` / the MF test
  console).
- Python **3.12+** with dev install: `.venv/bin/pip install -e '.[test,xades]'`
  — the `[xades]` extras are only needed for the certificate-auth test.

## How to run

```bash
# Everything that needs no credentials (Latarnia + public keys):
KSEF_LIVE=1 pytest tests/live

# The full suite (auth, sessions, UPO, rate-limits):
KSEF_LIVE=1 \
  KSEF_TEST_TOKEN="<your-token>" \
  KSEF_TEST_NIP="<your-nip>" \
  pytest tests/live -v
```

## Environment variables

| Variable | Required (full run) | Default | Meaning |
|----------|---------------------|---------|---------|
| `KSEF_LIVE` | yes | off | set to `1` (or `true`) to enable any live test |
| `KSEF_TEST_TOKEN` | for token/session tests | — | the KSeF test token for `KSEF_TEST_NIP` |
| `KSEF_TEST_NIP` | for token/session tests | — | taxpayer NIP you own the token for |
| `KSEF_TEST_BUYER_NIP` | no | `KSEF_TEST_NIP` | invoice buyer NIP; should be a real, registered VAT payer |
| `KSEF_TEST_BASE_URL` | no | `https://api-test.ksef.mf.gov.pl/v2` | API base URL override |
| `KSEF_TEST_TIMEOUT` | no | `30` | per-request timeout (seconds) |

## Notes and pitfalls

- **Buyer NIP matters.** KSeF validates the counterparty. If
  `KSEF_TEST_BUYER_NIP` (or the seller NIP, by default) is not a valid,
  registered VAT payer the invoice will be rejected in `wait_for_invoice`.
  Set it to a real counterparty you can invoice to.
- Invoice submission is **polled** with generous timeouts (
  `PollOptions(interval_seconds=5, timeout_seconds=180)`); on the test
  environment acceptance normally lands within seconds.
- Each `send_invoice`/`send_invoice_xml` uses a unique `issue_number`, so
  re-runs do not trip KSeF's "duplicate invoice number" rejection.
- These tests make **real requests** — never point them at production
  (`Environment.PRODUCTION`). The default base URL is the test environment.
- They are intentionally **not** wired into the default `pytest` run: without
  `KSEF_LIVE=1` every test here is skipped, so CI and local dev stay offline.