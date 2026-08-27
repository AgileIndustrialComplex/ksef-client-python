"""LIVE tests exercising the full online (interactive) session lifecycle.

These drive a real FA(3) session on the KSeF test environment:

    authenticate -> open -> send invoice -> poll status -> close -> UPO

covering both authentication paths:

* **token auth** (``authed_client``) - needs ``KSEF_TEST_TOKEN`` + NIP
* **certificate / XAdES auth** (``cert_authed_client``) - needs **only** a NIP

The full-flow cert test (``test_full_live_flow_with_certificate_auth``)
mirrors the canonical ``README`` quickstart end-to-end against the live env,
so it can be run with nothing but ``KSEF_TEST_NIP``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

pytestmark = [pytest.mark.live]

from ksef import FormCode, PollOptions  # noqa: E402
from ksef.fa3 import build_fa3  # noqa: E402

from tests.live.live_helpers import (  # noqa: E402
    expected_ksef_number_format,
    sample_invoice,
)


def _poll_options() -> PollOptions:
    # Invoicing on the test environment is usually accepted in a few seconds,
    # but give it a generous window so slow test-days don't fail spuriously.
    return PollOptions(interval_seconds=5.0, timeout_seconds=180.0)


@pytest.mark.live_nip
def test_full_live_flow_with_certificate_auth(
    cert_authed_client, live_nip: str, buyer_nip: str
):
    """The canonical full flow, authenticated by XAdES cert (NIP only).

    1. authenticate_with_certificate (done by the ``cert_authed_client`` fixture)
    2. open_online_session
    3. send_invoice
    4. wait_for_invoice (poll to a real 35-char KSeF number)
    5. get_invoice_status
    6. get_invoice_upo_by_reference
    7. close_online_session
    """
    client = cert_authed_client
    assert client.is_authenticated
    invoice = sample_invoice(live_nip, buyer_nip)

    # 2) open an interactive FA(3) session
    session, encryption = client.open_online_session(FormCode.fa3())
    assert session.reference_number, "no session reference returned"

    # 3) send the invoice (build_fa3 + AES-256-CBC envelope)
    sent = client.send_invoice(session.reference_number, invoice, encryption)
    assert sent.reference_number, "no per-invoice reference returned"
    inv_ref = sent.reference_number

    # 4) poll until a KSeF number is issued
    status = client.wait_for_invoice(
        session.reference_number, inv_ref, _poll_options()
    )
    expected_ksef_number_format(status.ksef_number)
    assert status.status is not None and status.status.code == 200
    assert status.acquisition_date is not None

    # 5) the quiet GETter agrees with the polled result
    queried = client.get_invoice_status(session.reference_number, inv_ref)
    assert queried.ksef_number == status.ksef_number

    # 6) UPO - the legal proof of acceptance - is downloadable by reference
    upo = client.get_invoice_upo_by_reference(
        session.reference_number, inv_ref
    )
    assert upo, "empty UPO"
    assert _ksef_number_text(upo) == status.ksef_number

    # 7) close the session (live endpoint returns an empty 200 body; verify the
    #    session settled as closed via get_session_status — 170 "closed" or 200)
    client.close_online_session(session.reference_number)
    after_close = client.get_session_status(session.reference_number)
    assert after_close.status.code in (170, 200)  # closed / processed successfully


@pytest.mark.live_token
def test_online_session_full_lifecycle_live(
    authed_client, live_nip: str, buyer_nip: str
):
    """open -> send_invoice -> wait_for_invoice -> statuses -> close -> UPO."""
    client = authed_client
    invoice = sample_invoice(live_nip, buyer_nip)

    # 1) open an interactive FA(3) session
    session, encryption = client.open_online_session(FormCode.fa3())
    assert session.reference_number, "no session reference returned"

    # 2) send the invoice (build_fa3 + AES-256-CBC envelope)
    sent = client.send_invoice(session.reference_number, invoice, encryption)
    assert sent.reference_number, "no per-invoice reference returned"
    inv_ref = sent.reference_number

    # 3) poll until a KSeF number is issued
    status = client.wait_for_invoice(
        session.reference_number, inv_ref, _poll_options()
    )
    expected_ksef_number_format(status.ksef_number)
    assert status.status is not None and status.status.code == 200
    assert status.acquisition_date is not None

    # 4) the quiet GETters agree with the polled result
    queried = client.get_invoice_status(session.reference_number, inv_ref)
    assert queried.ksef_number == status.ksef_number

    # 5) session status is queryable
    sess = client.get_session_status(session.reference_number)
    assert sess.status.code in (100, 170)

    # 6) close the session (live endpoint returns an empty 200 body; verify via status)
    client.close_online_session(session.reference_number)
    after_close = client.get_session_status(session.reference_number)
    assert after_close.status.code == 200  # "Sesja interaktywna przetworzona pomyślnie"

    # 7) UPO - the legal proof of acceptance - is downloadable by reference
    upo = client.get_invoice_upo_by_reference(
        session.reference_number, inv_ref
    )
    assert upo, "empty UPO"
    assert _ksef_number_text(upo) == status.ksef_number


@pytest.mark.live_token
def test_raw_xml_passthrough_send_live(
    authed_client, live_nip: str, buyer_nip: str
):
    """``send_invoice_xml`` accepts pre-built FA(3) XML (raw passthrough path)."""
    client = authed_client
    invoice = sample_invoice(live_nip, buyer_nip)
    xml = build_fa3(invoice)  # the document we'd otherwise send via send_invoice

    session, encryption = client.open_online_session(FormCode.fa3())
    sent = client.send_invoice_xml(
        session.reference_number,
        xml,
        encryption,
        invoice.issue_number,
    )
    assert sent.reference_number

    status = client.wait_for_invoice(
        session.reference_number, sent.reference_number, _poll_options()
    )
    expected_ksef_number_format(status.ksef_number)

    client.close_online_session(session.reference_number)


def _ksef_number_text(upo_xml: bytes) -> str:
    root = ET.fromstring(upo_xml)
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        # The UPO (http://upo.schematy.mf.gov.pl/...) carries the KSeF number in
        # NumerKSeFDokumentu inside the signed Dokument element.
        if tag in {"NumerKSeFDokumentu", "KSeFNumber", "KsefNumber"} and el.text:
            return el.text
    raise AssertionError("UPO did not contain a KSeF number element")