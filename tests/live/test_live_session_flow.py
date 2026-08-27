"""LIVE tests exercising the full online (interactive) session lifecycle.

These drive a real FA(3) session on the KSeF test environment:

    open -> send invoice -> poll status -> query statuses -> close -> UPO

plus the raw-XML passthrough send path (``send_invoice_xml``).

Requires ``KSEF_LIVE=1 KSEF_TEST_TOKEN=<token> KSEF_TEST_NIP=<NIP>``.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

pytestmark = [pytest.mark.live, pytest.mark.live_token]

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

    # 6) close the session
    closed = client.close_online_session(session.reference_number)
    assert closed.status.code == 170

    # 7) UPO — the legal proof of acceptance — is downloadable by reference
    upo = client.get_invoice_upo_by_reference(
        session.reference_number, inv_ref
    )
    assert upo, "empty UPO"
    assert _ksef_number_text(upo) == status.ksef_number


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


def _kse_number_text(upo_xml: bytes) -> str:
    root = ET.fromstring(upo_xml)
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] in {"KSeFNumber", "KsefNumber"} and el.text:
            return el.text
    raise AssertionError("UPO did not contain a KSeF number element")