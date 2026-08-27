"""Shared builders for the LIVE KSeF integration suite."""

from __future__ import annotations

import time
from datetime import date
from decimal import Decimal

from ksef import InvoiceData, InvoiceLine, Party
from ksef.fa3 import build_fa3


def sample_invoice(
    seller_nip: str,
    buyer_nip: str,
    *,
    issue_number: str | None = None,
) -> InvoiceData:
    """A deterministic-but-unique FA(3) invoice for the live environment.

    The seller NIP must be the one authenticated to the token; the buyer NIP
    should be a real, registered VAT payer (KSeF validates the counterparty).
    A unique ``issue_number`` avoids "duplicate invoice number" rejections
    when the suite is re-run.
    """
    invoice_number = issue_number or f"FV/LIVE/{int(time.time() * 1000)}"
    return InvoiceData(
        issue_number=invoice_number,
        issue_date=date.today(),
        seller=Party(
            nip=seller_nip,
            name="ksef-client-python Test Seller Sp. z o.o.",
            street="ul. Testowa 1",
            city="Warszawa",
            postal_code="00-001",
        ),
        buyer=Party(
            nip=buyer_nip,
            name="ksef-client-python Test Buyer S.A.",
            street="ul. Odbiorcy 2",
            city="Krakow",
            postal_code="30-002",
        ),
        lines=(
            InvoiceLine(
                name="Usluga testowa (live suite)",
                quantity=Decimal("2"),
                unit_price_net=Decimal("123.45"),
                vat_rate="23",
            ),
        ),
    )


def expected_ksef_number_format(ksef_number: str) -> None:
    """Assert the returned KSeF number looks like the 35-char legal identifier."""
    assert ksef_number, "no KSeF number returned"
    assert len(ksef_number) == 35, (
        f"KSeF number has {len(ksef_number)} chars, expected 35"
    )


def unique_issue_number() -> str:
    return f"FV/LIVE/{int(time.time() * 1000)}"