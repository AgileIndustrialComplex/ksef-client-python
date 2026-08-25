"""Unit tests: FA(3) XML builder."""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from ksef.fa3 import FA3_NAMESPACE, InvoiceData, InvoiceLine, Party, build_fa3, parse_fa3_ksef_fields


def sample_invoice() -> InvoiceData:
    seller = Party(nip="5265877635", name="Sprzedawca Sp. z o.o.", street="ul. Główna 1", city="Warszawa", postal_code="00-001")
    buyer = Party(nip="1234567890", name="Nabywca S.A.", street="ul. Boczna 2", city="Kraków", postal_code="30-002")
    return InvoiceData(
        issue_number="FV/1/08/2026",
        issue_date=date(2026, 8, 25),
        seller=seller,
        buyer=buyer,
        lines=(
            InvoiceLine(name="Konsultacja", quantity=Decimal("2"), unit_price_net=Decimal("100.00"), vat_rate="23"),
            InvoiceLine(name="Usługa zw.", quantity=Decimal("1"), unit_price_net=Decimal("50.00"), vat_rate="zw"),
        ),
    )


def test_build_fa3_structure():
    xml = build_fa3(sample_invoice())
    text = xml.decode()
    assert 'kodSystemowy="FA (3)"' in text
    assert 'wersjaSchemy="1-0E"' in text
    assert "<P_2>FV/1/08/2026</P_2>" in text
    assert "<StawkaVAT>23</StawkaVAT>" in text
    assert "<StawkaVAT>zw</StawkaVAT>" in text
    assert f'xmlns="{FA3_NAMESPACE}"' in text


def test_totals_math():
    inv = sample_invoice()
    assert inv.total_net == Decimal("250.00")
    assert inv.total_vat == Decimal("46.00")  # only the 23% line carries VAT
    assert inv.total_gross == Decimal("296.00")
    xml = build_fa3(inv).decode()
    assert "<Netto>250.00</Netto>" in xml
    assert "<Brutto>296.00</Brutto>" in xml


def test_parse_fields_roundtrip():
    xml = build_fa3(sample_invoice())
    fields = parse_fa3_ksef_fields(xml)
    assert fields["P_2"] == "FV/1/08/2026"
    assert fields["P_1"] == "2026-08-25"
