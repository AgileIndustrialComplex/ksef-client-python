"""FA(3) invoice XML generation using only :mod:`xml.etree`.

Builds a minimal-but-valid subset of the KSeF FA(3) logical structure
(EN 16931-based). Covers the fields needed to submit a basic VAT invoice;
complex cases (attachments, corrections, collective identifiers) are left as
raw-XML passthrough via :func:`KSeFClient.send_invoice_xml`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from typing import Iterable
from xml.etree import ElementTree as ET


FA3_NAMESPACE = "http://crd.gov.pl/wzor/2026/06/30/13775/"


@dataclass(frozen=True, slots=True)
class InvoiceLine:
    """A single invoice line item."""

    name: str
    quantity: Decimal
    unit_price_net: Decimal
    vat_rate: str  # coded rate per FA(3): "23", "8", "5", "0", "zw", "np", "oo"
    unit: str = "szt."
    gtu_code: str | None = None

    @property
    def line_net(self) -> Decimal:
        return self.quantity * self.unit_price_net


@dataclass(frozen=True, slots=True)
class Party:
    nip: str
    name: str
    street: str
    city: str
    postal_code: str
    country: str = "PL"


@dataclass(frozen=True, slots=True)
class InvoiceData:
    """Minimal FA(3) invoice."""

    issue_number: str
    issue_date: date
    seller: Party
    buyer: Party
    lines: tuple[InvoiceLine, ...] = field(default_factory=tuple)

    @property
    def total_net(self) -> Decimal:
        return sum((line.line_net for line in self.lines), Decimal("0"))

    @property
    def total_vat(self) -> Decimal:
        total = Decimal("0")
        for line in self.lines:
            try:
                rate = Decimal(line.vat_rate)
            except Exception:
                continue  # zw / np / oo carry no numeric rate
            total += line.line_net * rate / Decimal("100")
        return total

    @property
    def total_gross(self) -> Decimal:
        return self.total_net + self.total_vat


def build_fa3(invoice: InvoiceData) -> bytes:
    """Serialise :class:`InvoiceData` to FA(3) XML bytes."""
    ns = FA3_NAMESPACE
    ET.register_namespace("", ns)
    root = ET.Element(f"{{{ns}}}Faktura")

    def sub(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
        el = ET.SubElement(parent, f"{{{ns}}}{tag}")
        if text is not None:
            el.text = text
        return el

    # -- header ----------------------------------------------------------
    kod = sub(root, "KodFormularza", "FA")
    kod.set("kodSystemowy", "FA (3)")
    kod.set("wersjaSchemy", "1-0E")
    sub(root, "WariantFormularza", "3")
    sub(root, "DataWytworzeniaFa", invoice.issue_date.isoformat())
    sub(root, "SystemInfo", "ksef-client-python")

    # -- subject ---------------------------------------------------------
    podmiot = sub(root, "Podmiot1")
    dane = sub(podmiot, "DaneIdentyfikacyjne")
    sub(dane, "NIP", invoice.seller.nip)
    sub(dane, "Nazwa", invoice.seller.name)
    adres = sub(podmiot, "Adres")
    sub(adres, "KodKraju", invoice.seller.country)
    sub(adres, "AdresL1", f"{invoice.seller.street}; {invoice.seller.postal_code} {invoice.seller.city}")

    nabywca = sub(root, "Podmiot2")
    dane2 = sub(nabywca, "DaneIdentyfikacyjne")
    sub(dane2, "NIP", invoice.buyer.nip)
    sub(dane2, "Nazwa", invoice.buyer.name)
    adres2 = sub(nabywca, "Adres")
    sub(adres2, "KodKraju", invoice.buyer.country)
    sub(adres2, "AdresL1", f"{invoice.buyer.street}; {invoice.buyer.postal_code} {invoice.buyer.city}")

    # -- amounts ---------------------------------------------------------
    fa = sub(root, "Fa")
    sub(fa, "KodWaluty", "PLN")
    sub(fa, "P_1", invoice.issue_date.isoformat())
    sub(fa, "P_2", invoice.issue_number)
    sub(fa, "P_15", f"{invoice.total_gross:.2f}")

    # -- lines -----------------------------------------------------------
    for idx, line in enumerate(invoice.lines, start=1):
        wiersz = sub(fa, "FaWiersz")
        wiersz.set("numerWierszaFa", str(idx))
        sub(wiersz, "P_7", line.name)
        sub(wiersz, "P_8A", line.unit)
        sub(wiersz, "P_8B", f"{line.quantity}")
        sub(wiersz, "P_9A", f"{line.unit_price_net:.2f}")
        sub(wiersz, "P_11", f"{line.line_net:.2f}")
        stawka = sub(wiersz, "P_12", line.vat_rate)
        if line.gtu_code:
            stawka.set("gtuCode", line.gtu_code)

    # -- totals by rate --------------------------------------------------
    rates: dict[str, Decimal] = {}
    for line in invoice.lines:
        rates.setdefault(line.vat_rate, Decimal("0"))
        rates[line.vat_rate] += line.line_net
    for rate, net in sorted(rates.items()):
        podsum = sub(fa, "PodsumaVAT")
        sub(podsum, "StawkaVAT", rate)
        try:
            Decimal(rate)
            sub(podsum, "Netto", f"{net:.2f}")
        except Exception:
            pass  # non-numeric rates are reported in StawkaVAT only

    suma = sub(fa, "SumaPodatek")
    sub(suma, "Netto", f"{invoice.total_net:.2f}")
    sub(suma, "Podatek", f"{invoice.total_vat:.2f}")
    sub(suma, "Brutto", f"{invoice.total_gross:.2f}")

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)  # type: ignore[no-any-return]


def parse_fa3_ksef_fields(xml_bytes: bytes) -> dict[str, str]:
    """Extract P_1/P_2 style scalar fields from an existing FA(3) document."""
    root = ET.fromstring(xml_bytes)
    out: dict[str, str] = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in {"P_1", "P_2", "P_15"} and el.text:
            out[tag] = el.text
    return out


__all__ = [
    "FA3_NAMESPACE",
    "InvoiceData",
    "InvoiceLine",
    "Party",
    "build_fa3",
    "parse_fa3_ksef_fields",
]

# Keep Iterable imported lazily for typing users.
_ = Iterable
