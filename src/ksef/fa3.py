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


FA3_NAMESPACE = "http://crd.gov.pl/wzor/2025/06/25/13775/"  # official FA(3) targetNamespace


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
    """Serialise :class:`InvoiceData` to schema-valid FA(3) XML bytes.

    Builds a minimal FA(3) document that validates against the official
    ``schemat_FA-3_v1-0E.xsd`` (verified live: KSeF rejects an FA(2)-shaped /
    wrong-namespace document at semantic validation with code 450).
    """
    ns = FA3_NAMESPACE
    ET.register_namespace("", ns)

    def q(tag: str) -> str:
        return f"{{{ns}}}{tag}"

    def sub(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
        el = ET.SubElement(parent, q(tag))
        if text is not None:
            el.text = text
        return el

    def money(value: Decimal | int | float | str) -> str:
        return f"{Decimal(value):.2f}"

    root = ET.Element(q("Faktura"))

    # -- header (Naglowek) -------------------------------------------------
    nag = sub(root, "Naglowek")
    kod = sub(nag, "KodFormularza", "FA")
    kod.set("kodSystemowy", "FA (3)")
    kod.set("wersjaSchemy", "1-0E")
    sub(nag, "WariantFormularza", "3")
    from datetime import datetime, timezone

    sub(nag, "DataWytworzeniaFa", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    sub(nag, "SystemInfo", "ksef-client-python")

    # -- subjects ----------------------------------------------------------
    def party(parent: ET.Element, p: Party, *, buyer: bool) -> None:
        ident = sub(parent, "DaneIdentyfikacyjne")
        sub(ident, "NIP", p.nip or "0")
        sub(ident, "Nazwa", p.name)
        adres = sub(parent, "Adres")
        sub(adres, "KodKraju", p.country or "PL")
        sub(adres, "AdresL1", f"{p.street}; {p.postal_code} {p.city}")
        if buyer:
            sub(parent, "JST", "2")
            sub(parent, "GV", "2")

    p1 = sub(root, "Podmiot1")
    party(p1, invoice.seller, buyer=False)
    p2 = sub(root, "Podmiot2")
    party(p2, invoice.buyer, buyer=True)

    # -- amounts -----------------------------------------------------------
    fa = sub(root, "Fa")
    sub(fa, "KodWaluty", "PLN")
    sub(fa, "P_1", invoice.issue_date.isoformat())
    sub(fa, "P_2", invoice.issue_number)

    # per-rate buckets: 1->23%, 2->8%, 3->5%, 4->0%, 5->zw (non-numeric)
    buckets: dict[str, Decimal] = {r: Decimal("0") for r in ("23", "8", "5", "0", "zw")}
    vat_by: dict[str, Decimal] = {r: Decimal("0") for r in ("23", "8", "5", "0", "zw")}
    rate_idx = {"23": 1, "8": 2, "5": 3, "0": 4, "zw": 5}
    for line in invoice.lines:
        net = line.line_net.quantize(Decimal("0.01"))
        rate_coded = "zw" if not _is_numeric(line.vat_rate) else line.vat_rate
        idx = rate_idx.get(rate_coded)
        if idx is None:
            raise ValueError(f"VAT rate {line.vat_rate!r} is not mappable to FA(3) coded rates")
        buckets[rate_coded] += net
        if _is_numeric(rate_coded):
            vat_by[rate_coded] += (net * Decimal(rate_coded) / Decimal(100)).quantize(Decimal("0.01"))
    for idx, rate in ((1, "23"), (2, "8"), (3, "5")):
        if buckets[rate]:
            sub(fa, f"P_13_{idx}", money(buckets[rate]))
            sub(fa, f"P_14_{idx}", money(vat_by[rate]))
    if buckets["0"]:
        sub(fa, "P_13_4", money(buckets["0"]))
        sub(fa, "P_14_4", money(vat_by["0"]))
    if buckets["zw"]:
        sub(fa, "P_13_5", money(buckets["zw"]))

    total_net = sum(buckets.values(), Decimal("0"))
    total_vat = sum(vat_by.values(), Decimal("0"))
    sub(fa, "P_15", money(total_net + total_vat))

    # -- Adnotacje (all required by the schema) ----------------------------
    ad = sub(fa, "Adnotacje")
    sub(ad, "P_16", "2")
    sub(ad, "P_17", "2")
    sub(ad, "P_18", "2")
    sub(ad, "P_18A", "2")
    zw = sub(ad, "Zwolnienie")
    sub(zw, "P_19N", "1")
    nst = sub(ad, "NoweSrodkiTransportu")
    sub(nst, "P_22N", "1")
    sub(ad, "P_23", "2")
    pm = sub(ad, "PMarzy")
    sub(pm, "P_PMarzyN", "1")

    sub(fa, "RodzajFaktury", "VAT")

    # -- lines -----------------------------------------------------------
    for idx, line in enumerate(invoice.lines, start=1):
        w = sub(fa, "FaWiersz")
        sub(w, "NrWierszaFa", str(idx))
        sub(w, "P_7", line.name)
        sub(w, "P_8A", line.unit)
        sub(w, "P_8B", f"{line.quantity:.3f}")
        sub(w, "P_9A", money(line.unit_price_net))
        sub(w, "P_11", money(line.line_net.quantize(Decimal("0.01"))))
        stawka = sub(w, "P_12", str(int(line.vat_rate)) if _is_numeric(line.vat_rate) else line.vat_rate)
        if line.gtu_code:
            stawka.set("gtuCode", line.gtu_code)

    rz = sub(fa, "Rozliczenie")
    sub(rz, "DoZaplaty", money(total_net + total_vat))

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)  # type: ignore[no-any-return]


def _is_numeric(value: str) -> bool:
    try:
        Decimal(value)
        return True
    except Exception:
        return False


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
