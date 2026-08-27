"""Command-line tools for ksef-client-python.

Currently one command, ``gen-cert``: generate the RSA keypair + self-signed
X.509 certificate used for **KSeF certificate (XAdES) authentication**.

KSeF authenticates a machine/integrator with a qualified seal certificate and
its private key (the *client* key pair). On the **test environment** a
self-signed certificate is accepted, so you can generate one here and point
the client at the resulting ``cert.pem`` / ``key.pem`` via
``ksef.xades.LoadedCertificate.from_pem(...)``.

Usage
-----
.. code-block:: bash

    # basic, no key password
    ksef-client gen-cert --nip 5265877635 --out ./certs

    # password-protected key + custom subject
    ksef-client gen-cert --nip 5265877635 --out ./certs \
        --cn "My Sp. z o.o." --country PL --days 365 --key-size 2048 \
        --ask-password

    # list help
    ksef-client gen-cert --help
"""

from __future__ import annotations

import argparse
import datetime
import getpass
import sys
from pathlib import Path
from typing import Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
)
from cryptography.x509.oid import NameOID

DEFAULT_COUNTRY = "PL"
DEFAULT_DAYS = 365
DEFAULT_KEY_SIZE = 2048
DEFAULT_OUT = Path("./certs")


def _serial_number_oid(country: str, serial_number: str) -> str:
    """KSeF reads the taxpayer identity from the cert's serial-number field.

    PL personal/seal certs carry the value as ``TINPL-<NIP>`` (Poland's TIN).
    For other countries fall back to ``<country>-<serial>`` so the identifier
    shape stays meaningful.
    """
    if country.upper() == "PL":
        return f"TINPL-{serial_number}"
    return f"{country.upper()}-{serial_number}"


def generate_keypair(key_size: int = DEFAULT_KEY_SIZE) -> rsa.RSAPrivateKey:
    """Generate a fresh RSA private key with a public exponent of 65537."""
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def self_signed_certificate(
    key: rsa.RSAPrivateKey,
    subject: x509.Name,
    *,
    days: int = DEFAULT_DAYS,
) -> x509.Certificate:
    """Build a self-signed X.509 cert (CA:false) for the given key + subject."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )


def write_key_pair(
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey,
    out_dir: Path,
    key_password: bytes | None,
) -> tuple[Path, Path]:
    """Write ``cert.pem`` + ``key.pem`` into ``out_dir``; return their paths."""
    out_dir.mkdir(parents=True, exist_ok=True)

    cert_path = out_dir / "cert.pem"
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )

    encryption = (
        BestAvailableEncryption(key_password) if key_password else NoEncryption()
    )
    key_path = out_dir / "key.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            encryption,
        )
    )
    return cert_path, key_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ksef-client",
        description="Generate an RSA key pair + self-signed X.509 cert for KSeF "
        "certificate (XAdES) authentication against the test environment.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser(
        "gen-cert",
        help="generate an RSA key pair + self-signed certificate",
        description="Generate a private key + self-signed X.509 certificate for "
        "KSeF XAdES authentication (accessor cert/key). Cert files get written "
        "as <out>/cert.pem and <out>/key.pem.",
    )
    gen.add_argument("--nip", required=True, help="taxpayer NIP (binds the cert subject)")
    gen.add_argument(
        "--cn",
        default=None,
        help="certificate Common Name (default: derived from NIP)",
    )
    gen.add_argument("--country", default=DEFAULT_COUNTRY, help=f"country code (default {DEFAULT_COUNTRY})")
    gen.add_argument("--days", type=int, default=DEFAULT_DAYS, help=f"certificate validity days (default {DEFAULT_DAYS})")
    gen.add_argument("--key-size", type=int, default=DEFAULT_KEY_SIZE, help=f"RSA key size (default {DEFAULT_KEY_SIZE})")
    gen.add_argument("--out-dir", type=Path, default=DEFAULT_OUT, help=f"output directory (default {DEFAULT_OUT})")
    gen.add_argument(
        "--ask-password",
        action="store_true",
        help="prompt for a password and encrypt the private key (default: no password)",
    )
    gen.set_defaults(handler=_cmd_gen_cert)
    return parser


def _cmd_gen_cert(args: argparse.Namespace) -> int:
    cn = args.cn or f"ksef-client test {args.nip}"
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.COUNTRY_NAME, args.country),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, _serial_number_oid(args.country, args.nip)),
        ]
    )
    key = generate_keypair(args.key_size)
    cert = self_signed_certificate(key, subject, days=args.days)

    password: bytes | None = None
    if args.ask_password:
        p1 = getpass.getpass("Private-key password: ")
        p2 = getpass.getpass("Repeat password: ")
        if p1 != p2:
            print("error: passwords do not match", file=sys.stderr)
            return 1
        if p1:
            password = p1.encode()

    cert_path, key_path = write_key_pair(cert, key, args.out_dir, password)

    print(f"wrote certificate: {cert_path}")
    print(f"wrote private key: {key_path}  ({'password-protected' if password else 'no password'})")
    print(
        "load via:\n"
        "  from ksef.xades import LoadedCertificate\n"
        f"  LoadedCertificate.from_pem({str(cert_path)!r}, {str(key_path)!r}"
        + (f", key_password={bytes(password)!r})" if password else ")")
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 2
    return int(handler(args))  # handler() returns an int exit code


if __name__ == "__main__":
    raise SystemExit(main())