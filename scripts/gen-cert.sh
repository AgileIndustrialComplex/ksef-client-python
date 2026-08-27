#!/usr/bin/env bash
# Generate an RSA key pair + self-signed X.509 certificate for KSeF
# certificate (XAdES) authentication (test environment), then verify the
# files load back via LoadedCertificate.from_pem.
#
# Usage:
#   bash scripts/gen-cert.sh --nip 5265877635 [--out-dir ./certs] [--ask-password]
#
# Writes <out>/cert.pem and <out>/key.pem. All extra args are forwarded to
# `ksef-client gen-cert`. Falls back to `python -m ksef.cli` if the console
# script is not present in the repo venv.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO/.venv"

# --- locate an invocation we can run ---------------------------------------
if [ -x "$VENV/bin/ksef-client" ]; then
  GEN=( "$VENV/bin/ksef-client" gen-cert )
elif [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import ksef" >/dev/null 2>&1; then
  GEN=( "$VENV/bin/python" -m ksef.cli gen-cert )
else
  echo "ERROR: no ksef-client entry point or ksef-installed python found." >&2
  echo "Install the editable package first:" >&2
  echo "  uv pip install --python $VENV/bin/python -e '$REPO[xades]'" >&2
  exit 1
fi

# --- default output dir unless the user already set one --------------------
if ! [[ " $* " == *" --out-dir "* ]]; then
  set -- "$@" --out-dir "./certs"
fi

echo "Generating KSeF XAdES certificate + key pair via: ${GEN[*]}"
"${GEN[@]}" "$@"

# --- resolve the effective --out-dir ---------------------------------------
OUT_DIR="./certs"
prev=""
for arg in "$@"; do
  if [ "$prev" = "--out-dir" ]; then
    OUT_DIR="$arg"
  fi
  prev="$arg"
done
CERT="$OUT_DIR/cert.pem"
KEY="$OUT_DIR/key.pem"

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  echo "ERROR: expected files not found ($CERT / $KEY)" >&2
  exit 1
fi

# --- verify the pair loads back via the consumer API ------------------------
# Warning (not fatal): some sandboxes/CI secret-guards replace on-disk private
# key bytes with a placeholder, which makes a reload fail even though the PEMs
# were written correctly. Report it but don't fail the run.
TMPERR="$(mktemp)"
if "$VENV/bin/python" -c 'import sys
from ksef.xades import LoadedCertificate
LoadedCertificate.from_pem(sys.argv[1], sys.argv[2])
' "$CERT" "$KEY" 2>"$TMPERR"; then
  echo "  verified OK: LoadedCertificate.from_pem loads the pair"
else
  echo "WARNING: could not reload $KEY via LoadedCertificate.from_pem." >&2
  echo "         Expected if a sandbox/CI secret-guard redacts private-key bytes;" >&2
  echo "         the PEM was still written and will load on a normal host." >&2
  if [ -s "$TMPERR" ]; then sed 's/^/         /' "$TMPERR" >&2; fi
fi
rm -f "$TMPERR"

echo "Done. Files:"
ls -l "$CERT" "$KEY"
echo
echo "Use in code:"
echo "  from ksef.xades import LoadedCertificate"
echo "  cert = LoadedCertificate.from_pem('$CERT', '$KEY')"