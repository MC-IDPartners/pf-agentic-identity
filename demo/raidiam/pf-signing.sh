#!/usr/bin/env bash
# PingFederate's federation signing key, certified by Raidiam: an organisation-level server_signing certificate, as
# CBA's authorisation servers hold theirs (CN=op-commbiz). PingFederate signs its Entity Configuration with its
# current OAuth/OIDC signing key, so that key must be one Raidiam vouches for: static keys
# (terraform/signing-keys.tf), this key active, published under Raidiam's kid (the certificate's x5t#S256).
#
#   raidiam/pf-signing.sh csr [<common name>]      the key (RSA 2048) and a CSR for it; CN defaults to op-pingfederate-rig.
#                                                  Upload it at organisation level as a server_signing certificate.
#   raidiam/pf-signing.sh import <certificate>     Raidiam's certificate (PEM) -> keys/raidiam/pf-signing/signing.p12
#                                                  and kid.txt, for terraform/signing-keys.tf
#
# Under keys/raidiam/pf-signing/ (git-ignored). The key is kept if it exists.
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="/C=;/CN="
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$HERE/keys/raidiam/pf-signing"
mkdir -p "$DIR"; chmod 700 "$DIR"

case "${1:-}" in
  csr)
    cn="${2:-op-pingfederate-rig}"
    [[ -f "$DIR/signing.key.pem" ]] || ( umask 177; openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DIR/signing.key.pem" 2>/dev/null )
    openssl req -new -key "$DIR/signing.key.pem" -subj "/C=GB/O=CBA Trust Framework/OU=CBA-123/CN=$cn" -sha256 -out "$DIR/signing.csr"
    echo "wrote     keys/raidiam/pf-signing/signing.csr  (upload at organisation level as server_signing)"
    ;;
  import)
    cert="${2:?usage: $0 import <certificate PEM from Raidiam>}"
    openssl x509 -in "$cert" -noout >/dev/null
    # The key and the certificate must belong together.
    [[ "$(openssl x509 -in "$cert" -noout -pubkey)" == "$(openssl pkey -in "$DIR/signing.key.pem" -pubout)" ]] \
      || { echo "ERROR: $cert is not for keys/raidiam/pf-signing/signing.key.pem" >&2; exit 1; }
    cp "$cert" "$DIR/signing.crt.pem"
    # Raidiam's kid is the certificate's x5t#S256.
    openssl x509 -in "$cert" -outform DER | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=' > "$DIR/kid.txt"
    ( umask 177; openssl pkcs12 -export -inkey "$DIR/signing.key.pem" -in "$cert" -name pf-raidiam-signing \
        -passout pass:changeit -out "$DIR/signing.p12" )
    echo "wrote     keys/raidiam/pf-signing/signing.p12 and kid.txt ($(cat "$DIR/kid.txt"))"
    ;;
  *) echo "usage: $0 csr [<common name>] | import <certificate>" >&2; exit 1 ;;
esac
