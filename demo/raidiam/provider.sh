#!/usr/bin/env bash
# The agent provider: a federation entity of its own, vouched for by Raidiam (its own software statement, ClientId
# the entity host's root, e.g. https://host.docker.internal:8443), that hosts the agents' entity configurations and
# publishes its attester key - so PingFederate trusts the attestations it signs (/attest) through the federation - and
# the SPIFFE bindings of every agent it hosts, which PingFederate's own attester reads. The pattern of CBA's agent
# provider (https://provider.demo.cba.raidiam.io). See README.md, "Attesters trusted through the federation".
#
#   raidiam/provider.sh keys          the provider's federation entity key (RSA 2048, as Raidiam certifies
#                                     rtssigning keys) and the attester's signing key (EC P-256, ES256)
#   raidiam/provider.sh csr <ssid> [<subject prefix>]
#                                     a CSR for the entity key, for software statement <ssid> to certify;
#                                     <subject prefix> defaults to /C=GB/O=CBA Trust Framework/OU=CBA-123
#
# Keys under keys/raidiam/provider/ (git-ignored). Idempotent: an existing key is kept.
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="/C=;/CN="
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$HERE/keys/raidiam/provider"
mkdir -p "$DIR"; chmod 700 "$DIR"

keys() {
  for spec in entity:rsa:PS256 attester:ec:ES256; do
    IFS=: read -r name type alg <<< "$spec"
    if [[ -f "$DIR/$name.private.jwk.json" ]]; then echo "kept      keys/raidiam/provider/$name.*"; continue; fi
    ( umask 177
      # shellcheck disable=SC2016
      KEY_NAME="$name" KEY_TYPE="$type" KEY_ALG="$alg" KEYS_DIR="$DIR" node -e '
        const { generateKeyPairSync, createHash } = require("crypto");
        const fs = require("fs");
        const { privateKey, publicKey } = process.env.KEY_TYPE === "rsa"
          ? generateKeyPairSync("rsa", { modulusLength: 2048 })
          : generateKeyPairSync("ec", { namedCurve: "P-256" });
        const pub = publicKey.export({ format: "jwk" });
        const members = pub.kty === "RSA" ? { e: pub.e, kty: pub.kty, n: pub.n } : { crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y };
        const kid = createHash("sha256").update(JSON.stringify(members)).digest("base64url");
        const meta = { kid, use: "sig", alg: process.env.KEY_ALG };
        const dir = process.env.KEYS_DIR, name = process.env.KEY_NAME;
        fs.writeFileSync(`${dir}/${name}.private.jwk.json`, JSON.stringify({ ...privateKey.export({ format: "jwk" }), ...meta }));
        fs.writeFileSync(`${dir}/${name}.key.pem`, privateKey.export({ format: "pem", type: "pkcs8" }));
        fs.writeFileSync(`${dir}/${name}.public.jwks.json`, JSON.stringify({ keys: [{ ...pub, ...meta }] }));
      ' )
    chmod 644 "$DIR/$name.public.jwks.json"
    echo "generated keys/raidiam/provider/$name.*"
  done
}

csr() {
  local ssid="${1:?usage: $0 csr <software statement id> [<subject prefix>]}"
  local prefix="${2:-/C=GB/O=CBA Trust Framework/OU=CBA-123}"
  [[ -f "$DIR/entity.key.pem" ]] || { echo "ERROR: no entity key - run $0 keys" >&2; exit 1; }
  openssl req -new -key "$DIR/entity.key.pem" -subj "$prefix/CN=$ssid" -sha256 -out "$DIR/entity-$ssid.csr"
  echo "wrote     keys/raidiam/provider/entity-$ssid.csr  (upload as an rtssigning key)"
}

case "${1:-}" in
  keys) keys ;;
  csr) shift; csr "$@" ;;
  *) echo "usage: $0 keys | csr <software statement id> [<subject prefix>]" >&2; exit 1 ;;
esac
