#!/usr/bin/env bash
# The agent-r flow's resource server (spire-workload's rs-accounts): a federation entity of its own, vouched for by
# Raidiam (its own software statement, ClientId the resource's URL, e.g. https://host.docker.internal:8446), whose
# oauth_resource metadata names PingFederate as its authorisation server. See README.md, "The agent-r flow".
#
#   raidiam/resource.sh keys          the resource's federation entity key (RSA 2048, as Raidiam certifies
#                                     rtssigning keys)
#   raidiam/resource.sh csr <ssid> [<subject prefix>]
#                                     a CSR for it, for software statement <ssid> to certify; <subject prefix>
#                                     defaults to /C=GB/O=CBA Trust Framework/OU=CBA-123
#
# Keys under ${DIR#$HERE/}/ (git-ignored). Idempotent: an existing key is kept.
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="/C=;/CN="
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# RESOURCE=<name> (default rs-accounts): keys/raidiam/<name>/, one directory per resource server.
DIR="$HERE/keys/raidiam/${RESOURCE:-rs-accounts}"
mkdir -p "$DIR"; chmod 700 "$DIR"

keys() {
  if [[ -f "$DIR/entity.private.jwk.json" ]]; then echo "kept      ${DIR#$HERE/}/entity.*"; return; fi
  ( umask 177
    # shellcheck disable=SC2016
    KEYS_DIR="$DIR" node -e '
      const { generateKeyPairSync, createHash } = require("crypto");
      const fs = require("fs");
      const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const pub = publicKey.export({ format: "jwk" });
      const kid = createHash("sha256").update(JSON.stringify({ e: pub.e, kty: pub.kty, n: pub.n })).digest("base64url");
      const meta = { kid, use: "sig", alg: "PS256" };
      const dir = process.env.KEYS_DIR;
      fs.writeFileSync(`${dir}/entity.private.jwk.json`, JSON.stringify({ ...privateKey.export({ format: "jwk" }), ...meta }));
      fs.writeFileSync(`${dir}/entity.key.pem`, privateKey.export({ format: "pem", type: "pkcs8" }));
      fs.writeFileSync(`${dir}/entity.public.jwks.json`, JSON.stringify({ keys: [{ ...pub, ...meta }] }));
    ' )
  chmod 644 "$DIR/entity.public.jwks.json"
  # The container reads the key as its own user.
  chmod 644 "$DIR/entity.private.jwk.json"
  echo "generated ${DIR#$HERE/}/entity.*"
}

csr() {
  local ssid="${1:?usage: $0 csr <software statement id> [<subject prefix>]}"
  local prefix="${2:-/C=GB/O=CBA Trust Framework/OU=CBA-123}"
  [[ -f "$DIR/entity.key.pem" ]] || { echo "ERROR: no entity key - run $0 keys" >&2; exit 1; }
  openssl req -new -key "$DIR/entity.key.pem" -subj "$prefix/CN=$ssid" -sha256 -out "$DIR/entity-$ssid.csr"
  echo "wrote     ${DIR#$HERE/}/entity-$ssid.csr  (upload as an rtssigning key)"
}

case "${1:-}" in
  keys) keys ;;
  csr) shift; csr "$@" ;;
  *) echo "usage: $0 keys | csr <software statement id> [<subject prefix>]" >&2; exit 1 ;;
esac
