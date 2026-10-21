#!/usr/bin/env bash
# The federated attested client: a client registered in Raidiam whose own Entity Configuration says which SPIFFE IDs
# are its instances (spiffe_client_bindings), so PingFederate's attester learns them through the federation
# (OIDF_ATTESTER_FEDERATION_ENTITY) instead of from a client PingFederate holds. See README.md, "Attestation from a
# federation entity".
#
#   [AGENT=<name>] raidiam/attested-client.sh keys
#                                            the client's federation entity key and its bridge key (RSA 2048, as
#                                            Raidiam certifies rtssigning keys), and the entity host's TLS
#                                            certificate from the rig's runtime CA
#   raidiam/attested-client.sh csr <ssid> [<subject prefix>]
#                                            a CSR for each key, for software statement <ssid> to certify;
#                                            <subject prefix> defaults to /C=GB/O=CBA Trust Framework/OU=CBA-123
#
# Keys under keys/raidiam/attested-client/ (git-ignored). Idempotent: an existing key is kept.
set -euo pipefail
export MSYS2_ARG_CONV_EXCL="/C=;/CN="
HERE="$(cd "$(dirname "$0")/.." && pwd)"
# AGENT=<name> keeps another agent's keys apart, under keys/raidiam/agents/<name>/ (the sub-agents, each serving its own Entity Configuration);
# PRINCIPAL=<slot> a Principal version slot's, under keys/raidiam/principals/<slot>/ (the marketplace deploys versions
# into slots; the provider makes their CSRs itself); unset, the Principal's, under keys/raidiam/attested-client/.
DIR="$HERE/keys/raidiam/${AGENT:+agents/$AGENT}"
[[ -n "${AGENT:-}" ]] || DIR="$HERE/keys/raidiam/attested-client"
[[ -z "${PRINCIPAL:-}" ]] || DIR="$HERE/keys/raidiam/principals/$PRINCIPAL"
mkdir -p "$DIR"; chmod 700 "$DIR"

keys() {
  for name in entity bridge; do
    if [[ -f "$DIR/$name.private.jwk.json" ]]; then echo "kept      ${DIR#$HERE/}/$name.*"; continue; fi
    ( umask 177
      # shellcheck disable=SC2016
      KEY_NAME="$name" KEYS_DIR="$DIR" node -e '
        const { generateKeyPairSync, createHash } = require("crypto");
        const fs = require("fs");
        const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
        const pub = publicKey.export({ format: "jwk" });
        const kid = createHash("sha256").update(JSON.stringify({ e: pub.e, kty: pub.kty, n: pub.n })).digest("base64url");
        const meta = { kid, use: "sig", alg: "PS256" };
        const dir = process.env.KEYS_DIR, name = process.env.KEY_NAME;
        fs.writeFileSync(`${dir}/${name}.private.jwk.json`, JSON.stringify({ ...privateKey.export({ format: "jwk" }), ...meta }));
        fs.writeFileSync(`${dir}/${name}.key.pem`, privateKey.export({ format: "pem", type: "pkcs8" }));
        fs.writeFileSync(`${dir}/${name}.public.jwks.json`, JSON.stringify({ keys: [{ ...pub, ...meta }] }));
      ' )
    chmod 644 "$DIR/$name.public.jwks.json"
    echo "generated ${DIR#$HERE/}/$name.*"
  done
  # The entity host's certificate, from the rig's runtime CA, which PingFederate already trusts (runtime-tls.tf):
  # one for the host, kept with the Principal's keys.
  if [[ -z "${AGENT:-}${PRINCIPAL:-}" && ! -f "$DIR/entity-host-tls.crt" ]]; then
    CA="$HERE/keys/pf-runtime-tls-ca"
    [[ -f "$CA.key" ]] || { echo "ERROR: no keys/pf-runtime-tls-ca.key - run ../gen-keys.sh (up.sh does)" >&2; exit 1; }
    ( cd "$DIR" && umask 177
      openssl req -new -newkey rsa:2048 -nodes -keyout entity-host-tls.key -subj "/CN=host.docker.internal" \
        -out entity-host-tls.csr >/dev/null 2>&1
      printf 'subjectAltName=DNS:host.docker.internal,DNS:localhost\nextendedKeyUsage=serverAuth\n' > entity-host-tls.ext
      openssl x509 -req -in entity-host-tls.csr -CA "$CA.crt" -CAkey "$CA.key" -CAcreateserial -days 397 \
        -extfile entity-host-tls.ext -out entity-host-tls.crt >/dev/null 2>&1
      rm -f entity-host-tls.csr entity-host-tls.ext )
    chmod 644 "$DIR/entity-host-tls.crt"
    echo "generated keys/raidiam/attested-client/entity-host-tls.* (from the rig's runtime CA)"
  fi
}

csr() {
  local ssid="${1:?usage: $0 csr <software statement id> [<subject prefix>]}"
  local prefix="${2:-/C=GB/O=CBA Trust Framework/OU=CBA-123}"
  for name in entity bridge; do
    [[ -f "$DIR/$name.key.pem" ]] || { echo "ERROR: no $name key - run $0 keys" >&2; exit 1; }
    openssl req -new -key "$DIR/$name.key.pem" -subj "$prefix/CN=$ssid" -sha256 -out "$DIR/$name-$ssid.csr"
    echo "wrote     ${DIR#$HERE/}/$name-$ssid.csr  (upload as an rtssigning key)"
  done
}

case "${1:-}" in
  keys) keys ;;
  csr) shift; csr "$@" ;;
  *) echo "usage: $0 keys | csr <software statement id> [<subject prefix>]" >&2; exit 1 ;;
esac
