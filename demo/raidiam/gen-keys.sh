#!/usr/bin/env bash
# The raidiam profile's two key pairs, under keys/raidiam/ (git-ignored, like every key under keys/):
#
#   attester-signing   PingFederate's attester signs the client attestations it issues with this (the attestation
#                      client's attestation_signing_jwk), and its token endpoint trusts the public half
#                      (oidf.mock.attesters, rendered by render-runtime-keys.sh) - a development hook, refused in
#                      production, standing in for an attester trusted through a federation chain.
#   bridge-<client>    attest_jwt_client_auth's bridge: having checked an attestation, the token-endpoint filter
#                      signs a private_key_jwt for the attested client with the private half, and PingFederate
#                      authenticates it against the public half registered on the client (terraform/attestation.tf).
#
# EC P-256 / ES256, as the 0.1.4 rig used. Idempotent, like ../gen-keys.sh: an existing key is kept, because the
# archive already exported holds its public half. Delete keys/raidiam/ to rotate, then author again.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
KEYS="$HERE/keys/raidiam"
CLIENT="${SPIRE_ATTESTATION_CLIENT_ID:-spire-workload}"
mkdir -p "$KEYS"; chmod 700 "$KEYS"
command -v node >/dev/null || { echo "ERROR: node is required (it exports JWKs natively)" >&2; exit 1; }

for name in attester-signing "bridge-$CLIENT"; do
  if [[ -f "$KEYS/$name.private.jwk.json" ]]; then
    echo "kept      keys/raidiam/$name.*"
    continue
  fi
  ( umask 177
    # shellcheck disable=SC2016
    KEY_NAME="$name" KEYS_DIR="$KEYS" node -e '
      const { generateKeyPairSync, createHash } = require("crypto");
      const fs = require("fs");
      const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
      const pub = publicKey.export({ format: "jwk" });
      const kid = createHash("sha256").update(JSON.stringify({ crv: pub.crv, kty: pub.kty, x: pub.x, y: pub.y })).digest("base64url");
      const meta = { kid, use: "sig", alg: "ES256" };
      const dir = process.env.KEYS_DIR, name = process.env.KEY_NAME;
      fs.writeFileSync(`${dir}/${name}.private.jwk.json`, JSON.stringify({ ...privateKey.export({ format: "jwk" }), ...meta }));
      fs.writeFileSync(`${dir}/${name}.public.jwks.json`, JSON.stringify({ keys: [{ ...pub, ...meta }] }));
    ' )
  chmod 644 "$KEYS/$name.public.jwks.json"
  echo "generated keys/raidiam/$name.*"
done
