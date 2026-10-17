#!/usr/bin/env bash
# The gateway's keys, under keys/gateway/ (git-ignored):
#   pep-ssf.*   the key coaz-pep authenticates to PingFederate with (private_key_jwt, PS256) as the Shared Signals
#               receiver rig-pep-ssf-receiver (terraform/ssf-pep.tf): it holds ssf.manage, and polls its stream.
# Idempotent: an existing key is kept.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DIR="$HERE/keys/gateway"
mkdir -p "$DIR"; chmod 700 "$DIR"
if [[ -f "$DIR/pep-ssf.private.jwk.json" ]]; then echo "kept      keys/gateway/pep-ssf.*"; exit 0; fi
( umask 177
  # shellcheck disable=SC2016
  KEYS_DIR="$DIR" node -e '
    const { generateKeyPairSync, createHash } = require("crypto");
    const fs = require("fs");
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pub = publicKey.export({ format: "jwk" });
    const kid = createHash("sha256").update(JSON.stringify({ e: pub.e, kty: pub.kty, n: pub.n })).digest("base64url");
    const meta = { kid, use: "sig", alg: "PS256" };
    fs.writeFileSync(`${process.env.KEYS_DIR}/pep-ssf.private.jwk.json`, JSON.stringify({ ...privateKey.export({ format: "jwk" }), ...meta }));
    fs.writeFileSync(`${process.env.KEYS_DIR}/pep-ssf.public.jwks.json`, JSON.stringify({ keys: [{ ...pub, ...meta }] }));
  ' )
# The container reads it as its own user; the directory stays 0700 on the host.
chmod 644 "$DIR/pep-ssf.private.jwk.json" "$DIR/pep-ssf.public.jwks.json"
echo "generated keys/gateway/pep-ssf.*"
