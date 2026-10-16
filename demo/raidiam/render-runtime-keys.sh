#!/usr/bin/env bash
# The two files docker-compose.raidiam.yml mounts into the running PingFederate, rendered for one issuer into
# keys/raidiam/runtime/ (git-ignored):
#
#   mock-attesters.json        {<issuer>: <attester's public JWKS>} - the attester PingFederate's token endpoint
#                              trusts with no federation chain (oidf.mock.attesters; development only).
#   bridge-signing-keys.json   {<client>: {jwk: <bridge private JWK>, attesters: [<issuer>]}} - the bridge key
#                              per attested client (OIDF_BRIDGE_SIGNING_KEYS, OIDF_BRIDGE_SIGNER_BACKING=config),
#                              and the attesters that client's attestations may come from.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
ISSUER="${1:?usage: $0 <issuer>}"
KEYS="$HERE/keys/raidiam"
CLIENT="${SPIRE_ATTESTATION_CLIENT_ID:-spire-workload}"
for f in attester-signing.public.jwks.json "bridge-$CLIENT.private.jwk.json"; do
  [[ -f "$KEYS/$f" ]] || { echo "ERROR: no keys/raidiam/$f - run raidiam/gen-keys.sh (up.sh does)" >&2; exit 1; }
done
mkdir -p "$KEYS/runtime"; chmod 700 "$KEYS/runtime"
( umask 177
  ISSUER="$ISSUER" CLIENT="$CLIENT" KEYS="$KEYS" ATTESTED="${RAIDIAM_ATTESTED_CLIENT_ID:-}" node -e '
    const fs = require("fs"), k = process.env.KEYS, iss = process.env.ISSUER.replace(/\/+$/, "");
    const read = f => JSON.parse(fs.readFileSync(`${k}/${f}`, "utf8"));
    fs.writeFileSync(`${k}/runtime/mock-attesters.json`, JSON.stringify({ [iss]: read("attester-signing.public.jwks.json") }));
    const bridges = { [process.env.CLIENT]: { jwk: read(`bridge-${process.env.CLIENT}.private.jwk.json`), attesters: [iss] } };
    // The federated attested client (attested-client.sh), when RAIDIAM_ATTESTED_CLIENT_ID names it.
    if (process.env.ATTESTED) bridges[process.env.ATTESTED] = { jwk: read("attested-client/bridge.private.jwk.json"), attesters: [iss] };
    fs.writeFileSync(`${k}/runtime/bridge-signing-keys.json`, JSON.stringify(bridges));
  ' )
# PingFederate reads them as its own user; the directory stays 0700 on the host.
chmod 644 "$KEYS/runtime/mock-attesters.json" "$KEYS/runtime/bridge-signing-keys.json"
echo "rendered  keys/raidiam/runtime/ for issuer $ISSUER"
