#!/usr/bin/env bash
# The files docker-compose.raidiam.yml mounts into the running PingFederate, rendered for one issuer into
# keys/raidiam/runtime/ (git-ignored):
#
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
  ISSUER="$ISSUER" CLIENT="$CLIENT" KEYS="$KEYS" ATTESTED="${RAIDIAM_ATTESTED_CLIENT_ID:-}" PROVIDER="${RAIDIAM_PROVIDER_ID:-}" HOSTED="${RAIDIAM_HOSTED_AGENTS:-}" BACKING="${RAIDIAM_BRIDGE_BACKING:-config}" SLOTS="${RAIDIAM_PRINCIPAL_SLOTS-principal-1 principal-2 principal-3 principal-4}" node -e '
    const fs = require("fs"), k = process.env.KEYS, iss = process.env.ISSUER.replace(/\/+$/, "");
    const read = f => JSON.parse(fs.readFileSync(`${k}/${f}`, "utf8"));
    const bridges = { [process.env.CLIENT]: { jwk: read(`bridge-${process.env.CLIENT}.private.jwk.json`), attesters: [iss] } };
    // The federated attested client (attested-client.sh), when RAIDIAM_ATTESTED_CLIENT_ID names it, and the agents
    // of the provider: attested by the attester PingFederate co-hosts or, with RAIDIAM_PROVIDER_ID (provider.sh), by the provider -
    // either trusted through its federation chain.
    const provider = process.env.PROVIDER.replace(/\/+$/, "");
    const attesters = provider ? [iss, provider] : [iss];
    if (process.env.ATTESTED) bridges[process.env.ATTESTED] = { jwk: read("attested-client/bridge.private.jwk.json"), attesters };
    // The provider sub-agents (RAIDIAM_HOSTED_AGENTS): <provider>/agent/<name>, their keys under agents/<name>/.
    for (const name of process.env.HOSTED.split(/[\s,]+/).filter(Boolean)) {
      if (!provider) throw new Error("RAIDIAM_HOSTED_AGENTS needs RAIDIAM_PROVIDER_ID");
      bridges[`${provider}/agent/${name}`] = { jwk: read(`agents/${name}/bridge.private.jwk.json`), attesters };
    }
    // The Principal version slots (raidiam/attested-client.sh PRINCIPAL=<slot>): <provider>/agent/<slot>, ready for the
    // marketplace to deploy into while PingFederate runs - it reads this file only at start-up.
    for (const slot of process.env.SLOTS.split(/[\s,]+/).filter(Boolean)) {
      if (!provider || !fs.existsSync(`${k}/principals/${slot}/bridge.private.jwk.json`)) continue;
      bridges[`${provider}/agent/${slot}`] = { jwk: read(`principals/${slot}/bridge.private.jwk.json`), attesters };
    }
    // RAIDIAM_BRIDGE_BACKING=vault (../openbao): the same clients, each naming its bridge key in OpenBao instead of
    // carrying it, and a template for the agents of the provider - an agent enrolled while PingFederate runs (its key
    // bridge-<name> created in the vault by the provider) needs no entry, no slot and no restart.
    if (process.env.BACKING === "vault") {
      const vault = {};
      for (const [client, entry] of Object.entries(bridges)) {
        if (provider && client.startsWith(`${provider}/agent/`)) continue; // the template serves these
        vault[client] = { key_ref: `bridge-${client}`, attesters: entry.attesters };
      }
      if (provider) {
        vault["*"] = { key_ref: "bridge-{client_suffix}", client_id_prefix: `${provider}/agent/`, attesters };
      }
      fs.writeFileSync(`${k}/runtime/bridge-signing-keys.json`, JSON.stringify(vault));
    } else {
      fs.writeFileSync(`${k}/runtime/bridge-signing-keys.json`, JSON.stringify(bridges));
    }
  ' )
#   truststore.p12             the JDK's CAs plus the rig's runtime CA, as PingFederate's JVM default trust store
#                              (JAVA_OPTS in docker-compose.raidiam.yml). The modules' federation and remote-JWKS fetches
#                              check certificates against that store, not PingFederate's trusted CAs, so this is what
#                              lets them reach the rig's own hosts - the entity host, SPIRE's OIDC provider - with
#                              certificates checked, Raidiam's included.
KEYTOOL="$(command -v keytool || true)"
[[ -n "$KEYTOOL" || -z "${JAVA_HOME:-}" ]] || KEYTOOL="$JAVA_HOME/bin/keytool"
[[ -n "$KEYTOOL" ]] || { echo "ERROR: keytool not found - put a JDK's bin on PATH or set JAVA_HOME" >&2; exit 1; }
# The image's own CAs, so PingFederate keeps exactly the roots it ships with; on a first run, before the image is
# built, the host JDK's.
IMAGE="${PF_RIG_NAME:-pf-agentic-identity}/pingfederate:local"
CACERTS="$KEYS/runtime/image-cacerts"
if ! MSYS_NO_PATHCONV=1 docker run --rm --entrypoint cat "$IMAGE" /opt/java/lib/security/cacerts > "$CACERTS" 2>/dev/null; then
  CACERTS="$(cd "$(dirname "$(command -v "$KEYTOOL")")/.." && pwd)/lib/security/cacerts"
  echo "NOTE: no $IMAGE yet - the trust store starts from the host JDK's CAs; run up.sh again to use the image's" >&2
fi
[[ -s "$CACERTS" ]] || { echo "ERROR: no JDK cacerts at $CACERTS" >&2; exit 1; }
# Unprotected, as the JDK builds its own cacerts: the JVM reads that file with no password, and a store whose
# certificates keytool encrypted (its default) reads as holding none.
UNPROTECTED=(-J-Dkeystore.pkcs12.certProtectionAlgorithm=NONE -J-Dkeystore.pkcs12.macAlgorithm=NONE)
rm -f "$KEYS/runtime/truststore.p12"
"$KEYTOOL" "${UNPROTECTED[@]}" -importkeystore -noprompt -srckeystore "$CACERTS" -srcstorepass changeit \
  -destkeystore "$KEYS/runtime/truststore.p12" -deststoretype PKCS12 -deststorepass changeit >/dev/null 2>&1
"$KEYTOOL" "${UNPROTECTED[@]}" -importcert -noprompt -alias pf-agentic-identity-rig-ca -file "$HERE/keys/pf-runtime-tls-ca.crt" \
  -keystore "$KEYS/runtime/truststore.p12" -storetype PKCS12 -storepass changeit >/dev/null
# PingFederate reads them as its own user; the directory stays 0700 on the host.
chmod 644 "$KEYS/runtime/bridge-signing-keys.json" "$KEYS/runtime/truststore.p12"
echo "rendered  keys/raidiam/runtime/ for issuer $ISSUER"
