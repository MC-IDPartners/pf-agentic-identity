#!/usr/bin/env bash
# Copies the JWT-SVID keys of a SPIRE trust bundle to keys/raidiam/spire-bundle.jwks.json, which
# terraform/attestation.tf puts on the attestation client as attestation_spiffe_bundle. PingFederate verifies
# the workload's JWT-SVIDs against it offline; it never calls SPIRE.
#
#   docker exec <spire-server> /opt/spire/bin/spire-server bundle show -format spiffe > bundle.json
#   raidiam/import-spire-bundle.sh bundle.json
#
# SPIRE rotates these keys (its ca_ttl); when it does, import the new bundle and author again.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:?usage: $0 <spire bundle, spiffe format>}"
mkdir -p "$HERE/keys/raidiam"
SRC="$SRC" OUT="$HERE/keys/raidiam/spire-bundle.jwks.json" node -e '
  const fs = require("fs");
  const keys = (JSON.parse(fs.readFileSync(process.env.SRC, "utf8")).keys || []).filter(k => k.use === "jwt-svid");
  if (!keys.length) { console.error("ERROR: " + process.env.SRC + " holds no jwt-svid keys"); process.exit(1); }
  fs.writeFileSync(process.env.OUT, JSON.stringify({ keys }));
  console.log("imported  keys/raidiam/spire-bundle.jwks.json (" + keys.length + " jwt-svid key(s))");
'
