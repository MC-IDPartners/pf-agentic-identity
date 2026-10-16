#!/usr/bin/env bash
# Export the authoring PingFederate's realised config as the rig's deploy artefact.
#
#   data.zip                               the configArchive the image's drop-in-deployer imports
#   overlay/pf.jwk                         the master key that archive's secrets are encrypted under
#   overlay/pingfederate-system-keys.xml   and its system keys
#
# All three are git-ignored and must stay so: a configArchive is a plain zip with pf.jwk inside it.
# This rig ships the archive in plaintext, which the image build warns about, because the key is one
# this script's PingFederate generated for itself an hour ago and protects three public JWKS and one
# generated secret. Do not copy that reasoning to an environment whose key protects anything else.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${PF_AUTHOR_ENV:?set PF_AUTHOR_ENV to the env file the authoring container was started with}"
HOST="${PF_ADMIN_HOST:-https://localhost:19999}"
[[ "$HOST" =~ ^https://(localhost|127\.0\.0\.1)(:[0-9]+)?$ ]] || { echo "ERROR: PF_ADMIN_HOST must be local" >&2; exit 1; }

umask 177
PW="$(sed -n 's/^PING_IDENTITY_PASSWORD=//p' "$PF_AUTHOR_ENV")"
code="$(curl -sk --max-time 180 -u "administrator:$PW" -H 'X-XSRF-Header: PingFederate' \
  -o "$HERE/data.zip.tmp" -w '%{http_code}' "$HOST/pf-admin-api/v1/configArchive/export")"
[[ "$code" == "200" ]] || { rm -f "$HERE/data.zip.tmp"; echo "ERROR: export returned HTTP $code" >&2; exit 1; }

# An archive without these imports cleanly and produces a rig that fails the suite for reasons that
# look like PingFederate's: the wrong issuer, or a listener still offering CBC suites.
listing="$(unzip -l "$HERE/data.zip.tmp")"
for member in pf.jwk pingfederate-system-keys.xml config-store/com.pingidentity.crypto.SunJCEManager.xml \
              config-store/org.sourceid.openid.ciba.handlers.CibaHelper.xml \
              config-store/org.sourceid.oauth20.domain.AuthzServerManagerImpl.xml; do
  grep -q " $member\$" <<<"$listing" || { rm -f "$HERE/data.zip.tmp"; echo "ERROR: archive has no $member" >&2; exit 1; }
done
if unzip -p "$HERE/data.zip.tmp" config-store/com.pingidentity.crypto.SunJCEManager.xml | grep -q '_CBC_'; then
  rm -f "$HERE/data.zip.tmp"
  echo "ERROR: the archive still enables CBC cipher suites - stage config-store/ into the authoring" >&2
  echo "       PingFederate and restart it before exporting (see README.md). The image overlay alone" >&2
  echo "       is not enough: an import of this archive would write the stock list back to disk." >&2
  exit 1
fi

ciba_window="$(unzip -p "$HERE/data.zip.tmp" config-store/org.sourceid.openid.ciba.handlers.CibaHelper.xml | LC_ALL=C grep -ac 'nbfMaxPastInMinutes">60<' || true)"
if [[ "${ciba_window:-0}" -eq 0 ]]; then
  rm -f "$HERE/data.zip.tmp"
  echo "ERROR: the archive's CIBA request-object window is not 60 minutes - stage config-store/ into the" >&2
  echo "       authoring PingFederate before it first starts (author.sh does), then re-export." >&2
  exit 1
fi
audience_rule="$(unzip -p "$HERE/data.zip.tmp" config-store/org.sourceid.oauth20.domain.AuthzServerManagerImpl.xml \
  | LC_ALL=C grep -ac 'Rfc7523bisCompliantAudienceVerification"[^>]*>false<' || true)"
if [[ "${audience_rule:-0}" -eq 0 ]]; then
  rm -f "$HERE/data.zip.tmp"
  echo "ERROR: the archive accepts only the issuer as a client assertion's audience, which fails the SSF plan's" >&2
  echo "       client at the token endpoint - stage config-store/ into the authoring PingFederate before it first" >&2
  echo "       starts (author.sh does), then re-export." >&2
  exit 1
fi
# COUNT the matches; never `grep -q` here. Under `set -o pipefail`, grep -q exits at its first match,
# unzip dies of SIGPIPE, and the pipeline reports failure - a plugin that IS in the archive reads as
# absent (the assemble script has the same note, learned the same way). No member pattern: with none, unzip
# prints every member, and a '*' pattern matches nothing under Git for Windows' unzip.
sim_hits="$(unzip -p "$HERE/data.zip.tmp" 2>/dev/null | LC_ALL=C grep -ac 'SimOobAuthenticator' || true)"
if [[ "${sim_hits:-0}" -eq 0 ]]; then
  rm -f "$HERE/data.zip.tmp"
  echo "ERROR: the archive has no CIBA simulator instance - was terraform/ciba.tf applied against an" >&2
  echo "       authoring PingFederate that had plugins/ciba-sim in its deploy directory (author.sh)?" >&2
  exit 1
fi

mv "$HERE/data.zip.tmp" "$HERE/data.zip"
mkdir -p "$HERE/overlay"; chmod 700 "$HERE/overlay"
unzip -o -q -j "$HERE/data.zip" pf.jwk pingfederate-system-keys.xml -d "$HERE/overlay"
echo "exported data.zip ($(wc -c < "$HERE/data.zip" | tr -d ' ') bytes) and overlay/ - none of it is for git"
