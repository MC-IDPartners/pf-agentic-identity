#!/usr/bin/env bash
# Start the LOCAL PingFederate that terraform/ is applied to and that export.sh exports from.
#
# It is the stock image the rig's own image is built FROM (build/pf-version.env), not the rig's image: authoring needs
# an admin API and an empty server, and the rig's image imports an archive at boot and would overwrite
# whatever terraform had applied the next time it restarted.
#
#   PF_AUTHOR_ENV   a KEY=VALUE file holding PING_IDENTITY_PASSWORD - the admin password this server is
#                   created with. Generate one (umask 177; never commit it) and keep using it: apply.sh
#                   and export.sh read the same file. It becomes the archive's admin password.
#   ~/.pingidentity/config  the DevOps user and key the image fetches its evaluation licence with
#   PF_LICENSE_FILE a pingfederate.lic instead: staged into the server's conf/, so the image fetches nothing
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${PF_AUTHOR_ENV:?set PF_AUTHOR_ENV to a KEY=VALUE file holding PING_IDENTITY_PASSWORD}"
NAME="${PF_AUTHOR_NAME:-pf-conformance-author}"
PING_CONFIG="${PING_DEVOPS_CONFIG:-$HOME/.pingidentity/config}"
# shellcheck source=layout.sh
. "$HERE/layout.sh"
# The image the rig's Dockerfile is built FROM, pulled by the same digest: build/pf-version.env is the one
# place it is written down (layout.sh finds it in either tree).
# shellcheck disable=SC1090,SC1091
. "$PFAI_VERSION_ENV"
IMAGE="${PF_IMAGE:?}@${PF_IMAGE_DIGEST:?}"
ADMIN_PORT="${PF_AUTHOR_ADMIN_PORT:-19999}"; RUNTIME_PORT="${PF_AUTHOR_RUNTIME_PORT:-19031}"

docker rm -f "$NAME" >/dev/null 2>&1 || true
# CREATE_INITIAL_ADMIN_USER: the image defaults it to false and then never accepts the licence
# agreement or creates the administrator, and every admin API call answers 403
# license_agreement_not_accepted for as long as you care to wait.
LICENCE_ENV=()
[[ -n "${PF_LICENSE_FILE:-}" ]] || LICENCE_ENV=(--env-file "$PING_CONFIG")
docker create --name "$NAME" \
  ${LICENCE_ENV[@]+"${LICENCE_ENV[@]}"} --env-file "$PF_AUTHOR_ENV" \
  -e PING_IDENTITY_ACCEPT_EULA=YES -e CREATE_INITIAL_ADMIN_USER=true \
  -p "127.0.0.1:$RUNTIME_PORT:9031" -p "127.0.0.1:$ADMIN_PORT:9999" "$IMAGE" >/dev/null
# Staged BEFORE first start so the server comes up with it and the exported archive carries it; see
# config-store/com.pingidentity.crypto.SunJCEManager.xml for why the archive has to.
# (docker cp will not create missing parents, and the stock image's /opt/in is empty - hence the tree.)
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/instance/server/default/data/config-store" "$STAGE/instance/server/default/deploy"
cp "$HERE"/config-store/*.xml "$STAGE/instance/server/default/data/config-store/"
# The CIBA simulator plugin, so terraform/ciba.tf can create an instance of it: PingFederate lists a
# plugin descriptor only for a jar in its deploy directory. Taken from the conformance stage, which up.sh
# writes before it authors, from the reactor or from a release; refused rather than skipped, because an
# archive authored without it has no CIBA and the first sign would be the FAPI-CIBA plan failing on every
# module.
PLUGIN="$PFAI_IMAGE_DIR/modules/pf.plugins.ciba-sim.jar"
[[ -f "$PLUGIN" ]] || { echo "ERROR: no $PLUGIN - stage the conformance profile first; up.sh does (stage-modules.sh or stage-from-release.sh, --profile conformance)" >&2; exit 1; }
cp "$PLUGIN" "$STAGE/instance/server/default/deploy/"
# A licence file, where the base image's licence hook looks before it would fetch an evaluation licence.
if [[ -n "${PF_LICENSE_FILE:-}" ]]; then
  mkdir -p "$STAGE/instance/server/default/conf"
  cp "$PF_LICENSE_FILE" "$STAGE/instance/server/default/conf/pingfederate.lic"
  chmod 644 "$STAGE/instance/server/default/conf/pingfederate.lic"
fi
docker cp "$STAGE/instance" "$NAME:/opt/in/"
docker start "$NAME" >/dev/null

PW="$(sed -n 's/^PING_IDENTITY_PASSWORD=//p' "$PF_AUTHOR_ENV")"
for _ in $(seq 1 60); do
  code="$(curl -sk --max-time 8 -u "administrator:$PW" -H 'X-XSRF-Header: PingFederate' -o /dev/null \
    -w '%{http_code}' "https://127.0.0.1:$ADMIN_PORT/pf-admin-api/v1/version" || true)"
  [[ "$code" == "200" ]] && { echo "authoring PingFederate ready: admin https://localhost:$ADMIN_PORT, runtime https://localhost:$RUNTIME_PORT"; exit 0; }
  sleep 5
done
echo "ERROR: admin API never answered 200 (last: $code). docker logs $NAME" >&2; exit 1
