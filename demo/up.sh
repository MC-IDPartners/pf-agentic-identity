#!/usr/bin/env bash
# Clone, run this, and have a PingFederate with every module in it answering on https://localhost:9031.
#
# Nothing here is a deploy. It is the one-machine version of what a conformance run or a demo needs:
#
#   1. gen-keys.sh          the suite's key pairs and certificates, three secrets    (git-ignored)
#   2. author.sh            a stock PF 13.1.3 with an admin API, on localhost:29999
#   3. apply.sh apply       terraform/ -> that server: OAuth server, tokens, clients, login form
#   4. export.sh            its realised config as data.zip - PF's own saved state    (git-ignored)
#   5. mvn package + stage  the module jars from this repo (run FIRST: author.sh needs the CIBA plugin), or
#      stage-from-release   with PF_RELEASE, or in a tree with no pom.xml, from a release's verified assets
#   6. compose-context.sh   the image build context: this repo's Dockerfile + that archive
#   7. docker compose up    the image, built and running, with vars.env and your licence details
#
# You supply ONE thing: licence details. The image bakes no licence; the base image fetches an
# evaluation licence at boot with PING_IDENTITY_DEVOPS_USER and PING_IDENTITY_DEVOPS_KEY, read from
# $PING_DEVOPS_CONFIG (default ~/.pingidentity/config, a KEY=VALUE file). Nothing licensed and no key
# is ever written under this directory in a form git would take.
#
#   PF_PORT_HTTPS / PF_PORT_HTTP / PF_PORT_ADMIN
#                   host ports for PF's 9031 / 9080 / 9999 (defaults the same), when another PF has them.
#   PF_BASE_URL     the origin PF advertises as its issuer. Default https://localhost:$PF_PORT_HTTPS,
#                   which is what a suite on this machine reaches. For a PF on a public address, set it
#                   to that origin - it is baked into the archive at step 3.
#   SKIP_AUTHOR=1   reuse an existing data.zip (steps 1-4 skipped); rebuild the image only.
#   SKIP_BUILD=1    reuse the staged module jars (step 5 skipped), in either mode.
#   PF_RELEASE      <version> (0.6.1 or later) or <dir>: stage the modules from that release's assets instead of
#                   building them - stage-from-release.sh fetches a version anonymously into its cache, or takes
#                   a directory of assets, and stages nothing that does not verify against SHA256SUMS. No Maven
#                   then. In a tree with no pom.xml (the public one) this is the only mode, and with PF_RELEASE
#                   unset the version is the image directory's release.env. conformance/layout.sh decides.
#   PF_RIG_NAME     the container, image and compose project (default pf-agentic-identity, project
#                   "conformance"). Another name runs a second rig beside the first - another checkout's -
#                   instead of replacing it; give it its own PF_PORT_* and PF_AUTHOR_*_PORT too.
#   PF_RIG_SLOT     0 to 44: take the slot's ports (layout.sh's pfai_slot_ports: 57100 + 20 x slot, offsets 0-4)
#                   for PF_PORT_* and PF_AUTHOR_*_PORT, and name the rig pf-rig-s<slot> unless PF_RIG_NAME says
#                   otherwise. A port set explicitly still wins. Unset keeps the ports above.
#   PF_PROFILE      federation: PF is its own Trust Anchor (vars.federation.env), for the suite's
#                   deployed-entity plan. federation-op: that, and PF joined to the suite's own federation
#                   (vars.federation-op.env) with PAR optional and the suite's CA trusted, for the OP plan -
#                   run the suite with suite/suite-compose.yml. raidiam: PF as an OP in Raidiam's CBA
#                   federation (vars.raidiam.env) with SPIFFE client attestation, for demo/spire-workload -
#                   see raidiam/README.md. Unset: federation stays inert, as the FAPI, SSF and CIBA plans want it.
#   SPIRE_BUNDLE_FILE  raidiam: a SPIRE trust bundle (spire-server bundle show -format spiffe); with it the
#                   attestation client spire-workload is authored, without it the attestation flow is left out.
#   RAIDIAM_ATTESTED_CLIENT_ID  raidiam: the Entity Identifier of a Raidiam-registered client whose own Entity
#                   Configuration carries its spiffe_client_bindings (spire-workload's entity-host serves it): the
#                   attester then takes SPIFFE bindings from it first. See raidiam/README.md.
#   RAIDIAM_RESOURCE_ID  raidiam: the Entity Identifier of the agent-r flow's resource server (spire-workload's
#                   rs-accounts); PingFederate gets a token manager answering RFC 8707 requests that name it.
#   RAIDIAM_PAYMENTS_RESOURCE_ID  raidiam: rs-payments' Entity Identifier (agents calling agents).
#   RAIDIAM_HOSTED_AGENTS  raidiam, with RAIDIAM_PROVIDER_ID: the provider's sub-agents, e.g. "accounts-agent
#                   payments-agent" (<provider>/agent/<name>): token managers for them, the token exchange that lets
#                   them call on for an agent, and their bridge keys. See ../gateway/README.md.
#   RAIDIAM_PROVIDER_ID  raidiam, with RAIDIAM_ATTESTED_CLIENT_ID: the Entity Identifier of the agent provider
#                   (raidiam/provider.sh), whose Entity Configuration publishes the attester's key: the attester signs
#                   as it, and the token endpoint trusts it through the federation. See raidiam/README.md.
#   RAIDIAM_SPIFFE_SOURCE  raidiam: where PingFederate's attester reads which SPIFFE IDs are which agents. authority
#                   (default): Raidiam's statements (AdditionalSoftwareMetadata, published as value policies);
#                   provider: the provider's Entity Configuration (spiffe_client_bindings).
#   SUITE_PORT      federation-op: the port suite/suite-compose.yml publishes the suite on (default 9643).
#   SUITE_BASE_URL  federation-op: the suite's origin as its compose file gives it (default
#                   https://host.docker.internal:$SUITE_PORT). SUITE_ALIAS: the plan's alias.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; REPO="$(cd "$HERE/.." && pwd)"
# Reactor mode builds this checkout's modules, as it always has; release mode builds none.
[[ -n "${PF_RELEASE:-}" || ! -f "$REPO/pom.xml" ]] || export PF_AGENTIC_IDENTITY_HOME="$REPO"
# shellcheck source=layout.sh
. "$HERE/layout.sh"
if [[ -n "${PF_RIG_SLOT:-}" ]]; then
  pfai_slot_ports "$PF_RIG_SLOT" || exit 1
  export PF_RIG_NAME="${PF_RIG_NAME:-pf-rig-s$PF_RIG_SLOT}"
  export PF_PORT_HTTPS="${PF_PORT_HTTPS:-$PFAI_PORT_RIG_HTTPS}" PF_PORT_HTTP="${PF_PORT_HTTP:-$PFAI_PORT_RIG_HTTP}"
  export PF_PORT_ADMIN="${PF_PORT_ADMIN:-$PFAI_PORT_RIG_ADMIN}"
  export PF_AUTHOR_ADMIN_PORT="${PF_AUTHOR_ADMIN_PORT:-$PFAI_PORT_RIG_AUTHOR_ADMIN}"
  export PF_AUTHOR_RUNTIME_PORT="${PF_AUTHOR_RUNTIME_PORT:-$PFAI_PORT_RIG_AUTHOR_RUNTIME}"
fi
export PF_RIG_NAME="${PF_RIG_NAME:-pf-agentic-identity}"
# The default rig keeps the project name docker compose always gave it (this directory's), so an existing
# one is still this project's to stop; any other name is a project of its own.
if [[ "$PF_RIG_NAME" == pf-agentic-identity ]]; then
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-conformance}"
else
  export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-$PF_RIG_NAME}"
fi
# The authoring container: named and ported for this rig, so it never collides with another rig's.
export PF_AUTHOR_NAME="${PF_AUTHOR_NAME:-$PF_RIG_NAME-author}"
export PF_AUTHOR_ADMIN_PORT="${PF_AUTHOR_ADMIN_PORT:-29999}" PF_AUTHOR_RUNTIME_PORT="${PF_AUTHOR_RUNTIME_PORT:-29031}"
export PF_ADMIN_HOST="https://localhost:$PF_AUTHOR_ADMIN_PORT"
export PF_PORT_HTTPS="${PF_PORT_HTTPS:-9031}" PF_PORT_HTTP="${PF_PORT_HTTP:-9080}" PF_PORT_ADMIN="${PF_PORT_ADMIN:-9999}"
export PF_BASE_URL="${PF_BASE_URL:-https://localhost:$PF_PORT_HTTPS}"
LOCAL="https://localhost:$PF_PORT_HTTPS"
export TF_VAR_pf_base_url="$PF_BASE_URL"
case "${PF_PROFILE:-}" in
  "" | federation | federation-op | raidiam) ;;
  *) echo "ERROR: PF_PROFILE=$PF_PROFILE is not a profile this rig has (federation, federation-op, raidiam)" >&2; exit 1 ;;
esac
SUITE_PORT="${SUITE_PORT:-9643}"
SUITE_BASE_URL="${SUITE_BASE_URL:-https://host.docker.internal:$SUITE_PORT}"
SUITE_ALIAS="${SUITE_ALIAS:-pf-agentic-identity-federation-op}"

PING_CONFIG="${PING_DEVOPS_CONFIG:-$HOME/.pingidentity/config}"
[[ -f "$PING_CONFIG" ]] || {
  echo "ERROR: no licence details at $PING_CONFIG." >&2
  echo "       Create a KEY=VALUE file with PING_IDENTITY_DEVOPS_USER and PING_IDENTITY_DEVOPS_KEY (your" >&2
  echo "       Ping DevOps credentials), or point PING_DEVOPS_CONFIG at one. See README.md." >&2
  exit 1; }
TOOLS=(docker terraform node curl unzip)
[[ "$PFAI_MODE" == release ]] || TOOLS+=(mvn)
for tool in "${TOOLS[@]}"; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool is required" >&2; exit 1; }
done
if [[ "$PFAI_MODE" == release ]]; then
  command -v sha256sum >/dev/null || command -v shasum >/dev/null || { echo "ERROR: sha256sum or shasum is required" >&2; exit 1; }
fi

# The authoring PF's admin password: generated once, kept git-ignored, reused so apply/export agree.
export PF_AUTHOR_ENV="${PF_AUTHOR_ENV:-$HERE/.author.env}"
if [[ ! -f "$PF_AUTHOR_ENV" ]]; then
  ( umask 177; printf 'PING_IDENTITY_PASSWORD=%s\n' "$(openssl rand -base64 30 | tr -d '/+=')Aa1" > "$PF_AUTHOR_ENV" )
  echo "generated $PF_AUTHOR_ENV (the authoring PF's admin password; git-ignored)"
fi

# Stage first: author.sh stages the CIBA simulator from modules/ into the authoring server, because
# terraform/ciba.tf can only instantiate a plugin PingFederate can see.
if [[ "${SKIP_BUILD:-0}" != 1 || ! -f "$PFAI_IMAGE_DIR/modules/MANIFEST" ]]; then
  if [[ "$PFAI_MODE" == release ]]; then
    "$PFAI_IMAGE_DIR/stage-from-release.sh" --profile conformance ${PF_RELEASE:+"$PF_RELEASE"}
  else
    ( cd "$REPO" && mvn -q -DskipTests package && build/pingfederate/stage-modules.sh --profile conformance )
  fi
fi

if [[ "${SKIP_AUTHOR:-0}" != 1 ]]; then
  "$HERE/gen-keys.sh"
  if [[ "${PF_PROFILE:-}" == federation-op ]]; then
    # The OP plan's RP sends its request object by value at the authorization endpoint, which PAR REQUIRED
    # refuses; and PF fetches the suite RP's jwks_uri itself, over TLS it checks against its trusted CAs.
    export TF_VAR_par_status=ENABLED
    TF_VAR_trusted_ca_file_data="$(openssl x509 -in "$HERE/keys/suite-tls-ca.crt" -outform DER | base64 | tr -d '\n')"
    export TF_VAR_trusted_ca_file_data
  fi
  if [[ "${PF_PROFILE:-}" == raidiam ]]; then
    # The attester's and the bridge's keys, and - with SPIRE_BUNDLE_FILE - the SPIRE bundle the attestation
    # client verifies JWT-SVIDs with; terraform/attestation.tf authors the client from them.
    "$HERE/raidiam/gen-keys.sh"
    if [[ -n "${SPIRE_BUNDLE_FILE:-}" ]]; then
      "$HERE/raidiam/import-spire-bundle.sh" "$SPIRE_BUNDLE_FILE"
      export TF_VAR_spire_attestation_client=true
    else
      echo "NOTE: SPIRE_BUNDLE_FILE unset - no attestation client; the federation flows still work" >&2
    fi
    # The agent-r flow's resource server: a token manager answering requests that name it (terraform/resource.tf).
    [[ -z "${RAIDIAM_RESOURCE_ID:-}" ]] || export TF_VAR_rs_accounts_resource="$RAIDIAM_RESOURCE_ID"
    # Agents calling agents: rs-payments, and the provider's sub-agents as resources (and delegated callers).
    [[ -z "${RAIDIAM_PAYMENTS_RESOURCE_ID:-}" ]] || export TF_VAR_rs_payments_resource="$RAIDIAM_PAYMENTS_RESOURCE_ID"
    for agent in ${RAIDIAM_HOSTED_AGENTS:-}; do
      case "$agent" in
        accounts-agent) export TF_VAR_accounts_agent_resource="${RAIDIAM_PROVIDER_ID:?RAIDIAM_HOSTED_AGENTS needs RAIDIAM_PROVIDER_ID}/agent/$agent" ;;
        payments-agent) export TF_VAR_payments_agent_resource="${RAIDIAM_PROVIDER_ID:?RAIDIAM_HOSTED_AGENTS needs RAIDIAM_PROVIDER_ID}/agent/$agent" ;;
      esac
    done
  fi
  "$HERE/author.sh"
  # One resource at a time: in parallel, PingFederate has twice read back its server settings as the defaults straight
  # after they were written, and the provider fails the apply ("inconsistent result after apply").
  "$HERE/apply.sh" apply -auto-approve -parallelism=1
  "$HERE/export.sh"
  docker rm -f "$PF_AUTHOR_NAME" >/dev/null 2>&1 || true
else
  [[ -f "$HERE/data.zip" ]] || { echo "ERROR: SKIP_AUTHOR=1 but no data.zip - run without it first" >&2; exit 1; }
fi

CTX="$("$HERE/compose-context.sh")"

# The running PF's environment: vars.env with the issuer substituted on the lines that carry it (the
# introspection endpoint is the container's own loopback and stays), plus the one generated secret the
# servlet needs (its other half is in the archive). Rendered into the git-ignored context.
# A profile adds variables after vars.env's; it sets names vars.env leaves unset. {{SUITE_BASE_URL}},
# {{SUITE_ALIAS}} and {{PUBLIC_JWKS:name}} (keys/name.public.jwks.json, on one line) are filled in.
PROFILE_VARS=()
case "${PF_PROFILE:-}" in
  federation) PROFILE_VARS=("$HERE/vars.federation.env") ;;
  federation-op) PROFILE_VARS=("$HERE/vars.federation.env" "$HERE/vars.federation-op.env") ;;
  raidiam) PROFILE_VARS=("$HERE/vars.raidiam.env") ;;
esac
if [[ "${PF_PROFILE:-}" == raidiam ]]; then
  # The bridge keys, mounted by docker-compose.raidiam.yml; they name the issuer, so they are rendered for this one.
  # The Principal version slots the marketplace deploys into (spire-workload/principals.py): their keys, made once.
  if [[ -n "${RAIDIAM_PROVIDER_ID:-}" ]]; then
    for slot in ${RAIDIAM_PRINCIPAL_SLOTS-principal-1 principal-2 principal-3 principal-4}; do
      PRINCIPAL="$slot" "$HERE/raidiam/attested-client.sh" keys >/dev/null
    done
  fi
  "$HERE/raidiam/render-runtime-keys.sh" "$PF_BASE_URL"
  # ":" explicitly: docker compose splits COMPOSE_FILE on ";" on Windows by default.
  export COMPOSE_PATH_SEPARATOR=":" COMPOSE_FILE="docker-compose.yml:docker-compose.raidiam.yml"
  # RAIDIAM_BRIDGE_BACKING=vault: the bridge keys in OpenBao (openbao/; spire-workload's openbao service, set up by
  # openbao/setup.py), PingFederate's token mounted from keys/openbao/pf-bridge.token.
  if [[ "${RAIDIAM_BRIDGE_BACKING:-config}" == vault ]]; then
    [[ -f "$HERE/keys/openbao/pf-bridge.token" ]] || { echo "ERROR: RAIDIAM_BRIDGE_BACKING=vault but no keys/openbao/pf-bridge.token - run openbao/setup.py" >&2; exit 1; }
    COMPOSE_FILE="$COMPOSE_FILE:docker-compose.openbao.yml"
  fi
fi
cat "$HERE/vars.env" ${PROFILE_VARS[@]+"${PROFILE_VARS[@]}"} \
  | sed -E "/^(OIDF_SSF_ISSUER|OIDF_FEDERATION_[A-Z_]+)=/ s#https://localhost:9031#$PF_BASE_URL#" \
  | KEYS="$HERE/keys" SUITE_BASE_URL="$SUITE_BASE_URL" SUITE_ALIAS="$SUITE_ALIAS" python3 -c '
import json, os, re, sys
text = sys.stdin.read().replace("{{SUITE_BASE_URL}}", os.environ["SUITE_BASE_URL"]).replace("{{SUITE_ALIAS}}", os.environ["SUITE_ALIAS"])
public = lambda m: json.dumps(json.load(open(os.path.join(os.environ["KEYS"], m.group(1) + ".public.jwks.json"))), separators=(",", ":"))
sys.stdout.write(re.sub(r"\{\{PUBLIC_JWKS:([a-z0-9-]+)\}\}", public, text))' > "$CTX/vars.env"
sed -n 's/^TF_VAR_ssf_introspection_client_secret=/OIDF_SSF_INTROSPECTION_CLIENT_SECRET=/p' "$HERE/secrets.env" >> "$CTX/vars.env"
if [[ "${PF_PROFILE:-}" == raidiam ]]; then
  if [[ "${RAIDIAM_BRIDGE_BACKING:-config}" == vault ]]; then
    { echo "OIDF_BRIDGE_SIGNER_BACKING=vault"
      echo "OIDF_BRIDGE_VAULT_ADDR=${OPENBAO_ADDR:-http://host.docker.internal:8200}"
      echo "OIDF_BRIDGE_VAULT_TOKEN_FILE=/opt/pf-raidiam/pf-bridge.token"
    } >> "$CTX/vars.env"
  fi
  # PingFederate's own attester, trusted through the federation like anyone else's: it signs with its own key
  # (attester-signing), which PingFederate's Entity Configuration publishes as oauth_client_attester.jwks - so its
  # token endpoint, or any other authorisation server in the federation, verifies its attestations by resolving
  # PingFederate's chain to Raidiam's anchor (FederationAttesterKeyResolver). No mock attesters.
  { echo "OIDF_ATTESTER_SIGNING_JWK=$(tr -d '\n' < "$HERE/keys/raidiam/attester-signing.private.jwk.json")"
    echo "OIDF_FEDERATION_ATTESTER_JWKS=$(tr -d '\n' < "$HERE/keys/raidiam/attester-signing.public.jwks.json")"
  } >> "$CTX/vars.env"
  # Which SPIFFE IDs are instances of which client. RAIDIAM_SPIFFE_SOURCE=authority (the default): Raidiam's own word
  # - each agent's statement carries its SPIFFE binding (AdditionalSoftwareMetadata: spiffe_id, spiffe_trust_domain,
  # spiffe_bundle_endpoint, client_attesters), which the authority publishes as value policies on
  # openid_relying_party, so the attester takes every entity the authority lists whose chain resolves to a binding
  # naming PingFederate (OIDF_ATTESTER_ISSUER). provider: the spiffe_client_bindings of one federation entity, chain-
  # validated to the anchor - the agent provider (RAIDIAM_PROVIDER_ID, raidiam/provider.sh), whose Entity
  # Configuration binds all the agents it hosts, else the attested client itself. Either way the agents' Entity
  # Configurations and SPIRE's keys are served from the Docker host, a private address the fetch policy refuses
  # unless named.
  BINDINGS_ENTITY="${RAIDIAM_PROVIDER_ID:-${RAIDIAM_ATTESTED_CLIENT_ID:-}}"
  AUTHORITY="$(sed -n 's/^OIDF_FEDERATION_TRUST_ANCHORS=\([^,]*\).*/\1/p' "$HERE/vars.raidiam.env" | head -1)"
  if [[ "${RAIDIAM_SPIFFE_SOURCE:-authority}" == authority && -n "$AUTHORITY" ]]; then
    { echo "OIDF_ATTESTER_FEDERATION_AUTHORITY=$AUTHORITY"
      echo "OIDF_ATTESTER_ISSUER=$PF_BASE_URL"
    } >> "$CTX/vars.env"
  elif [[ -n "$BINDINGS_ENTITY" ]]; then
    echo "OIDF_ATTESTER_FEDERATION_ENTITY=$BINDINGS_ENTITY" >> "$CTX/vars.env"
  fi
  if [[ -n "$BINDINGS_ENTITY" ]]; then
    echo "OIDF_FETCH_HOST_ALLOWLIST=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.urlsplit(sys.argv[1]).hostname)' "$BINDINGS_ENTITY")" >> "$CTX/vars.env"
  fi
fi
chmod 600 "$CTX/vars.env"

( cd "$HERE" && PING_DEVOPS_CONFIG="$PING_CONFIG" docker compose up -d --build )

echo "waiting for PingFederate (licence fetch + archive import take a minute or two)..."
for _ in $(seq 1 60); do
  if curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$LOCAL/.well-known/openid-configuration" | grep -q 200; then
    echo
    echo "PingFederate is up (issuer $PF_BASE_URL):"
    echo "  OAuth/OIDC discovery  $LOCAL/.well-known/openid-configuration"
    echo "  SSF transmitter       $LOCAL/.well-known/ssf-configuration"
    echo "  OpenID Federation     $LOCAL/.well-known/openid-federation${PF_PROFILE:+  (profile $PF_PROFILE)}"
    echo "  plain HTTP listener   http://localhost:$PF_PORT_HTTP/"
    echo "  admin console         https://localhost:$PF_PORT_ADMIN/pingfederate  (administrator / the password in $PF_AUTHOR_ENV)"
    echo
    echo "Next: README.md 'Testing it' - render the suite configurations and run a plan."
    exit 0
  fi
  sleep 5
done
echo "ERROR: PingFederate did not answer on $PF_PORT_HTTPS within five minutes. docker compose -f $HERE/docker-compose.yml logs pingfederate" >&2
exit 1
