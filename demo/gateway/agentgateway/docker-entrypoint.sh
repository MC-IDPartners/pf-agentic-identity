#!/bin/sh
# Render the agentgateway config from its template, then start the gateway.
set -e

: "${RESOURCE_HOST:=rs-accounts:8446}"
: "${RESOURCE_ID:=https://host.docker.internal:8446}"
: "${EXTAUTHZ_HOST:=coaz-pep:9191}"

# A private CA mounted at /usr/local/share/ca-certificates/ (e.g. the rig's) joins the trusted roots.
update-ca-certificates >/dev/null 2>&1 || true

sed -e "s|__RESOURCE_HOST__|${RESOURCE_HOST}|g" \
    -e "s|__RESOURCE_ID__|${RESOURCE_ID}|g" \
    -e "s|__EXTAUTHZ_HOST__|${EXTAUTHZ_HOST}|g" \
    /etc/agentgateway/config.yaml.template > /etc/agentgateway/config.yaml

exec /app/agentgateway -f /etc/agentgateway/config.yaml
