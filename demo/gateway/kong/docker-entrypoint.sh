#!/bin/sh
# Render the declarative config from its template, then start Kong.
#   KONG_TEMPLATE  which edge this Kong is: kong.yml.template (one resource - rs-accounts, rs-payments) or
#                  provider.yml.template (the agent provider: its agents' MCP, and the provider itself)
set -e

: "${KONG_TEMPLATE:=kong.yml.template}"
: "${RESOURCE_URL:=http://rs-accounts:8446}"
: "${RESOURCE_ID:=https://host.docker.internal:8446}"
: "${RESOURCE_LABEL:=rs-accounts MCP}"
: "${COAZ_URL:=http://coaz-pep:9192}"
: "${PROVIDER_URL:=https://entity-host:8443}"
: "${PROVIDER_ID:=https://host.docker.internal:8443}"
: "${ACCOUNTS_AGENT_URL:=http://accounts-agent:8090}"
: "${PAYMENTS_AGENT_URL:=http://payments-agent:8090}"

sed -e "s|__RESOURCE_URL__|${RESOURCE_URL}|g" \
    -e "s|__RESOURCE_ID__|${RESOURCE_ID}|g" \
    -e "s|__RESOURCE_LABEL__|${RESOURCE_LABEL}|g" \
    -e "s|__COAZ_URL__|${COAZ_URL}|g" \
    -e "s|__PROVIDER_URL__|${PROVIDER_URL}|g" \
    -e "s|__PROVIDER_ID__|${PROVIDER_ID}|g" \
    -e "s|__ACCOUNTS_AGENT_URL__|${ACCOUNTS_AGENT_URL}|g" \
    -e "s|__PAYMENTS_AGENT_URL__|${PAYMENTS_AGENT_URL}|g" \
    "/kong/${KONG_TEMPLATE}" > /kong/kong.yml

exec /docker-entrypoint.sh kong docker-start
