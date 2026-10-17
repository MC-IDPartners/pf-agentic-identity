#!/bin/sh
# Render the declarative config from its template, then start Kong.
set -e

: "${RESOURCE_URL:=http://rs-accounts:8446}"
: "${RESOURCE_ID:=https://host.docker.internal:8446}"
: "${COAZ_URL:=http://coaz-pep:9192}"

sed -e "s|__RESOURCE_URL__|${RESOURCE_URL}|g" \
    -e "s|__RESOURCE_ID__|${RESOURCE_ID}|g" \
    -e "s|__COAZ_URL__|${COAZ_URL}|g" \
    /kong/kong.yml.template > /kong/kong.yml

exec /docker-entrypoint.sh kong docker-start
