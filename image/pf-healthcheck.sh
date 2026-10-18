#!/bin/sh
#
# The image's HEALTHCHECK: healthy when PingFederate's own liveness check passes and, on a node that serves the
# runtime, when /pf/heartbeat.ping and /agentic-identity/health/live both answer 200 on the runtime port.
#
# LIVE, NOT READY. /agentic-identity/health/ready answers 503 while an enabled component is not ready, and some of
# those states are not ones a restart fixes: a PingFederate that is its own trust anchor must serve its entity
# configuration before anyone can pin its keys, and is not ready until they are (F-0192). Docker does nothing
# with an unhealthy container by itself, but orchestrators replace one, so a healthcheck on ready would restart
# such a node for ever. Route traffic on ready instead (build/pingfederate/README.md, "The healthcheck").
#
# The base image's /opt/liveness.sh runs first, unchanged: on a standalone or admin node it waits for the file
# PingFederate's post-start hook writes when start-up has finished, then asks the heartbeat for any answer. An
# admin node (OPERATIONAL_MODE=CLUSTERED_CONSOLE) serves no runtime, so its check ends there.
#
# Env (each as the base image reads it): OPERATIONAL_MODE, PF_ENGINE_PORT, and PF_RUN_PF_HTTPS_PORT, which the
# base image's hooks let override the engine port. PF_LIVENESS names the base check (default /opt/liveness.sh);
# test-entrypoint.sh points it, and curl on the PATH, at stubs.
#
# Exit status: 0 healthy, 1 not - the only two a Docker healthcheck may return. What failed is printed, and
# Docker keeps it in the container's health log (docker inspect).
set -u

PORT="${PF_RUN_PF_HTTPS_PORT:-${PF_ENGINE_PORT:-9031}}"

"${PF_LIVENESS:-/opt/liveness.sh}" || { echo "pf-healthcheck: PingFederate's liveness check failed"; exit 1; }
[ "${OPERATIONAL_MODE:-}" != CLUSTERED_CONSOLE ] || { echo "pf-healthcheck: an admin node; PingFederate's liveness check passed"; exit 0; }

for path in /pf/heartbeat.ping /agentic-identity/health/live; do
    # -k: this is PingFederate's own certificate on loopback, which is often self-signed; no credential is sent.
    code="$(curl -sk -o /dev/null --max-time 5 -w '%{http_code}' "https://127.0.0.1:$PORT$path" 2>/dev/null)"
    [ "$code" = 200 ] || { echo "pf-healthcheck: $path on port $PORT answered ${code:-nothing}, not 200"; exit 1; }
done
echo "pf-healthcheck: /pf/heartbeat.ping and /agentic-identity/health/live answer 200 on port $PORT"
exit 0
