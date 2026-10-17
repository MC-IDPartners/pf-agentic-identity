# Kong OSS, the gateway in front of the rig's MCP resource (replacing agentgateway): DB-less, TLS at the resource's
# identifier, and the coaz-pep plugin - a thin delegate that sends every MCP request to coaz-pep's check API and
# applies its verdict. The security checks (token signature, DPoP, Shared Signals, COAZ -> AuthZEN) are all in
# coaz-pep; none are in Lua.
FROM kong:3.7

USER root
COPY plugins/coaz-pep /usr/local/share/lua/5.1/kong/plugins/coaz-pep
COPY kong.yml.template provider.yml.template /kong/
COPY docker-entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh && mkdir -p /kong && chown -R kong /kong
USER kong

ENV KONG_DATABASE=off
ENV KONG_DECLARATIVE_CONFIG=/kong/kong.yml
ENV KONG_PLUGINS=bundled,coaz-pep
# The identifier it serves, with the rig's certificate: 8446 (rs-accounts) unless the service says otherwise.
ENV KONG_PROXY_LISTEN="0.0.0.0:8446 ssl"
ENV KONG_SSL_CERT=/tls/tls.crt
ENV KONG_SSL_CERT_KEY=/tls/tls.key
ENV KONG_ADMIN_LISTEN=off
# The plugin forwards the JSON-RPC body; keep it in memory, not spooled to a file.
ENV KONG_NGINX_HTTP_CLIENT_BODY_BUFFER_SIZE=64k
ENV KONG_NGINX_HTTP_CLIENT_MAX_BODY_SIZE=64k

EXPOSE 8446
ENTRYPOINT ["/custom-entrypoint.sh"]
