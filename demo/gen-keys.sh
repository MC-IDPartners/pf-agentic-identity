#!/usr/bin/env bash
# Generate the conformance suite's key pairs and certificates, and the rig's three generated secrets.
#
# Eight key pairs: the suite's five clients, each authenticating by private_key_jwt - two FAPI 2.0
# clients (the plan needs a second one to prove a code or a token is bound to the first), one SSF
# receiver and two CIBA clients - and, for the OpenID Federation OP plan, the suite's own trust anchor,
# its relying party's entity keys and that RP's client keys. PF holds only the PUBLIC half
# (terraform/clients.tf reads keys/*.public.jwks.json; the federation-op profile pins the anchor's); the
# private half goes into the suite configuration and nowhere else. Then an mTLS CA with two client
# certificates the FAPI-CIBA plan's configuration insists on, a TLS CA and certificate for a suite run
# with suite/suite-compose.yml, and secrets.env: the test user's password and two client secrets (the SSF
# introspection client's and the event operator's). Nothing written here is committed.
#
# And PingFederate's own runtime certificate (F-0362): a CA, pf-runtime-tls-ca, and a leaf, pf-runtime-tls,
# naming localhost, host.docker.internal, $PF_RIG_NAME and the host of $PF_BASE_URL, which terraform/
# runtime-tls.tf imports as the runtime (and admin) server certificate, with the CA in PingFederate's trusted CAs. A
# module in PingFederate that calls PingFederate at its own issuer then checks the host name against a certificate
# that carries it, with no JDK switch. The leaf is reissued when the names
# change - another rig name or issuer - and kept otherwise; the CA is kept.
#
# Idempotent: an existing key or secret is kept, because regenerating one silently invalidates the
# archive already exported with its public half in it. Delete keys/ or secrets.env to rotate, then
# re-apply terraform and re-export.
set -euo pipefail
# Git for Windows rewrites an argument that looks like a POSIX path, openssl's -subj "/CN=..." among them; this
# leaves those alone, and means nothing elsewhere.
export MSYS2_ARG_CONV_EXCL="/CN="
HERE="$(cd "$(dirname "$0")" && pwd)"
KEYS="$HERE/keys"
mkdir -p "$KEYS"; chmod 700 "$KEYS"
command -v node >/dev/null || { echo "ERROR: node is required (it exports JWKs natively)" >&2; exit 1; }

# The suite-* keys are the suite's own federation, for the OpenID Federation OP plan: its trust anchor, its RP's
# entity keys and its RP's client keys. The suite signs with the private halves; PF pins the anchor's public half.
for name in fapi2-client1 fapi2-client2 ssf-receiver ciba-client1 ciba-client2 suite-trust-anchor suite-rp-ec suite-rp-client; do
  if [[ -f "$KEYS/$name.private.jwks.json" ]]; then
    echo "kept      keys/$name.*"
    continue
  fi
  ( umask 177
    # The ${...} below are JavaScript template literals, expanded by node and not by the shell.
    # shellcheck disable=SC2016
    KEY_NAME="$name" KEYS_DIR="$KEYS" node -e '
      const { generateKeyPairSync, createHash } = require("crypto");
      const fs = require("fs");
      const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const pub = publicKey.export({ format: "jwk" });
      // RFC 7638 thumbprint as the kid, so the same key always gets the same name.
      const kid = createHash("sha256").update(JSON.stringify({ e: pub.e, kty: pub.kty, n: pub.n })).digest("base64url");
      const meta = { kid, use: "sig", alg: "PS256" };
      const dir = process.env.KEYS_DIR, name = process.env.KEY_NAME;
      fs.writeFileSync(`${dir}/${name}.private.jwks.json`, JSON.stringify({ keys: [{ ...privateKey.export({ format: "jwk" }), ...meta }] }, null, 2));
      fs.writeFileSync(`${dir}/${name}.public.jwks.json`, JSON.stringify({ keys: [{ ...pub, ...meta }] }, null, 2));
    ' )
  chmod 644 "$KEYS/$name.public.jwks.json"
  echo "generated keys/$name.*"
done

# mTLS material for the FAPI-CIBA plan: a throwaway CA and a client certificate for each client. The
# suite's static-client configuration insists on mtls/mtls2 (cert, key, ca) whatever the client
# authentication method, and reads the key as PKCS#8 RSA - hence genpkey, not genrsa. PingFederate is
# never given any of it: FAPI-CIBA's certificate binding is a product gap on 13.x (README.md), and
# private_key_jwt is the authentication method under test.
if [[ -f "$KEYS/mtls-ca.crt" ]]; then
  echo "kept      keys/mtls-*"
else
  ( umask 177; cd "$KEYS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 397 -keyout mtls-ca.key -out mtls-ca.crt \
      -subj "/CN=pf-agentic-identity conformance mTLS CA" >/dev/null 2>&1
    for c in mtls-client1 mtls-client2; do
      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$c.key" >/dev/null 2>&1
      openssl req -new -key "$c.key" -subj "/CN=$c" -out "$c.csr" >/dev/null 2>&1
      openssl x509 -req -in "$c.csr" -CA mtls-ca.crt -CAkey mtls-ca.key -CAcreateserial -days 397 -out "$c.crt" >/dev/null 2>&1
      rm -f "$c.csr"
    done
    rm -f mtls-ca.srl )
  chmod 644 "$KEYS"/mtls-*.crt
  echo "generated keys/mtls-* (a CA and two client certificates)"
fi

# TLS for a conformance suite run with suite/docker-compose.yml, for the OpenID Federation OP plan. PF fetches
# the suite RP's jwks_uri itself and checks the certificate like any other, so the suite's certificate has to
# name the host PF reaches it by and chain to a CA PF trusts: this CA, which the federation-op profile imports.
if [[ -f "$KEYS/suite-tls-ca.crt" ]]; then
  echo "kept      keys/suite-tls-*"
else
  ( umask 177; cd "$KEYS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 397 -keyout suite-tls-ca.key -out suite-tls-ca.crt \
      -subj "/CN=pf-agentic-identity conformance suite CA" >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -nodes -keyout suite-tls.key -subj "/CN=host.docker.internal" -out suite-tls.csr >/dev/null 2>&1
    printf 'subjectAltName=DNS:host.docker.internal,DNS:localhost.emobix.co.uk,DNS:localhost\nextendedKeyUsage=serverAuth\n' > suite-tls.ext
    openssl x509 -req -in suite-tls.csr -CA suite-tls-ca.crt -CAkey suite-tls-ca.key -CAcreateserial -days 397 \
      -extfile suite-tls.ext -out suite-tls.crt >/dev/null 2>&1
    rm -f suite-tls.csr suite-tls.ext suite-tls-ca.srl )
  chmod 644 "$KEYS"/suite-tls-ca.crt "$KEYS"/suite-tls.crt "$KEYS"/suite-tls.key
  echo "generated keys/suite-tls-* (a CA and the suite's certificate)"
fi

# --- PingFederate's runtime certificate (F-0362) ---
RIG_NAME="${PF_RIG_NAME:-pf-agentic-identity}"
BASE_HOST="${PF_BASE_URL:-https://localhost:9031}"; BASE_HOST="${BASE_HOST#https://}"; BASE_HOST="${BASE_HOST%%/*}"
BASE_HOST="${BASE_HOST%:*}"
SANS="$(printf '%s\n' localhost host.docker.internal "$RIG_NAME" "$BASE_HOST" | awk 'NF && !seen[$0]++ { print (/^[0-9.]+$/ ? "IP:" : "DNS:") $0 }' | paste -sd, -)"
if [[ -f "$KEYS/pf-runtime-tls-ca.crt" ]]; then
  echo "kept      keys/pf-runtime-tls-ca.*"
else
  ( umask 177; cd "$KEYS"
    openssl req -x509 -newkey rsa:2048 -nodes -days 397 -keyout pf-runtime-tls-ca.key -out pf-runtime-tls-ca.crt \
      -subj "/CN=pf-agentic-identity rig runtime CA" \
      -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1 )
  chmod 644 "$KEYS/pf-runtime-tls-ca.crt"
  rm -f "$KEYS/pf-runtime-tls.sans"
  echo "generated keys/pf-runtime-tls-ca.* (the rig's runtime CA)"
fi
if [[ -f "$KEYS/pf-runtime-tls.p12" && "$(cat "$KEYS/pf-runtime-tls.sans" 2>/dev/null)" == "$SANS" ]]; then
  echo "kept      keys/pf-runtime-tls.* ($SANS)"
else
  ( umask 177; cd "$KEYS"
    openssl req -new -newkey rsa:2048 -nodes -keyout pf-runtime-tls.key -subj "/CN=$RIG_NAME" -out pf-runtime-tls.csr >/dev/null 2>&1
    printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature,keyEncipherment\nbasicConstraints=critical,CA:FALSE\n' "$SANS" > pf-runtime-tls.ext
    openssl x509 -req -in pf-runtime-tls.csr -CA pf-runtime-tls-ca.crt -CAkey pf-runtime-tls-ca.key -CAcreateserial -days 397 \
      -extfile pf-runtime-tls.ext -out pf-runtime-tls.crt >/dev/null 2>&1
    # The PKCS#12 password is not a secret worth the name - the key is a rig's and the file never leaves keys/ - but
    # PingFederate's import wants one; terraform reads it from secrets.env.
    openssl rand -hex 16 > pf-runtime-tls.p12.pass
    openssl pkcs12 -export -inkey pf-runtime-tls.key -in pf-runtime-tls.crt -certfile pf-runtime-tls-ca.crt \
      -name pf-runtime-tls -passout file:pf-runtime-tls.p12.pass -out pf-runtime-tls.p12
    printf '%s' "$SANS" > pf-runtime-tls.sans
    rm -f pf-runtime-tls.csr pf-runtime-tls.ext pf-runtime-tls-ca.srl )
  chmod 644 "$KEYS/pf-runtime-tls.crt"
  echo "generated keys/pf-runtime-tls.* ($SANS)"
fi

SECRETS="$HERE/secrets.env"
if [[ -f "$SECRETS" ]]; then
  echo "kept      secrets.env"
else
  ( umask 177
    rand() { openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-"$1"; }
    {
      echo "# Generated by gen-keys.sh. Never committed. Sourced by apply.sh as TF_VAR_*."
      echo "TF_VAR_test_user_password=$(rand 24)"
      echo "TF_VAR_ssf_introspection_client_secret=$(rand 40)"
      echo "TF_VAR_ssf_emitter_client_secret=$(rand 40)"
    } > "$SECRETS" )
  echo "generated secrets.env"
fi
# A secret added after secrets.env was first generated: appended, never regenerated, so the ones the
# archive already carries stay valid.
if ! grep -q '^TF_VAR_ssf_emitter_client_secret=' "$SECRETS"; then
  ( umask 177; echo "TF_VAR_ssf_emitter_client_secret=$(openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-40)" >> "$SECRETS" )
  echo "added     TF_VAR_ssf_emitter_client_secret to secrets.env"
fi
# The runtime certificate's PKCS#12 password follows the file: rewritten whenever the certificate was reissued.
( umask 177
  grep -v '^TF_VAR_pf_runtime_tls_password=' "$SECRETS" > "$SECRETS.tmp" || true
  echo "TF_VAR_pf_runtime_tls_password=$(cat "$KEYS/pf-runtime-tls.p12.pass")" >> "$SECRETS.tmp"
  mv "$SECRETS.tmp" "$SECRETS" )
