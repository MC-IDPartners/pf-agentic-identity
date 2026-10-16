"""Workload that finds its authorisation server in the Raidiam directory and gets a token from it.

Flow:
  0. Directory (DIRECTORY_URL set): pick the authorisation server from the Raidiam participants list; its
     Issuer is the PingFederate to use, reached through ISSUER_HOST_OVERRIDE.
  Then, by AUTH_MODE:
  federation (default when ENTITY_ID is set) - OpenID Federation automatic registration:
  1. Sign the workload's own Entity Configuration and fetch the Subordinate Statements above it from Raidiam.
  2. POST client_credentials with a private_key_jwt whose trust_chain header carries that chain. PingFederate
     validates the chain, registers the workload as a client on the spot, and issues the token.
  federation-discovery - the same registration, but PingFederate resolves the trust chain itself:
  1. Serve the workload's Entity Configuration at <ENTITY_ID>/.well-known/openid-federation (entity_host.py).
  2. POST client_credentials with a plain private_key_jwt, no trust_chain. PingFederate fetches that document,
     follows authority_hints to Raidiam, validates to its pinned anchor, registers the client and issues the token.
  attestation - client attestation using the real SPIRE agent:
  1. Discovery: PingFederate says which audience the JWT-SVID must carry and where its endpoints are.
  2. Check that the SPIRE agent issues an SVID for that audience.
  3. Full flow: SVID -> PF attestation mint -> token endpoint -> access token.

`python workload.py entity` prints the public JWK and Entity Configuration to give Raidiam, and exits.
`python workload.py csr "/C=AU/O=CBA/OU=CBA-123/CN=<SoftwareStatementId>"` prints a CSR for the entity key.

Environment variables:
    DIRECTORY_URL        Raidiam directory API, e.g. https://data.directory.cba.raidiam.io
    AUTHORISATION_SERVER_ID   the AuthorisationServerId to use (or AUTHORISATION_SERVER_NAME, its
                         CustomerFriendlyName, when the id is unset)
    ISSUER_HOST_OVERRIDE host[:port] to connect to in place of the issuer's, e.g. host.docker.internal:9031
    AUTH_MODE            federation or attestation
    ENTITY_ID            federation: the workload's Entity Identifier, registered in Raidiam
    ENTITY_KEY_FILE      federation: its private JWK (default /keys/entity.jwk; created if missing)
    ENTITY_KEY_TYPE      federation: RSA (default; what Raidiam certifies for rtssigning) or EC, for a new key
    AUTHORITY_HINT       federation: the Raidiam authority that is the workload's immediate superior
    TRUST_ANCHOR         federation: the trust anchor PingFederate has pinned
    CLIENT_NAME          federation: client_name in the Entity Configuration (default spire-workload)
    SCOPE                federation: optional scope for the token request
    FEDERATION_AUTHORIZATION_DETAILS  federation: optional JSON authorization_details for the token request
    ATTESTER_URL         PingFederate base URL, e.g. https://host.docker.internal:9031 (also argv[1]); the
                         directory's Issuer replaces it when DIRECTORY_URL is set
    EVIDENCE_AUDIENCE    audience the attester expects on the JWT-SVID. Only used when the discovery
                         document names none; if unset, the document's pop_audience is used
    SPIRE_SOCKET         SPIRE agent Workload API socket (default /run/spire/sockets/agent.sock)
    SPIRE_AGENT          path to the spire-agent binary (default spire-agent)
    PROOF_MODE           "pop" (attestation PoP JWT, default) or "dpop" (DPoP combined mode)
    AUTHORIZATION_DETAILS optional JSON, e.g. [{"type":"sales_agent","sales_regions":["EMEA"]}]
    TRACE                1 (default) prints the redacted wire trace; 0 to disable
    VERBOSE              1 enables DEBUG logging
    REPEAT_SECONDS       0 (default) runs once and exits; >0 repeats every N seconds
"""
import base64
import dataclasses
import hashlib
import json
import logging
import os
import sys
import time
import traceback
import uuid

from client_attestation_sdk import ClientAttestation
from client_attestation_sdk.attester import MintRequest, PingFederateProfile
from client_attestation_sdk.svid_source import SpireWorkloadApiSvidSource

import entity_host
import federation


def claims(jwt: str) -> dict:
    """Decode a JWT's payload without verifying it (for display only)."""
    payload = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def env_flag(name: str, default: str) -> bool:
    return os.environ.get(name, default) == "1"


def _instance_proof_with_exp(self, typ: str, audience: str) -> str:
    """MintRequest.instance_proof, plus the exp PingFederate's attester requires from 0.6.0 ('iat' and 'exp' are
    required, with 'exp' after 'iat' by at most 300 s). client-attestation-sdk 1.2.0 still sends iat alone."""
    now = int(time.time())
    claims = {"aud": audience, "jti": str(uuid.uuid4()), "iat": now, "exp": now + 60}
    if self.challenge:
        claims["challenge"] = self.challenge
    return self.sign(claims, typ)


MintRequest.instance_proof = _instance_proof_with_exp

# ATTESTATION_CLIENT_ID: name the client at mint. Unnamed, PingFederate's attester picks a client from its index of
# PingFederate's own attestation clients; named, it asks its resolvers about that client - the federation entity
# (OIDF_ATTESTER_FEDERATION_ENTITY) first - and checks the SVID against that client's bindings. The SDK's token flow
# never sets MintRequest.client_id, so the mint is wrapped to.
_mint = PingFederateProfile.mint


def _mint_naming_client(self, transport, metadata, request):
    client_id = os.environ.get("ATTESTATION_CLIENT_ID")
    if client_id and not request.client_id:
        request = dataclasses.replace(request, client_id=client_id)
    return _mint(self, transport, metadata, request)


PingFederateProfile.mint = _mint_naming_client


def build(attester_url: str):
    spire = SpireWorkloadApiSvidSource(
        socket_path=os.environ.get("SPIRE_SOCKET", "/run/spire/sockets/agent.sock"),
        spire_agent=os.environ.get("SPIRE_AGENT", "spire-agent"),
    )
    trace: list = []  # each wire call as a redacted curl string
    authz = os.environ.get("AUTHORIZATION_DETAILS")

    def make(metadata=None):
        return ClientAttestation(
            attester_url,
            evidence=spire,  # force SPIRE, no auto-detect
            pop_method="dpop_combined" if os.environ.get("PROOF_MODE", "pop").lower() == "dpop" else "attestation_pop_jwt",
            authorization_details=json.loads(authz) if authz else None,
            allow_insecure=attester_url.startswith("http://"),
            trace=trace,
            metadata=metadata,
            # The SDK will not take the SVID audience from discovery alone; it must be pinned. It also
            # cross-checks the pin against the discovery document's evidence_audience.
            evidence_audience=os.environ.get("EVIDENCE_AUDIENCE") or None,
            # PingFederate consumes the attestation challenge at mint; re-presenting it at the token
            # endpoint is rejected as use_attestation_challenge. Only the mint gets it.
            challenge_at_token=False,
        )

    ca = make()
    meta = ca.attester_metadata()
    changes = {}
    # PingFederate 0.1.4's discovery document names no evidence_audience, which the SDK requires. Discover
    # as usual, then supply the audience ourselves: EVIDENCE_AUDIENCE, or else the document's pop_audience.
    if not meta.evidence_audience:
        audience = os.environ.get("EVIDENCE_AUDIENCE") or meta.pop_audience
        if audience:
            changes["evidence_audience"] = audience
    # From 0.6.0 PingFederate's attester advertises its own challenge endpoint, GET only, which this SDK POSTs
    # to (405). The attester requires no challenge unless it says so (challenge_required), so the mint goes
    # without one then; the SDK fetches none when no endpoint is advertised.
    if meta.challenge_endpoint and not (meta.document or {}).get("challenge_required", False):
        changes["challenge_endpoint"] = None
    if changes:
        ca = make(metadata=dataclasses.replace(meta, **changes))
    return spire, ca, trace


def run_once(spire, ca, trace) -> None:
    try:
        # 1. Discovery: PF says which audience the JWT-SVID must carry.
        meta = ca.attester_metadata()
        print("evidence_audience   :", meta.evidence_audience, flush=True)
        print("attestation_endpoint:", meta.attestation_endpoint, flush=True)
        print("token_endpoint      :", meta.token_endpoint, flush=True)

        # 2. Check the SPIRE agent issues an SVID for that audience.
        audience = meta.evidence_audience or os.environ.get("EVIDENCE_AUDIENCE")
        if not audience:
            raise RuntimeError(
                "No evidence audience: the discovery document names none and EVIDENCE_AUDIENCE is not set"
            )
        svid = spire.fetch(audience)
        c = claims(svid)
        print(f"\nJWT-SVID sub (SPIFFE ID): {c.get('sub')} | aud: {c.get('aud')}", flush=True)

        # 3. Full flow: SVID -> PF attestation mint -> token endpoint.
        token = ca.token()
    finally:
        if env_flag("TRACE", "1") and trace:
            print("\n--- wire trace ---", flush=True)
            for line in trace:
                print(line, "\n", flush=True)

    # Never print the token itself, only a fingerprint.
    print(f"access token: {len(token)} chars, sha256 {hashlib.sha256(token.encode()).hexdigest()[:12]}", flush=True)
    try:
        print(json.dumps(claims(token), indent=2), flush=True)  # skipped if PF issues opaque tokens
    except Exception:
        print("(token is not a JWT)", flush=True)


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


def entity_key():
    return federation.load_or_create_key(os.environ.get("ENTITY_KEY_FILE", "/keys/entity.jwk"),
                                         os.environ.get("ENTITY_KEY_TYPE", "RSA"))


def entity_configuration(private, public) -> str:
    return federation.entity_configuration(require_env("ENTITY_ID"), private, public, require_env("AUTHORITY_HINT"),
                                           os.environ.get("CLIENT_NAME", "spire-workload"))


def print_csr(subject: str) -> None:
    """A CSR for the entity key, for Raidiam to certify: python workload.py csr "/C=AU/O=../OU=../CN=.."."""
    private, _ = entity_key()
    print(federation.certificate_request(private, subject).decode(), end="")


def print_entity() -> None:
    """What Raidiam needs to vouch for this workload: its Entity Identifier and public key."""
    private, public = entity_key()
    print("Entity Identifier :", require_env("ENTITY_ID"))
    print("Authority hint    :", require_env("AUTHORITY_HINT"))
    print("Public JWK        :", json.dumps(public))
    print("\nEntity Configuration (serve at <ENTITY_ID>/.well-known/openid-federation if Raidiam fetches it):")
    print(entity_configuration(private, public))


def directory_server():
    """The authorisation server the directory names, or None when DIRECTORY_URL is unset."""
    directory = os.environ.get("DIRECTORY_URL")
    if not directory:
        return None
    server = federation.find_authorisation_server(directory, os.environ.get("AUTHORISATION_SERVER_ID"),
                                                  os.environ.get("AUTHORISATION_SERVER_NAME"))
    print(f"directory: {server['CustomerFriendlyName']} ({server['AuthorisationServerId']})", flush=True)
    print(f"issuer   : {server['Issuer']} via {federation.reachable(server['Issuer'])}", flush=True)
    return server


def run_federation_once(server) -> None:
    """Directory -> discovery -> trust chain -> private_key_jwt -> token, PF registering the client on the way."""
    entity_id = require_env("ENTITY_ID")
    authority = require_env("AUTHORITY_HINT")
    anchor = require_env("TRUST_ANCHOR")
    discovery = federation.discover(server)
    print("token_endpoint      :", discovery["token_endpoint"], flush=True)

    private, public = entity_key()
    about_leaf = federation.subordinate_statement(authority, entity_id)
    public["kid"] = federation.vouched_kid(about_leaf, public)
    print("entity key          :", public["kid"], flush=True)
    chain = federation.trust_chain(entity_configuration(private, public), about_leaf, authority, anchor)
    print(f"trust chain         : {len(chain)} statements "
          + " -> ".join(f"{c.get('iss')}" for c in map(claims, chain[1:])), flush=True)

    # aud is the token endpoint PF publishes (https://localhost:9031/...), not the URL we connect to.
    assertion = federation.client_assertion(entity_id, private, public, discovery["token_endpoint"], chain)
    authz = os.environ.get("FEDERATION_AUTHORIZATION_DETAILS")
    response = federation.request_token(discovery, entity_id, assertion,
                                        json.loads(authz) if authz else None, os.environ.get("SCOPE"))
    token = response["access_token"]
    print(f"access token: {len(token)} chars, sha256 {hashlib.sha256(token.encode()).hexdigest()[:12]}", flush=True)
    try:
        print(json.dumps(claims(token), indent=2), flush=True)
    except Exception:
        print("(token is not a JWT)", flush=True)


_entity_host = None


def run_federation_discovery_once(server) -> None:
    """Directory -> discovery -> private_key_jwt with NO trust chain -> token. PingFederate finds the chain itself:
    it fetches this workload's Entity Configuration (served here), follows authority_hints to Raidiam, validates
    to the pinned anchor, registers the client and issues the token."""
    global _entity_host
    entity_id = require_env("ENTITY_ID")
    discovery = federation.discover(server)
    print("token_endpoint      :", discovery["token_endpoint"], flush=True)

    private, public = entity_key()
    # Sign under the kid Raidiam publishes for this key, so PingFederate matches the leaf's signature to the key
    # its superior vouches for. Looked up once, for the kid only; nothing fetched here is sent to PingFederate.
    try:
        public["kid"] = federation.vouched_kid(
            federation.subordinate_statement(require_env("AUTHORITY_HINT"), entity_id), public)
    except Exception as e:
        print(f"WARNING: Raidiam does not vouch for {entity_id} with this key yet ({e}); PingFederate will "
              "refuse the chain until it does", flush=True)
    print("entity key          :", public["kid"], flush=True)

    # Only needed if PingFederate must fetch <ENTITY_ID>/.well-known/openid-federation itself (renewal by discovery).
    if _entity_host is None and os.environ.get("ENTITY_SERVE", "0") == "1":
        _entity_host = entity_host.serve(entity_id, lambda: entity_configuration(private, public))

    # 1. Explicit registration with the Entity Configuration alone: PingFederate resolves the chain from
    #    authority_hints (Raidiam authority -> trust anchor), applies Raidiam's policy and registers the client.
    #    The token endpoint (0.7.0) never discovers a client it has not registered, so this comes first.
    endpoint = federation.registration_endpoint(server["Issuer"])
    request = federation.entity_configuration(entity_id, private, public, require_env("AUTHORITY_HINT"),
                                              os.environ.get("CLIENT_NAME", "spire-workload"),
                                              audience=server["Issuer"])
    print("register            :", endpoint, "(Entity Configuration only, no trust chain)", flush=True)
    registered = federation.explicit_register(endpoint, request)
    rp = registered.get("metadata", {}).get("openid_relying_party", {})
    print(f"registered          : client_id {rp.get('client_id') or registered.get('sub')}, "
          f"trust_anchor {registered.get('trust_anchor')}, exp {registered.get('exp')}", flush=True)

    # 2. The token request: a plain private_key_jwt, no trust_chain header.
    assertion = federation.client_assertion(entity_id, private, public, discovery["token_endpoint"])
    print("client_assertion    : private_key_jwt, no trust_chain header - PingFederate resolves it", flush=True)
    authz = os.environ.get("FEDERATION_AUTHORIZATION_DETAILS")
    response = federation.request_token(discovery, entity_id, assertion,
                                        json.loads(authz) if authz else None, os.environ.get("SCOPE"))
    token = response["access_token"]
    print(f"access token: {len(token)} chars, sha256 {hashlib.sha256(token.encode()).hexdigest()[:12]}", flush=True)
    try:
        print(json.dumps(claims(token), indent=2), flush=True)
    except Exception:
        print("(token is not a JWT)", flush=True)


def spiffe_client_bindings(client_id: str, issuer: str) -> list:
    """Which SPIFFE IDs are instances of this client, and how the attester checks them: one binding per ID
    (SPIFFE_IDS, comma-separated; a trailing * matches a path prefix). The attester reads these from this
    entity's chain-validated Entity Configuration (OIDF_ATTESTER_FEDERATION_ENTITY).

    The trust domain's keys: SPIRE_BUNDLE_URL, a JWKS of its current JWT-SVID keys that the attester fetches at
    issuance (SPIRE's OIDC Discovery Provider serves one), so SPIRE's rotations and revocations reach it; else
    SPIRE_BUNDLE_FILE, a copy, which goes stale when SPIRE rotates."""
    trust_roots = ({"bundle_url": os.environ["SPIRE_BUNDLE_URL"]} if os.environ.get("SPIRE_BUNDLE_URL")
                   else {"bundle": json.load(open(require_env("SPIRE_BUNDLE_FILE")))})
    entitlement = json.loads(os.environ.get(
        "ENTITLEMENT", '[{"type":"sales_agent","sales_regions":["EMEA","APAC","AMER"]}]'))
    return [{"client_id": client_id, "spiffe_id": spiffe_id.strip(), "issuer": issuer,
             "evidence_type": "spiffe-jwt", "trust_domain": os.environ.get("TRUST_DOMAIN", "example.org"),
             **trust_roots, "entitlement": entitlement, "ttl": int(os.environ.get("ATTESTATION_TTL", "300"))}
            for spiffe_id in os.environ.get("SPIFFE_IDS", "spiffe://example.org/my-workload").split(",")]


def run_entity_host() -> None:
    """The federated attested client's owner, long-running: serves the client's Entity Configuration - its
    Raidiam authority, its keys, and spiffe_client_bindings - and keeps the client registered at PingFederate.

    The client authenticates with its bridge key (CLIENT_JWKS_FILE, the public half; PingFederate holds the
    private half), so no instance holds a key of the client's. 0.7.0's token endpoint never registers a client
    it has not seen, and an explicit registration ends with its chain, so this registers explicitly now and again
    every REGISTER_EVERY seconds, ahead of the chain's expiry."""
    entity_id = require_env("ENTITY_ID")
    authority = require_env("AUTHORITY_HINT")
    server = directory_server()
    issuer = server["Issuer"]
    private, public = entity_key()
    with open(require_env("CLIENT_JWKS_FILE")) as f:
        client_jwks = json.load(f)
    bindings = spiffe_client_bindings(entity_id, issuer)
    print(f"entity host: client {entity_id}, {len(bindings)} SPIFFE binding(s): "
          + ", ".join(b["spiffe_id"] for b in bindings), flush=True)

    def sign(audience=None):
        return federation.entity_configuration(entity_id, private, public, authority,
                                               os.environ.get("CLIENT_NAME", "spire-attested-client"),
                                               audience=audience, client_jwks=client_jwks,
                                               extra_claims={"spiffe_client_bindings": bindings})

    entity_host.serve(entity_id, sign)
    every = int(os.environ.get("REGISTER_EVERY", "600"))
    while True:
        try:
            # Sign under the kid Raidiam publishes for the entity key; until Raidiam vouches, nothing registers.
            public["kid"] = federation.vouched_kid(federation.subordinate_statement(authority, entity_id), public)
            registered = federation.explicit_register(federation.registration_endpoint(issuer), sign(issuer))
            print(f"entity host: registered {entity_id} at {issuer} until {registered.get('exp')}", flush=True)
            time.sleep(every)
        except Exception as e:
            print(f"entity host: registration failed, retrying in 30 s: {e}", flush=True)
            time.sleep(30)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "entity-host":
        run_entity_host()
        return
    if len(sys.argv) > 1 and sys.argv[1] == "entity":
        print_entity()
        return
    if len(sys.argv) > 2 and sys.argv[1] == "csr":
        print_csr(sys.argv[2])
        return
    repeat = int(os.environ.get("REPEAT_SECONDS", "0"))
    if env_flag("VERBOSE", "0"):
        logging.basicConfig(level=logging.DEBUG)
    mode = os.environ.get("AUTH_MODE") or ("federation" if os.environ.get("ENTITY_ID") else "attestation")

    state = None
    while True:
        try:
            if mode == "federation":
                run_federation_once(directory_server())
            elif mode == "federation-discovery":
                run_federation_discovery_once(directory_server())
            else:
                if state is None:
                    server = directory_server()
                    if server:
                        attester_url = federation.reachable(server["Issuer"])
                        # The SVID's audience is the attestation issuer, which is PingFederate's issuer.
                        os.environ.setdefault("EVIDENCE_AUDIENCE", server["Issuer"])
                    else:
                        attester_url = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
                            "ATTESTER_URL", "https://pf.example.com")
                    state = build(attester_url)
                run_once(*state)
        except Exception:
            traceback.print_exc()
            state = None  # rebuild on the next pass
            if repeat <= 0:
                sys.exit(1)
        if repeat <= 0:
            return
        time.sleep(repeat)


if __name__ == "__main__":
    main()