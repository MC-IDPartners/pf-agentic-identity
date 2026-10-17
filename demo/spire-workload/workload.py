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
from urllib.parse import urlsplit

import jwt
import requests

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


def spiffe_client_bindings(client_id: str, issuer: str, spiffe_ids: str = None) -> list:
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
            for spiffe_id in (spiffe_ids or os.environ.get("SPIFFE_IDS", "spiffe://example.org/my-workload")).split(",")]


def provider_entity(provider_id: str, authority: str, hosted: list) -> dict:
    """The agent provider (raidiam/provider.sh; the pattern of CBA's https://provider.demo.cba.raidiam.io): an entity
    of its own, with its own Raidiam software statement, whose Entity Configuration publishes

    - its own attester key - as metadata.oauth_client_attester.jwks, where an authorisation server's token endpoint
      looks for it (PingFederate's FederationAttesterKeyResolver), and as federation_entity.attestation_jwks, where
      CBA's provider puts it - for the attestations it signs itself (/attest);
    - spiffe_client_bindings: which SPIFFE IDs are instances of which of its agents, for every agent it hosts. Those
      naming PingFederate as issuer are what PingFederate's attester reads (OIDF_ATTESTER_FEDERATION_ENTITY = the
      provider), trusting them because the provider's chain resolves to Raidiam's anchor.

    PROVIDER_KEY_FILE: its federation entity key, certified by Raidiam. ATTESTER_JWKS_FILE: the public half of its
    attester key. Returns sign(), vouch() - sign under the kid Raidiam publishes - and agents(), the /agents listing."""
    private, public = federation.load_or_create_key(require_env("PROVIDER_KEY_FILE"))
    with open(require_env("ATTESTER_JWKS_FILE")) as f:
        attester_jwks = json.load(f)
    name = os.environ.get("PROVIDER_NAME", "SPIRE Agent Provider (POC)")

    def sign():
        now = int(time.time())
        claims = {
            "iss": provider_id, "sub": provider_id, "iat": now, "exp": now + 3600,
            "jwks": {"keys": [public]},
            "authority_hints": [authority],
            "spiffe_client_bindings": [b for _, bindings in hosted for b in bindings if b["issuer"] != provider_id],
            "metadata": {
                "federation_entity": {"organization_name": name, "homepage_uri": provider_id,
                                      "attestation_jwks": attester_jwks},
                "oauth_client_attester": {"jwks": attester_jwks},
            },
        }
        return jwt.encode(claims, private, algorithm=public["alg"],
                          headers={"typ": federation.ENTITY_STATEMENT_TYP, "kid": public["kid"]})

    def vouch():
        public["kid"] = federation.vouched_kid(federation.subordinate_statement(authority, provider_id), public)

    def agents():
        return {"publisher": provider_id,
                "agents": [{"entity_id": entity_id, "spiffe_id": b["spiffe_id"], "trust_domain": b["trust_domain"],
                            "published": True} for entity_id, bindings in hosted for b in bindings
                           if b["issuer"] == provider_id]}

    return {"sign": sign, "vouch": vouch, "agents": agents, "attest": provider_attester(provider_id, hosted)}


def provider_attester(provider_id: str, hosted: list):
    """POST /attest - the provider attesting an instance of one of its agents itself, as CBA's provider does for
    agent-r: {client_id, instance_jwk} in, {wallet_attestation, issuer} out, signed with the attester key
    (ATTESTER_PRIVATE_FILE) that the provider's Entity Configuration publishes. PingFederate's token endpoint
    trusts it through the provider's chain. ATTESTER=provider on an agent picks this over PingFederate's attester.

    Unlike CBA's provider, which attests whatever key it is sent, this one wants the instance's workload identity
    too: "svid", a JWT-SVID addressed to the provider. It is verified against the trust domain's live keys (the
    binding's bundle_url, SPIRE's OIDC Discovery Provider) and its SPIFFE ID must be bound to client_id. Without the
    attester's private key the provider serves no /attest."""
    path = os.environ.get("ATTESTER_PRIVATE_FILE", "")
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        attester_jwk = json.load(f)
    attester_key = jwt.PyJWK(attester_jwk).key
    ttl = int(os.environ.get("PROVIDER_ATTESTATION_TTL", "3600"))
    bindings = {(entity_id, b["spiffe_id"]): b for entity_id, bs in hosted for b in bs if b["issuer"] == provider_id}

    def spire_keys(binding: dict) -> jwt.PyJWKSet:
        if binding.get("bundle_url"):
            resp = requests.get(binding["bundle_url"], timeout=10, verify=federation.pf_verify())
            resp.raise_for_status()
            return jwt.PyJWKSet.from_dict(resp.json())
        return jwt.PyJWKSet.from_dict(binding["bundle"])

    def attest(request: dict):
        client_id, instance_jwk, svid = request.get("client_id"), request.get("instance_jwk"), request.get("svid")
        if not client_id or not isinstance(instance_jwk, dict) or not svid:
            return 400, {"error": "invalid_request", "error_description": "client_id, instance_jwk and svid are required"}
        if any(k in instance_jwk for k in ("d", "p", "q", "k")):
            return 400, {"error": "invalid_request", "error_description": "instance_jwk carries private key material"}
        public = {k: v for k, v in instance_jwk.items() if k in ("kty", "crv", "x", "y", "n", "e", "kid", "alg", "use")}
        spiffe_id = jwt.decode(svid, options={"verify_signature": False}).get("sub")
        binding = bindings.get((client_id, spiffe_id))
        if not binding:
            print(f"provider: refused {spiffe_id} for {client_id}: not one of its instances", flush=True)
            return 403, {"error": "instance_not_authorized",
                         "error_description": f"{spiffe_id} is not an instance of {client_id}"}
        header = jwt.get_unverified_header(svid)
        try:
            key = next(k for k in spire_keys(binding).keys if k.key_id == header.get("kid"))
            claims = jwt.decode(svid, key.key, algorithms=[header["alg"]], audience=provider_id)
        except (StopIteration, jwt.PyJWTError, requests.RequestException) as e:
            print(f"provider: refused the SVID for {client_id}: {e!r}", flush=True)
            return 403, {"error": "invalid_evidence", "error_description": f"the JWT-SVID did not verify: {e}"}
        if not spiffe_id.startswith(f"spiffe://{binding['trust_domain']}/"):
            return 403, {"error": "invalid_evidence", "error_description": "the SVID is outside the agent's trust domain"}
        now = int(time.time())
        attestation = jwt.encode(
            {"iss": provider_id, "sub": client_id, "iat": now, "exp": min(now + ttl, claims["exp"] + ttl),
             "jti": str(uuid.uuid4()), "cnf": {"jwk": public},
             # What the provider checked, for whoever reads the attestation later.
             "spiffe_id": spiffe_id, "trust_domain": binding["trust_domain"]},
            attester_key, algorithm=attester_jwk.get("alg", "ES256"),
            headers={"typ": "oauth-client-attestation+jwt", "kid": attester_jwk["kid"]})
        print(f"provider: attested an instance of {client_id} ({spiffe_id}), key {public.get('kid') or '-'}", flush=True)
        return 200, {"wallet_attestation": attestation, "issuer": provider_id, "client_id": client_id, "expires_at": now + ttl}

    return attest


def attester_bindings(client_id: str, issuer: str, provider_id: str, spiffe_ids: str = None) -> list:
    """The client's SPIFFE bindings once per attester that may attest its instances: PingFederate's own (issuer; its
    attester checks the JWT-SVID's audience is its issuer) and, with a provider, the provider's /attest. PingFederate's
    come first: its attester takes a client's first binding for an ID."""
    out = spiffe_client_bindings(client_id, issuer, spiffe_ids)
    if provider_id:
        out += spiffe_client_bindings(client_id, provider_id, spiffe_ids)
    return out


def hosted_agents(provider_id: str, authority: str, issuer: str) -> list:
    """The agents this host serves: the Principal (ENTITY_ID, as ever) and, with a provider, each of HOSTED_AGENTS
    at <provider>/agent/<name> - an agent other agents call: a client and a resource (interface "agent"), CBA's
    pattern. Each: its entity key, its bridge key's public half (the client's only key), its SPIFFE bindings, and
    for a hosted agent its oauth_resource metadata."""
    principal_private, principal_public = entity_key()
    with open(require_env("CLIENT_JWKS_FILE")) as f:
        principal_jwks = json.load(f)
    agents = [{"id": require_env("ENTITY_ID"), "private": principal_private, "public": principal_public,
               "client_jwks": principal_jwks, "name": os.environ.get("CLIENT_NAME", "spire-attested-client"),
               "bindings": attester_bindings(require_env("ENTITY_ID"), issuer, provider_id), "resource": None}]
    capabilities = dict(pair.split("=", 1) for pair in os.environ.get("AGENT_CAPABILITIES", "").split(",") if "=" in pair)
    for name in filter(None, os.environ.get("HOSTED_AGENTS", "").replace(",", " ").split()):
        if not provider_id:
            raise RuntimeError("HOSTED_AGENTS needs PROVIDER_ID: the provider hosts them")
        agent_id = f"{provider_id}/agent/{name}"
        private, public = federation.load_or_create_key(f"/agents/{name}/entity.private.jwk.json")
        with open(f"/agents/{name}/bridge.public.jwks.json") as f:
            client_jwks = json.load(f)
        capability = capabilities.get(name, "")
        agents.append({
            "id": agent_id, "private": private, "public": public, "client_jwks": client_jwks,
            "name": f"POC {name.replace('-agent', '').title()} Agent",
            "bindings": attester_bindings(agent_id, issuer, provider_id,
                                          f"spiffe://{os.environ.get('TRUST_DOMAIN', 'example.org')}/{name}"),
            "resource": {
                "resource": agent_id, "resource_name": f"POC {name.replace('-agent', '').title()} Agent",
                "authorization_servers": [issuer], "authorization_details_types_supported": [capability] if capability else [],
                "bearer_methods_supported": ["header"], "dpop_bound_access_tokens_required": True,
                "endpoints": [agent_id + "/mcp/v1"], "resource_documentation": agent_id + "/.well-known/oauth-protected-resource",
                "https://cba.com.au/federation/interface": "agent"}})
    return agents


def run_entity_host() -> None:
    """The agent provider's host, long-running: serves each hosted agent's Entity Configuration - its Raidiam
    authority, its keys, its spiffe_client_bindings and, for an agent others call, its oauth_resource metadata - and
    keeps each registered at PingFederate.

    Each client authenticates with its bridge key (the public half here; PingFederate holds the private half), so no
    instance holds a key of the client's. 0.7.0's token endpoint never registers a client it has not seen, and an
    explicit registration ends with its chain, so this registers each explicitly now and again every REGISTER_EVERY
    seconds, ahead of the chain's expiry."""
    authority = require_env("AUTHORITY_HINT")
    server = directory_server()
    issuer = server["Issuer"]
    # Each agent's instances are attested by PingFederate's own attester (/federation/attestation), which reads their
    # bindings from the provider's Entity Configuration and signs with the key PingFederate's own Entity Configuration
    # publishes; or, with an agent provider (PROVIDER_ID), by the provider itself (/attest), with the key its Entity
    # Configuration publishes. Either way PingFederate's token endpoint trusts the attester through its chain to
    # Raidiam's anchor.
    provider_id = os.environ.get("PROVIDER_ID", "").rstrip("/")
    agents = hosted_agents(provider_id, authority, issuer)
    for ag in agents:
        print(f"entity host: client {ag['id']}, SPIFFE binding(s) "
              + ", ".join(dict.fromkeys(b["spiffe_id"] for b in ag["bindings"]))
              + (f", resource for {ag['resource']['authorization_details_types_supported']}" if ag["resource"] else "")
              + f"; attested by {' or '.join(dict.fromkeys(b['issuer'] for b in ag['bindings']))}", flush=True)

    def signer(ag):
        def sign(audience=None):
            return federation.entity_configuration(
                ag["id"], ag["private"], ag["public"], authority, ag["name"], audience=audience,
                client_jwks=ag["client_jwks"], extra_claims={"spiffe_client_bindings": ag["bindings"]},
                extra_metadata={"oauth_resource": ag["resource"]} if ag["resource"] else None)
        return sign

    principal = agents[0]
    others, documents, actions, provider = {}, {}, {}, None
    for ag in agents[1:]:
        others[ag["id"]] = signer(ag)
        documents[urlsplit(ag["id"]).path + "/.well-known/oauth-protected-resource"] = (lambda r: lambda: r)(ag["resource"])
    if provider_id:
        provider = provider_entity(provider_id, authority, [(ag["id"], ag["bindings"]) for ag in agents])
        others[provider_id] = provider["sign"]
        documents["/agents"] = provider["agents"]
        if provider["attest"]:
            actions["/attest"] = provider["attest"]
    entity_host.serve(principal["id"], signer(principal), others, documents, actions)
    every = int(os.environ.get("REGISTER_EVERY", "600"))
    while True:
        failed = False
        if provider:
            # Until Raidiam vouches for the provider's key, its attestations are refused; the clients still register.
            try:
                provider["vouch"]()
            except Exception as e:
                print(f"entity host: provider not vouched for yet: {e}", flush=True)
        for ag in agents:
            try:
                # Sign under the kid Raidiam publishes for the entity key; until Raidiam vouches, nothing registers.
                ag["public"]["kid"] = federation.vouched_kid(federation.subordinate_statement(authority, ag["id"]),
                                                              ag["public"])
                registered = federation.explicit_register(federation.registration_endpoint(issuer), signer(ag)(issuer))
                print(f"entity host: registered {ag['id']} at {issuer} until {registered.get('exp')}", flush=True)
            except Exception as e:
                failed = True
                print(f"entity host: registration of {ag['id']} failed: {e}", flush=True)
        time.sleep(30 if failed else every)


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