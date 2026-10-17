"""agent: agent-r's flow (C:/Work/ID Partners/CBA/Federated Agentic/code/agent-r), inside the protected network.

It is handed one thing - the identifier its agent was issued (AGENT_ID) - and works the rest out from the
federation, as agent-r does:

  1. instance key     a key of this running copy's own (INSTANCE_KEY_FILE), created on first run; it never leaves
  2. attestation      POST <provider>/attest {client_id, instance_jwk, svid}: the agent provider - the federation
                      entity that hosts this agent - attests this copy. agent-r sends no evidence; this sends the
                      container's JWT-SVID, which the provider checks against SPIRE and the agent's bindings
  3. envelope         its own capabilities: its chain resolved to the pinned anchor, Raidiam's policy applied,
                      authorization_details_types read off the result. Raidiam's /resolve cannot reach an entity
                      in the protected network, so the chain is resolved here (fedresolve)
  4. discovery        the resources in the federation: Raidiam's /list?entity_type=oauth_resource, resolved, plus
                      RESOURCE_IDS - the network's own, which Raidiam cannot list - resolved here; keeps those that
                      serve the job's capability through an authorisation server the agent can use
  5. token            the resource's authorisation server: attest_jwt_client_auth (attestation + PoP, a challenge
                      retry), client_credentials, RFC 8707 resource = the resource
  6. call             the resource's MCP endpoint: tools/list, then the job's tool

JOB picks the job (list-accounts, get-balance); the capability it needs must be in the envelope, or the run stops
before a request is built - agent-r's rule.
"""
import asyncio
import hashlib
import base64
import concurrent.futures
import json
import os
import sys
import time
import uuid
from urllib.parse import quote

import jwt
import requests
from client_attestation_sdk.svid_source import SpireWorkloadApiSvidSource
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

import federation
import fedresolve

JOBS = {
    "list-accounts": {"label": "Accounts API", "capability": "accounts_read", "tool": "list_accounts", "args": {}},
    "get-balance": {"label": "Funding account balance", "capability": "accounts_read", "tool": "get_balance",
                    "args": {"account_id": "acc-002"}},
    # Outside an accounts reader's envelope: the agent refuses it before building a request.
    "pay-supplier": {"label": "Supplier payment", "capability": "payment_initiation", "tool": "pay_supplier",
                     "args": {"invoice_id": "inv-001"}},
}


# What the run did, step by step, printed as one line at the end - "AGENT_RESULT {json}" - whatever the outcome, for
# a harness to check (harness.py). outcome: "ok", "refused" (the agent or a party refused, by design) or "error".
RESULT = {"outcome": None, "reason": None, "steps": {}}


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638: what a token's cnf.jkt is, for an EC key."""
    canon = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canon.encode()).digest()).rstrip(b"=").decode()


def say(step: str, text: str) -> None:
    print(f"[{step}] {text}", flush=True)


def record(step: str, **data) -> None:
    RESULT["steps"].setdefault(step, {}).update(data)


class Refused(SystemExit):
    """The run stopped for a trust reason - a refusal by the agent itself, the provider, the authorisation server
    or the resource - rather than a fault."""

    def __init__(self, step: str, reason: str):
        super().__init__(reason)
        self.step, self.reason = step, reason


def instance_key(path: str):
    if os.path.exists(path):
        with open(path) as f:
            jwk = json.load(f)
        return ECAlgorithm.from_jwk(json.dumps(jwk)), {k: jwk[k] for k in ("kty", "crv", "x", "y", "kid")}
    private = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(private))
    jwk["kid"] = str(uuid.uuid4())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(jwk, f)
    os.chmod(path, 0o600)
    return private, {k: jwk[k] for k in ("kty", "crv", "x", "y", "kid")}


def discover_resources(resolver, authority: str, anchor: str, local: list, ca) -> list:
    """Raidiam's listing (resolved by Raidiam) and the network's own resources (resolved here)."""
    found = {}
    try:
        listed = requests.get(f"{authority}/list", params={"entity_type": "oauth_resource"}, timeout=20).json()
    except Exception as e:
        listed = []
        say("discover", f"the authority could not list its resources: {e}")
    say("discover", f"Raidiam lists {len(listed)} resource(s); {len(local)} more inside this network")

    def remote(sub):
        r = requests.get(f"{authority}/resolve", timeout=20, params={
            "sub": sub, "trust_anchor": anchor, "entity_type": "oauth_resource"})
        if not r.ok or r.text.strip().startswith("{"):
            return None
        return sub, fedresolve._claims(r.text.strip()).get("metadata", {}).get("oauth_resource")

    def internal(sub):
        try:
            return sub, resolver.resolve(sub, "oauth_resource")["metadata"]["oauth_resource"]
        except Exception as e:
            say("discover", f"{sub} did not resolve: {e}")
            return None

    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        for result in [*pool.map(remote, [s for s in listed if s not in local]), *pool.map(internal, local)]:
            if result and result[1]:
                found[result[0]] = result[1]
    return [{"entity_id": sub, **meta} for sub, meta in sorted(found.items())]


def public_jwk(key) -> dict:
    """The instance key's public half, as a DPoP proof names it."""
    jwk = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    return {k: jwk[k] for k in ("kty", "crv", "x", "y")}


def dpop_proof(key, htm: str, htu: str, access_token: str = None, nonce: str = None) -> str:
    """An RFC 9449 proof signed by the instance key: the key the provider attested (the attestation's cnf), so the
    token PingFederate issues is bound to this instance (cnf.jkt), and every call proves possession of it."""
    claims = {"htm": htm, "htu": htu.split("?")[0].split("#")[0], "iat": int(time.time()), "jti": str(uuid.uuid4())}
    if access_token:
        claims["ath"] = base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()).rstrip(b"=").decode()
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(claims, key, "ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk(key)})


def token(issuer: str, resource: str, client_id: str, attestation: str, key) -> str:
    """attest_jwt_client_auth in DPoP combined mode: the attestation, and a DPoP proof from the instance key in place
    of the attestation PoP. The token comes back DPoP-bound to the instance (token_type DPoP, cnf.jkt)."""
    discovery = requests.get(federation.reachable(issuer.rstrip("/") + "/.well-known/openid-configuration"),
                             timeout=15, verify=federation.pf_verify()).json()
    if "attest_jwt_client_auth_dpop" not in discovery.get("token_endpoint_auth_methods_supported", []):
        raise RuntimeError(f"{issuer} does not accept attest_jwt_client_auth_dpop")
    endpoint = federation.reachable(discovery["token_endpoint"])
    nonce = challenge = None
    for _ in range(3):
        proof = dpop_proof(key, "POST", discovery["token_endpoint"], nonce=nonce)
        if challenge:  # an attestation challenge rides in the proof in combined mode
            claims = jwt.decode(proof, options={"verify_signature": False})
            proof = jwt.encode({**claims, "challenge": challenge}, key, "ES256",
                               headers={"typ": "dpop+jwt", "jwk": public_jwk(key)})
        r = requests.post(endpoint, timeout=20, verify=federation.pf_verify(),
                          data={"grant_type": "client_credentials", "resource": resource},
                          headers={"OAuth-Client-Attestation": attestation, "DPoP": proof})
        if r.ok:
            body = r.json()
            if body.get("token_type", "").lower() != "dpop":
                raise RuntimeError(f"the token came back {body.get('token_type')}, not DPoP-bound")
            return body["access_token"]
        nonce = r.headers.get("DPoP-Nonce") or nonce
        challenge = r.headers.get("OAuth-Client-Attestation-Challenge") or challenge
        if not (r.headers.get("DPoP-Nonce") or r.headers.get("OAuth-Client-Attestation-Challenge")):
            raise RuntimeError(f"the authorisation server refused this agent: {r.status_code} {r.text[:300]}")
    raise RuntimeError("the DPoP nonce / attestation challenge handshake did not complete")


class DPoPAuth:
    """httpx auth for the MCP client: every request carries the bound token and a fresh proof from the instance key."""

    def __new__(cls, key, access_token: str):
        import httpx

        class _Auth(httpx.Auth):
            def auth_flow(self, request):
                request.headers["Authorization"] = f"DPoP {access_token}"
                request.headers["DPoP"] = dpop_proof(key, request.method, str(request.url), access_token)
                yield request

        return _Auth()


async def call_mcp(endpoint: str, access_token: str, tool: str, args: dict, key=None):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    async with streamablehttp_client(endpoint, auth=DPoPAuth(key, access_token)) as (r, w, _):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools = await session.list_tools()
            say("call", "tools offered: " + ", ".join(t.name for t in tools.tools))
            result = await session.call_tool(tool, args)
            text = next((c.text for c in result.content if getattr(c, "type", "") == "text"), "{}")
            if result.isError:
                raise RuntimeError(text)
            return json.loads(text)


def main() -> None:
    agent = os.environ["AGENT_ID"]
    provider = os.environ["AGENT_PROVIDER"].rstrip("/")
    authority, anchor = os.environ["AUTHORITY"], os.environ["TRUST_ANCHOR"]
    job_id = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("JOB", "list-accounts")
    job = JOBS[job_id]
    RESULT.update(agent=agent, job=job_id, capability=job["capability"])
    local = [r.strip() for r in os.environ.get("RESOURCE_IDS", "").split(",") if r.strip()]
    # Public roots for Raidiam, the network's CA for everything inside it; httpx (MCP) reads SSL_CERT_FILE.
    ca = fedresolve.ca_bundle(os.environ.get("PF_CA_FILE"))
    os.environ["SSL_CERT_FILE"] = os.environ["PF_CA_FILE"] = ca
    resolver = fedresolve.Resolver(anchor, fedresolve.pinned_anchor_jwks(), ca)
    print(f"\nI am {agent}\nasked to do: {job['label']} ({job_id}), which needs {job['capability']}\n", flush=True)

    # 1. This copy's key.
    key, public = instance_key(os.environ.get("INSTANCE_KEY_FILE", "/state/instance.jwk"))
    say("instance", f"key {public['kid']} (stays in this container)")
    record("instance", kid=public["kid"])

    # 2. The provider attests this copy, on the strength of what SPIRE says it is.
    svid = SpireWorkloadApiSvidSource(socket_path=os.environ.get("SPIRE_SOCKET", "/run/spire/sockets/agent.sock"),
                                      spire_agent=os.environ.get("SPIRE_AGENT", "spire-agent")).fetch(provider)
    spiffe_id = jwt.decode(svid, options={'verify_signature': False})['sub']
    say("attest", f"SPIRE says this container is {spiffe_id}")
    record("attest", spiffe_id=spiffe_id)
    r = requests.post(f"{provider}/attest", json={"client_id": agent, "instance_jwk": public, "svid": svid},
                      timeout=20, verify=ca)
    if not r.ok:
        record("attest", status=r.status_code, error=r.json().get("error") if r.headers.get("content-type", "").startswith("application/json") else None)
        raise Refused("attest", f"the provider would not attest this copy: {r.status_code} {r.text}")
    attestation = r.json()["wallet_attestation"]
    claims = jwt.decode(attestation, options={"verify_signature": False})
    say("attest", f"attested by {claims['iss']} as an instance of {claims['sub']} until {time.ctime(claims['exp'])}")
    record("attest", status=200, iss=claims["iss"], sub=claims["sub"], cnf_kid=claims.get("cnf", {}).get("jwk", {}).get("kid"))

    # 3. What the federation lets this agent do.
    me = resolver.resolve(agent, "openid_relying_party")
    rp = me["metadata"]["openid_relying_party"]
    envelope = rp.get("authorization_details_types") or []
    say("envelope", f"chain of {len(me['chain'])} to the anchor; Raidiam grants {envelope or 'no capabilities'}; "
                    f"grant types {rp.get('grant_types')}")
    record("envelope", chain_length=len(me["chain"]), authorization_details_types=envelope,
           grant_types=rp.get("grant_types") or [])
    if job["capability"] not in envelope:
        raise Refused("envelope", f"refused before a request was built: {job['capability']} is not in this agent's envelope "
                         f"({envelope or 'empty'}). The bank sets it on the agent's registration in Raidiam.")
    if "client_credentials" not in (rp.get("grant_types") or []):
        raise Refused("envelope", "refused: this agent is not governed to act as itself (no client_credentials)")

    # 4. Which service, behind which authorisation server.
    resources = discover_resources(resolver, authority, anchor, local, ca)
    usable_as = os.environ.get("AUTHORISATION_SERVER") or federation.find_authorisation_server(
        os.environ["DIRECTORY_URL"], os.environ.get("AUTHORISATION_SERVER_ID"))["Issuer"]
    candidates = [res for res in resources if job["capability"] in (res.get("authorization_details_types_supported") or [])]
    for res in candidates:
        if usable_as.rstrip("/") not in [a.rstrip("/") for a in res.get("authorization_servers") or []]:
            say("discover", f"skip {res['entity_id']}: protected by {res.get('authorization_servers')}, not {usable_as}")
    chosen = next((res for res in candidates
                   if usable_as.rstrip("/") in [a.rstrip("/") for a in res.get("authorization_servers") or []]), None)
    if not chosen:
        record("discover", resources=len(resources), candidates=[c["entity_id"] for c in candidates])
        raise Refused("discover", f"no resource in the federation serves {job['capability']} through {usable_as}")
    say("discover", f"chose {chosen['entity_id']} ({chosen.get('resource_name')}), interface "
                    f"{chosen.get('https://cba.com.au/federation/interface')}, authorisation server {usable_as}")
    record("discover", resources=len(resources), chosen=chosen["entity_id"], resource=chosen["resource"],
           authorisation_server=usable_as)

    # 5. A token for that resource, the agent authenticating with its attestation.
    try:
        access_token = token(usable_as, chosen["resource"], agent, attestation, key)
    except RuntimeError as e:
        raise Refused("token", str(e))
    at = jwt.decode(access_token, options={"verify_signature": False})
    say("token", f"client_id {at.get('client_id')}, aud {at.get('aud')}, bound to this instance's key "
                 f"(cnf.jkt {(at.get('cnf') or {}).get('jkt')}), expires {time.ctime(at['exp'])}")
    record("token", client_id=at.get("client_id"), aud=at.get("aud"), iss=at.get("iss"),
           cnf_jkt=(at.get("cnf") or {}).get("jkt"), instance_jkt=jwk_thumbprint(public_jwk(key)))

    # 6. The call.
    endpoint = (chosen.get("endpoints") or [chosen["resource"].rstrip("/") + "/mcp"])[0]
    try:
        result = asyncio.run(call_mcp(endpoint, access_token, job["tool"], job["args"], key))
    except Exception as e:
        status = next((getattr(x, "response", None).status_code for x in getattr(e, "exceptions", [e])
                       if getattr(x, "response", None) is not None), None)
        record("call", endpoint=endpoint, tool=job["tool"], status=status)
        raise Refused("call", f"the resource refused the call: {status or e!r}")
    say("call", f"{job['tool']} at {endpoint}:")
    print(json.dumps(result, indent=2), flush=True)
    record("call", endpoint=endpoint, tool=job["tool"], status=200, decision=result.get("decision"))


if __name__ == "__main__":
    code = 0
    try:
        main()
        RESULT["outcome"] = "ok"
    except Refused as e:
        print(e.reason, flush=True)
        RESULT.update(outcome="refused", reason=e.reason, refused_at=e.step)
        code = 2
    except Exception as e:  # a fault, not a refusal
        import traceback
        traceback.print_exc()
        RESULT.update(outcome="error", reason=f"{type(e).__name__}: {e}")
        code = 1
    print("AGENT_RESULT " + json.dumps(RESULT), flush=True)
    sys.exit(code)
