"""rs-accounts: an MCP resource server inside the protected network - the rig's stand-in for CBA's
https://rs-accounts.demo.cba.raidiam.io, which agent-r finds through the federation and calls.

It is a federation entity of its own (its own Raidiam software statement, RESOURCE_ID), and serves:

  /.well-known/openid-federation      its Entity Configuration: oauth_resource metadata naming this rig's
                                      PingFederate as its authorisation server, the capabilities it serves
                                      (authorization_details_types_supported) and "interface": "mcp"
  /.well-known/oauth-protected-resource   the same, as RFC 9728 protected resource metadata
  /mcp/v1                             the MCP endpoint (streamable HTTP), tools list_accounts and get_balance

A call to /mcp/v1 needs a bearer token, and passes three checks:
  1. the token: signed by the authorisation server it names (its JWKS, from its discovery document), meant for
     this resource (aud), unexpired, an access token (typ at+jwt);
  2. the caller is a federation member now: its client_id resolved through Raidiam's chain to the pinned anchor
     (fedresolve - the agent sits in the protected network too, so the chain is resolved here, not by Raidiam);
  3. the capability: the client's federation metadata grants REQUIRED_CAPABILITY (authorization_details_types),
     whatever the token says - a resource checks again regardless, as CBA's do.

Environment: RESOURCE_ID, RESOURCE_NAME, RESOURCE_KEY_FILE (its entity key, certified by Raidiam), AUTHORITY_HINT,
TRUST_ANCHOR, TRUST_ANCHOR_ENV_FILE, AUTHORISATION_SERVER (an issuer; else the Raidiam directory's, as workload.py
finds it), ISSUER_HOST_OVERRIDE, PF_CA_FILE, RESOURCE_TLS_CERT/KEY, RESOURCE_LISTEN_PORT, REQUIRED_CAPABILITY.
"""
import contextvars
import json
import os
import time
from urllib.parse import urlsplit

import jwt
import requests
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

import federation
import fedresolve

RESOURCE_ID = os.environ["RESOURCE_ID"].rstrip("/")
RESOURCE_NAME = os.environ.get("RESOURCE_NAME", "Rig Business Banking Accounts")
AUTHORITY = os.environ["AUTHORITY_HINT"]
CAPABILITY = os.environ.get("REQUIRED_CAPABILITY", "accounts_read")
MCP_PATH = "/mcp/v1"
CA = fedresolve.ca_bundle(os.environ.get("PF_CA_FILE"))
RESOLVER = fedresolve.Resolver(os.environ["TRUST_ANCHOR"], fedresolve.pinned_anchor_jwks(), CA)


def authorisation_server() -> str:
    if os.environ.get("AUTHORISATION_SERVER"):
        return os.environ["AUTHORISATION_SERVER"].rstrip("/")
    server = federation.find_authorisation_server(os.environ["DIRECTORY_URL"], os.environ.get("AUTHORISATION_SERVER_ID"))
    return server["Issuer"].rstrip("/")


ISSUER = authorisation_server()
PRIVATE, PUBLIC = federation.load_or_create_key(os.environ["RESOURCE_KEY_FILE"])


def resource_metadata() -> dict:
    return {
        # The shape of CBA's resources (their ApiMetadata on the authorisation server's Raidiam record).
        "resource": RESOURCE_ID,
        "resource_name": RESOURCE_NAME,
        "description": "Lists the business accounts visible to the calling agent, and reports balances and "
                       "available funds on each account.",
        "keywords": ["business accounts", "balances"],
        "resource_documentation": RESOURCE_ID + "/.well-known/oauth-protected-resource",
        "authorization_servers": [ISSUER],
        "scopes_supported": ["accounts.read"],
        "authorization_details_types_supported": ["accounts_read"],
        "bearer_methods_supported": ["header"],
        # Enforced by the gateway in front (coaz-pep), not by this server.
        "dpop_bound_access_tokens_required": True,
        "https://cba.com.au/federation/interface": "mcp",
        "https://cba.com.au/federation/division": "Rig",
        "endpoints": [RESOURCE_ID + MCP_PATH],
    }


def entity_configuration() -> str:
    now = int(time.time())
    claims = {
        "iss": RESOURCE_ID, "sub": RESOURCE_ID, "iat": now, "exp": now + 3600,
        "jwks": {"keys": [PUBLIC]},
        "authority_hints": [AUTHORITY],
        "metadata": {
            "federation_entity": {"organization_name": RESOURCE_NAME, "homepage_uri": RESOURCE_ID},
            "oauth_resource": resource_metadata(),
        },
    }
    return jwt.encode(claims, PRIVATE, algorithm=PUBLIC["alg"],
                      headers={"typ": federation.ENTITY_STATEMENT_TYP, "kid": PUBLIC["kid"]})


# ── the three checks ────────────────────────────────────────────────────────────────────────────────

_jwks = {"at": 0, "set": None}
_members: dict = {}  # client_id -> (expiry, resolved openid_relying_party metadata)
caller = contextvars.ContextVar("caller", default=None)


class Refused(Exception):
    def __init__(self, status: int, error: str, description: str):
        super().__init__(description)
        self.status, self.error, self.description = status, error, description


def as_keys() -> jwt.PyJWKSet:
    if not _jwks["set"] or time.time() - _jwks["at"] > 300:
        discovery = requests.get(federation.reachable(ISSUER + "/.well-known/openid-configuration"), timeout=10, verify=CA).json()
        keys = requests.get(federation.reachable(discovery["jwks_uri"]), timeout=10, verify=CA).json()
        _jwks.update(at=time.time(), set=jwt.PyJWKSet.from_dict(keys))
    return _jwks["set"]


def check_token(authorization: str) -> dict:
    # DPoP (the token bound to the agent instance's key) is enforced at the gateway, which verifies every proof
    # before a call gets here; this takes the token from either scheme and makes its own checks of it.
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() not in ("bearer", "dpop") or not token.strip():
        raise Refused(401, "invalid_token", "an access token is required")
    token = token.strip()
    try:
        header = jwt.get_unverified_header(token)
        if header.get("typ", "").lower() not in ("at+jwt", "application/at+jwt"):
            raise Refused(401, "invalid_token", f"not an access token (typ {header.get('typ')})")
        key = next((k for k in as_keys().keys if k.key_id == header.get("kid")), None)
        if key is None:
            _jwks["set"] = None
            key = next((k for k in as_keys().keys if k.key_id == header.get("kid")), None)
        if key is None:
            raise Refused(401, "invalid_token", f"no key {header.get('kid')} at {ISSUER}")
        return jwt.decode(token, key.key, algorithms=[header["alg"]], issuer=ISSUER, audience=RESOURCE_ID,
                          options={"require": ["exp", "iss", "aud"]})
    except jwt.PyJWTError as e:
        raise Refused(401, "invalid_token", f"the token did not verify: {e}")


def check_member(client_id: str) -> dict:
    cached = _members.get(client_id)
    if cached and cached[0] > time.time():
        return cached[1]
    try:
        resolved = RESOLVER.resolve(client_id, "openid_relying_party")
    except Exception as e:
        raise Refused(403, "insufficient_trust", f"{client_id} does not resolve to the trust anchor: {e}")
    rp = resolved["metadata"]["openid_relying_party"]
    _members[client_id] = (min(resolved["exp"], time.time() + 300), rp)
    return rp


def check(authorization: str) -> dict:
    claims = check_token(authorization)
    client_id = claims.get("client_id") or claims.get("sub")
    rp = check_member(client_id)
    granted = rp.get("authorization_details_types") or []
    if CAPABILITY not in granted:
        raise Refused(403, "insufficient_scope",
                      f"the federation does not grant {client_id} {CAPABILITY} (it holds {granted or 'nothing'})")
    return {"client_id": client_id, "capabilities": granted, "client_name": rp.get("client_name")}


# ── MCP ─────────────────────────────────────────────────────────────────────────────────────────────

# DNS rebinding protection stays on: requests must name the resource's own host (or RESOURCE_ALLOWED_HOSTS).
ALLOWED_HOSTS = [urlsplit(RESOURCE_ID).netloc, *filter(None, os.environ.get("RESOURCE_ALLOWED_HOSTS", "").split(","))]
mcp = FastMCP(RESOURCE_NAME, stateless_http=True, json_response=True, streamable_http_path=MCP_PATH,
              transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                                           allowed_hosts=ALLOWED_HOSTS, allowed_origins=[]))

ACCOUNTS = [
    {"account_id": "acc-001", "name": "Operating account", "bsb": "062-000", "balance": 184230.55, "currency": "AUD"},
    {"account_id": "acc-002", "name": "Funding account", "bsb": "062-000", "balance": 1250000.00, "currency": "AUD"},
    {"account_id": "acc-003", "name": "Payroll account", "bsb": "062-000", "balance": 96412.10, "currency": "AUD"},
]


@mcp.tool()
def list_accounts() -> dict:
    """Lists the business accounts visible to the calling agent, with their balances."""
    return {"accounts": ACCOUNTS, "decision": {"resource": RESOURCE_ID, **(caller.get() or {})}}


@mcp.tool()
def get_balance(account_id: str) -> dict:
    """Reports the balance and available funds on one account."""
    account = next((a for a in ACCOUNTS if a["account_id"] == account_id), None)
    if not account:
        return {"error": f"no account {account_id}"}
    return {**account, "available": account["balance"], "decision": {"resource": RESOURCE_ID, **(caller.get() or {})}}


@mcp.tool()
def pay_supplier(from_account: str, to_account: str, amount: float, currency: str = "AUD") -> dict:
    """Pays a supplier from one of the business accounts. Governed at the gateway: the PDP decides on the amount."""
    if not any(a["account_id"] == from_account for a in ACCOUNTS):
        return {"error": f"no account {from_account}"}
    return {"status": "accepted", "from_account": from_account, "to_account": to_account, "amount": amount,
            "currency": currency, "decision": {"resource": RESOURCE_ID, **(caller.get() or {})}}


# COAZ (the OpenID AuthZEN MCP profile): each tool says how a call maps to an AuthZEN evaluation, so a gateway PEP
# (../gateway/coaz-pep) can ask the PDP before the call reaches this server. String leaves are CEL over `params` (the
# tools/call params) and `token` (the access token's claims). The agent acts as itself, so the subject is its client_id.
# token_aud is left out on purpose: the PDP's banking package denies any audience but its own demo's.
from mcp import types as mcp_types  # noqa: E402

_AGENT = "has(token.client_id) ? token.client_id : (has(token.sub) ? token.sub : 'unknown-agent')"
_SUBJECT = [{"type": "'agent'", "identity": _AGENT,
             "properties": {"client_id": _AGENT, "agent_type": "'ai_assistant'",
                            "on_behalf_of": "has(token.sub) ? token.sub : ''"}}]
_CONTEXT = [{"channel": "'ai-agent'", "agent": _AGENT, "resource_server": f"'{RESOURCE_ID}'"}]
COAZ_MAPPINGS = {
    "list_accounts": {"subject": _SUBJECT, "action": [{"name": "'list_accounts'"}],
                      "resource": [{"type": "'customer'", "id": "'business'"}], "context": _CONTEXT},
    "get_balance": {"subject": _SUBJECT, "action": [{"name": "'get_balance'"}],
                    "resource": [{"type": "'account'", "id": "params.arguments.account_id"}], "context": _CONTEXT},
    # The PDP's own decision: the banking package denies a payment over 2000 outright.
    "pay_supplier": {"subject": _SUBJECT, "action": [{"name": "'make_payment'"}],
                     "resource": [{"type": "'account'", "id": "params.arguments.from_account",
                                   "properties": {"from_account": "params.arguments.from_account",
                                                  "to_account": "params.arguments.to_account"}}],
                     "context": [{**_CONTEXT[0], "amount": "params.arguments.amount",
                                  "currency": "has(params.arguments.currency) ? params.arguments.currency : 'AUD'"}]},
}


@mcp._mcp_server.list_tools()
async def _coaz_list_tools() -> list[mcp_types.Tool]:
    """tools/list with each tool's COAZ declaration attached."""
    tools = []
    for info in mcp._tool_manager.list_tools():
        schema, extra = dict(info.parameters), {}
        if info.name in COAZ_MAPPINGS:
            schema, extra = {**schema, "x-coaz-mapping": COAZ_MAPPINGS[info.name]}, {"coaz": True}
        tools.append(mcp_types.Tool(name=info.name, description=info.description, inputSchema=schema, **extra))
    return tools


@mcp.custom_route("/.well-known/openid-federation", methods=["GET"])
async def well_known_federation(request: Request) -> Response:
    return Response(entity_configuration(), media_type="application/entity-statement+jwt",
                    headers={"Cache-Control": "no-store"})


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def protected_resource(request: Request) -> Response:
    return JSONResponse(resource_metadata())


class BearerGate:
    """The checks in front of /mcp/v1; the caller's identity reaches the tools through a context variable."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/mcp"):
            return await self.app(scope, receive, send)
        authorization = dict(scope["headers"]).get(b"authorization", b"").decode()
        try:
            who = check(authorization)
        except Refused as e:
            print(f"rs-accounts: refused {scope['path']}: {e.error} - {e.description}", flush=True)
            challenge = f'Bearer resource_metadata="{RESOURCE_ID}/.well-known/oauth-protected-resource", error="{e.error}"'
            response = JSONResponse({"error": e.error, "error_description": e.description}, status_code=e.status,
                                    headers={"WWW-Authenticate": challenge})
            return await response(scope, receive, send)
        print(f"rs-accounts: {who['client_id']} allowed ({CAPABILITY} granted by the federation)", flush=True)
        token = caller.set(who)
        try:
            return await self.app(scope, receive, send)
        finally:
            caller.reset(token)


def vouch() -> None:
    """Sign under the kid Raidiam publishes for the entity key, once Raidiam vouches for it."""
    try:
        PUBLIC["kid"] = federation.vouched_kid(federation.subordinate_statement(AUTHORITY, RESOURCE_ID), PUBLIC)
        print(f"rs-accounts: Raidiam vouches for {RESOURCE_ID} (kid {PUBLIC['kid'][:16]}...)", flush=True)
    except Exception as e:
        print(f"rs-accounts: not vouched for yet: {e}", flush=True)


if __name__ == "__main__":
    vouch()
    print(f"rs-accounts: {RESOURCE_ID}, authorisation server {ISSUER}, requires {CAPABILITY}", flush=True)
    port = int(os.environ.get("RESOURCE_LISTEN_PORT") or urlsplit(RESOURCE_ID).port or 443)
    uvicorn.run(BearerGate(mcp.streamable_http_app()), host="0.0.0.0", port=port, log_level="warning",
                ssl_certfile=os.environ.get("RESOURCE_TLS_CERT"), ssl_keyfile=os.environ.get("RESOURCE_TLS_KEY"))
