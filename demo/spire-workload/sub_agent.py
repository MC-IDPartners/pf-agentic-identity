"""sub_agent: an agent other agents call - the Accounts agent or the Payments agent (../gateway/README.md, "Agents
calling agents"). CBA's pattern (invoice-settler-b-7): one federation entity, both a client (openid_relying_party) and
a resource (oauth_resource, interface "agent"), hosted by the agent provider at <provider>/agent/<name>.

It serves MCP at <its identifier>/mcp/v1, behind the gateway, which has already verified the caller's token (signature,
audience = this agent, DPoP from the caller's instance key, Shared Signals) and asked the PDP. For each tool call it:

  1. exchanges the caller's token at PingFederate (RFC 8693): subject_token = that token; resource = the resource it
     calls next; client authentication = its own attestation from the provider, in DPoP combined mode with its own
     instance key. The new token: sub = the caller, act = {sub: this agent}, aud = the resource, cnf.jkt = this
     instance's key;
  2. calls the resource through its gateway with that token and a DPoP proof per request;
  3. answers with the resource's result and the delegation it used.

Environment: AGENT_ID, AGENT_PROVIDER, AGENT_KIND (accounts | payments), DOWNSTREAM_RESOURCE (the resource's
identifier), AUTHORISATION_SERVER (an issuer), ISSUER_HOST_OVERRIDE, PF_CA_FILE, LISTEN_PORT, INSTANCE_KEY_FILE,
SPIRE_SOCKET, AGENT_ALLOWED_HOSTS.
"""
import contextvars
import os
import time
from urllib.parse import urlsplit

import jwt
import requests
import uvicorn
from client_attestation_sdk.svid_source import SpireWorkloadApiSvidSource
from mcp import types as mcp_types
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

import agent as a
import federation
import fedresolve

AGENT_ID = os.environ["AGENT_ID"].rstrip("/")
PROVIDER = os.environ["AGENT_PROVIDER"].rstrip("/")
KIND = os.environ["AGENT_KIND"]
DOWNSTREAM = os.environ["DOWNSTREAM_RESOURCE"].rstrip("/")
ISSUER = os.environ["AUTHORISATION_SERVER"].rstrip("/")
CA = fedresolve.ca_bundle(os.environ.get("PF_CA_FILE"))
os.environ["SSL_CERT_FILE"] = os.environ["PF_CA_FILE"] = CA
KEY, PUBLIC = a.instance_key(os.environ.get("INSTANCE_KEY_FILE", "/state/instance.jwk"))
MCP_PATH = urlsplit(AGENT_ID).path + "/mcp/v1"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
incoming = contextvars.ContextVar("incoming", default=None)
_attestation = {"jwt": None, "exp": 0}


def attestation() -> str:
    """This instance's attestation from the provider, on SPIRE's word; fetched again before it runs out."""
    if not _attestation["jwt"] or _attestation["exp"] - time.time() < 120:
        svid = SpireWorkloadApiSvidSource(socket_path=os.environ.get("SPIRE_SOCKET", "/run/spire/sockets/agent.sock"),
                                          spire_agent="spire-agent").fetch(PROVIDER)
        r = requests.post(PROVIDER + "/attest", json={"client_id": AGENT_ID, "instance_jwk": PUBLIC, "svid": svid},
                          verify=CA, timeout=20)
        r.raise_for_status()
        _attestation["jwt"] = r.json()["wallet_attestation"]
        _attestation["exp"] = jwt.decode(_attestation["jwt"], options={"verify_signature": False})["exp"]
    return _attestation["jwt"]


def exchange(subject_token: str) -> str:
    """RFC 8693 at PingFederate: the caller's token for one this agent may use at DOWNSTREAM, on the caller's behalf."""
    discovery = requests.get(federation.reachable(ISSUER + "/.well-known/openid-configuration"), timeout=15,
                             verify=CA).json()
    endpoint = federation.reachable(discovery["token_endpoint"])
    nonce = None
    for _ in range(2):
        r = requests.post(endpoint, timeout=20, verify=CA, data={
            "grant_type": TOKEN_EXCHANGE, "subject_token": subject_token, "subject_token_type": ACCESS_TOKEN,
            "requested_token_type": ACCESS_TOKEN, "resource": DOWNSTREAM},
            headers={"OAuth-Client-Attestation": attestation(),
                     "DPoP": a.dpop_proof(KEY, "POST", discovery["token_endpoint"], nonce=nonce)})
        if r.ok:
            return r.json()["access_token"]
        nonce = r.headers.get("DPoP-Nonce")
        if not nonce:
            raise RuntimeError(f"token exchange refused: {r.status_code} {r.text[:300]}")
    raise RuntimeError("token exchange: the DPoP nonce handshake did not complete")


async def delegate(tool: str, args: dict) -> dict:
    """Exchange the caller's token, then call tool at the downstream resource through its gateway."""
    caller = incoming.get()
    if not caller:
        return {"error": "no caller token"}
    try:
        token = exchange(caller)
    except Exception as e:
        print(f"{KIND}-agent: {e}", flush=True)
        return {"error": "delegation_refused", "detail": str(e)}
    claims = jwt.decode(token, options={"verify_signature": False})
    delegation = {"sub": claims.get("sub"), "act": claims.get("act"), "client_id": claims.get("client_id"),
                  "aud": claims.get("aud"), "cnf_jkt": (claims.get("cnf") or {}).get("jkt"),
                  "instance_jkt": a.jwk_thumbprint(a.public_jwk(KEY))}
    print(f"{KIND}-agent: {tool} for {claims.get('sub')} as {claims.get('client_id')} (act {claims.get('act')})",
          flush=True)
    try:
        result = await a.call_mcp(DOWNSTREAM + "/mcp/v1", token, tool, args, KEY)
    except Exception as e:
        return {"error": "downstream_refused", "detail": str(e)[:300], "delegation": delegation}
    return {"result": result, "delegation": delegation}


# DNS rebinding protection stays on: the gateway forwards to this container's compose name.
ALLOWED = [urlsplit(AGENT_ID).netloc, *filter(None, os.environ.get("AGENT_ALLOWED_HOSTS", "").split(","))]
mcp = FastMCP(f"POC {KIND.title()} Agent", stateless_http=True, json_response=True, streamable_http_path=MCP_PATH,
              transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True,
                                                           allowed_hosts=ALLOWED, allowed_origins=[]))


async def account_balance(account_id: str) -> dict:
    """The balance and available funds on one business account, read for the calling agent."""
    return await delegate("get_balance", {"account_id": account_id})


async def accounts_overview() -> dict:
    """The business accounts visible to the calling agent, with balances."""
    return await delegate("list_accounts", {})


async def pay_invoice(invoice_id: str, from_account: str, to_account: str, amount: float, currency: str = "AUD") -> dict:
    """Pays a supplier invoice from a business account, for the calling agent."""
    return await delegate("pay_invoice", {"invoice_id": invoice_id, "from_account": from_account,
                                          "to_account": to_account, "amount": amount, "currency": currency})


for _tool in {"accounts": (account_balance, accounts_overview), "payments": (pay_invoice,)}[KIND]:
    mcp.tool()(_tool)

# COAZ: how a call to this agent maps to an AuthZEN evaluation at the gateway - the same actions as the resources'
# (the caller is the subject), so the PDP decides the first hop on the same rules as the second.
_CALLER = "has(token.client_id) ? token.client_id : (has(token.sub) ? token.sub : 'unknown-agent')"
_SUBJECT = [{"type": "'agent'", "identity": _CALLER,
             "properties": {"client_id": _CALLER, "agent_type": "'ai_assistant'",
                            "on_behalf_of": "has(token.sub) ? token.sub : ''"}}]
_CONTEXT = [{"channel": "'agent-to-agent'", "agent": _CALLER, "callee": f"'{AGENT_ID}'"}]
COAZ = {
    "account_balance": {"subject": _SUBJECT, "action": [{"name": "'get_balance'"}],
                        "resource": [{"type": "'account'", "id": "params.arguments.account_id"}], "context": _CONTEXT},
    "accounts_overview": {"subject": _SUBJECT, "action": [{"name": "'list_accounts'"}],
                          "resource": [{"type": "'customer'", "id": "'business'"}], "context": _CONTEXT},
    "pay_invoice": {"subject": _SUBJECT, "action": [{"name": "'make_payment'"}],
                    "resource": [{"type": "'account'", "id": "params.arguments.from_account",
                                  "properties": {"from_account": "params.arguments.from_account",
                                                 "to_account": "params.arguments.to_account"}}],
                    "context": [{**_CONTEXT[0], "amount": "params.arguments.amount",
                                 "currency": "has(params.arguments.currency) ? params.arguments.currency : 'AUD'"}]},
}


@mcp._mcp_server.list_tools()
async def _coaz_list_tools() -> list[mcp_types.Tool]:
    tools = []
    for info in mcp._tool_manager.list_tools():
        schema, extra = dict(info.parameters), {}
        if info.name in COAZ:
            schema, extra = {**schema, "x-coaz-mapping": COAZ[info.name]}, {"coaz": True}
        tools.append(mcp_types.Tool(name=info.name, description=info.description, inputSchema=schema, **extra))
    return tools


class CallerToken:
    """Keeps the caller's token for the tool to exchange. No checks: the gateway in front made them."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        auth = dict(scope["headers"]).get(b"authorization", b"").decode()
        token = incoming.set(auth.partition(" ")[2].strip() or None)
        try:
            return await self.app(scope, receive, send)
        finally:
            incoming.reset(token)


if __name__ == "__main__":
    print(f"{KIND}-agent: {AGENT_ID}, MCP at {MCP_PATH}, calls {DOWNSTREAM}, instance key "
          f"{a.jwk_thumbprint(a.public_jwk(KEY))}", flush=True)
    uvicorn.run(CallerToken(mcp.streamable_http_app()), host="0.0.0.0", port=int(os.environ.get("LISTEN_PORT", "8090")),
                log_level="warning")
