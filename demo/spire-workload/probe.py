"""Calls the resource directly with the agent's own token, for harness.py's gateway and PDP checks - things the agent
itself would refuse to try. Prints one JSON line per probe: PROBE {"name", "http", "jsonrpc_error", "result"}.

    python probe.py                      # all probes
"""
import json
import os

import jwt
import requests
from client_attestation_sdk.svid_source import SpireWorkloadApiSvidSource

import agent as a
import fedresolve

ca = fedresolve.ca_bundle(os.environ["PF_CA_FILE"])
os.environ["SSL_CERT_FILE"] = os.environ["PF_CA_FILE"] = ca
resource = os.environ.get("RESOURCE_IDS", "https://host.docker.internal:8446").split(",")[0].strip()
endpoint = resource + "/mcp/v1"
headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def token() -> str:
    key, public = a.instance_key(os.environ.get("INSTANCE_KEY_FILE", "/state/instance.jwk"))
    provider, agent_id = os.environ["AGENT_PROVIDER"].rstrip("/"), os.environ["AGENT_ID"]
    svid = SpireWorkloadApiSvidSource(socket_path=os.environ.get("SPIRE_SOCKET", "/run/spire/sockets/agent.sock"),
                                      spire_agent="spire-agent").fetch(provider)
    att = requests.post(provider + "/attest", json={"client_id": agent_id, "instance_jwk": public, "svid": svid},
                        verify=ca, timeout=20).json()["wallet_attestation"]
    issuer = os.environ.get("AUTHORISATION_SERVER") or "https://bottle-platonic-parted.ngrok-free.dev"
    return a.token(issuer, resource, agent_id, att, key)


def call(name: str, bearer: str, tool: str, args: dict):
    r = requests.post(endpoint, headers={**headers, "Authorization": "Bearer " + bearer}, verify=ca, timeout=30,
                      json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
    body = {}
    try:
        body = r.json()
    except ValueError:
        pass
    print("PROBE " + json.dumps({"name": name, "http": r.status_code, "jsonrpc_error": body.get("error"),
                                 "result": (body.get("result") or {}).get("structuredContent")
                                 or (body.get("result") or {}).get("content")}), flush=True)


good = token()
claims = jwt.decode(good, options={"verify_signature": False})
forged = jwt.encode(claims, "not-pingfederates-key", algorithm="HS256")
call("forged_token", forged, "get_balance", {"account_id": "acc-002"})
call("pdp_permit", good, "get_balance", {"account_id": "acc-002"})
call("pdp_deny_large_payment", good, "pay_supplier", {"from_account": "acc-002", "to_account": "supplier-77", "amount": 5000})
