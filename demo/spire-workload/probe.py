"""Calls the resource directly with the agent's own token, for harness.py's gateway and PDP checks - things the agent
itself would refuse to try. Prints one JSON line per probe: PROBE {"name", "http", "jsonrpc_error", "result"}.

    python probe.py                      # the gateway and PDP probes
    PROBE=ssf EMIT_SECRET=... python probe.py   # Shared Signals: revoke, disable and re-enable the agent
"""
import json
import os
import time

import jwt
import requests
from client_attestation_sdk.svid_source import SpireWorkloadApiSvidSource

import agent as a
import federation
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


def emit(event_type: str, subject_sub: str) -> int:
    """Raise an event at PingFederate's SSF transmitter, as its operator (conformance-ssf-emitter, EMIT_SECRET)."""
    issuer = os.environ.get("AUTHORISATION_SERVER") or "https://bottle-platonic-parted.ngrok-free.dev"
    base = federation.reachable(issuer)
    tok = requests.post(base + "/as/token.oauth2", verify=ca, timeout=20, data={
        "grant_type": "client_credentials", "client_id": "conformance-ssf-emitter",
        "client_secret": os.environ["EMIT_SECRET"], "scope": "ssf.provision"}).json()["access_token"]
    r = requests.post(base + "/ssf/events:emit", verify=ca, timeout=20, headers={"Authorization": "Bearer " + tok},
                      json={"event_type": event_type, "event": {},
                            "subject": {"format": "iss_sub", "iss": issuer, "sub": subject_sub}})
    r.raise_for_status()
    return r.json().get("count", 0)


def status(bearer: str) -> int:
    """The HTTP status of a get_balance through the gateway: 200, or 401 when the PEP refuses the token."""
    r = requests.post(endpoint, headers={**headers, "Authorization": "Bearer " + bearer}, verify=ca, timeout=30,
                      json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                            "params": {"name": "get_balance", "arguments": {"account_id": "acc-002"}}})
    return r.status_code


def until(bearer: str, want: int, limit: float = 20.0):
    """Seconds until a call with bearer answers want, or None."""
    start = time.time()
    while time.time() - start < limit:
        if status(bearer) == want:
            return round(time.time() - start, 1)
        time.sleep(0.5)
    return None


def signals():
    """Shared Signals through the gateway: the PEP's stream from PingFederate's transmitter."""
    agent_id = os.environ["AGENT_ID"]
    caep, risc = "https://schemas.openid.net/secevent/caep/event-type/", "https://schemas.openid.net/secevent/risc/event-type/"
    first = token()
    out = {"name": "ssf", "before": status(first)}
    out["session_revoked_streams"] = emit(caep + "session-revoked", agent_id)
    out["old_token_refused_after_s"] = until(first, 401)
    time.sleep(1.2)  # a token issued in the same second as the event counts as before it
    second = token()
    out["new_token_after_session_revoked"] = status(second)
    out["account_disabled_streams"] = emit(risc + "account-disabled", agent_id)
    out["disabled_refused_after_s"] = until(second, 401)
    third = token()
    out["fresh_token_while_disabled"] = status(third)
    emit(risc + "account-enabled", agent_id)
    out["enabled_ok_after_s"] = until(third, 200)
    print("PROBE " + json.dumps(out), flush=True)


if os.environ.get("PROBE") == "ssf":
    signals()
    raise SystemExit(0)

good = token()
claims = jwt.decode(good, options={"verify_signature": False})
forged = jwt.encode(claims, "not-pingfederates-key", algorithm="HS256")
call("forged_token", forged, "get_balance", {"account_id": "acc-002"})
call("pdp_permit", good, "get_balance", {"account_id": "acc-002"})
call("pdp_deny_large_payment", good, "pay_supplier", {"from_account": "acc-002", "to_account": "supplier-77", "amount": 5000})
