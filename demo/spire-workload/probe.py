"""Calls the resource through the gateway with the agent's own tokens, for harness.py's gateway, DPoP and Shared Signals
checks - things the agent itself would refuse to try. Prints one JSON line per probe: PROBE {...}.

    python probe.py                              # gateway, PDP and DPoP probes
    PROBE=ssf EMIT_SECRET=... python probe.py    # Shared Signals: revoke, disable and re-enable the agent, then one
                                                 # instance of it while another carries on
    PROBE=emit EMIT_EVENT=... EMIT_SUB=... EMIT_SECRET=... python probe.py   # raise one event

Each "instance" is a key of its own, attested on this container's SVID by PingFederate's attester (agent.attest) - two
copies of the agent - and each token is DPoP-bound to its instance's key.
"""
import json
import os
import time

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import ec

import agent as a
import federation
import fedresolve

ca = fedresolve.ca_bundle(os.environ["PF_CA_FILE"])
os.environ["SSL_CERT_FILE"] = os.environ["PF_CA_FILE"] = ca
resource = os.environ.get("RESOURCE_IDS", "https://host.docker.internal:8446").split(",")[0].strip()
endpoint = resource + "/mcp/v1"
issuer = os.environ.get("AUTHORISATION_SERVER") or "https://bottle-platonic-parted.ngrok-free.dev"
agent_id = os.environ["AGENT_ID"]
headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
GET_BALANCE = {"name": "get_balance", "arguments": {"account_id": "acc-002"}}


class Instance:
    """One copy of the agent: its key, attested on SPIRE's word, and a DPoP-bound token for the resource."""

    def __init__(self, key_file: str):
        self.key, public = a.instance_key(key_file)
        self.jkt = a.jwk_thumbprint(a.public_jwk(self.key))
        self.attestation = a.attest(agent_id, self.key, public, issuer, ca)

    def token(self) -> str:
        return a.token(issuer, resource, agent_id, self.attestation, self.key)


def send(token: str, params: dict, scheme: str = "DPoP", proof_key=None, proof: str = None):
    """A tools/call through the gateway: (HTTP status, JSON-RPC error, result)."""
    h = {**headers, "Authorization": f"{scheme} {token}"}
    if scheme == "DPoP":
        h["DPoP"] = proof or a.dpop_proof(proof_key, "POST", endpoint, token)
    r = requests.post(endpoint, headers=h, verify=ca, timeout=30,
                      json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
    try:
        body = r.json()
    except ValueError:
        body = {}
    result = (body.get("result") or {}).get("structuredContent") or (body.get("result") or {}).get("content")
    return r.status_code, body.get("error"), result


def report(name: str, outcome):
    status, error, result = outcome
    print("PROBE " + json.dumps({"name": name, "http": status, "jsonrpc_error": error, "result": result}), flush=True)


def emit(event_type: str, subject: dict) -> int:
    """Raise an event at PingFederate's SSF transmitter, as its operator (conformance-ssf-emitter, EMIT_SECRET)."""
    base = federation.reachable(issuer)
    tok = requests.post(base + "/as/token.oauth2", verify=ca, timeout=20, data={
        "grant_type": "client_credentials", "client_id": "conformance-ssf-emitter",
        "client_secret": os.environ["EMIT_SECRET"], "scope": "ssf.provision"}).json()["access_token"]
    r = requests.post(base + "/ssf/events:emit", verify=ca, timeout=20, headers={"Authorization": "Bearer " + tok},
                      json={"event_type": event_type, "event": {}, "subject": subject})
    r.raise_for_status()
    return r.json().get("count", 0)


def status(instance: Instance, token: str) -> int:
    return send(token, GET_BALANCE, proof_key=instance.key)[0]


def until(instance: Instance, token: str, want: int, limit: float = 20.0):
    """Seconds until a call answers want, or None."""
    start = time.time()
    while time.time() - start < limit:
        if status(instance, token) == want:
            return round(time.time() - start, 1)
        time.sleep(0.5)
    return None


def signals():
    caep, risc = "https://schemas.openid.net/secevent/caep/event-type/", "https://schemas.openid.net/secevent/risc/event-type/"
    agent_subject = {"format": "iss_sub", "iss": issuer, "sub": agent_id}
    one, two = Instance("/state/instance.jwk"), Instance("/state/instance-2.jwk")
    first = one.token()
    out = {"name": "ssf", "before": status(one, first)}
    out["session_revoked_streams"] = emit(caep + "session-revoked", agent_subject)
    out["old_token_refused_after_s"] = until(one, first, 401)
    time.sleep(1.2)  # a token issued in the same second as the event counts as before it
    second = one.token()
    out["new_token_after_session_revoked"] = status(one, second)
    out["account_disabled_streams"] = emit(risc + "account-disabled", agent_subject)
    out["disabled_refused_after_s"] = until(one, second, 401)
    third = one.token()
    out["fresh_token_while_disabled"] = status(one, third)
    emit(risc + "account-enabled", agent_subject)
    out["enabled_ok_after_s"] = until(one, third, 200)

    # One instance, not the agent: the subject is that instance's key thumbprint, its tokens' cnf.jkt.
    token_one, token_two = one.token(), two.token()
    out["instances_differ"] = one.jkt != two.jkt
    emit(risc + "account-disabled", {"format": "opaque", "id": one.jkt})
    out["instance_refused_after_s"] = until(one, token_one, 401)
    out["other_instance_while_one_disabled"] = status(two, token_two)
    emit(risc + "account-enabled", {"format": "opaque", "id": one.jkt})
    out["instance_ok_after_s"] = until(one, token_one, 200)
    print("PROBE " + json.dumps(out), flush=True)


if os.environ.get("PROBE") == "emit":
    # One event about one agent (EMIT_EVENT, EMIT_SUB), for harness.py's agents-calling-agents stage.
    count = emit(os.environ["EMIT_EVENT"], {"format": "iss_sub", "iss": issuer, "sub": os.environ["EMIT_SUB"]})
    print("PROBE " + json.dumps({"name": "emit", "streams": count}), flush=True)
    raise SystemExit(0)

if os.environ.get("PROBE") == "ssf":
    signals()
    raise SystemExit(0)

me = Instance("/state/instance.jwk")
good = me.token()

claims = jwt.decode(good, options={"verify_signature": False})
report("forged_token", send(jwt.encode(claims, "not-pingfederates-key", algorithm="HS256"), GET_BALANCE, proof_key=me.key))
report("pdp_permit", send(good, GET_BALANCE, proof_key=me.key))
report("pdp_deny_large_payment", send(good, {"name": "pay_supplier", "arguments": {
    "from_account": "acc-002", "to_account": "supplier-77", "amount": 5000}}, proof_key=me.key))

# DPoP: the token is bound to this instance's key.
report("dpop_bound_token_as_bearer", send(good, GET_BALANCE, scheme="Bearer"))
report("dpop_proof_from_another_key", send(good, GET_BALANCE, proof_key=ec.generate_private_key(ec.SECP256R1())))
once = a.dpop_proof(me.key, "POST", endpoint, good)
report("dpop_proof_first_use", send(good, GET_BALANCE, proof=once))
report("dpop_proof_replayed", send(good, GET_BALANCE, proof=once))
print("PROBE " + json.dumps({"name": "dpop_binding", "cnf_jkt": (claims.get("cnf") or {}).get("jkt"),
                             "instance_jkt": me.jkt}), flush=True)
