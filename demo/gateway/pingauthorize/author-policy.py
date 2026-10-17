#!/usr/bin/env python3
"""Author the rig's PingAuthorize policy through the Policy Editor's (PAP's) REST API, commit it, and export the
deployment package the PDP loads (embedded mode, static file) - a package is digest-sealed, so it can only come from
the PAP.

    python author-policy.py [--pap https://localhost:8448] [--limit 1000] [--out rig.deploymentpackage]

Each run builds the policy from nothing on branch "rig" (deleting the branch if it exists): attributes, rules,
the policy and the policy set it hangs from; commits; creates a deployment package of that snapshot; writes its data.

The requests arrive through the PDP's AuthZEN servlet (flat-tuple), so the attributes are request parameters by the
names it gives them - actionName, amount, ... - as the banking package's were.

The policy (version 1):
  permit  list_accounts, get_balance, access_mcp (the MCP handshake)
  permit  make_payment
  deny    make_payment over --limit (deny overrides permit)
  - anything else is not permitted

The PAP is called as user "admin" (x-user-id), its demo-mode authentication. Standard library only.
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

CTX = ssl._create_unverified_context()  # the PAP's own self-signed certificate, on loopback


class Pap:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def call(self, method: str, path: str, body=None, branch: str = None, raw: bool = False):
        url = self.base + "/api" + path + (f"?branch={branch}" if branch else "")
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("x-user-id", "admin")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, context=CTX, timeout=60) as r:
                payload = r.read()
                if raw:
                    return payload
                return json.loads(payload) if payload.strip() else {}
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{method} {path}: HTTP {e.code} {e.read().decode()[:600]}")


def from_json(parent_id: str, path: str, value_type: str) -> dict:
    """A fallback resolver: the value at path inside another attribute (the AuthZEN objects arrive as JSON)."""
    return {"attributeResolverType": "attribute", "id": parent_id, "condition": {"empty": {}},
            "valueProcessor": {"type": "json-path", "expression": path, "valueType": value_type, "name": ""},
            "name": None}


def attribute(name: str, value_type: str = "STRING", fallbacks: list = ()) -> dict:
    return {"objectType": "AttributeDefinition", "type": "ATTRIBUTE", "name": name, "fullName": name,
            "description": "From the AuthZEN request (the servlet's flat tuple)", "parentId": None,
            "valueType": value_type, "defaultValue": None, "repetitionSource": None,
            "cacheConfig": {"timeToLive": 0, "scopeAttributeId": None, "strategy": "NO_CACHING"}, "secret": False,
            "permissions": {"inherit": True, "rolePermissions": []},
            "resolvers": [{"attributeResolverType": "request", "condition": {"empty": {}}, "valueProcessor": None,
                           "name": None}, *fallbacks],
            "querySettings": None, "valueProcessor": None, "properties": []}


def equals(attr_id: str, value: str) -> dict:
    return {"comparison": {"left": {"attribute": {"id": attr_id}}, "op": "Equals", "right": {"constant": {"value": value}}}}


def rule(name: str, description: str, condition: dict, effect: str) -> dict:
    return {"type": "Rule", "name": name, "description": description, "shared": False, "disabled": False,
            "permissions": {"inherit": True, "rolePermissions": []}, "condition": condition, "statements": [],
            "targets": [], "effectSettings": {"type": effect}, "properties": []}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--pap", default="https://localhost:8448")
    ap.add_argument("--branch", default="rig")
    ap.add_argument("--limit", default="1000", help="the most an agent may pay in one payment")
    ap.add_argument("--out", default="rig.deploymentpackage")
    a = ap.parse_args()
    pap = Pap(a.pap)

    # A fresh branch from the PAP's root snapshot.
    # The packages earlier runs made refer to the branch's snapshots, which keeps it from being deleted: theirs go.
    for pkg in pap.call("GET", "/deployment-packages").get("data", []):
        if pkg.get("name", "").startswith(a.branch + "-"):
            pap.call("DELETE", f"/deployment-packages/{pkg['id']}")
            print(f"deleted package {pkg['name']}")
    branches = pap.call("GET", "/version-control/branches")["data"]
    for b in branches:
        if b["name"] == a.branch:
            pap.call("DELETE", f"/version-control/branches/{b['id']}")
            print(f"deleted branch {a.branch}")
    root = pap.call("GET", "/version-control/snapshots/root")["id"]
    branch = pap.call("POST", f"/version-control/snapshots/{root}/branch", {"name": a.branch})
    print(f"branch {a.branch}: {branch['id']}")
    br = a.branch

    # The AuthZEN request's objects, as the servlet passes them (JSON), and the values read out of them when the
    # flat tuple does not carry them: the action's name, the amount from the context the COAZ mapping builds.
    action_obj = pap.call("POST", "/trust-framework/roots/ATTRIBUTE", attribute("action", "JSON"), br)["id"]
    context = pap.call("POST", "/trust-framework/roots/ATTRIBUTE", attribute("context", "JSON"), br)["id"]
    action = pap.call("POST", "/trust-framework/roots/ATTRIBUTE",
                      attribute("actionName", "STRING", [from_json(action_obj, "$.name", "STRING")]), br)["id"]
    amount = pap.call("POST", "/trust-framework/roots/ATTRIBUTE",
                      attribute("amount", "NUMBER", [from_json(context, "$.amount", "NUMBER")]), br)["id"]

    rules = [
        pap.call("POST", "/v2/policy-manager/rules", rule(
            "Permit reading accounts", "An agent may list accounts and read balances; the MCP handshake is allowed.",
            {"or": {"conditions": [equals(action, n) for n in ("list_accounts", "get_balance", "access_mcp")]}},
            "unconditionalPermit"), br)["id"],
        pap.call("POST", "/v2/policy-manager/rules", rule(
            "Permit payments", "An agent may initiate a payment, within the limit below.",
            equals(action, "make_payment"), "unconditionalPermit"), br)["id"],
        pap.call("POST", "/v2/policy-manager/rules", rule(
            f"Deny payments over {a.limit}", f"No agent may pay more than {a.limit} in one payment.",
            {"and": {"conditions": [equals(action, "make_payment"),
                                    {"comparison": {"left": {"attribute": {"id": amount}}, "op": "GreaterThan",
                                                    "right": {"constant": {"value": a.limit}}}}]}},
            "unconditionalDeny"), br)["id"],
    ]
    policy = pap.call("POST", "/v2/policy-manager/policies", {
        "type": "Policy", "name": "Rig agent authorization", "description": "What the rig's agents may do",
        "shared": False, "disabled": False, "combiningAlgorithm": {"algorithm": "DenyOverrides", "evaluateAll": False},
        "children": [{"id": r, "type": "Rule"} for r in rules], "repetitionSettings": None,
        "permissions": {"inherit": True, "rolePermissions": []}, "condition": {"empty": {}}, "statements": [],
        "targets": [], "properties": []}, br)["id"]
    policyset = pap.call("POST", "/v2/policy-manager/policysets", {
        "type": "PolicySet", "name": "Rig decision point", "description": "The root the PDP evaluates",
        "shared": False, "disabled": False, "combiningAlgorithm": {"algorithm": "DenyOverrides", "evaluateAll": False},
        "children": [{"id": policy, "type": "Policy"}], "repetitionSettings": None,
        "permissions": {"inherit": True, "rolePermissions": []}, "condition": {"empty": {}}, "statements": [],
        "targets": [], "properties": []}, br)["id"]
    print(f"policy set {policyset} <- policy {policy} <- {len(rules)} rules")

    commit = pap.call("POST", f"/version-control/branches/{branch['id']}/commit",
                      {"message": f"rig agent authorization, payment limit {a.limit}"})
    snapshot = commit.get("id") or pap.call("GET", f"/version-control/branches/{branch['id']}")["head"]
    print(f"committed snapshot {snapshot}")

    package = pap.call("POST", "/deployment-packages", {
        "name": f"rig-{snapshot[:8]}", "description": f"rig agent authorization, payment limit {a.limit}",
        "snapshotId": snapshot, "decisionNodeId": policyset})
    data = pap.call("GET", f"/deployment-packages/{package['id']}/data", raw=True)
    with open(a.out, "wb") as f:
        f.write(data)
    print(f"deployment package {package['id']} -> {a.out} ({len(data)} bytes)")


if __name__ == "__main__":
    sys.exit(main())
