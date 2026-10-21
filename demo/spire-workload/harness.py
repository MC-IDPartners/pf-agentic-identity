"""End-to-end harness for the agent-r flow (agent.py): checks that an agent is ready, runs it, and checks what it did.

    python harness.py                      # the newest Principal version the marketplace deployed (Raidiam hosts it)
    python harness.py --agent <entity id> --label <workload>   # a given one
    python harness.py --keep               # leave whatever it created (the SPIRE entry) in place
    python harness.py --report out.json    # also write the report as JSON
    python harness.py --brief              # one line per check (the default is verbose: each check's PoC objectives,
                                           # what it proves and its evidence, then the objectives' coverage)

There is no agent provider. The Principal is a federation-managed entity Raidiam hosts; the sub-agents serve their own
Entity Configurations; PingFederate's attester reads every agent's SPIFFE binding from Raidiam, and PingFederate
registers each agent from Raidiam at its first attested token request.

Stages, each a pass, a fail or a skip in the report:

  preflight    PingFederate answers; SPIRE's OIDC provider, the resources, the sub-agents and the gateways are up;
               Raidiam hosts the agent's Entity Configuration and vouches for it, publishing its bridge key, with
               capabilities; each sub-agent serves its own Entity Configuration
  spire        a SPIRE entry for the agent's SPIFFE ID, selecting containers by the label the agent runs under;
               created if missing (and removed afterwards, unless --keep)
  run          docker compose run agent <job>, under that label; its AGENT_RESULT line is what gets checked:
               attested by PingFederate's attester, for this agent and SPIFFE ID; the capability in its envelope;
               the resource chosen; a token for this agent with aud = the resource; the call allowed
  attesters    why PingFederate trusts the attestation and the agent: its own attester's key in its Entity
               Configuration, Raidiam vouching for PingFederate, the agent's SPIFFE binding published by Raidiam and
               read from there by the attester, no static (mock) attesters, and the agent registered from Raidiam
  negatives    another workload's container is refused attestation as the agent; a job outside the envelope is refused
               before a request is built; the resource refuses a call with no token
  gateway      with the agent's own token (probe.py): a forged token is refused at the gateway; the PDP permits
               get_balance; the PDP denies a large payment (COAZ -32401) before it reaches the resource
  a2a          agents calling agents: the Principal's pay-invoice - the Accounts and Payments agents found through the
               federation, each acting for it by token exchange (sub, act, its own DPoP key, its resource) - an
               over-limit invoice refused, and the Payments agent disabled by a signal while accounts carry on
  signals      Shared Signals (PROBE=ssf): session-revoked refuses the agent's existing token at the gateway but not a
               new one; account-disabled refuses every token; account-enabled lifts it - each within seconds

Standard library only; it shells out to docker and docker compose, and runs in-network checks inside the Accounts
agent's container. Deploying the Principal is the marketplace's (http://localhost:3000), which this reads.
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import textwrap
import time
import urllib.request
from urllib.parse import quote

import objectives

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.dirname(HERE)
AUTHORITY = "https://authority.directory.cba.raidiam.io/authority/5a27c88b-97ed-4d37-a3c8-59c66b19aa25"
ENV = {**os.environ, "MSYS_NO_PATHCONV": "1"}


# ── plumbing ────────────────────────────────────────────────────────────────────────────────────────

def sh(*args, check=False, timeout=600) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=HERE, env=ENV, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", check=check, timeout=timeout)


def compose(*args, timeout=600, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", *args], cwd=HERE, env={**ENV, **(env or {})}, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=timeout)


def in_network(code: str) -> str:
    """Python run inside the Accounts agent's container, which reaches everything in the rig by its internal name and
    trusts the rig's CA (the host's TLS interception can get in the way of the host's own calls)."""
    out = compose("exec", "-T", "accounts-agent", "python", "-c", code, timeout=120)
    if out.returncode:
        raise RuntimeError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else f"exit {out.returncode}")
    return out.stdout.strip()


def claims(jwt: str) -> dict:
    payload = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def raidiam_fetch(sub: str):
    with urllib.request.urlopen(f"{AUTHORITY}/fetch?sub={quote(sub, safe='')}", timeout=20) as r:
        return claims(r.read().decode())


def get(url: str, accept: str = "*/*") -> str:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": accept}), timeout=20) as r:
        return r.read().decode()


def deployed_principal(marketplace: str) -> dict:
    """The newest Principal version the marketplace deployed and Raidiam vouches for: its deploy record."""
    with urllib.request.urlopen(f"{marketplace}/api/agents?status=approved", timeout=20) as r:
        agents = json.load(r)["agents"]
    ready = [x for x in agents if x.get("kind") == "principal" and (x.get("deploy") or {}).get("hosted")
             and str((x.get("deploy") or {}).get("entityId", "")).startswith("https://rp.")]
    ready.sort(key=lambda x: x.get("updatedAt") or "", reverse=True)
    if not ready:
        raise SystemExit("harness: no Principal version Raidiam hosts is deployed - deploy one in the marketplace, "
                         "or name one with --agent and --label")
    return ready[0]["deploy"]


class Report:
    """Each check with the PoC objectives it evidences (objectives.py), what passing it proves, and its evidence;
    --brief prints one line per check, as before."""

    WIDTH = 110

    def __init__(self, verbose: bool = True):
        self.rows, self.verbose = [], verbose

    def stage(self, name: str, title: str = None):
        intro, tcs = objectives.STAGES.get(name, ("", []))
        if not self.verbose:
            print(f"\n{title or name}", flush=True)
            return
        print("\n" + "=" * self.WIDTH, flush=True)
        print(f"{name.upper()}" + (f"  {title}" if title else "") + (f"    [{' '.join(tcs)}]" if tcs else ""), flush=True)
        if intro:
            print(textwrap.fill(intro, self.WIDTH, initial_indent="  ", subsequent_indent="  "), flush=True)
        print("-" * self.WIDTH, flush=True)

    def add(self, stage: str, check: str, status: str, detail: str = "", evidence: list = None):
        tcs, why = objectives.classify(check)
        self.rows.append({"stage": stage, "check": check, "status": status, "detail": detail, "objectives": tcs,
                          "proves": why, "evidence": evidence or []})
        mark = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}[status]
        if not self.verbose:
            print(f"  {mark:4}  {stage:10} {check}" + (f"  - {detail}" if detail else ""), flush=True)
            return
        print(f"  {mark:4}  {check}" + (f"    [{' '.join(tcs)}]" if tcs else ""), flush=True)
        wrap = lambda label, text: textwrap.fill(text, self.WIDTH, initial_indent=f"        {label:9} ",
                                                 subsequent_indent=" " * 18)
        if why:
            print(wrap("proves:", why), flush=True)
        if detail:
            print(wrap("evidence:", detail), flush=True)
        for line in evidence or []:
            print(wrap("", line), flush=True)

    def expect(self, stage: str, check: str, ok: bool, detail: str = "", evidence: list = None):
        self.add(stage, check, "pass" if ok else "fail", detail, evidence)
        return ok

    @property
    def failed(self):
        return [r for r in self.rows if r["status"] == "fail"]

    def coverage(self) -> list:
        """Each PoC objective: what the run evidenced for it, or why the harness cannot."""
        out = []
        for tc, (title, domain) in objectives.OBJECTIVES.items():
            rows = [r for r in self.rows if tc in r["objectives"]]
            passed = sum(r["status"] == "pass" for r in rows)
            failed = sum(r["status"] == "fail" for r in rows)
            if failed:
                state = "FAILING"
            elif passed:
                state = "evidenced"
            elif rows:
                state = "not run"
            else:
                state = "out of scope"
            note = objectives.OUT_OF_SCOPE.get(tc, "") if state != "evidenced" or tc in ("TC-02", "TC-25") else ""
            out.append({"objective": tc, "title": title, "domain": domain, "state": state, "passed": passed,
                        "failed": failed, "checks": len(rows), "note": note})
        return out

    def print_coverage(self):
        print("\n" + "=" * self.WIDTH, flush=True)
        print("POC OBJECTIVES (Agentic IDAM - Trust Controller PoC Objectives, 10 July 2026)", flush=True)
        print("-" * self.WIDTH, flush=True)
        for c in self.coverage():
            counts = f"{c['passed']}/{c['checks']}" if c["checks"] else "-"
            print(f"  {c['objective']}  {c['state']:12} {counts:>6}  {c['title']}", flush=True)
            if c["note"]:
                print(f"{'':30}{c['note']}", flush=True)


# ── stages ──────────────────────────────────────────────────────────────────────────────────────────

def preflight(rep: Report, a) -> bool:
    rep.stage("preflight")
    ps = compose("ps", "--format", "json")
    running = set()
    for line in ps.stdout.splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        for row in item if isinstance(item, list) else [item]:
            if row.get("State") == "running":
                running.add(row.get("Service"))
    # gateway-agents is https://host.docker.internal:8443: the sub-agents' identities and MCP. There is no entity-host.
    for svc in ("spire-oidc", "rs-accounts", "rs-payments", "accounts-agent", "payments-agent",
                "gateway", "gateway-payments", "gateway-agents", "coaz-pep", "pingauthorize"):
        rep.expect("preflight", f"{svc} is running", svc in running,
                   "" if svc in running else f"docker compose up -d {svc}")
    if "accounts-agent" not in running:
        return False

    try:
        out = in_network(
            "import requests,os;r=requests.get('https://host.docker.internal:9031/.well-known/openid-configuration',"
            "verify=os.environ['PF_CA_FILE']);print(r.status_code, r.json().get('issuer'))")
        rep.expect("preflight", "PingFederate answers", out.startswith("200"), out)
    except Exception as e:
        rep.expect("preflight", "PingFederate answers", False, str(e))
        return False

    try:
        ec = claims(get(a.agent + "/.well-known/openid-federation", "application/entity-statement+jwt").strip())
        rp = (ec.get("metadata") or {}).get("openid_relying_party") or {}
        rep.expect("preflight", "Raidiam hosts the agent's Entity Configuration",
                   ec.get("iss") == a.agent and AUTHORITY in (ec.get("authority_hints") or []),
                   f"iss {ec.get('iss')}, authority_hints {ec.get('authority_hints')}, client_registration_types "
                   f"{rp.get('client_registration_types')}")
        keys = json.loads(get(rp["jwks_uri"], "application/json")).get("keys", []) if rp.get("jwks_uri") else (rp.get("jwks") or {}).get("keys", [])
        statement = raidiam_fetch(a.agent)
        rep.expect("preflight", "Raidiam vouches for the agent and publishes its bridge key",
                   statement.get("sub") == a.agent and any(k.get("x5c") for k in keys),
                   f"statement from {statement['iss'].rsplit('/', 1)[-1]}, exp {time.ctime(statement['exp'])}; "
                   f"{sum(bool(k.get('x5c')) for k in keys)} certified key(s) at {rp.get('jwks_uri', 'jwks')}")
        types = (statement.get("metadata_policy", {}).get("openid_relying_party", {})
                 .get("authorization_details_types", {}).get("value") or [])
        rep.add("preflight", "Raidiam grants the agent capabilities", "pass" if types else "fail",
                f"{types}" if types else "none - grant the agent a role carrying them (e.g. cba.accounts.reader)")
    except Exception as e:
        rep.expect("preflight", "Raidiam hosts and vouches for the agent", False, str(e))

    for name in ("accounts-agent", "payments-agent"):
        sub_agent = f"{a.origin}/agent/{name}"
        try:
            out = in_network(
                "import requests,os,base64,json;t=requests.get('" + sub_agent + "/.well-known/openid-federation',"
                "verify=os.environ['PF_CA_FILE']).text;p=t.split('.')[1];p+='='*(-len(p)%4);"
                "print(json.loads(base64.urlsafe_b64decode(p))['iss'])")
            rep.expect("preflight", f"the {name} serves its own Entity Configuration", out == sub_agent, out)
        except Exception as e:
            rep.expect("preflight", f"the {name} serves its own Entity Configuration", False, str(e))
    return not rep.failed or all(r["check"] == "Raidiam grants the agent capabilities" for r in rep.failed)


def spire_entry(rep: Report, a) -> bool:
    rep.stage("spire")
    server = ["docker", "exec", a.spire_server, "/opt/spire/bin/spire-server"]
    shown = sh(*server, "entry", "show", "-spiffeID", a.spiffe_id)
    if f"docker:label:app:{a.label}" in shown.stdout:
        rep.add("spire", f"entry {a.spiffe_id} <- docker:label:app:{a.label}", "pass", "exists")
        return True
    created = sh(*server, "entry", "create", "-spiffeID", a.spiffe_id, "-parentID", a.spire_parent,
                 "-selector", f"docker:label:app:{a.label}")
    ok = created.returncode == 0
    rep.expect("spire", f"entry {a.spiffe_id} <- docker:label:app:{a.label}", ok,
               "created" if ok else created.stderr.strip()[-200:])
    if ok:
        a.created.append(("spire", a.spiffe_id))
        time.sleep(10)  # the agent learns of a new entry on its next sync
    return ok


def run_agent(a, job: str, label: str) -> dict:
    out = compose("run", "--rm", "-l", f"app={label}", "agent", job,
                  env={"ATTESTED_CLIENT_ID": a.agent, "RAIDIAM_RESOURCE_ID": a.resource})
    line = next((l for l in reversed(out.stdout.splitlines()) if l.startswith("AGENT_RESULT ")), None)
    if not line:
        tail = (out.stdout + out.stderr).strip().splitlines()[-5:]
        return {"outcome": "error", "reason": "no AGENT_RESULT line: " + " | ".join(tail), "steps": {}}
    return json.loads(line[len("AGENT_RESULT "):])


def run(rep: Report, a) -> dict:
    rep.stage("run", f"{a.job} as {a.agent}")
    r = run_agent(a, a.job, a.label)
    s = r.get("steps", {})
    rep.expect("run", "the run completed", r.get("outcome") == "ok",
               r.get("reason") or "" if r.get("outcome") != "ok" else "")
    att = s.get("attest", {})
    rep.expect("run", "attested by PingFederate's attester", att.get("iss") == a.issuer,
               f"iss {att.get('iss')}, signing key {att.get('kid')}")
    rep.expect("run", "attested as this agent", att.get("sub") == a.agent, f"sub {att.get('sub')}")
    rep.expect("run", "SPIRE identified the container", att.get("spiffe_id") == a.spiffe_id, f"{att.get('spiffe_id')}")
    env = s.get("envelope", {})
    rep.expect("run", f"{r.get('capability')} is in the envelope",
               r.get("capability") in (env.get("authorization_details_types") or []),
               f"{env.get('authorization_details_types')}, chain of {env.get('chain_length')}")
    disc = s.get("discover", {})
    rep.expect("run", "found the resource through the federation", disc.get("resource") == a.resource,
               f"{disc.get('chosen')}" if disc else "not reached")
    tok = s.get("token", {})
    rep.expect("run", "token for this agent, for the resource",
               tok.get("client_id") == a.agent and tok.get("aud") == a.resource,
               f"client_id {tok.get('client_id')}, aud {tok.get('aud')}" if tok else "not reached")
    rep.expect("run", "the token is bound to this instance's key (cnf.jkt)",
               bool(tok.get("cnf_jkt")) and tok.get("cnf_jkt") == tok.get("instance_jkt"),
               f"cnf.jkt {tok.get('cnf_jkt')}, instance key {tok.get('instance_jkt')}" if tok else "not reached")
    call = s.get("call", {})
    rep.expect("run", "the resource allowed the call", call.get("status") == 200,
               f"{call.get('tool')}: {call.get('status')}" if call else "not reached")
    return r


def attesters(rep: Report, a, result: dict):
    """Why PingFederate's token endpoint trusted the attestation and the agent: PingFederate's own attester is an OpenID
    Federation entity like any other - its key in PingFederate's Entity Configuration, PingFederate in Raidiam's
    federation - the agent's SPIFFE binding is Raidiam's word, read from there, nothing is trusted statically, and
    PingFederate registered the agent from Raidiam on its verified attestation."""
    rep.stage("attesters")
    att = (result or {}).get("steps", {}).get("attest", {})
    try:
        out = in_network(
            "import requests,os,base64,json;t=requests.get('https://host.docker.internal:9031/.well-known/openid-federation',"
            "verify=os.environ['PF_CA_FILE']).text;p=t.split('.')[1];p+='='*(-len(p)%4);c=json.loads(base64.urlsafe_b64decode(p));"
            "print(json.dumps([k.get('kid') for k in c.get('metadata',{}).get('oauth_client_attester',{}).get('jwks',{}).get('keys',[])]))")
        kids = json.loads(out)
        rep.expect("attesters", "PingFederate publishes its attester key in its Entity Configuration (oauth_client_attester)",
                   att.get("kid") in kids, f"kids {kids}; the run's attestation was signed with {att.get('kid')}")
    except Exception as e:
        rep.expect("attesters", "PingFederate publishes its attester key in its Entity Configuration (oauth_client_attester)",
                   False, str(e))
    try:
        statement = raidiam_fetch(a.issuer)
        rep.expect("attesters", "Raidiam vouches for PingFederate, so its attester's key resolves through the federation",
                   statement.get("sub") == a.issuer,
                   f"subordinate statement from {statement['iss'].rsplit('/', 1)[-1]}, exp {time.ctime(statement['exp'])}")
    except Exception as e:
        rep.expect("attesters", "Raidiam vouches for PingFederate, so its attester's key resolves through the federation",
                   False, str(e))
    try:
        rp = raidiam_fetch(a.agent).get("metadata_policy", {}).get("openid_relying_party", {})
        value = lambda m: (rp.get(m) or {}).get("value")
        attesters_named = value("client_attesters") or []
        rep.expect("attesters", "Raidiam binds the agent's SPIFFE ID for PingFederate's attester",
                   value("spiffe_id") == a.spiffe_id and a.issuer in attesters_named,
                   f"spiffe_id {value('spiffe_id')}, bundle {value('spiffe_bundle_endpoint')}, attesters {attesters_named}")
    except Exception as e:
        rep.expect("attesters", "Raidiam binds the agent's SPIFFE ID for PingFederate's attester", False, str(e))
    try:
        out = in_network(
            "import requests,os,json;d=requests.get('https://host.docker.internal:9031/.well-known/client-attester',"
            "verify=os.environ['PF_CA_FILE']).json();print(json.dumps(d.get('resolver_plugins_active')))")
        active = json.loads(out) or []
        rep.expect("attesters", "PingFederate's attester reads the bindings from Raidiam (openid-federation-authority)",
                   bool(active) and active[0] == "openid-federation-authority" and "openid-federation" not in active,
                   f"resolver plugins, in order: {active}")
    except Exception as e:
        rep.expect("attesters", "PingFederate's attester reads the bindings from Raidiam (openid-federation-authority)",
                   False, str(e))
    inspect = sh("docker", "inspect", a.pf_container, "--format",
                 "{{range .Config.Env}}{{println .}}{{end}}{{range .Mounts}}{{println .Destination}}{{end}}")
    rep.expect("attesters", "PingFederate trusts no static attesters (no oidf.mock.attesters)",
               inspect.returncode == 0 and "mock" not in inspect.stdout.lower(),
               "every attester is trusted through its federation chain" if inspect.returncode == 0
               else inspect.stderr.strip()[-120:])
    registered = sh("docker", "exec", a.pf_container, "sh", "-c",
                    f"grep -h 'registered {a.agent} from the federation' /opt/out/instance/log/server.log | tail -1")
    line = registered.stdout.strip()
    rep.expect("attesters", "PingFederate registered the agent from Raidiam on its verified attestation",
               bool(line), line[:23] + " " + line[line.find("attest_jwt_client_auth"):][:120] if line
               else "no registration in PingFederate's log")


def negatives(rep: Report, a):
    rep.stage("negatives")
    r = run_agent(a, a.job, a.other_label)
    att = r.get("steps", {}).get("attest", {})
    rep.expect("negatives", f"a container labelled app={a.other_label} is refused attestation as the agent",
               r.get("outcome") == "refused" and r.get("refused_at") == "attest"
               and (att.get("status") == 403 or att.get("error") == "not_this_client"),
               f"{att.get('spiffe_id')}: {r.get('reason', '')[:110]}")

    r = run_agent(a, "loan-balance", a.label)
    rep.expect("negatives", "a job outside the envelope is refused before a request",
               r.get("outcome") == "refused" and r.get("refused_at") == "envelope", (r.get("reason") or "")[:110])

    try:
        out = in_network("import requests,os;print(requests.post('" + a.resource + "/mcp/v1',json={},"
                         "verify=os.environ['PF_CA_FILE']).status_code)")  # the gateway answers now
        rep.expect("negatives", "the resource refuses a call with no token", out == "401", out)
    except Exception as e:
        rep.expect("negatives", "the resource refuses a call with no token", False, str(e))
    rep.add("negatives", "a suspended agent is refused", "skip", "needs the marketplace on the live control plane")


def gateway(rep: Report, a):
    """The gateway in front of the resource, and the PDP behind it, probed with the agent's own token (probe.py)."""
    rep.stage("gateway")
    out = compose("run", "--rm", "-l", f"app={a.label}", "--entrypoint", "python", "agent", "probe.py",
                  env={"ATTESTED_CLIENT_ID": a.agent, "RAIDIAM_RESOURCE_ID": a.resource})
    probes = {}
    for line in out.stdout.splitlines():
        if line.startswith("PROBE "):
            p = json.loads(line[len("PROBE "):])
            probes[p["name"]] = p
    if not probes:
        tail = (out.stdout + out.stderr).strip().splitlines()[-3:]
        rep.expect("gateway", "probes ran", False, " | ".join(tail))
        return
    f = probes.get("forged_token", {})
    rep.expect("gateway", "a token not signed by PingFederate is refused at the gateway", f.get("http") == 401,
               f"HTTP {f.get('http')}")
    ok = probes.get("pdp_permit", {})
    rep.expect("gateway", "the PDP permits get_balance and the call reaches the resource",
               ok.get("http") == 200 and not ok.get("jsonrpc_error") and bool(ok.get("result")),
               f"HTTP {ok.get('http')}, error {ok.get('jsonrpc_error')}")
    b = probes.get("dpop_binding", {})
    rep.expect("gateway", "DPoP: the token is bound to the instance's key", bool(b.get("cnf_jkt")) and
               b.get("cnf_jkt") == b.get("instance_jkt"), f"cnf.jkt {b.get('cnf_jkt')}")
    for name, check in [("dpop_bound_token_as_bearer", "DPoP: the bound token presented as Bearer is refused"),
                        ("dpop_proof_from_another_key", "DPoP: a proof from another key (a stolen token) is refused"),
                        ("dpop_proof_replayed", "DPoP: a replayed proof is refused")]:
        p = probes.get(name, {})
        rep.expect("gateway", check, p.get("http") == 401, f"HTTP {p.get('http')}")
    first = probes.get("dpop_proof_first_use", {})
    rep.expect("gateway", "DPoP: the same proof's first use is accepted", first.get("http") == 200,
               f"HTTP {first.get('http')}")
    deny = probes.get("pdp_deny_large_payment", {})
    err = deny.get("jsonrpc_error") if isinstance(deny.get("jsonrpc_error"), dict) else {"message": str(deny.get("jsonrpc_error"))}
    rep.expect("gateway", "the PDP denies a 5000 payment (COAZ -32401) before it reaches the resource",
               err.get("code") == -32401, f"HTTP {deny.get('http')}, {err.get('code')}: {(err.get('message') or '')[:80]}")


def signals(rep: Report, a):
    """Shared Signals: PingFederate's transmitter, the PEP's stream (probe.py PROBE=ssf). The probe raises the events
    as the transmitter's operator (conformance-ssf-emitter), whose secret comes from ../secrets.env."""
    rep.stage("signals")
    secret = next((l.split("=", 1)[1].strip() for l in open(os.path.join(DEMO, "secrets.env"))
                   if l.startswith("TF_VAR_ssf_emitter_client_secret=")), "")
    if not secret:
        rep.add("signals", "Shared Signals", "skip", "no TF_VAR_ssf_emitter_client_secret in secrets.env")
        return
    out = subprocess.run(["docker", "compose", "run", "--rm", "-l", f"app={a.label}", "-e", "PROBE=ssf", "-e", "EMIT_SECRET",
                          "--entrypoint", "python", "agent", "probe.py"], cwd=HERE, capture_output=True, text=True,
                         encoding="utf-8", errors="replace", timeout=600,
                         env={**ENV, "EMIT_SECRET": secret, "ATTESTED_CLIENT_ID": a.agent,
                              "RAIDIAM_RESOURCE_ID": a.resource})
    line = next((l for l in out.stdout.splitlines() if l.startswith("PROBE ")), None)
    if not line:
        rep.expect("signals", "the probe ran", False, " | ".join((out.stdout + out.stderr).strip().splitlines()[-3:]))
        return
    p = json.loads(line[len("PROBE "):])
    fast = lambda s: s is not None and s <= 15  # a poll every 2 s; the margin is for a loaded host
    rep.expect("signals", "the agent's call works before any signal", p.get("before") == 200, f"HTTP {p.get('before')}")
    rep.expect("signals", "session-revoked: its existing token is refused at the gateway",
               p.get("session_revoked_streams", 0) >= 1 and fast(p.get("old_token_refused_after_s")),
               f"{p.get('session_revoked_streams')} stream(s), refused after {p.get('old_token_refused_after_s')} s")
    rep.expect("signals", "session-revoked: a token issued after it still works",
               p.get("new_token_after_session_revoked") == 200, f"HTTP {p.get('new_token_after_session_revoked')}")
    rep.expect("signals", "account-disabled: even a fresh token is refused",
               fast(p.get("disabled_refused_after_s")) and p.get("fresh_token_while_disabled") == 401,
               f"refused after {p.get('disabled_refused_after_s')} s, fresh token HTTP {p.get('fresh_token_while_disabled')}")
    rep.expect("signals", "account-enabled: the agent works again", fast(p.get("enabled_ok_after_s")),
               f"after {p.get('enabled_ok_after_s')} s")
    rep.expect("signals", "one instance disabled (opaque subject = its cnf.jkt) is refused",
               p.get("instances_differ") and fast(p.get("instance_refused_after_s")),
               f"after {p.get('instance_refused_after_s')} s")
    rep.expect("signals", "... while another instance of the same agent carries on",
               p.get("other_instance_while_one_disabled") == 200, f"HTTP {p.get('other_instance_while_one_disabled')}")
    rep.expect("signals", "... and the instance works again once re-enabled", fast(p.get("instance_ok_after_s")),
               f"after {p.get('instance_ok_after_s')} s")


def a2a(rep: Report, a):
    """Agents calling agents: the Principal's pay-invoice job - the Accounts and Payments agents found through the
    federation, each acting for the Principal by token exchange - then an over-limit invoice, then the Payments agent
    disabled by a signal while the Accounts agent carries on."""
    rep.stage("a2a", "agents calling agents")
    accounts_agent, payments_agent = f"{a.origin}/agent/accounts-agent", f"{a.origin}/agent/payments-agent"
    r = run_agent(a, "pay-invoice", a.label)
    s = r.get("steps", {})
    rep.expect("a2a", "pay-invoice completed", r.get("outcome") == "ok", r.get("reason") or "")
    d = s.get("discover", {})
    rep.expect("a2a", "both agents found through the federation by capability",
               d.get("accounts_agent") == accounts_agent and d.get("payments_agent") == payments_agent,
               f"{d.get('accounts_agent')}, {d.get('payments_agent')}")
    for step, callee, resource in (("accounts", accounts_agent, a.resource), ("payments", payments_agent, a.payments)):
        dl = (s.get(step) or {}).get("delegation") or {}
        act = dl.get("act")
        if isinstance(act, str):
            try:
                act = json.loads(act)
            except ValueError:
                pass
        rep.expect("a2a", f"{step}: the agent acted for the Principal (sub), as itself (client_id, act)",
                   dl.get("sub") == a.agent and dl.get("client_id") == callee and (act or {}).get("sub") == callee,
                   f"sub {dl.get('sub')}, act {dl.get('act')}" if dl else "not reached")
        rep.expect("a2a", f"{step}: its token is for its resource and bound to its own instance key",
                   dl.get("aud") == resource and bool(dl.get("cnf_jkt")) and dl.get("cnf_jkt") == dl.get("instance_jkt"),
                   f"aud {dl.get('aud')}, cnf.jkt {dl.get('cnf_jkt')}" if dl else "not reached")
        dec = (s.get(step) or {}).get("decision") or {}
        rep.expect("a2a", f"{step}: the resource checked both agents (decision names the Principal)",
                   dec.get("on_behalf_of") == a.agent and dec.get("client_id") == callee, f"{dec}"[:90])

    over = subprocess.run(["docker", "compose", "run", "--rm", "-l", f"app={a.label}", "-e", "INVOICE_AMOUNT=1500",
                           "agent", "pay-invoice"], cwd=HERE, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=600,
                          env={**ENV, "ATTESTED_CLIENT_ID": a.agent})
    line = next((l for l in reversed(over.stdout.splitlines()) if l.startswith("AGENT_RESULT ")), "AGENT_RESULT {}")
    o = json.loads(line[len("AGENT_RESULT "):])
    rep.expect("a2a", "an invoice over the policy's limit is refused at the Payments agent (PingAuthorize)",
               o.get("outcome") == "refused" and o.get("refused_at") == "payments", (o.get("reason") or "")[:90])

    secret = next((l.split("=", 1)[1].strip() for l in open(os.path.join(DEMO, "secrets.env"))
                   if l.startswith("TF_VAR_ssf_emitter_client_secret=")), "")
    if not secret:
        rep.add("a2a", "a disabled sub-agent", "skip", "no TF_VAR_ssf_emitter_client_secret in secrets.env")
        return

    def emit(event):
        out = subprocess.run(["docker", "compose", "run", "--rm", "-l", f"app={a.label}", "-e", "PROBE=emit",
                              "-e", "EMIT_SECRET", "-e", "EMIT_EVENT", "-e", "EMIT_SUB", "--entrypoint", "python",
                              "agent", "probe.py"], cwd=HERE, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=300,
                             env={**ENV, "EMIT_SECRET": secret, "EMIT_SUB": payments_agent, "ATTESTED_CLIENT_ID": a.agent,
                                  "EMIT_EVENT": "https://schemas.openid.net/secevent/risc/event-type/" + event})
        return '"streams": 1' in out.stdout or '"streams": 2' in out.stdout

    try:
        emitted = emit("account-disabled")
        time.sleep(4)  # a poll or two
        r = run_agent(a, "pay-invoice", a.label)
        steps = r.get("steps", {})
        rep.expect("a2a", "Payments agent disabled (signal): the payment is refused ...",
                   emitted and r.get("refused_at") == "payments", (r.get("reason") or "")[:90])
        rep.expect("a2a", "... while the Accounts agent still answers for the Principal",
                   bool((steps.get("accounts") or {}).get("delegation")), "")
    finally:
        emit("account-enabled")
        time.sleep(4)


def decisions_logged(rep: Report, a):
    """TC-18: every decision the gateway's PEP made during the run is in its log, with principal and reason."""
    rep.stage("logging", "trust decisions logged")
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a.started - 5))
    lines = compose("logs", "--no-log-prefix", "--since", since, "coaz-pep").stdout.splitlines()
    permits = [l for l in lines if " PERMIT " in l]
    denies = [l for l in lines if " DENY " in l]
    refused = [l for l in lines if "refused" in l]
    signals = [l for l in lines if "ssf: " in l]
    # Each sample from its message on: past the timestamp, at the PEP's label or the receiver's "ssf:".
    sample = [l[min(i for i in (l.find("["), l.find("ssf: ")) if i >= 0):][:220]
              for l in (permits[:1] + denies[:1] + refused[:1] + signals[:1])]
    rep.expect("logging", "decisions are logged at the gateway with principal and reason",
               bool(permits) and bool(denies) and bool(refused),
               f"{len(permits)} permits, {len(denies)} PDP denials, {len(refused)} refusals (token, DPoP, signal), "
               f"{len(signals)} signals received - in coaz-pep's log since the run began", sample)


def cleanup(a):
    for kind, what in reversed(a.created):
        if kind == "spire":
            entries = sh("docker", "exec", a.spire_server, "/opt/spire/bin/spire-server", "entry", "show",
                         "-spiffeID", what).stdout
            for entry_id in re.findall(r"Entry ID\s*:\s*(\S+)", entries):
                sh("docker", "exec", a.spire_server, "/opt/spire/bin/spire-server", "entry", "delete", "-entryID", entry_id)
            print(f"  removed SPIRE entry {what}", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--agent", help="the Principal's entity id (default: the newest version the marketplace deployed)")
    p.add_argument("--marketplace", default="http://localhost:3000")
    p.add_argument("--origin", default="https://host.docker.internal:8443", help="where the sub-agents are served")
    p.add_argument("--issuer", default="https://bottle-platonic-parted.ngrok-free.dev", help="PingFederate's issuer")
    p.add_argument("--pf-container", default="pf-agentic-identity")
    p.add_argument("--resource", default="https://host.docker.internal:8446")
    p.add_argument("--payments", default="https://host.docker.internal:8447", help="rs-payments' identifier")
    p.add_argument("--label", help="the docker label app=<label> the agent runs under (its deploy's workload)")
    p.add_argument("--spiffe-id", help="default spiffe://example.org/<label>")
    p.add_argument("--other-label", default="my-workload", help="another workload's label, for the negative test")
    p.add_argument("--job", default="list-accounts")
    p.add_argument("--spire-server", default="spire-spire-server-1")
    p.add_argument("--spire-parent", default="spiffe://example.org/spire/agent/x509pop/agent1")
    p.add_argument("--skip-negatives", action="store_true")
    p.add_argument("--keep", action="store_true", help="leave what the harness created")
    p.add_argument("--report", default=os.path.join(HERE, "reports", "latest.json"),
                   help="write the report as JSON here (default reports/latest.json, which the marketplace's "
                        "Objectives page reads)")
    p.add_argument("--brief", action="store_true", help="one line per check, no objectives, explanations or evidence")
    a = p.parse_args()
    a.created = []
    a.origin = a.origin.rstrip("/")
    if not a.agent:
        d = deployed_principal(a.marketplace)
        a.agent, a.label, a.spiffe_id = d["entityId"], a.label or d["slot"], a.spiffe_id or d["spiffeId"]
    if not a.label:
        raise SystemExit("harness: --agent needs --label, the workload it runs as")
    a.spiffe_id = a.spiffe_id or f"spiffe://example.org/{a.label}"

    rep = Report(verbose=not a.brief)
    print(f"harness: {a.agent} ({a.spiffe_id}), job {a.job}, attested by PingFederate's attester", flush=True)
    started = a.started = time.time()
    result = None
    try:
        if preflight(rep, a) and spire_entry(rep, a):
            result = run(rep, a)
            attesters(rep, a, result)
            if not a.skip_negatives:
                negatives(rep, a)
                gateway(rep, a)
                signals(rep, a)
                a2a(rep, a)
                decisions_logged(rep, a)
    finally:
        if not a.keep:
            cleanup(a)
    if not a.brief:
        rep.print_coverage()
    passed = sum(r["status"] == "pass" for r in rep.rows)
    print(f"\n{passed} passed, {len(rep.failed)} failed, {sum(r['status'] == 'skip' for r in rep.rows)} skipped "
          f"in {time.time() - started:.0f} s", flush=True)
    if a.report:
        os.makedirs(os.path.dirname(os.path.abspath(a.report)), exist_ok=True)
        with open(a.report, "w") as f:
            json.dump({"agent": a.agent, "job": a.job, "attester": "pingfederate", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "checks": rep.rows, "objectives": rep.coverage(), "agent_result": result}, f, indent=2)
    sys.exit(1 if rep.failed else 0)


if __name__ == "__main__":
    main()
