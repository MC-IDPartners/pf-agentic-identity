"""End-to-end harness for the agent-r flow (agent.py): checks that an agent is ready, runs it, and checks what it did.

    python harness.py                      # the rig's agent, https://host.docker.internal:8443/agent/spire-client
    python harness.py --keep               # leave whatever it created (the SPIRE entry) in place
    python harness.py --report out.json    # also write the report as JSON

Stages, each a pass, a fail or a skip in the report:

  preflight    PingFederate answers; the provider (entity-host), SPIRE's OIDC provider and the resource are up;
               Raidiam vouches for the agent and its key; the provider serves the agent's Entity Configuration;
               the agent's registration at PingFederate is current (else entity-host is restarted to renew it)
  spire        a SPIRE entry for the agent's SPIFFE ID, selecting containers by the label the agent runs under;
               created if missing (and removed afterwards, unless --keep)
  run          docker compose run agent <job>, under that label; its AGENT_RESULT line is what gets checked:
               attested by the provider, for this agent and SPIFFE ID; the capability in its envelope; the
               resource chosen; a token for this agent with aud = the resource; the call allowed
  negatives    another workload's container is refused at /attest; a job outside the envelope is refused before
               a request is built; the resource refuses a call with no token

Standard library only; it shells out to docker and docker compose, and runs in-network checks inside the provider's
container. The provisioning stages - an agent registered through the marketplace, its keys certified, the provider
hosting it - come later (see ../raidiam/README.md, "The test harness").
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from urllib.parse import quote

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
    """Python run inside the provider's container, which reaches everything in the rig by its internal name and
    trusts the rig's CA (the host's TLS interception can get in the way of the host's own calls)."""
    out = compose("exec", "-T", "entity-host", "python", "-c", code, timeout=120)
    if out.returncode:
        raise RuntimeError(out.stderr.strip().splitlines()[-1] if out.stderr.strip() else f"exit {out.returncode}")
    return out.stdout.strip()


def claims(jwt: str) -> dict:
    payload = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def raidiam_fetch(sub: str):
    with urllib.request.urlopen(f"{AUTHORITY}/fetch?sub={quote(sub, safe='')}", timeout=20) as r:
        return claims(r.read().decode())


class Report:
    def __init__(self):
        self.rows = []

    def add(self, stage: str, check: str, status: str, detail: str = ""):
        self.rows.append({"stage": stage, "check": check, "status": status, "detail": detail})
        mark = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}[status]
        print(f"  {mark:4}  {stage:10} {check}" + (f"  - {detail}" if detail else ""), flush=True)

    def expect(self, stage: str, check: str, ok: bool, detail: str = ""):
        self.add(stage, check, "pass" if ok else "fail", detail)
        return ok

    @property
    def failed(self):
        return [r for r in self.rows if r["status"] == "fail"]


# ── stages ──────────────────────────────────────────────────────────────────────────────────────────

def preflight(rep: Report, a) -> bool:
    print("\npreflight", flush=True)
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
    for svc in ("entity-host", "spire-oidc", "rs-accounts"):
        rep.expect("preflight", f"{svc} is running", svc in running,
                   "" if svc in running else f"docker compose up -d {svc}")
    if "entity-host" not in running:
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
        statement = raidiam_fetch(a.agent)
        with open(os.path.join(DEMO, "keys/raidiam/attested-client/entity.public.jwks.json")) as f:
            mine = json.load(f)["keys"][0]["n"]
        vouched = any(k.get("n") == mine for k in statement.get("jwks", {}).get("keys", []))
        rep.expect("preflight", "Raidiam vouches for the agent's entity key", vouched,
                   f"statement from {statement['iss'].rsplit('/', 1)[-1]}, exp {time.ctime(statement['exp'])}")
        types = (statement.get("metadata_policy", {}).get("openid_relying_party", {})
                 .get("authorization_details_types", {}).get("value") or [])
        rep.add("preflight", "Raidiam grants the agent capabilities", "pass" if types else "fail",
                f"{types}" if types else "none - grant the agent a role carrying them (e.g. cba.accounts.reader)")
    except Exception as e:
        rep.expect("preflight", "Raidiam vouches for the agent", False, str(e))

    try:
        out = in_network(
            "import requests,os,base64,json;t=requests.get('" + a.agent + "/.well-known/openid-federation',"
            "verify=os.environ['PF_CA_FILE']).text;p=t.split('.')[1];p+='='*(-len(p)%4);"
            "print(json.loads(base64.urlsafe_b64decode(p))['iss'])")
        rep.expect("preflight", "the provider serves the agent's Entity Configuration", out == a.agent, out)
    except Exception as e:
        rep.expect("preflight", "the provider serves the agent's Entity Configuration", False, str(e))

    rep.expect("preflight", "the agent is registered at PingFederate", registration_current(a), "")
    return not rep.failed or all(r["check"] == "Raidiam grants the agent capabilities" for r in rep.failed)


def registration_current(a) -> bool:
    """The provider's last registration of the agent, still in force; else entity-host is restarted to renew it
    (a restart of PingFederate drops every explicit registration)."""
    def last_expiry():
        logs = compose("logs", "--no-log-prefix", "entity-host").stdout
        hits = re.findall(rf"registered {re.escape(a.agent)} at \S+ until (\d+)", logs)
        return int(hits[-1]) if hits else 0

    if last_expiry() > time.time() + 60:
        return True
    compose("restart", "entity-host")
    for _ in range(12):
        time.sleep(5)
        if last_expiry() > time.time() + 60:
            return True
    return False


def spire_entry(rep: Report, a) -> bool:
    print("\nspire", flush=True)
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
                  env={"ATTESTED_CLIENT_ID": a.agent, "RAIDIAM_PROVIDER_ID": a.provider, "RAIDIAM_RESOURCE_ID": a.resource})
    line = next((l for l in reversed(out.stdout.splitlines()) if l.startswith("AGENT_RESULT ")), None)
    if not line:
        tail = (out.stdout + out.stderr).strip().splitlines()[-5:]
        return {"outcome": "error", "reason": "no AGENT_RESULT line: " + " | ".join(tail), "steps": {}}
    return json.loads(line[len("AGENT_RESULT "):])


def run(rep: Report, a) -> dict:
    print(f"\nrun: {a.job} as {a.agent}", flush=True)
    r = run_agent(a, a.job, a.label)
    s = r.get("steps", {})
    rep.expect("run", "the run completed", r.get("outcome") == "ok",
               r.get("reason") or "" if r.get("outcome") != "ok" else "")
    att = s.get("attest", {})
    rep.expect("run", "attested by the provider", att.get("iss") == a.provider, f"iss {att.get('iss')}")
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
    call = s.get("call", {})
    rep.expect("run", "the resource allowed the call", call.get("status") == 200,
               f"{call.get('tool')}: {call.get('status')}" if call else "not reached")
    return r


def negatives(rep: Report, a):
    print("\nnegatives", flush=True)
    r = run_agent(a, a.job, a.other_label)
    att = r.get("steps", {}).get("attest", {})
    rep.expect("negatives", f"a container labelled app={a.other_label} is refused at /attest",
               r.get("outcome") == "refused" and r.get("refused_at") == "attest" and att.get("status") == 403,
               f"{att.get('spiffe_id')}: {r.get('reason', '')[:90]}")

    r = run_agent(a, "pay-supplier", a.label)
    rep.expect("negatives", "a job outside the envelope is refused before a request",
               r.get("outcome") == "refused" and r.get("refused_at") == "envelope", (r.get("reason") or "")[:110])

    try:
        out = in_network("import requests,os;print(requests.post('" + a.resource + "/mcp/v1',json={},"
                         "verify=os.environ['PF_CA_FILE']).status_code)")
        rep.expect("negatives", "the resource refuses a call with no token", out == "401", out)
    except Exception as e:
        rep.expect("negatives", "the resource refuses a call with no token", False, str(e))
    rep.add("negatives", "a suspended agent is refused", "skip", "needs the marketplace on the live control plane")


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
    p.add_argument("--agent", default="https://host.docker.internal:8443/agent/spire-client")
    p.add_argument("--provider", default="https://host.docker.internal:8443")
    p.add_argument("--resource", default="https://host.docker.internal:8446")
    p.add_argument("--label", default="spire-client", help="the docker label app=<label> the agent runs under")
    p.add_argument("--spiffe-id", default="spiffe://example.org/spire-client")
    p.add_argument("--other-label", default="my-workload", help="another workload's label, for the negative test")
    p.add_argument("--job", default="list-accounts")
    p.add_argument("--spire-server", default="spire-spire-server-1")
    p.add_argument("--spire-parent", default="spiffe://example.org/spire/agent/x509pop/agent1")
    p.add_argument("--skip-negatives", action="store_true")
    p.add_argument("--keep", action="store_true", help="leave what the harness created")
    p.add_argument("--report", help="write the report as JSON here")
    a = p.parse_args()
    a.created = []

    rep = Report()
    print(f"harness: {a.agent} ({a.spiffe_id}), job {a.job}", flush=True)
    started = time.time()
    result = None
    try:
        if preflight(rep, a) and spire_entry(rep, a):
            result = run(rep, a)
            if not a.skip_negatives:
                negatives(rep, a)
    finally:
        if not a.keep:
            cleanup(a)
    passed = sum(r["status"] == "pass" for r in rep.rows)
    print(f"\n{passed} passed, {len(rep.failed)} failed, {sum(r['status'] == 'skip' for r in rep.rows)} skipped "
          f"in {time.time() - started:.0f} s", flush=True)
    if a.report:
        with open(a.report, "w") as f:
            json.dump({"agent": a.agent, "job": a.job, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                       "checks": rep.rows, "agent_result": result}, f, indent=2)
    sys.exit(1 if rep.failed else 0)


if __name__ == "__main__":
    main()
