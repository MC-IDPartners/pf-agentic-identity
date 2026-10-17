# The gateway and the PDP in front of the rig's MCP resource

The rig's resource (`spire-workload`'s `rs-accounts`) sits behind a gateway, a policy enforcement point and
PingAuthorize, vendored from `idp-agentic-demo` (commit `0a5f85f`) and adapted:

```
agent ──Bearer──▶ gateway (agentgateway, https://host.docker.internal:8446 - the resource's identifier)
                     │  /.well-known/*  ──────────────────────────────────────────────▶ rs-accounts (passed through)
                     │  /mcp/*  ext_authz
                     ▼
                  coaz-pep ── 1. the token: signature (PingFederate's JWKS), typ at+jwt, iss, aud, exp
                     │        2. tools/call: the tool's x-coaz-mapping (from tools/list) -> an AuthZEN request
                     ▼
                  PingAuthorize 11.1 (AuthZEN servlet -> embedded PDP, banking deployment package)
                     │  permit
                     ▼
                  rs-accounts ── its own checks still: the token, the agent's chain to Raidiam, its capability
```

| Directory | What | Changed from upstream |
|---|---|---|
| `agentgateway/` | solo.io agentgateway v1.3.1, re-plated on debian-slim for its entrypoint | Listens at the resource's identifier with the rig's certificate; routes `/.well-known/*` through and `/mcp` via ext_authz; CA roots added. **Not** its `jwtAuth`: once that verifies a token it removes the `Authorization` header, so neither the PEP nor the resource would see it |
| `coaz-pep/` | The PEP: Envoy ext_authz gRPC, COAZ (OpenID AuthZEN MCP profile) | `verify.go`: verifies access tokens (RS256/PS256/ES256 against a JWKS, `typ`, `iss`, `aud`, `exp`/`nbf`) - upstream only decoded them. `omit_token_aud` route option |
| `pingauthorize/` | PingAuthorize 11.1, the AuthZEN servlet extension, the banking deployment package | Rig-only dev keys for the servlet; no Railway |

The resource declares, per tool, how a call maps to an AuthZEN request (`x-coaz-mapping` in `rs_accounts.py`):
`list_accounts`, `get_balance` and `pay_supplier` (as `make_payment`, with the amount).

## Running it

From `spire-workload/`, with the rest of the rig up (`../raidiam/README.md`, "The agent-r flow"):

```bash
docker compose up -d rs-accounts pingauthorize coaz-pep gateway   # PingAuthorize takes a minute on first start
python harness.py                                                  # 26 checks, the gateway's among them
```

PingAuthorize fetches a DevOps evaluation licence on start from `~/.pingidentity/config`
(`PING_IDENTITY_DEVOPS_USER`/`KEY`), as PingFederate does. It is not published on the host.

Decisions are in coaz-pep's log (`docker compose logs -f coaz-pep`): `COAZ PERMIT tools/call get_balance ...`,
`COAZ DENY tools/call pay_supplier: Access denied`, `token refused: ...`.

## The policy, for now

PingAuthorize runs the upstream demo's **banking** package: it permits `list_accounts` and `get_balance`, denies a
payment over 2000, and needs step-up between 500 and 2000. It pins the audience to its own demo's
(`https://api.northwind.example/bank`), so the PEP - which has verified the audience itself - doesn't send it
(`omit_token_aud`). Its consent and proofing lookups call that demo's Railway services; the rig's flows don't reach
them.

Next: the rig's own policy, authored in the PingAuthorize PAP 11.1 (a deployment package is digest-sealed - it can only
come from the PAP), deciding on federation facts - the agent's capabilities and trust marks from Raidiam, its
attester, its SPIFFE ID - from a federation PIP.
