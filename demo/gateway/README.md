# The gateway and the PDP in front of the rig's MCP resource

The rig's resource (`spire-workload`'s `rs-accounts`) sits behind a gateway, a policy enforcement point and
PingAuthorize, vendored from `idp-agentic-demo` (commit `0a5f85f`) and adapted:

```
agent ──DPoP──▶ gateway (Kong, https://host.docker.internal:8446 - the resource's identifier)
                     │  /.well-known/*  ──────────────────────────────────────────────▶ rs-accounts (passed through)
                     │  /mcp*  plugin coaz-pep -> POST /v1/mcp/check
                     ▼
                  coaz-pep ── 1. the token: signature (PingFederate's JWKS), typ at+jwt, iss, aud, exp
                     │        2. the DPoP proof from the agent instance's key; Shared Signals revocations
                     │        3. tools/call: the tool's x-coaz-mapping (from tools/list) -> an AuthZEN request
                     ▼
                  PingAuthorize 11.1 (AuthZEN servlet -> embedded PDP, banking deployment package)
                     │  permit
                     ▼
                  rs-accounts ── its own checks still: the token, the agent's chain to Raidiam, its capability
```

| Directory | What | Changed from upstream |
|---|---|---|
| `kong/` | Kong OSS 3.7, DB-less | Listens at the resource's identifier with the rig's certificate; `/.well-known/*` through, `/mcp` via the plugin. The plugin (`coaz-pep`) is new: a thin delegate that sends **every** request to coaz-pep's HTTP check API and applies its verdict. The upstream `authzen-pdp` plugin made its own checks in Lua - tokens decoded but not verified, DPoP without the proof's signature - and delegated only `tools/call`; none of that is kept |
| `coaz-pep/` | The PEP: an HTTP check API (Kong) and Envoy ext_authz gRPC; COAZ (OpenID AuthZEN MCP profile) | `verify.go`: verifies access tokens (RS256/PS256/ES256 against a JWKS, `typ`, `iss`, `aud`, `exp`/`nbf`) - upstream only decoded them. `dpop.go`, `ssf.go` (below). `omit_token_aud` route option |
| `pingauthorize/` | PingAuthorize 11.1, the AuthZEN servlet extension, the banking deployment package | Rig-only dev keys for the servlet; no Railway |

The resource declares, per tool, how a call maps to an AuthZEN request (`x-coaz-mapping` in `rs_accounts.py`):
`list_accounts`, `get_balance` and `pay_supplier` (as `make_payment`, with the amount).

## Running it

From `spire-workload/`, with the rest of the rig up (`../raidiam/README.md`, "The agent-r flow"):

```bash
docker compose up -d rs-accounts pingauthorize coaz-pep gateway   # PingAuthorize takes a minute on first start
python harness.py                                                  # 40 checks: the gateway's, DPoP's and the signals' among them
```

PingAuthorize fetches a DevOps evaluation licence on start from `~/.pingidentity/config`
(`PING_IDENTITY_DEVOPS_USER`/`KEY`), as PingFederate does. It is not published on the host.

Kong replaced agentgateway, which the rig used first: agentgateway's own `jwtAuth` removes the `Authorization` header
once it has verified a token, so the PEP checked tokens instead, over ext_authz. Kong needs no such workaround - the
PEP's check API is the same pipeline - and any gateway that can call it can take Kong's place.

Decisions are in coaz-pep's log (`docker compose logs -f coaz-pep`): `COAZ PERMIT tools/call get_balance ...`,
`COAZ DENY tools/call pay_supplier: Access denied`, `token refused: ...`.

## Tokens bound to the agent instance (DPoP)

The token is bound to the key the provider attested - the agent instance's own, proven by its SPIRE SVID:

1. The agent asks for a token with `attest_jwt_client_auth` in **DPoP combined mode**: the provider's attestation
   (`cnf.jwk` = the instance key) and a DPoP proof signed by that key, instead of the attestation PoP. The module
   checks the proof's key is the attestation's `cnf` key; PingFederate issues `token_type: DPoP` with
   `cnf.jkt` = the instance key's thumbprint. No PingFederate setting is needed.
2. Every call carries `Authorization: DPoP <token>` and a fresh proof from the instance key (the agent's MCP client
   signs one per request).
3. The **gateway** enforces it - not the resource (`coaz-pep/cmd/coaz-pep/dpop.go`, route settings `require_dpop`,
   `dpop_htu_base` in `kong/kong.yml.template`): the proof's signature under its own `jwk` (public only), that key's thumbprint = `cnf.jkt`,
   `typ`, `alg`, `htm`, `htu` (the resource's URL as the client addressed it), `ath` = the token's hash, age within
   60 s, `jti` not replayed. A bound token presented as Bearer is refused on any route (RFC 9449 §7.1). The resource
   publishes `dpop_bound_access_tokens_required: true` and takes the token from either scheme.

The upstream check compared the thumbprint with `cnf.jkt` but never verified the proof's signature - anyone with a
stolen token could name the victim's key in a proof header and pass - nor `ath`, `htu`, age or replay.
`dpop_test.go` covers each.

## Shared Signals

coaz-pep is also a Shared Signals receiver (`coaz-pep/cmd/coaz-pep/ssf.go`): it polls a stream from PingFederate's
SSF transmitter (RFC 8936 poll, so nothing has to reach the PEP) as `rig-pep-ssf-receiver` (`../terraform/ssf-pep.tf`;
private_key_jwt with `keys/gateway/pep-ssf.*` from `gen-keys.sh`, scope `ssf.manage`), verifies each SET against
PingFederate's JWKS, and refuses tokens at once:

| Event about an agent | Effect at the PEP |
|---|---|
| CAEP `session-revoked` | its tokens issued at or before the event are refused; a token issued after it works |
| RISC `account-disabled` | every token refused, until |
| RISC `account-enabled` | lifts it |

Subjects are `iss_sub` - `iss` PingFederate, `sub` the agent's `client_id`, as in its tokens - or `opaque`: the
`client_id`, or **one instance's key thumbprint** (its tokens' `cnf.jkt`), which refuses that instance alone while the
agent's other instances carry on. `session-revoked` needs the token's `iat`, which PingFederate's token manager leaves out unless told
(`Include Issued At Claim`, `../terraform/resource.tf`); a token without one is refused, the safe way round.

Without it, a withdrawn agent keeps working until the resource's cache (300 s) and its registration at PingFederate
(about 20 minutes) run out - Raidiam cannot push into the network. With it the gateway refuses within a poll, about
two seconds (harness stage `signals`; events raised through PingFederate's `/ssf/events:emit`).

Next transmitters: the agent provider (an instance it stops attesting - the subject its key thumbprint) and the
marketplace (an agent it suspends) - both inside the network.

## Agents calling agents

A **Principal** agent (the rig's first agent, `…/agent/spire-client`) has work done by two agents it finds through
the federation: the **Accounts agent** and the **Payments agent**, each acting on its behalf.

```
Principal ──(OIDF: agents by capability, interface "agent")──▶ Accounts agent / Payments agent
   │ token aud = the agent, DPoP from the Principal's instance key
   ▼
Kong :8443 (the provider's edge) ─▶ coaz-pep ─▶ PingAuthorize ─▶ the agent (sub_agent.py)
                                                                    │ token exchange (RFC 8693) at PingFederate
                                                                    │ sub = Principal, act = {sub: the agent},
                                                                    │ aud = its resource, cnf = its own instance key
                                                                    ▼
                                 Kong :8446 / :8447 ─▶ coaz-pep ─▶ PingAuthorize ─▶ rs-accounts / rs-payments
                                                                                    (both agents' capabilities
                                                                                     checked in Raidiam)
```

| Piece | What |
|---|---|
| The agents (`../spire-workload/sub_agent.py`) | CBA's pattern (`invoice-settler-b-7`): one entity, a client **and** a resource (`interface: agent`) - a Raidiam software statement whose ClientId is `<provider>/agent/<name>`, and an ApiResource with that `resource`, joined by the identifier. Each runs under its own SPIRE identity (`spiffe://example.org/<name>`), is attested by the provider, and serves MCP at `<its id>/mcp/v1` |
| The provider (entity-host, `HOSTED_AGENTS`) | Hosts their Entity Configurations (with `oauth_resource` metadata), bindings and registrations, beside the Principal's |
| Kong on **8443** (`kong/provider.yml.template`) | The provider's edge: an agent's MCP must live under its identifier, on the provider's origin. `/agent/<name>/mcp` through coaz-pep (audience = that agent); everything else to entity-host |
| Kong on **8447** | rs-payments (`rs_accounts.py`, `RESOURCE_KIND=payments`): `pay_invoice`, `payment_initiation` |
| PingFederate (`../terraform/token-exchange.tf`, `resource.tf`) | A token manager per resource (each its own `aud`); a JWT processor for its own tokens as subject tokens; the delegation policy as the default (federated clients cannot be given one); `act` stamped per resource - a literal, since PingFederate 13 refuses an OGNL `act` - and emitted **as a JSON string**, not the object RFC 8693 asks for (the token manager has no option for it). The PEP and the resource read both |
| coaz-pep | An audience per route (`token_audience`); a signal about any party in a token - client, `sub`, `act.sub`, the bound instance - refuses it |
| rs-accounts / rs-payments | Check **every** agent in a delegated token holds the capability: a Principal cannot reach through an agent what it does not hold, nor the other way round |

`docker compose run --rm agent pay-invoice` runs the Principal's job (`INVOICE_AMOUNT`, default 420): it finds both
agents, has the Accounts agent read the operating account, and the Payments agent pay if the funds cover it. The
harness's `a2a` stage checks each hop's delegation (`sub`, `act`, audience, the sub-agent's own key), the resources'
decisions, an over-limit invoice refused by PingAuthorize at the first hop, and the Payments agent disabled by a
signal while the Accounts agent carries on.

Raidiam, per agent: the software statement, its entity and bridge keys (`AGENT=<name> ../raidiam/attested-client.sh`),
the ApiResource (family "POC Banking Agents") and roles - `cba.agentic.member` plus a capability role
(`cba.agentic.servicing.assistant` for `accounts_read`, `cba.agentic.ap.orchestrator` for `payment_initiation`). The
Principal holds `cba.agentic.ap.orchestrator` too: it cannot delegate what it does not hold.

## The policy

The rig's own, authored in the PingAuthorize Policy Editor (PAP 11.1, `pingauthorize-pap`, `https://localhost:8448`)
through its REST API: `pingauthorize/author-policy.py` builds it on branch `rig`, commits, and exports the sealed
deployment package the PDP loads (`pingauthorize/rig.deploymentpackage`; embedded mode). A package is digest-sealed,
so it only ever comes from the PAP.

| Rule | Effect |
|---|---|
| `list_accounts`, `get_balance`, `access_mcp` | permit |
| `make_payment` | permit |
| `make_payment` over the limit (`--limit`, default 1000) | deny (deny overrides permit) |
| anything else | not permitted |

The attributes come from the AuthZEN servlet's request: `actionName` (else the `action` object's `$.name`) and
`amount` (else the `context` object's `$.amount`, which the COAZ mapping puts there).

```bash
docker compose up -d pingauthorize-pap
python ../gateway/pingauthorize/author-policy.py --limit 1000     # -> rig.deploymentpackage
docker compose build pingauthorize && docker compose up -d --force-recreate pingauthorize
```

Next: decisions on federation facts - the agents' capabilities and trust marks from Raidiam, their attester and
SPIFFE ID - through a federation PIP; today the resources check capabilities, the PDP the actions and limits.
`omit_token_aud` stays until the policy reads the audience.
