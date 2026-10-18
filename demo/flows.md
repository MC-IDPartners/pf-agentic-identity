# The rig's flows, by PoC objective

How the rig proves each objective in *Agentic IDAM - Trust Controller PoC Objectives* (10 July 2026): a brief description,
the checks that prove it, and the flow as a sequence diagram. Two things produce the evidence:

- **the control centre**: the agent marketplace (`marketplace/`, http://localhost:3000). It deploys Principal versions,
  suspends and reinstates them, and runs scenarios as them.
- **the harness**: `spire-workload/harness.py`, whose checks are mapped to objectives in `spire-workload/objectives.py`.

The marketplace's Objectives page shows the current evidence for each objective. The objectives the rig cannot show by
running something are listed under [Documentary objectives](#documentary-objectives).

The parties, as named in the diagrams:

| Name | What it is |
|---|---|
| Operator | the person at the marketplace, signed in to Raidiam |
| Marketplace | the Agent registry and control centre (`marketplace/`) |
| Raidiam | the Trust Controller: the CBA federation's authority and trust anchor, and its admin API |
| Provider | the agent provider (`entity-host`, behind Kong on 8443): it hosts the agents' Entity Configurations and holds their keys |
| SPIRE | SPIRE server and agent: workload registration and attestation |
| Agent | a Principal agent instance (`agent.py`), e.g. `principal-1` |
| PingFed | PingFederate with the OpenID Federation modules: the token endpoint, the co-hosted attester, the SSF transmitter |
| Gateway | Kong with the coaz-pep plugin, in front of every resource and every agent other agents call |
| PDP | PingAuthorize |
| Resource | rs-accounts or rs-payments (MCP) |
| SubAgent | the Accounts or Payments agent (`sub_agent.py`) |

---

## TC-01 Marketplace registration triggers the Agent Identity workflow

**What it shows:** approving a Principal version in the marketplace starts the whole identity workflow. That covers the
statement, the certificates, the roles, its publication and its workload registration, with no step done by hand.

**Proved by:** the marketplace's *deploy* action, whose log records each step against Raidiam's API.

```mermaid
sequenceDiagram
    participant Op as Operator
    participant MP as Marketplace
    participant PR as Provider
    participant RD as Raidiam
    participant SP as SPIRE
    Op->>MP: register Principal Agent 1.0.0, then approve
    MP->>PR: claim a Principal slot
    PR-->>MP: principal-1, its entity id and SPIFFE ID
    MP->>RD: POST softwarestatements, ClientId is the slot
    RD-->>MP: statement id
    MP->>PR: CSRs for this statement
    MP->>RD: POST certificates rtssigning, entity and bridge
    MP->>RD: POST authorityclaims, one per role
    MP->>PR: host principal-1
    MP->>SP: entry spiffe://example.org/principal-1
    MP-->>Op: deployed, with the step log
```

## TC-02 The Trust Controller governs approval, suspension and withdrawal

**What it shows:** the agent's standing is Raidiam's. Approval is a statement Raidiam vouches for. Suspension sets that
statement `Suspended`, after which Raidiam's authority stops issuing a subordinate statement for it, and every party that
resolves trust through Raidiam refuses the agent.

**Proved by:** the marketplace's *suspend* and *reinstate* actions, the *while suspended* scenario, and the harness's
`Raidiam vouches for the agent's entity key` check.

```mermaid
sequenceDiagram
    participant MP as Marketplace
    participant RD as Raidiam
    participant AG as Agent
    MP->>RD: PUT softwarestatement, Status Suspended
    AG->>RD: fetch, the authority's statement about me
    RD-->>AG: 404, not vouched for
    AG-->>MP: refused at the envelope step
    MP->>RD: PUT softwarestatement, Status Active
    AG->>RD: fetch, the authority's statement about me
    RD-->>AG: subordinate statement, keys and metadata policy
    AG-->>MP: acts again
```

## TC-03 Token flow with an Agent Identity trust check before access

**What it shows:** before an agent touches a resource it is attested, its trust chain is resolved and checked, and it
gets a token for that resource bound to its instance key. The gateway, the PDP and the resource then each check the token
and the agent before the call is allowed.

**Proved by:** the *acts as itself* scenario, and the harness's `run` and `gateway` stages.

```mermaid
sequenceDiagram
    participant AG as Agent
    participant SP as SPIRE
    participant PF as PingFed
    participant RD as Raidiam
    participant GW as Gateway
    participant PDP as PDP
    participant RS as Resource
    AG->>SP: JWT-SVID
    AG->>PF: attestation request, SVID and instance key proof
    PF-->>AG: client attestation
    AG->>PF: token, attest_jwt_client_auth with DPoP, resource rs-accounts
    PF->>RD: the agent's chain to the anchor
    PF-->>AG: access token, aud rs-accounts, cnf.jkt of the instance key
    AG->>GW: MCP tools/call with DPoP proof
    GW->>GW: signature, audience, DPoP binding, signals
    GW->>PDP: AuthZEN decision
    PDP-->>GW: permit
    GW->>RS: the call
    RS->>RD: the caller's chain and capability
    RS-->>AG: result
```

## TC-04 A lifecycle event revokes or disables the Agent Identity

**What it shows:** a suspension takes effect within seconds, not when a token expires. Shared Signals events from
PingFederate's transmitter reach the gateway, which refuses existing tokens (`session-revoked`) or every token
(`account-disabled`). A single instance can be disabled by its key thumbprint while the agent's other instances carry on.

**Proved by:** the harness's `signals` stage, the *Payments agent disabled* check in the `a2a` stage, and the
marketplace's *suspend* action, which raises `account-disabled`.

```mermaid
sequenceDiagram
    participant MP as Marketplace
    participant PF as PingFed
    participant GW as Gateway
    participant AG as Agent
    AG->>GW: call with a valid token
    GW-->>AG: 200
    MP->>PF: events emit, account-disabled for the agent
    PF->>GW: SET on the gateway's stream, polled
    AG->>GW: call with the same token
    GW-->>AG: 401, the agent is disabled
    MP->>PF: events emit, account-enabled
    PF->>GW: SET
    AG->>GW: call
    GW-->>AG: 200
```

## TC-05 Publishing, updating and withdrawing Entity Configurations

**What it shows:** each agent's identity is a standard OpenID Federation Entity Configuration, published by its provider.
Deploying a version publishes it, suspending withdraws it, and reinstating publishes it again.

**Proved by:** the harness's `the provider serves the agent's Entity Configuration` check, and the marketplace's
deploy, suspend and reinstate actions.

```mermaid
sequenceDiagram
    participant MP as Marketplace
    participant PR as Provider
    participant PF as PingFed
    participant RD as Raidiam
    MP->>PR: host principal-1
    PF->>PR: GET principal-1 well-known openid-federation
    PR-->>PF: Entity Configuration, signed, with authority_hints and SPIFFE bindings
    PF->>RD: the authority's statement about principal-1
    MP->>PR: withdraw principal-1
    PF->>PR: GET principal-1 well-known openid-federation
    PR-->>PF: 404, its chain no longer resolves
```

## TC-06 The marketplace as Agent registry, separate from identity and trust

**What it shows:** the marketplace holds the catalogue record: owner, version, evidence and lifecycle state. Raidiam holds
the identity. The two are joined by the software statement ID, never copied.

**Proved by:** the marketplace's *deploy* action. The record keeps `softwareStatementId` and reads Raidiam back rather
than storing its own copy.

```mermaid
sequenceDiagram
    participant Op as Operator
    participant MP as Marketplace
    participant RD as Raidiam
    Op->>MP: register, owner version repository SBOM
    MP->>MP: catalogue record, status pending
    MP->>RD: create the statement
    RD-->>MP: statement id
    MP->>MP: keep the statement id, status approved
    Op->>MP: view the agent
    MP->>RD: read back the statement, certificates and roles
    RD-->>MP: what the Trust Controller holds
```

## TC-07 Orchestration across agent workflow events and identity workflows

**What it shows:** one marketplace event drives many systems in order: provider, Raidiam, SPIRE and PingFederate. The
deploy waits for the downstream result (Raidiam vouching, PingFederate registering) and resumes where it stopped if a
step fails.

**Proved by:** the marketplace's *deploy* action, and its resumption after a refused step.

```mermaid
sequenceDiagram
    participant MP as Marketplace
    participant PR as Provider
    participant RD as Raidiam
    participant SP as SPIRE
    participant PF as PingFed
    MP->>PR: claim slot
    MP->>RD: statement, certificates, roles
    Note over MP,RD: progress kept on the record, a failed step resumes on the next approve
    MP->>PR: host
    MP->>SP: registration entry
    PR->>PF: explicit registration, woken by the deploy
    loop until trusted
        MP->>PR: status
        PR->>RD: does the authority vouch for these keys
        PR-->>MP: vouched, registered until
    end
```

## TC-08 Policy enforcement for trust decisions

**What it shows:** decisions come from the federation and from policy, not from the client. The capability envelope comes
from the agent's Raidiam roles, and PingAuthorize decides each call on the action and its context. The rig's policy
permits reads and payments, and denies a payment over 1000.

**Proved by:** the *outside its envelope* and *over the policy limit* scenarios, and the harness's
`the PDP permits` / `the PDP denies` checks.

```mermaid
sequenceDiagram
    participant AG as Agent
    participant RD as Raidiam
    participant GW as Gateway
    participant PDP as PDP
    AG->>RD: my chain, with the metadata policy applied
    RD-->>AG: authorization_details_types, without lending_read
    AG->>AG: loan-balance needs lending_read, refused before a request
    AG->>GW: pay_invoice, amount 1500
    GW->>PDP: AuthZEN, action make_payment, amount 1500
    PDP-->>GW: deny, over the limit
    GW-->>AG: COAZ error -32401
```

## TC-09 Federation bridge for an existing authorisation server

**What it shows:** PingFederate, an existing enterprise authorisation server, joins the federation without being rebuilt.
It resolves chains, applies Raidiam's metadata policy, registers clients from them, and publishes its own Entity
Configuration under Raidiam's authority.

**Proved by:** the harness's `PingFederate answers`, `the agent is registered at PingFederate`,
`Raidiam vouches for PingFederate` and `token for this agent, for the resource` checks.

```mermaid
sequenceDiagram
    participant PR as Provider
    participant PF as PingFed
    participant RD as Raidiam
    PR->>PF: explicit registration, the agent's Entity Configuration
    PF->>RD: fetch the authority's statement, then the anchor's
    PF->>PF: verify down from the pinned anchor key, apply metadata policy
    PF-->>PR: registered, until the chain expires
    RD->>PF: GET well-known openid-federation
    PF-->>RD: PingFed's Entity Configuration, authority hint, signing keys, attester key
```

## TC-10 The Trust Controller as authoritative source

**What it shows:** every party takes what an agent is and may do from Raidiam, not from local configuration. That covers
PingFederate when it registers the client, the agent when it reads its own envelope, the agents finding each other by
capability, and the resource when it checks the caller.

**Proved by:** the harness's `found the resource through the federation`, `found through the federation by capability`
and `acted for the Principal` checks, and the *agents act on its behalf* scenario.

```mermaid
sequenceDiagram
    participant AG as Agent
    participant RD as Raidiam
    participant PF as PingFed
    participant RS as Resource
    AG->>RD: list oauth_resource entities, and resolve each
    RD-->>AG: resources with authorization servers and capabilities
    AG->>AG: pick the one serving accounts_read through PingFed
    AG->>PF: token request
    PF->>RD: the agent's chain and policy
    AG->>RS: call
    RS->>RD: the caller's chain and its granted capability
```

## TC-11 The OpenID Federation target state

**What it shows:** standard OpenID Federation throughout: Entity Configurations, subordinate statements, metadata policy
and trust chains to a pinned anchor. Attesters are trusted the same way, with no static shortcuts. The deviations are
explicit: explicit registration, local chain resolution inside the protected network, and `act` as a string.

**Proved by:** the harness's `PingFederate publishes its attester key` and
`PingFederate trusts no static attesters` checks, and the Entity Configuration checks.

```mermaid
sequenceDiagram
    participant AG as Agent
    participant PF as PingFed
    participant RD as Raidiam
    AG->>PF: token with an attestation issued by PingFed's attester
    PF->>PF: the attestation's issuer is an entity, resolve it
    PF->>RD: PingFed's chain to the pinned anchor
    PF->>PF: key from metadata oauth_client_attester jwks
    PF-->>AG: token, no mock attesters consulted
```

## TC-12 Overlay compatibility with the enterprise authorisation server landscape

**What it shows:** the federation overlays existing infrastructure. PingFederate issues the tokens, and attestation is
pluggable: PingFederate's own attester or the agent provider's, each trusted the same way through its chain.

**Proved by:** the *attested by the provider instead* scenario, and the harness's `attesters` stage
(`the same job attested by the provider instead is trusted too`).

```mermaid
sequenceDiagram
    participant AG as Agent
    participant PF as PingFed
    participant PR as Provider
    participant RD as Raidiam
    alt PingFed attests
        AG->>PF: attestation request with SVID
        PF-->>AG: attestation, iss PingFed
    else the provider attests
        AG->>PR: attest with SVID
        PR-->>AG: attestation, iss provider
    end
    AG->>PF: token with the attestation
    PF->>RD: the attester's chain, its oauth_client_attester key
    PF-->>AG: token
```

## TC-14 Identity and authentication controls

**What it shows:** no anonymous or bearer-only access. Tokens are sender-constrained to the instance key with DPoP: a
token presented as a bearer, a proof from another key or a replayed proof is refused. Only PingFederate's signatures are
honoured, and each hop of a delegated call has its own bound token.

**Proved by:** the harness's `DPoP` checks, `refuses a call with no token`, `not signed by PingFederate`, and
`bound to its own instance key` in the `a2a` stage.

```mermaid
sequenceDiagram
    participant AG as Agent
    participant X as Attacker
    participant GW as Gateway
    AG->>GW: token with a DPoP proof from the instance key
    GW-->>AG: 200
    X->>GW: the stolen token as Bearer
    GW-->>X: 401
    X->>GW: the stolen token with a proof from another key
    GW-->>X: 401, cnf.jkt mismatch
    X->>GW: a replayed proof
    GW-->>X: 401, jti seen
    X->>GW: no token
    GW-->>X: 401
```

## TC-15 Secure configuration and hardening

**What it shows:** partly evidenced. Trust shortcuts are gone: no mock attesters, and every attester is trusted through
the federation. The rig's remaining development shortcuts are listed in `raidiam/PROTECTED-ENVIRONMENTS.md` (section 13),
each with its production equivalent.

**Proved by:** the harness's `PingFederate trusts no static attesters` check. The flow is TC-11's.

## TC-18 Security logging of trust decisions

**What it shows:** every decision at the gateway is logged with its principal and its reason: permits, PDP denials,
refusals (token, DPoP, signal) and signals received. Everything can be traced to a run.

**Proved by:** the harness's `decisions are logged at the gateway with principal and reason` check.

```mermaid
sequenceDiagram
    participant AG as Agent
    participant GW as Gateway
    participant PDP as PDP
    participant LOG as coaz-pep log
    AG->>GW: call
    GW->>PDP: decision
    PDP-->>GW: permit or deny
    GW->>LOG: PERMIT or DENY, client, sub, tool, reason
    GW->>LOG: refused, token, DPoP or signal, with the principal
```

## TC-19 Observability and monitoring

**What it shows:** the components' state and every step of a flow can be seen. The harness's preflight checks every
service, each agent run emits a structured `AGENT_RESULT`, and the marketplace shows each deploy's step log, each version's
live status (provider, Raidiam, PingFederate) and each scenario's run.

**Proved by:** the harness's `is running` checks and the decision log. The marketplace's agent page shows it live.

```mermaid
sequenceDiagram
    participant Op as Operator
    participant MP as Marketplace
    participant PR as Provider
    participant RD as Raidiam
    Op->>MP: open principal-1
    MP->>PR: status
    PR->>RD: does the authority vouch for its keys
    PR-->>MP: hosted, vouched with kids, registered at PingFed until
    MP-->>Op: status, deploy log, scenario runs with verdicts
```

## TC-21 Recoverability and rebuild

**What it shows:** the environment rebuilds from code. `up.sh` recreates PingFederate from its archive and configuration,
compose recreates the rest, and the agents re-register by themselves. The marketplace keeps its Raidiam session and deploy
progress across restarts.

**Proved by:** the harness's `is running` checks after a rebuild.

```mermaid
sequenceDiagram
    participant Op as Operator
    participant UP as up.sh
    participant PF as PingFed
    participant PR as Provider
    Op->>UP: PF_PROFILE=raidiam up.sh
    UP->>UP: render keys, bridge slots, trust store, environment
    UP->>PF: start from the archive
    PF-->>UP: discovery answers
    PR->>PF: explicit registration of every hosted agent
    PF-->>PR: registered
```

## TC-25 Agent Identity metadata and external evidence

**What it shows:** partly evidenced. The catalogue holds the agent's evidence (owner, repository, SBOM) and Raidiam's
statement references it in `AdditionalSoftwareMetadata` (SPIFFE ID, trust domain, version, catalogue ID). The provider's
Entity Configuration publishes the agents' SPIFFE bindings. Wiring a full manifest is still open.

**Proved by:** the marketplace's *deploy* action, and the harness's `the provider binds the agents' SPIFFE IDs` check.

```mermaid
sequenceDiagram
    participant MP as Marketplace
    participant RD as Raidiam
    participant PR as Provider
    participant PF as PingFed
    MP->>RD: statement with AdditionalSoftwareMetadata, spiffe_id, version, catalogue id
    PR->>PR: Entity Configuration with spiffe_client_bindings
    PF->>PR: the provider's configuration, through its chain
    PF->>PF: which SPIFFE IDs are instances of which agent
```

## TC-26 Cryptographic assurance with no private-key custody in the Trust Controller

**What it shows:** Raidiam certifies public keys and never holds a private one. The provider makes every key, sends only
CSRs, and signs with its own keys under the kids Raidiam publishes. Each instance's key never leaves its container.

**Proved by:** the marketplace's *deploy* action (CSRs only), the harness's `Raidiam vouches for the agent's entity key`
and `attested by` checks.

```mermaid
sequenceDiagram
    participant PR as Provider
    participant MP as Marketplace
    participant RD as Raidiam
    participant AG as Agent
    PR->>PR: entity and bridge keys, private halves kept
    PR-->>MP: CSRs only
    MP->>RD: certify the CSRs
    RD-->>MP: certificates, public keys and kids
    RD->>RD: publishes the public keys in its subordinate statement
    AG->>AG: instance key made in the container, never sent
```

## TC-27 A governed, versioned capability envelope

**What it shows:** what an agent may do is governed by Raidiam roles, which become `authorization_details_types` through
metadata policy. The envelope is consumed by the agent itself, by the resource, and through delegation: each agent in a
chain is checked, so a capability can't be passed through another agent.

**Proved by:** the harness's `is in the envelope`, `a job outside the envelope` and `checked both agents` checks, and the
*outside its envelope* scenario.

```mermaid
sequenceDiagram
    participant MP as Marketplace
    participant RD as Raidiam
    participant AG as Agent
    participant SA as SubAgent
    participant RS as Resource
    MP->>RD: grant cba.agentic.ap.orchestrator
    RD->>RD: role metadata, authorization_details_types value six types
    AG->>RD: resolve my chain
    RD-->>AG: envelope includes accounts_read, not lending_read
    AG->>SA: delegate account_balance
    SA->>RS: token, sub the Principal, act the SubAgent
    RS->>RD: both chains
    RS->>RS: both envelopes include accounts_read
```

## TC-28 Automated workload registration and SPIFFE/SPIRE attestation

**What it shows:** the workload identity is registered by the deploy, not by hand. Attestation rests on what SPIRE says
the container is, never on what the agent claims. A container SPIRE identifies as another workload gets no attestation as
the agent, and one instance can be withdrawn by its key.

**Proved by:** the marketplace's *deploy* action (SPIRE entry), the *another workload claims to be it* scenario, and the
harness's `spire` stage, `SPIRE identified the container` and `attested as this agent` checks.

```mermaid
sequenceDiagram
    participant MP as Marketplace
    participant SP as SPIRE
    participant AG as Agent
    participant PF as PingFed
    participant PR as Provider
    MP->>SP: entry principal-1 for docker label app principal-1
    AG->>SP: Workload API, as container app principal-1
    SP-->>AG: JWT-SVID spiffe://example.org/principal-1
    AG->>PF: attestation request, SVID and instance key proof
    PF->>PR: the provider's spiffe_client_bindings, through its chain
    PF->>SP: SPIRE's live JWT-SVID keys
    PF-->>AG: attestation for principal-1, cnf the instance key
    Note over AG,PF: a container SPIRE knows as my-workload gets no attestation as principal-1
```

---

## Documentary objectives

These objectives are about decisions, documents or operations, not anything the rig can run:

| Objective | Where it is covered |
|---|---|
| TC-13 Deployment model options and CBA boundary implications | `raidiam/PROTECTED-ENVIRONMENTS.md`: the outbound-only model, where Raidiam lists and vouches but cannot resolve |
| TC-16 Vulnerability identification and remediation | vulnerability management, documentary |
| TC-17 Network protection, segmentation and isolation | network design, documentary; the rig runs on one Docker network |
| TC-20 Data protection and recovery | data protection and backup, documentary |
| TC-22 Support, operating model and vendor enablement | documentary |
| TC-23 Commercial and procurement implications | documentary |
| TC-24 Implementation gaps and internal build effort | the gap registers in the READMEs: explicit registration, `act` as a string, bridge-key slots, the operator session for Raidiam's admin API |
