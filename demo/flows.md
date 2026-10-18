# The rig's flows, by PoC objective

How the rig proves each objective in *Agentic IDAM - Trust Controller PoC Objectives* (10 July 2026): a brief description,
the checks that prove it, and the flow as a sequence diagram. Two things produce the evidence:

- **the control centre**: the agent marketplace (`marketplace/`, http://localhost:3000). It deploys Principal versions,
  suspends and reinstates them, and runs scenarios as them.
- **the harness**: `spire-workload/harness.py`, whose checks are mapped to objectives in `spire-workload/objectives.py`.

The marketplace's Objectives page shows the current evidence for each objective. The objectives the rig cannot show by
running something are listed under [Documentary objectives](#documentary-objectives).

The parties, as named in the diagrams:

| Name | What it is | What it does | Why it is necessary |
|---|---|---|---|
| Operator | The person running the demo: an agent owner or approver, signed in to Raidiam through the marketplace | Registers, approves, suspends and reinstates agents, and runs scenarios | Agent identities are governed, not self-asserted. Someone accountable decides an agent may exist and act (TC-01, TC-02) |
| Marketplace | The Agent registry and control centre (`marketplace/`, Node) | Holds the catalogue record (owner, version, evidence, lifecycle). On approval it drives the identity workflow: statement, certificates and roles in Raidiam, the provider slot, the SPIRE entry. It runs scenarios and shows the objectives' evidence | Keeps the business record of an agent separate from its identity (TC-06), and orchestrates the identity workflow from a registry event (TC-01, TC-07) |
| Raidiam | The Trust Controller: the CBA federation's authority and trust anchor, with its admin API and directory | Holds software statements, certified public keys and roles. It publishes signed subordinate statements with keys and metadata policy (the capability envelope), lists entities, and stops vouching when a statement is suspended | The single authoritative source of who an agent is and what it may do (TC-10). Every party trusts an agent only through a chain to its pinned anchor, never through local configuration |
| Provider | The agent provider (`entity-host`, behind Kong on 8443), CBA's pattern | Hosts the agents' Entity Configurations and their SPIFFE bindings, holds their entity keys and makes their CSRs, enrols each agent's bridge key in the KMS (or, without one, holds it too), registers the agents at PingFederate, and can attest instances itself (`/attest`) | Agents need an owner that publishes their federation identity and keeps their keys out of the Trust Controller (TC-05, TC-26). It is the organisation that answers for the agents it hosts |
| SPIRE | The SPIRE server and agent: the workload identity system (SPIFFE) | Attests running containers by their properties (Docker labels) and issues JWT-SVIDs, e.g. `spiffe://example.org/principal-1`. Its OIDC provider (`spire-oidc`) serves the trust domain's live keys | Ties an agent identity to the workload actually running it, from evidence the workload cannot forge (TC-28). Without it, anything holding a key could claim to be the agent |
| Agent | A Principal agent instance (`agent.py`), e.g. `principal-1`, in its own container | Gets itself attested, reads its own envelope from Raidiam, finds resources and other agents through the federation, gets DPoP-bound tokens, and calls resources or delegates to sub-agents | The subject of the PoC: an autonomous workload acting on its own identity, or on someone's behalf, under the bank's controls |
| PingFed | PingFederate with the OpenID Federation modules: the bank's existing authorisation server | Resolves and validates trust chains and registers clients from them. Its co-hosted attester attests instances on SPIRE's evidence. Its token endpoint (`attest_jwt_client_auth` + DPoP, token exchange) issues tokens, signing each attested agent's bridge assertion in the KMS, and its SSF transmitter emits lifecycle events | Shows that the enterprise authorisation server can join the federation as it is (TC-09, TC-12). It issues every token, so trust decisions are enforced where credentials are minted |
| KMS | OpenBao's transit engine (`openbao`, optional: `RAIDIAM_BRIDGE_BACKING=vault`), standing in for the bank's KMS or HSM | Holds each agent's bridge key, never exported. It creates a key when the provider enrols an agent, makes its CSR for Raidiam to certify, and signs PingFederate's bridge assertion for the agent at each attested token request. PingFederate's token may only sign, the provider's only create keys and get their CSRs | PingFederate can only authenticate an attested agent through a `private_key_jwt` signed with a key of that agent's. Held here, no bridge private key sits in a file or in PingFederate's configuration (TC-26), and keys found by name mean agents are enrolled with no limit and no restart |
| Gateway | Kong with the coaz-pep plugin, in front of every resource and every agent other agents call | Verifies the token (signature, audience, expiry), the DPoP proof and replay, and the Shared Signals state. It asks the PDP per call and logs every decision | Puts enforcement in the network path rather than in each resource (TC-03, TC-14, TC-18), and makes lifecycle events take effect in seconds (TC-04) |
| PDP | PingAuthorize, through its AuthZEN interface; its policy is authored through the PAP API | Decides each call on the action, its arguments and its context, e.g. permits reads, denies payments over 1000 | Separates policy from code: business rules on what an agent may do change without redeploying anything (TC-08) |
| Resource | rs-accounts and rs-payments: MCP servers inside the protected network, federation entities of their own | Serve the banking tools (balances, payments). They check the token again, and the caller's (and on-behalf-of party's) chain and capability in Raidiam | The protected assets the controls exist for. Their federation identity lets agents find them by capability (TC-10) |
| SubAgent | The Accounts and Payments agents (`sub_agent.py`): both a client and a resource, hosted by the provider | Accept calls from the Principal, exchange its token (RFC 8693, `sub` the Principal, `act` themselves) and call their resource with a token bound to their own instance | Prove agents calling agents: delegation is explicit and checked at every hop, so no capability passes through an agent that lacks it (TC-27) |
| Attacker | Anyone holding a stolen token or proof (TC-14's diagram only) | Replays tokens and proofs, or presents them from another key | Shows that sender-constrained tokens are useless to anyone but the attested instance |
| coaz-pep log | The gateway PEP's decision log (TC-18's diagram only) | Records each permit, deny, refusal and signal with the principal and the reason | The audit trail for trust decisions (TC-18, TC-19) |
| up.sh | The rig's build and start script (TC-21's diagram only) | Renders keys, bridge slots, the trust store and the environment, and starts PingFederate from its archive | Proves the environment rebuilds from code (TC-21) |

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

## The agent provider, and a production alternative without it

### Why the rig uses a provider

The rig follows CBA's own agentic pattern (`provider.demo.cba.raidiam.io`, agent-r): agents are hosted by an **agent
provider**, a federation entity Raidiam vouches for. The provider publishes each agent's Entity Configuration, holds its
keys, binds its SPIFFE IDs and can attest its instances.

We used it for three reasons:
- **The rig mirrors the architecture CBA is evaluating.** Third parties hosting agents is part of that architecture.
- **Raidiam couldn't carry what attestation needs.** When the rig was built, Raidiam's federation-managed entities lacked
  `authority_hints`, and Raidiam still doesn't publish per-statement metadata such as SPIFFE bindings. The binding of a
  workload to an agent therefore had to live in an Entity Configuration we control.
- **The private keys stay with the agents' owner** (TC-26). The provider shows what that owner does: it makes the CSRs
  and signs with keys the Trust Controller never holds.

### An alternative for production

Most of the provider's jobs can be absorbed by the systems already in the picture:
- **Raidiam** hosts and signs each agent's Entity Configuration: a federation-managed statement, resolvable by Raidiam
  itself even when the agent runs in a protected network. Raidiam would also carry the SPIFFE binding on the statement.
- **A vault (OpenBao or a KMS)** creates the bridge key on demand. Only PingFederate uses it, and only its CSR leaves.
- **PingFederate** attests instances against the binding Raidiam vouches for, and registers the agent on first use by
  resolving it through Raidiam.
- **The marketplace's pipeline** drives the statement, the CSR, the roles and the SPIRE entry.

That removes a component, the provider's keys and hosting, and the pre-made bridge-key slots. Every binding becomes
governed in one place, the Trust Controller.

It depends on two changes outside the bank's control:
- **Raidiam** must publish SPIFFE metadata in its statements.
- **PingFederate's modules** must register an unknown, Raidiam-resolvable client at an attested token request.

Raidiam-hosted Entity Configurations already carry `authority_hints` and resolve through the authority (checked
2026-10-18). Until those two changes land, the bindings can live in PingFederate's client store, written by the
marketplace, though that makes them local rather than federation-governed.

```mermaid
sequenceDiagram
    participant Op as Operator
    participant MP as Marketplace
    participant VT as Vault
    participant RD as Raidiam
    participant SP as SPIRE
    participant AG as Agent
    participant PF as PingFed
    Op->>MP: approve Principal Agent 1.0.0
    MP->>RD: POST softwarestatements, federation-managed, with SPIRE metadata
    Note over MP,RD: spiffe_id, trust_domain, bundle_url - needs Raidiam to publish them
    RD->>RD: hosts and signs the agent's Entity Configuration
    RD-->>MP: statement id, client id on Raidiam's host
    MP->>VT: create the agent's bridge key
    VT-->>MP: CSR only
    MP->>RD: POST certificates rtssigning
    MP->>RD: POST authorityclaims, the agent's roles
    MP->>SP: entry spiffe://example.org/principal-1 for the agent's workload
    AG->>SP: Workload API
    SP-->>AG: JWT-SVID spiffe://example.org/principal-1
    AG->>PF: attestation request, SVID and instance key proof
    PF->>RD: resolve the agent, Entity Configuration and the authority's statement
    RD-->>PF: binding, keys and capability envelope, all vouched by Raidiam
    PF->>SP: the trust domain's live JWT-SVID keys
    PF-->>AG: attestation, cnf the instance key
    AG->>PF: token, attest_jwt_client_auth with DPoP
    PF->>PF: unknown client, register it from the resolved chain
    Note over PF: needs the module to register on first attested use
    PF->>VT: sign the bridge client assertion
    PF-->>AG: access token bound to the instance key
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
