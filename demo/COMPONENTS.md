# The rig's components

Every component the rig runs, grouped by layer: what it is, what it does, and why it matters for the PoC. For the parties
in the flows and the flows themselves, see [flows.md](flows.md). Ports are the host's.

## Trust and federation

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **Raidiam** (external) | The CBA federation's Trust Controller: its authority, trust anchor, directory and admin API | Holds software statements, certified public keys and roles. It publishes signed subordinate statements with keys and metadata policy (the capability envelope), lists entities, and stops vouching for a suspended statement | The single source of who an agent is and what it may do. Every party trusts an agent only through a chain to Raidiam's pinned anchor (TC-02, TC-10, TC-27) |
| **ngrok** (external) | A public tunnel to PingFederate's runtime port | Gives PingFederate a public issuer (`PF_BASE_URL`), so Raidiam can fetch its discovery document and Entity Configuration | Raidiam must reach PingFederate to vouch for it. Everything else stays inside the protected network (TC-13) |

## Identity provider

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **PingFederate** (`pf-agentic-identity`, 9031) | PingFederate 13.1.3 with the OpenID Federation modules (0.7.0, plus the OpenBao bridge change) | The bank's authorisation server: it issues every token, DPoP-bound to the agent's instance key, for one resource. It publishes its own Entity Configuration under Raidiam. Its configuration is authored by terraform and baked into an archive | Shows that the existing enterprise authorisation server can join the federation as it is (TC-09, TC-12) |
| ↳ federation and registration modules | Servlets and filters in PingFederate | Resolve and validate agents' chains to the pinned anchor, apply Raidiam's metadata policy, and register agents from it | The client is built from the Trust Controller's trust material, not configured by hand (TC-09, TC-10) |
| ↳ attester | PingFederate's co-hosted client attester | Attests an agent instance on its SPIRE JWT-SVID, reading the agents' SPIFFE bindings through the provider's chain, and signs with a key PingFederate's Entity Configuration publishes | Ties a token to an attested workload, with the attester itself trusted through the federation (TC-28, TC-11) |
| ↳ attestation auth (bridge) | The `attest_jwt_client_auth` filter at the token endpoint | Verifies the attestation and DPoP proof, then signs a `private_key_jwt` for the agent with its bridge key, the only credential PingFederate's engine accepts | Lets an attested instance authenticate with no client key of its own (TC-26, TC-28) |
| ↳ token exchange | An RFC 8693 processor and token managers per resource | Exchanges the caller's token for one at the next resource: `sub` the caller, `act` the acting agent, bound to that agent's own key | Makes delegation between agents explicit and checkable at every hop (TC-03, TC-27) |
| ↳ SSF transmitter | PingFederate's Shared Signals transmitter | Emits CAEP and RISC events (`session-revoked`, `account-disabled`, `account-enabled`) to its receivers' streams | Carries lifecycle events to enforcement in seconds (TC-04) |

## Key management

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **OpenBao** (`openbao`, 8200; optional) | OpenBao's transit engine, standing in for the bank's KMS or HSM (`RAIDIAM_BRIDGE_BACKING=vault`) | Holds each agent's bridge key, never exported. It creates a key when the provider enrols an agent and makes its CSR for Raidiam, and it signs PingFederate's bridge assertion at each attested token request. PingFederate's token may only sign; the provider's may only create keys and get their CSRs | No bridge private key sits in a file or in PingFederate's configuration. Keys are found by name, so agents are enrolled with no limit and no restart (TC-26, TC-01) |
| `openbao/setup.py` | The vault's set-up script | Initialises OpenBao once, unseals it (after every restart), enables transit, writes the two policies and their tokens, and imports the bridge keys already in use | Makes the vault reproducible, and keeps keys Raidiam already certified valid when moving to it (TC-21) |

## Workload identity

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **SPIRE server** (`spire-spire-server-1`, 8081) | The SPIFFE trust domain's server, `example.org` | Holds the registration entries (SPIFFE ID ← Docker label) and signs SVIDs. The marketplace adds an entry for each version it deploys | The authority for which workload is which agent (TC-28) |
| **SPIRE agent** (`spire-spire-agent-1`) | The node agent, attested to the server with x509pop | Identifies each container by its Docker labels and issues it a JWT-SVID through the Workload API | An agent's identity comes from what the platform observes, not from anything the agent claims (TC-28) |
| **SPIRE OIDC provider** (`spire-oidc`, 8445) | SPIRE's OIDC Discovery Provider | Serves the trust domain's live JWT-SVID keys, which the attesters verify SVIDs against | SPIRE's key rotations reach every verifier, and with the keys unreachable nothing is attested (TC-28) |

## Agent provider and agents

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **entity-host** (behind 8443) | The agent provider, CBA's pattern, with its own Raidiam statement | Hosts the agents' Entity Configurations, its own with the agents' SPIFFE bindings, and `/agents`. It registers the agents at PingFederate and can attest instances (`/attest`). Its admin API (8091, internal only) claims versions and makes their CSRs, the bridge key's in OpenBao | The owner that publishes the agents' federation identity and keeps their private keys out of the Trust Controller (TC-05, TC-26) |
| **gateway-provider** (Kong, 8443) | The provider's edge | Passes Entity Configurations, `/attest` and `/agents` to entity-host. It enforces the gateway checks on the sub-agents' MCP, and routes `/cb` to the marketplace (its Raidiam sign-in callback) | One public origin for the provider and the agents it hosts, as their identifiers require |
| **agent** (run on demand) | The Principal agent (`agent.py`), one container per run, e.g. a deployed `principal-N` | Gets its instance attested, reads its envelope from Raidiam, finds resources and agents by capability, gets DPoP-bound tokens, calls resources or delegates to sub-agents. It reports each step (`AGENT_RESULT`) | The subject of the PoC: an autonomous workload acting under the bank's controls (TC-03) |
| **accounts-agent**, **payments-agent** | Sub-agents (`sub_agent.py`): each a client and an MCP resource, hosted by the provider | Accept a call from the Principal, exchange its token, and call their resource with a token bound to their own instance | Agents calling agents, with delegation checked at every hop (TC-27) |

## Resources and enforcement

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **rs-accounts**, **rs-payments** | MCP resource servers inside the protected network, each a federation entity | Serve the banking tools (balances, payments). They check the token again, and every party's chain and capability in Raidiam | The protected assets, found by agents through the federation by capability (TC-10) |
| **gateway**, **gateway-payments** (Kong, 8446, 8447) | Kong in front of each resource, with the `coaz-pep` plugin | Route each MCP call through the policy enforcement point before the resource | Enforcement in the network path rather than in each resource (TC-03) |
| **coaz-pep** | The policy enforcement point Kong delegates to | Verifies the token's signature, audience and expiry, the DPoP proof and replay, and the Shared Signals state (a poll stream from PingFederate). It asks the PDP per call and logs every decision with its principal and reason | Sender-constrained access, lifecycle events in seconds, an audit trail (TC-04, TC-14, TC-18) |
| **pingauthorize** | PingAuthorize, the PDP, through AuthZEN | Decides each call on its action, arguments and context, e.g. permits reads, denies payments over 1000 | Business policy separate from code (TC-08) |
| **pingauthorize-pap** (8448, local) | PingAuthorize's Policy Administration Point | Holds the policy, authored through its API (`gateway/pingauthorize/author-policy.py`) and deployed to the PDP as a package | Policy authored and versioned through an API, not by hand (TC-08) |

## Control centre

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **marketplace** (3000) | The agent marketplace: Agent registry and control centre | Holds the catalogue. On approval it deploys a Principal version: Raidiam statement, CSRs, roles, hosting, SPIRE entry, OpenBao key. It suspends and reinstates versions, runs scenarios as them, collects evidence packs, and shows the objectives report. An operator signs in to Raidiam through it | The registry event that drives the identity workflow, and the place the PoC is demonstrated and evidenced (TC-01, TC-06, TC-07) |
| **marketplace-mongo** | The marketplace's database | Keeps the catalogue, deploy progress, runs, the hash-chained evidence packs, and the Raidiam session | Evidence that survives restarts, and can be checked for tampering (TC-18) |

## Tooling

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **harness.py** | The end-to-end test harness | Runs 63 checks, mapped to the objectives, and writes `reports/latest.json` for the objectives page | Repeatable proof that the whole rig works (TC-19, TC-21) |
| **probe.py** | The harness's probes | Tries what the agent never would: forged, replayed and stolen tokens, and Shared Signals events | Proves the refusals, not only the successes (TC-04, TC-14) |
| **up.sh** + **terraform** | PingFederate's build and configuration | Authors PingFederate's configuration with terraform, exports it as an archive, renders keys and settings, and starts PingFederate. With `RAIDIAM_BRIDGE_BACKING=vault` it points the bridge at OpenBao | The environment rebuilds from code (TC-21) |
| **raidiam/*.sh** | Key and CSR scripts | Make the federation keys and CSRs for the provider, agents, resources and PingFederate's signing key | Raidiam certifies keys made here; it never sees a private one (TC-26) |
