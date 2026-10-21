# The rig's components

Every component the rig runs, grouped by layer: what it is, what it does, and why it matters for the PoC. For the parties
in the flows and the flows themselves, see [flows.md](flows.md). Ports are the host's.

## Trust and federation

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **Raidiam** (external) | The CBA federation's Trust Controller: its authority, trust anchor, directory and admin API | Holds software statements, certified public keys and roles. It hosts and signs each Principal version's Entity Configuration (a federation-managed statement), publishes signed subordinate statements with keys and metadata policy (the capability envelope and the SPIFFE bindings), lists entities, and stops vouching for a suspended statement | The single source of who an agent is and what it may do. Every party trusts an agent only through a chain to Raidiam's pinned anchor (TC-02, TC-10, TC-27) |
| **ngrok** (external) | A public tunnel to PingFederate's runtime port | Gives PingFederate a public issuer (`PF_BASE_URL`), so Raidiam can fetch its discovery document and Entity Configuration | Raidiam must reach PingFederate to vouch for it. Everything else stays inside the protected network (TC-13) |

## Identity provider

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **PingFederate** (`pf-agentic-identity`, 9031) | PingFederate 13.1.3 with the OpenID Federation modules (0.7.0, plus the OpenBao bridge change) | The bank's authorisation server: it issues every token, DPoP-bound to the agent's instance key, for one resource. It publishes its own Entity Configuration under Raidiam. Its configuration is authored by terraform and baked into an archive | Shows that the existing enterprise authorisation server can join the federation as it is (TC-09, TC-12) |
| ↳ federation and registration modules | Servlets and filters in PingFederate | Resolve and validate agents' chains to the pinned anchor, apply Raidiam's metadata policy, and register agents from it. Once an agent's attestation verifies at the token endpoint, a client PingFederate does not have is registered by discovery through its chain (`OIDF_ATTESTATION_AUTO_REGISTRATION=true`): nobody registers agents beforehand, and an unauthenticated request triggers no discovery | The client is built from the Trust Controller's trust material, not configured by hand or ahead of time (TC-09, TC-10, TC-01) |
| ↳ attester | PingFederate's co-hosted client attester, the rig's only attester | Attests an agent instance on its SPIRE JWT-SVID. It reads the agents' SPIFFE bindings from Raidiam's authority (`OIDF_ATTESTER_FEDERATION_AUTHORITY`, `OIDF_ATTESTER_ISSUER`; resolver `openid-federation-authority`): it lists the authority's relying parties, resolves each chain to the pinned anchor, and takes those whose resolved metadata has a `spiffe_id` and `spiffe_bundle_endpoint` and names PingFederate in `client_attesters`. It signs with a key PingFederate's Entity Configuration publishes | Ties a token to an attested workload, with the attester itself trusted through the federation (TC-28, TC-11) |
| ↳ attestation auth (bridge) | The `attest_jwt_client_auth` filter at the token endpoint | Verifies the attestation and DPoP proof, then signs a `private_key_jwt` for the agent with its bridge key, the only credential PingFederate's engine accepts. The assertion's `kid` is the one the client's registered keys (for a Principal, Raidiam's `jwks_uri`) give the bridge key, matched on the key. The bridge-keys file names each key: `bridge-{client_suffix}` for every client under `https://rp.directory.cba.raidiam.io/openid_relying_party/`, and an entry per sub-agent (`bridge-accounts-agent`, `bridge-payments-agent`) | Lets an attested instance authenticate with no client key of its own (TC-26, TC-28) |
| ↳ token exchange | An RFC 8693 processor and token managers per resource | Exchanges the caller's token for one at the next resource: `sub` the caller, `act` the acting agent, bound to that agent's own key | Makes delegation between agents explicit and checkable at every hop (TC-03, TC-27) |
| ↳ SSF transmitter | PingFederate's Shared Signals transmitter | Emits CAEP and RISC events (`session-revoked`, `account-disabled`, `account-enabled`) to its receivers' streams | Carries lifecycle events to enforcement in seconds (TC-04) |

## Key management

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **OpenBao** (`openbao`, 8200) | OpenBao's transit engine, standing in for the bank's KMS or HSM (`RAIDIAM_BRIDGE_BACKING=vault`; Principal versions need it, having no key files) | Holds each agent's bridge key, never exported. It creates a key when the marketplace enrols an agent and makes and signs its CSR for Raidiam, and it signs PingFederate's bridge assertion at each attested token request. PingFederate's token may only sign; the marketplace's enrolment token may only create keys and get their CSRs | No bridge private key sits in a file or in PingFederate's configuration. Keys are found by name, so agents are enrolled with no limit and no restart (TC-26, TC-01) |
| `openbao/setup.py` | The vault's set-up script | Initialises OpenBao once, unseals it (after every restart), enables transit, writes the two policies and their tokens (`pf-bridge.token` for PingFederate, `enrolment/enrolment.token` for the marketplace), and imports the bridge keys already in use | Makes the vault reproducible, and keeps keys Raidiam already certified valid when moving to it (TC-21) |

## Workload identity

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **SPIRE server** (`spire-spire-server-1`, 8081) | The SPIFFE trust domain's server, `example.org` | Holds the registration entries (SPIFFE ID ← Docker label) and signs SVIDs. The marketplace adds an entry for each version it deploys (`spiffe://example.org/agent-<first 8 characters of its statement id>`) | The authority for which workload is which agent (TC-28) |
| **SPIRE agent** (`spire-spire-agent-1`) | The node agent, attested to the server with x509pop | Identifies each container by its Docker labels and issues it a JWT-SVID through the Workload API | An agent's identity comes from what the platform observes, not from anything the agent claims (TC-28) |
| **SPIRE OIDC provider** (`spire-oidc`, 8445) | SPIRE's OIDC Discovery Provider | Serves the trust domain's live JWT-SVID keys, which the attester verifies SVIDs against | SPIRE's key rotations reach every verifier, and with the keys unreachable nothing is attested (TC-28) |

## Agents

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **gateway-agents** (Kong, 8443; `gateway/kong/agents.yml.template`) | The sub-agents' edge, at `https://host.docker.internal:8443` (the origin `RAIDIAM_PROVIDER_ID` names) | Passes `/agent/<name>/.well-known/*` to the sub-agent itself, routes `/agent/<name>/mcp*` through coaz-pep, and routes `/cb` to the marketplace (its Raidiam sign-in callback) | One origin for the agents other agents call, as their identifiers require: each agent's identity and its MCP under the same URL (TC-05, TC-03) |
| **agent** (run on demand) | The Principal agent (`agent.py`), one container per run, as a Principal version the marketplace deployed: Raidiam hosts its Entity Configuration, and the container runs under the version's workload label (`agent-<first 8 characters of its statement id>`) | Gets its instance attested, reads its envelope from Raidiam, finds resources and agents by capability, gets DPoP-bound tokens, calls resources or delegates to sub-agents. It reports each step (`AGENT_RESULT`) | The subject of the PoC: an autonomous workload acting under the bank's controls (TC-03) |
| **accounts-agent**, **payments-agent** | Sub-agents (`sub_agent.py`): each a client and an MCP resource at `https://host.docker.internal:8443/agent/<name>`, with its own Raidiam statement | Serve their own Entity Configuration, signed with their entity key (`keys/raidiam/agents/<name>/`) under the kid Raidiam publishes, and their protected resource metadata. Accept a call from the Principal, exchange its token, and call their resource with a token bound to their own instance. Their SPIFFE bindings are on their Raidiam statements, and PingFederate registers them at their first attested token request | Agents calling agents, with delegation checked at every hop (TC-27) |

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
| **marketplace** (3000) | The agent marketplace: Agent registry and control centre | Holds the catalogue. On approval it deploys a Principal version: a federation-managed Raidiam statement (Raidiam hosts its Entity Configuration), its SPIFFE binding, its bridge key created in OpenBao (enrolment token) and certified by Raidiam, its roles and its SPIRE entry, then waits until Raidiam vouches for it. It suspends and reinstates versions (Raidiam status and Shared Signals), runs scenarios as them, collects evidence packs, and shows the objectives report. An operator signs in to Raidiam through it | The registry event that drives the identity workflow, and the place the PoC is demonstrated and evidenced (TC-01, TC-06, TC-07) |
| **marketplace-mongo** | The marketplace's database | Keeps the catalogue, deploy progress, runs, the hash-chained evidence packs, and the Raidiam session | Evidence that survives restarts, and can be checked for tampering (TC-18) |

## Tooling

| Component | What it is | What it does | Why it matters |
|---|---|---|---|
| **harness.py** | The end-to-end test harness | Tests the newest Principal version the marketplace deployed, which Raidiam hosts: 64 checks mapped to the objectives (63 passed, 1 skipped at the last run), among them that Raidiam hosts and vouches for the agent, that each sub-agent serves its own Entity Configuration, that PingFederate's attester reads the bindings from Raidiam, and that PingFederate registered the agent on its verified attestation. It writes `reports/latest.json` for the objectives page | Repeatable proof that the whole rig works (TC-19, TC-21) |
| **probe.py** | The harness's probes | Tries what the agent never would: forged, replayed and stolen tokens, and Shared Signals events | Proves the refusals, not only the successes (TC-04, TC-14) |
| **up.sh** + **terraform** | PingFederate's build and configuration | Authors PingFederate's configuration with terraform, exports it as an archive, renders keys and settings, and starts PingFederate. With `RAIDIAM_BRIDGE_BACKING=vault` it points the bridge at OpenBao | The environment rebuilds from code (TC-21) |
| **raidiam/*.sh** | Key and CSR scripts | Make the federation keys and CSRs for the sub-agents, resources and PingFederate's signing key. A Principal version has no key files: its bridge key is created in OpenBao | Raidiam certifies keys made here; it never sees a private one (TC-26) |
