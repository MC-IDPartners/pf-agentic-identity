# Running in a protected environment

What changes when every component - PingFederate, the agents, the resource servers - is
privately hosted (for example in a bank's AWS accounts) and can call Raidiam, but Raidiam cannot call back.

This rig already runs that way: nothing on `host.docker.internal` is reachable from Raidiam, so each point below was
either observed here or follows directly from it. Where something is inferred rather than observed, it says so.

## Summary

| Interaction | With outbound-only connectivity |
|---|---|
| Your entities calling Raidiam (fetch, list, keystore) | Works |
| Internal parties resolving each other (PingFederate, agent, resource) | Works, with chains resolved locally - as PingFederate does, and the agent and resource do with `spire-workload/fedresolve.py` |
| Your agent calling an external authorisation server or API | Only with the trust chain carried in the request |
| Raidiam listing your entities, and vouching for them (`/list`, `/fetch`) | Works |
| An external party, or Raidiam, resolving your entities (`/resolve`, the listing's status) | Does not work, except for entities Raidiam hosts (the Principal agents, see 4) |
| Raidiam telling you about a withdrawal or a change | Does not work - poll instead |

## Hard roadblocks

These follow from the connectivity itself; no configuration removes them.

### 1. Nobody outside can resolve your entities

Resolving an entity starts by fetching its own Entity Configuration (`<entity>/.well-known/openid-federation`).
Another bank's authorisation server, a partner's agent, or Raidiam's own resolver cannot reach it. Observed:
Raidiam's `/resolve` for this rig's entities answers *failed to retrieve leaf entity configuration*.

**Way round it:** carry the chain in the request. The `federation` flow puts the agent's whole chain in the client
assertion's `trust_chain` header, and PingFederate validates it without fetching anything (OIDFED §12.1). For an
attested client, the attestation can carry the attester's chain the same way.

**Limit:** every outbound call must carry its chain, and a party that insists on discovering you itself cannot be
used.

### 2. Raidiam lists private entities, but cannot check them

Raidiam's `/list` does name the rig's private entities - the agents under `openid_relying_party`, an agent other
agents call under `oauth_resource` once its ApiResource is processed - and its `/fetch` returns its signed statement
about each without reaching them. (Earlier in the rig's life they were missing from `/list`, apparently until their
roles and ApiResources were in; the reason was not that Raidiam could not reach them.)

What fails is everything that fetches the entity itself: Raidiam's `/resolve` (404), and the status a listing shows
for an entry - *entity configuration: … Max retries exceeded … /agent/payments-agent/.well-known/openid-federation
(ConnectTimeoutError)*: from Raidiam's network the internal name leads nowhere.

So discovery and trust work from outside the network - an identifier from `/list`, Raidiam's statement from
`/fetch` - and resolution has to happen inside it, by a party that can reach the entity's own configuration: the
rig's agents and resources resolve chains themselves (`spire-workload/fedresolve.py`), as PingFederate does.
Expect the listing's status column to show these errors for every private entity; they are not faults.

### 3. Raidiam cannot push anything

Software statements carry a notification webhook (`NotificationWebhookStatus`), which cannot reach a private
endpoint. When the bank withdraws an agent in Raidiam, nothing tells PingFederate; it notices at its next chain
resolution:

| Where | How long a withdrawn agent can keep working |
|---|---|
| PingFederate's attester (the bindings it reads from Raidiam's authority) | up to 300 s (how often it reads the authority) |
| A registration at PingFederate | until its chain expires, about 20 minutes |
| A resource server's membership check (`rs_accounts.py`) | up to 300 s, or the chain's expiry if sooner |

Plan for polling, or shorter cache lifetimes - or signal inside the network: the gateway's PEP receives Shared
Signals from PingFederate's transmitter and refuses a revoked or disabled agent within about two seconds
(`../gateway/README.md`, "Shared Signals"). The party that knows - the marketplace, which suspends the agent - is
inside the network too.

## Workable, but to fix for production

### 4. Federation-managed entities, hosted by Raidiam

Raidiam hosts each Principal agent's Entity Configuration: every Principal version is a federation-managed statement,
at `https://rp.directory.cba.raidiam.io/openid_relying_party/<statement id>`, signed by Raidiam. That removed the need
for an internal entity host, the agent provider (`entity-host`), which the rig no longer has. It also takes the
Principals out of roadblock 1: their configurations are on Raidiam's host, so anyone can resolve them.

Two things stopped this before, and both are now fixed in Raidiam:

- its federation-managed configurations had no `authority_hints`, so they could not be resolved (PingFederate:
  *Leaf JWT not found in trust chain*). They now carry them and resolve through the authority (checked 2026-10-18);
- `AdditionalSoftwareMetadata` was never published, so workload details such as SPIFFE bindings could not travel
  through Raidiam. The authority now publishes it as value policies on `openid_relying_party`, and PingFederate's
  attester reads the bindings from there.

What remains: Raidiam keeps at most 255 characters of that metadata (counted on its own re-serialisation, and over it
answers 500 rather than a validation error), so it carries the SPIFFE binding and nothing else. The sub-agents, which
other agents call, still serve their own Entity Configurations from inside the network.

### 5. Shared organisation keys

Raidiam's statement about an entity lists the whole organisation's key set (16 keys for CBA-123, other teams' among
them - CBA's agent provider's, for one) besides the entity's own certified keys. So any holder of an organisation key
can sign an Entity Configuration Raidiam will vouch for under any of the organisation's entity identifiers.

Raise this with Raidiam and the bank's security team: per-entity keys, or at least per-team key sets, would limit
the blast radius.

### 6. PingFederate's trust store

The OpenID Federation modules' outbound HTTPS - chain resolution, remote JWKS, SPIRE bundles - trusts only the JDK's
`cacerts` file. Not PingFederate's trusted CAs, and not `-Djavax.net.ssl.trustStore`.

With a private CA, the image needs a `cacerts` holding the public roots (for Raidiam) **and** the private CA (for the
internal entities). It must be an unprotected PKCS12, as the JDK builds its own (`certProtectionAlgorithm=NONE`,
`macAlgorithm=NONE`); keytool's default encrypts the certificates, and the JVM then reads the store as empty.
`render-runtime-keys.sh` shows how.

### 7. PingFederate 0.7.0 does not register unknown clients at the token endpoint

`TokenChannel.discoversUnknownClients()` is false in 0.7.0, so an agent had to be registered explicitly
(`/federation/register`) - the agent provider's job - and registered again before each registration ended with its
chain.

The rig's modules now do what Raidiam's own authorisation server does: with `OIDF_ATTESTATION_AUTO_REGISTRATION=true`,
once an attestation verifies, a client PingFederate does not have is registered by discovery through its chain. A
request that is not authenticated still discovers nothing. A restart of PingFederate still drops the registrations,
and each agent is registered again at its next attested token request. The change is newer than 0.7.0 and not yet in
a release.

### 8. Entity identifiers are permanent

An entity identifier is a Raidiam software statement's `ClientId`, which cannot be changed. In a private network it
must be an internal DNS name (a Route 53 private hosted zone, say) that every internal party resolves to the same
service, on the same port. Choose the final names before registering anything; moving a service means new statements,
new keys and new CSRs.

### 9. PingFederate's own entity

- If PingFederate's issuer is private too, nobody outside can resolve it, or read its discovery document.
- Its `authority_hints` must name the CBA authority, which vouches for its issuer, not the anchor, which does not
  (`OIDF_FEDERATION_TRUST_ANCHORS` in `vars.raidiam.env`; client chains are unaffected - tested with every flow).
- It signs its Entity Configuration with PingFederate's current OAuth signing key, which PingFederate generates and
  rotates itself, so Raidiam has never certified it: Raidiam's resolver refuses the chain (*subordinate statement
  ... does not contain the key used to sign the subject entity's Entity Configuration*). The fix is static OAuth/OIDC
  signing keys - a key Raidiam certified, imported into PingFederate - which makes rotation a manual, certified step.
  Done here (`raidiam/pf-signing.sh`, `terraform/signing-keys.tf`): an organisation-level `server_signing`
  certificate, as CBA's authorisation servers hold theirs, and Raidiam's `/resolve` now accepts PingFederate's chain.
  Two traps: Raidiam's kid is the certificate's `x5t#S256`, and PingFederate publishes the key once more per
  algorithm under `<kid>_RS256`, which is the one the federation module signs with - so the RS256 key id
  (`rsa_algorithm_active_key_ids`) must be Raidiam's kid itself.

### 10. DPoP

All 18 resources registered in the CBA directory set `dpop_bound_access_tokens_required: true`, and the API family
schemas pin it (`"const": true`). This rig's agent and resource do not use DPoP yet, and PingFederate's token manager
would need DPoP-bound tokens enabled. A CBA family cannot be reused anyway: its schema also pins
`authorization_servers` to that family's own issuer. A resource behind PingFederate needs a family of its own.

## Operational risks

### 11. Raidiam is a runtime dependency on the outbound path

Every new chain resolution calls Raidiam's fetch endpoints (and its keystore, for `jwks_uri`s in policy), through your
egress - a NAT gateway or proxy, with Raidiam's hosts allow-listed. Raidiam's statements last about 20-30 minutes, so
a Raidiam outage longer than that stops new registrations and resolutions; those already cached keep working until
they expire. Monitor the egress path and Raidiam's availability, and size cache lifetimes against it.

### 12. Trust anchor key rotation is manual

PingFederate (`OIDF_FEDERATION_TRUST_ANCHOR_JWKS`) and the agents and resources (`fedresolve.pinned_anchor_jwks`)
pin the anchor's key; that pin is what makes the chains trustworthy. When Raidiam rotates the key, update the pin from
the anchor's Entity Configuration, checked out of band.

### 13. The rig's development shortcuts

| Shortcut | In production |
|---|---|
| Attester trust | already as in production: no `oidf.mock.attesters`; PingFederate's attester, the only one, is trusted through its federation chain |
| Bridge keys in a file (`OIDF_BRIDGE_SIGNER_BACKING=config`) | OpenBao (`vault`) |
| Attester private keys inline (`OIDF_ATTESTER_SIGNING_JWK`, `attestation_signing_jwk`) | an OpenBao key reference |
| TLS from the rig's own CA | the bank's private CA (see 6) |
| The marketplace drives Docker through its socket (SPIRE entries, agent runs) | a deployment pipeline with its own, scoped credentials (SPIRE's API, the platform's) |
| An operator's Raidiam session, kept in an unauthenticated Mongo on the compose network | client credentials (`directory:management`) once Raidiam allows them, secrets in a vault |
| The SSF emitter's secret mounted into the marketplace (`secrets.env`) | the lifecycle events raised by the Trust Controller as an SSF transmitter |
| OpenBao on plain HTTP, one unseal key and its root token in `keys/openbao/` | TLS, Shamir shares or auto-unseal through a KMS/HSM, no root token at rest |

## What already works

- PingFederate resolves internal entities itself, fetching each leaf internally and only the statements from Raidiam.
- `spire-workload/fedresolve.py` does the same for the agent and the resource: leaf from inside, the authority's and
  the anchor's statements from Raidiam's `/fetch`, every signature verified down from the pinned anchor key, Raidiam's
  policy applied.
- PingFederate's attester attests instances on SPIRE's word, against the SPIFFE bindings Raidiam's authority
  publishes, and its attestations are trusted through PingFederate's chain.
- Raidiam hosts the Principal agents' Entity Configurations, and PingFederate registers an agent from its chain at its
  first attested token request - nobody registers it beforehand.
- The bridge keys are created in OpenBao when an agent is deployed, and only their CSRs leave it.
- A resource is vouched for by Raidiam - a software statement with its identifier as `ClientId`, plus an ApiResource
  - without Raidiam reaching it.
