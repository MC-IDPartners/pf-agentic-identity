# Running in a protected environment

What changes when every component - PingFederate, the agent provider, the agents, the resource servers - is
privately hosted (for example in a bank's AWS accounts) and can call Raidiam, but Raidiam cannot call back.

This rig already runs that way: nothing on `host.docker.internal` is reachable from Raidiam, so each point below was
either observed here or follows directly from it. Where something is inferred rather than observed, it says so.

## Summary

| Interaction | With outbound-only connectivity |
|---|---|
| Your entities calling Raidiam (fetch, list, keystore) | Works |
| Internal parties resolving each other (PingFederate, agent, resource) | Works, with chains resolved locally - as PingFederate does, and the agent and resource do with `spire-workload/fedresolve.py` |
| Your agent calling an external authorisation server or API | Only with the trust chain carried in the request |
| An external party, or Raidiam, discovering or resolving your entities | Does not work |
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

### 2. Self-hosted entities are missing from Raidiam's `/list`

The provider and the agent are absent from the authority's `/list`, although Raidiam vouches for both (its `/fetch`
returns a statement for each). Raidiam most likely cannot list them because it cannot fetch their configurations to
learn their entity types (inferred).

- **Agent-to-agent discovery through Raidiam does not work:** another agent cannot find yours there.
- **Resources are different:** a resource is a software statement whose `ClientId` is the resource identifier, plus
  an ApiResource on its authorisation server's record whose `resource` is that same identifier. Raidiam joins the two
  by identifier: the authority's statement about the resource carries the software statement's keys and policy, and
  the ApiResource's metadata as `oauth_resource` policy - the API family's schema turned into policy (its enums become
  `subset_of`, its required members `essential`). The authority vouches for a private resource without reaching it.
  But `/list?entity_type=oauth_resource` does not list it: hours after the authority vouched for this rig's resource,
  the listing still held only CBA's 18 public ones. An agent inside the network has to know its private resources
  (`RESOURCE_IDS`) - it still verifies each through Raidiam's chain.

### 3. Raidiam cannot push anything

Software statements carry a notification webhook (`NotificationWebhookStatus`), which cannot reach a private
endpoint. When the bank withdraws an agent in Raidiam, nothing tells PingFederate; it notices at its next chain
resolution:

| Where | How long a withdrawn agent can keep working |
|---|---|
| PingFederate's attester (the entity and its bindings) | up to 300 s (its cache) |
| An explicit registration at PingFederate | until its chain expires, about 20 minutes |
| A resource server's membership check (`rs_accounts.py`) | up to 300 s, or the chain's expiry if sooner |

Plan for polling, or shorter cache lifetimes - or signal inside the network: the gateway's PEP receives Shared
Signals from PingFederate's transmitter and refuses a revoked or disabled agent within about two seconds
(`../gateway/README.md`, "Shared Signals"). The transmitters that know - the provider, the marketplace - are inside
the network too.

## Workable, but to fix for production

### 4. Federation-managed entities do not help

Letting Raidiam host each Entity Configuration would remove the need for an internal entity host, but:

- Raidiam's federation-managed configurations have no `authority_hints`, so they cannot be resolved (PingFederate:
  *Leaf JWT not found in trust chain*; Raidiam's own `/resolve` fails the same way);
- `AdditionalSoftwareMetadata` is never published, in either mode, so workload details such as SPIFFE bindings cannot
  travel through Raidiam.

So an internal entity host - the agent provider, `entity-host` here - is needed regardless.

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

`TokenChannel.discoversUnknownClients()` is false, so:

- the provider must register its agents explicitly (`/federation/register`), and keep re-registering them;
- an explicit registration ends when its chain expires (about 20 minutes with Raidiam), and the token endpoint does
  not renew it;
- every restart of PingFederate drops the registrations.

Raidiam's own authorisation server registers an attested agent on its first token request. Doing the same here needs
a change to the module.

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
| `oidf.mock.attesters` (the `spire-workload` client's attester, trusted with no chain) | removed: attesters trusted through the federation only, as the agent provider is |
| Bridge keys in a file (`OIDF_BRIDGE_SIGNER_BACKING=config`) | OpenBao (`vault`) |
| Attester private keys inline (`OIDF_ATTESTER_SIGNING_JWK`, `attestation_signing_jwk`) | an OpenBao key reference |
| The provider's attester key in a mounted file | an HSM or KMS key (AWS KMS, say) |
| TLS from the rig's own CA | the bank's private CA (see 6) |

## What already works

- PingFederate resolves internal entities itself, fetching each leaf internally and only the statements from Raidiam.
- `spire-workload/fedresolve.py` does the same for the agent and the resource: leaf from inside, the authority's and
  the anchor's statements from Raidiam's `/fetch`, every signature verified down from the pinned anchor key, Raidiam's
  policy applied.
- The agent provider attests instances on SPIRE's word, and PingFederate trusts its attestations through the
  provider's chain.
- A resource is vouched for by Raidiam - a software statement with its identifier as `ClientId`, plus an ApiResource
  - without Raidiam reaching it.
