# pf-agentic-identity

Agentic and workload identity for PingFederate: OpenID Federation 1.0, OAuth 2.0 Attestation-Based Client
Authentication, Rich Authorization Requests with an external policy decision point, Shared Signals (SSF, CAEP
and RISC), a device enrolment service and the Grant Management API, delivered as PingFederate modules, a war
and plugin jars. This repository carries the released artefacts, the documentation an operator needs to
configure, deploy and upgrade them, and the specifications they implement.

Generated from a private source repository at each release; raise issues here, pull requests are not accepted.
The source code is not published here.

## Download and verify a release

Each release's assets are on its release page: the module jars, `oidf.war`, `gm-api.war`, the plugin jars,
`MANIFEST`, `SHA256SUMS` and `PROVENANCE.txt`. With the GitHub CLI:

```sh
gh release download v0.7.0 -R ID-Partners/pf-agentic-identity -D vendor/
```

or anonymously, one asset at a time:

```sh
curl -fsSLO https://github.com/ID-Partners/pf-agentic-identity/releases/download/v0.7.0/SHA256SUMS
curl -fsSLO https://github.com/ID-Partners/pf-agentic-identity/releases/download/v0.7.0/<asset>
```

Then check every file against `SHA256SUMS` before you use it, and record what you took:

```sh
( cd vendor && sha256sum -c SHA256SUMS )          # Linux
( cd vendor && shasum -a 256 -c SHA256SUMS )      # macOS
grep -E '^(commit|tag):' vendor/PROVENANCE.txt >> VENDORED.txt
```

`PROVENANCE.txt` names the source commit and the tag the release was built from. Every release here, from
v0.3.0, carries the assets it was first published with in the source repository, so its checksums are unchanged.

This release runs on PingFederate 13.1.3. Every release here is a `jakarta.servlet` build for
PingFederate 13.1.x; the v0.1.x releases, built for 13.0.x, are not published here.

## The image and the demo

`image/` builds a PingFederate image with this release's modules merged into PingFederate's own war. Stage the
release's assets into it, verified against `SHA256SUMS`, then build:

```sh
image/stage-from-release.sh 0.7.0
docker build --target capability image/
```

[image/README.md](image/README.md) describes the targets, the build arguments and the runtime environment.

`demo/` is a conformance rig: `demo/up.sh` stages the same release, boots a configured PingFederate in Docker and
prints where it answers. It needs Docker and Terraform, and a PingFederate licence of your own: the image bakes
none. Either Ping DevOps credentials, with which PingFederate fetches an evaluation licence at boot, or a
`pingfederate.lic` file - "Licensing PingFederate", below. [demo/README.md](demo/README.md) says what the rig
configures.

## Licensing PingFederate

The image carries no licence and accepts no licence agreement for you. Whatever you license it with, set
`PING_IDENTITY_ACCEPT_EULA=YES` at run time, or the entrypoint stops the boot. Then give it one of two things.

**Ping DevOps credentials (the default).** `PING_IDENTITY_DEVOPS_USER` and `PING_IDENTITY_DEVOPS_KEY` in the
container's environment; the base image's licence hook fetches an evaluation licence with them at every start.
Register at https://devops.pingidentity.com/how-to/devopsRegistration/. Evaluation licences are short-lived (about
seven days) and re-fetched only when the container starts, and each start needs Ping's licence service to be
reachable.

**A licence file (`pingfederate.lic`).** The licence Ping Identity issued you - a production, development or
extended evaluation licence - used as it is, with no DevOps account and no call to Ping at boot. The base image's
licence hook fetches an evaluation licence only when the server has no `pingfederate.lic`, and its bootstrap copies
everything under `/opt/in` over the server before the hooks run, so a file at

```
/opt/in/instance/server/default/conf/pingfederate.lic
```

is the licence PingFederate starts with, and the DevOps variables can be left out. The licence must cover the
PingFederate version the image runs (13.1.3 for this release; the file's `Version` line says which it covers), and
PingFederate's user (uid 9031, gid 0) must be able to read it.

- **The demo rig:** `PF_LICENSE_FILE=/path/to/pingfederate.lic demo/up.sh`. It licenses both PingFederates the rig
  starts - the authoring server Terraform configures (`author.sh` stages the file into it) and the rig itself
  (`demo/docker-compose.license.yml` mounts it read-only) - and `~/.pingidentity/config` is then not needed. It
  works with every profile, `PF_PROFILE=raidiam` included.
- **Your own Docker Compose:** mount it.

  ```yaml
  services:
    pingfederate:
      environment:
        PING_IDENTITY_ACCEPT_EULA: "YES"
      volumes:
        - ./pingfederate.lic:/opt/in/instance/server/default/conf/pingfederate.lic:ro
  ```
- **Kubernetes:** keep it in a Secret and mount the one key with `subPath`.

  ```sh
  kubectl create secret generic pingfederate-license --from-file=pingfederate.lic=./pingfederate.lic
  ```
  ```yaml
  volumeMounts:
    - name: license
      mountPath: /opt/in/instance/server/default/conf/pingfederate.lic
      subPath: pingfederate.lic
      readOnly: true
  volumes:
    - name: license
      secret:
        secretName: pingfederate-license
  ```
- **A server profile:** put it at `instance/server/default/conf/pingfederate.lic` in the profile; the base image
  lays the profile over `/opt/in` the same way.

Do not `COPY` a licence into an image you build from this one: every layer is distributed with the image, and
anyone who can pull it has your licence. Keep it out of git as well (`demo/.gitignore` ignores `*.lic`). To move
from one way to the other, add or remove the file; a file that is present wins over the DevOps variables, which
are then never used. A licence that has expired, or does not cover 13.1, leaves PingFederate unlicensed, with the
reason in its log (`docker logs <container>`).

## Setting up agents in Raidiam

With `PF_PROFILE=raidiam` PingFederate is an OpenID Provider in Raidiam's federation, and the rig's agents are
federation entities under Raidiam's authority. PingFederate holds nothing per agent in advance: its attester reads
each agent's SPIFFE binding from Raidiam, and its token endpoint registers the agent from its trust chain at the
agent's first attested token request (`OIDF_ATTESTATION_AUTO_REGISTRATION=true`). Set up the profile itself first -
PingFederate's authorisation server record in Raidiam, SPIRE, and the rig - as
[demo/raidiam/README.md](demo/raidiam/README.md#running-it) says.

Every agent then needs four things: a **software statement** in Raidiam, a **SPIFFE identity** in SPIRE, a **bridge
key** that PingFederate signs the agent's client assertions with, and an **Entity Configuration** that says who the
agent is. Who serves that Entity Configuration is the one choice:

| | Raidiam-hosted metadata (the Principal agents) | Self-hosted metadata (the sub-agents) |
|---|---|---|
| The statement's management type | **Federation managed** (`openid_entity_federation_managed` in the admin API) | **Self managed** |
| The agent's Entity Identifier | Raidiam's: `https://rp.directory.cba.raidiam.io/openid_relying_party/<statement id>` | yours: the statement's `ClientId`, an HTTPS URL you serve, e.g. `https://agents.example.com/agent/accounts-agent` |
| Its Entity Configuration | served and signed by Raidiam | served by the agent at `<entity id>/.well-known/openid-federation`, signed with its own entity key |
| Keys certified in Raidiam (`rtssigning`) | one: the bridge key | two: the entity key and the bridge key |
| Who can resolve it | anyone, Raidiam's own resolver included | only those who can reach it - in a protected network, PingFederate and your own components ([PROTECTED-ENVIRONMENTS.md](demo/raidiam/PROTECTED-ENVIRONMENTS.md)) |
| In the rig | deployed by the agent marketplace | `accounts-agent` and `payments-agent` (`demo/spire-workload/sub_agent.py`) |

### What both kinds need in Raidiam and SPIRE

- **The SPIFFE binding**, on the statement's `AdditionalSoftwareMetadata`. Raidiam's authority publishes it as value
  policies on the agent's `openid_relying_party` metadata, which no entity can override, and PingFederate's attester
  attests a JWT-SVID only for the agent whose binding names it and names PingFederate:

  ```json
  {
    "spiffe_id": "spiffe://example.org/accounts-agent",
    "spiffe_trust_domain": "example.org",
    "spiffe_bundle_endpoint": "https://host.docker.internal:8445/keys",
    "client_attesters": ["https://<PingFederate's issuer>"]
  }
  ```

  Raidiam keeps at most 255 characters of it, counted on its own re-serialisation, so leave out anything else
  (`spiffe_bundle_format` included). `spiffe_bundle_endpoint` must serve SPIRE's *current* JWT-SVID keys with `use`
  `sig` or no `use`: SPIRE's OIDC Discovery Provider (the rig's `spire-oidc`), not SPIRE's own bundle endpoint. One
  SPIFFE ID binds one agent; an ID two statements bind is refused at issuance.
- **Its roles**, as authority claims on the statement (`POST .../softwarestatements/{id}/authorityclaims`, from the
  organisation's own claims): `cba.agentic.member` and a capability role, such as `cba.agentic.servicing.assistant`
  (`accounts_read`, `openid_credential`). The agent's `authorization_details_types` come from these roles, not from
  fields on the statement.
- **A SPIRE registration entry** whose SPIFFE ID is the binding's, selected by the agent's workload - in the rig,
  `spiffe://example.org/<name>` ← `docker:label:app:<name>`.
- **The status.** `Active`; setting it `Suspended` withdraws the authority's statement about the agent (its `/fetch`
  answers 404), so its chain no longer resolves. The marketplace's suspend also raises a Shared Signals
  `account-disabled` at PingFederate's transmitter.

### Raidiam-hosted metadata

Approve a Principal version in the agent marketplace (http://localhost:3000) and it does all of it, against
Raidiam's admin API and OpenBao: a statement set to Federation managed, related to PingFederate, the SPIFFE binding, the
bridge key `bridge-<statement id>` created in OpenBao (not exportable; OpenBao makes and signs its CSR), its
`rtssigning` certificate, the roles, the SPIRE entry `spiffe://example.org/agent-<first 8 characters of the
statement id>`, and a wait until Raidiam serves and vouches for the Entity Configuration. It needs the rig started
with `RAIDIAM_BRIDGE_BACKING=vault` and an operator signed in to Raidiam from the marketplace.
[demo/raidiam/README.md](demo/raidiam/README.md#the-control-centre-the-marketplace-deploys-principal-versions) lists
each call, if you would rather make them yourself.

### Self-hosted metadata

The agent serves its own Entity Configuration, and Raidiam only vouches for it. For an agent called `<name>`, at
`<origin>/agent/<name>` (in the rig, `<origin>` is `RAIDIAM_PROVIDER_ID`, Kong on `https://host.docker.internal:8443`):

1. **Choose the Entity Identifier** - `<origin>/agent/<name>`, an HTTPS URL PingFederate can reach. It becomes the
   statement's `ClientId`, which Raidiam does not let you change afterwards, and the `client_id` PingFederate
   registers.
2. **Make its keys** - an entity key, which signs the Entity Configuration, and a bridge key, which PingFederate
   signs the agent's client assertions with (RSA 2048, `PS256`):

   ```sh
   AGENT=<name> demo/raidiam/attested-client.sh keys     # keys/raidiam/agents/<name>/entity.* and bridge.*
   ```
3. **Register it in Raidiam** - a software statement under your organisation, its management type **Self managed**, `ClientId` the Entity
   Identifier, `private_key_jwt`, related to PingFederate's authorisation server; then certify both keys as
   `rtssigning` from their CSRs, and add the SPIFFE binding and the roles (above):

   ```sh
   AGENT=<name> demo/raidiam/attested-client.sh csr <statement id> ["/C=GB/O=<framework org>/OU=<org id>"]
   ```

   An agent other agents call is also a resource: add an ApiResource on PingFederate's authorisation server record,
   under an API family of its own, whose `resource` is byte-for-byte the `ClientId`
   ([demo/gateway/README.md](demo/gateway/README.md)).
4. **Serve its Entity Configuration** at `<entity id>/.well-known/openid-federation`, as
   `application/entity-statement+jwt`, signed afresh with a short `exp` (the rig: an hour). It must carry:
   - `iss` and `sub` the Entity Identifier, and `authority_hints` Raidiam's authority;
   - `jwks` the entity key's public half, and a JWS header `kid` matching it - the `kid` *Raidiam* gives that key in
     its statement about the agent (the authority's `federation_fetch_endpoint`, `?sub=<entity id>`), which is not
     the key's thumbprint. Raidiam names certified keys its own way, and PingFederate looks the `kid` up in the keys
     the chain vouches for;
   - `metadata.openid_relying_party`: `client_registration_types` including `automatic`, `grant_types`,
     `token_endpoint_auth_method` `private_key_jwt`, and `jwks` the **bridge** key's public half - those are the keys
     the client authenticates with;
   - for an agent that is also a resource, `metadata.oauth_resource` (and the same document at
     `<entity id>/.well-known/oauth-protected-resource`).

   The SPIFFE binding is **not** in it: it is Raidiam's word, read from Raidiam. In the rig, `sub_agent.py`
   (`SelfHosted`) does all of this from `AGENT_ID`, `AUTHORITY_HINT`, `ENTITY_KEY_FILE` and `BRIDGE_JWKS_FILE`, looks
   up Raidiam's `kid` at start-up and hourly, and Kong routes `/agent/<name>/.well-known/` to it.
5. **Let PingFederate reach it.** The modules' federation fetches trust the JVM's `cacerts` and nothing else: with a
   publicly trusted certificate there is nothing to do; with the rig's own CA, `raidiam/render-runtime-keys.sh`
   builds the trust store `docker-compose.raidiam.yml` mounts over `cacerts`. A host on a private address must be in
   `OIDF_FETCH_HOST_ALLOWLIST`, which `up.sh` sets from `RAIDIAM_PROVIDER_ID`'s host.
6. **Give PingFederate its bridge key.** `RAIDIAM_HOSTED_AGENTS="<name> ..."` with `RAIDIAM_PROVIDER_ID` on `up.sh`
   adds `<origin>/agent/<name>` to the bridge-keys file: the key itself from `keys/raidiam/agents/<name>/`, or with
   `RAIDIAM_BRIDGE_BACKING=vault` the OpenBao key `bridge-<name>` (`demo/openbao/setup.py` imports it). The rig's
   Terraform knows `accounts-agent` and `payments-agent` as resources; another agent that is a resource needs its
   own token manager, as `terraform/resource.tf` makes theirs.

   ```sh
   PF_PROFILE=raidiam SPIRE_BUNDLE_FILE=$PWD/spire-bundle.json PF_BASE_URL=https://<your public issuer> \
   RAIDIAM_PROVIDER_ID=https://host.docker.internal:8443 RAIDIAM_HOSTED_AGENTS="accounts-agent payments-agent" \
   demo/up.sh
   cd demo/spire-workload && docker compose up -d spire-oidc accounts-agent payments-agent gateway-agents
   ```
7. **Check it.** The Entity Configuration answers, and Raidiam vouches for it:

   ```sh
   curl -sk https://localhost:8443/agent/<name>/.well-known/openid-federation     # a JWT; iss = sub = the entity id
   curl -s "<authority's federation_fetch_endpoint>?sub=<url-encoded entity id>"   # Raidiam's statement about it
   ```

   PingFederate registers the agent at its first attested token request, and logs `verified attestation ...`;
   `python harness.py` in `demo/spire-workload` runs the flows end to end. Every restart of PingFederate drops the
   registrations, and each agent is registered again at its next attested request.

## Documentation

- [docs/operator/](docs/operator/README.md) - deploying, health, preflight and upgrading.
- [docs/configuration/](docs/configuration/README.md) - every setting, by component.
- [docs/federation/](docs/federation/README.md) - OpenID Federation: how it works, configuration, limits.
- [docs/releases/](docs/releases/README.md) - each release's notes, and [CHANGELOG.md](CHANGELOG.md).

Report a vulnerability as [SECURITY.md](SECURITY.md) says, never in an issue.

## Licence

Apache License 2.0: [LICENSE](LICENSE) and [NOTICE](NOTICE). PingFederate and the Ping Identity images are
Ping Identity's, under their own licence.
