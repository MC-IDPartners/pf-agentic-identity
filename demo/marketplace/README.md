# CBA Agent Marketplace

A small agent marketplace that registers software statements in Raidiam Connect.

The catalogue owns the agent as a registered thing. The control plane owns its
identity. Approving an agent here creates its software statement and grants its
roles; suspending it sets that statement to Inactive. The two records are joined
by a reference, not by a copy.

## Run it

```bash
cp .env.example .env     # optional: it runs without one
docker compose up --build
```

Then open <http://localhost:3000>.

With no Raidiam credentials set, the app starts in **mock mode**: no outbound
call is made, identifiers are generated locally, and every step is still written
to the deployment log. The full lifecycle is demonstrable offline.

## The four pages

| Page | What it does |
| --- | --- |
| `/` Catalogue | Every registered agent, its status, entity and role count. Filter by state. |
| `/new` Register | Creates a software statement. Entities and roles come from the directory. |
| `/agents/:id` Agent | The catalogue record, what the control plane issued, and the deployment log. |
| `/instances` Instances | Everything published into Raidiam, with statement ids, roles and status. |

## Lifecycle

```
pending ──approve──> approved ──suspend──> suspended
                        ^                       │
                        └───────approve─────────┘
```

- **pending** — registered in the catalogue. Nothing has reached the control plane.
- **approved** — the software statement is created, each role is granted as an
  authority claim, and the record is read back. Reinstating a suspended agent
  returns its existing statement to Active rather than creating a second one.
- **suspended** — the statement is set to Inactive, so no new trust can be
  established from it.

A refused control-plane write leaves the marketplace status unchanged and records
the refusal in both the log and the history. The record never claims an identity
that was not created.

## Federation entities

Entities are read live from the public participants export at
`https://data.directory.cba.raidiam.io` and cached in Mongo for an hour. If the
directory is unreachable the app falls back to the snapshot in
`seed/participants.json`, and the register page says which it used.

Only the roles an organisation actually holds can be requested. The browser
filters the checklist and the server re-validates, so a role that belongs to a
different entity is rejected rather than sent on.

The snapshot currently carries four entities: `CBA-123` (CBA-Payments, with the
agentic roles and six authorisation servers), `CBA-BANKWEST`, `CBA-COMMSEC` and
`CBA-ASB`.

## Connecting to the live control plane

Set the credentials in `.env` and restart. The masthead switches from
`CONTROL PLANE · MOCK` to `LIVE CONTROL PLANE`.

```bash
RAIDIAM_BASE_URL=https://matls-api.directory.cba.raidiam.io
RAIDIAM_TOKEN_URL=https://matls-auth.directory.cba.raidiam.io/token
RAIDIAM_CLIENT_ID=…
RAIDIAM_CLIENT_SECRET=…
RAIDIAM_SCOPE=directory:software
```

For a tenant that requires mutual TLS, put the files in `./certs` (mounted at
`/certs`) and set:

```bash
RAIDIAM_CERT_PATH=/certs/client.crt
RAIDIAM_KEY_PATH=/certs/client.key
RAIDIAM_CA_PATH=/certs/ca.crt
```

**Check the endpoint paths before you switch off mock mode.** I could not find
published documentation for the Raidiam Connect admin API, so the client is built
against the conventional Open Banking Directory shape. All three paths are
overridable:

```bash
RAIDIAM_PATH_SOFTWARE_STATEMENTS=/organisations/{orgId}/softwarestatements
RAIDIAM_PATH_SOFTWARE_STATEMENT=/organisations/{orgId}/softwarestatements/{ssId}
RAIDIAM_PATH_AUTHORITY_CLAIMS=/organisations/{orgId}/softwarestatements/{ssId}/authorityclaims
```

The response field used for the new statement id is tried in this order:
`SoftwareStatementId`, `softwareStatementId`, `id`. Adjust `src/raidiam.js` if
your tenant returns something else.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/entities` | Federation entities, their authorisation servers and roles. `?refresh=true` forces a re-fetch. |
| `GET` | `/api/agents` | All agents. Filter with `?status=` or `?organisationId=`. |
| `POST` | `/api/agents` | Register an agent. Returns it as pending. |
| `GET` | `/api/agents/:softwareId` | One agent, with its steps and history. |
| `POST` | `/api/agents/:softwareId/approve` | Approve or reinstate. Writes to the control plane. |
| `POST` | `/api/agents/:softwareId/suspend` | Suspend. Sets the statement Inactive. |
| `DELETE` | `/api/agents/:softwareId` | Remove from the catalogue. Refused while approved. |
| `GET` | `/api/instances` | Agents holding a record in Raidiam. |
| `GET` | `/api/config` | Which mode the control plane is in. |
| `GET` | `/healthz` | Liveness. |

Send `x-actor: your.name` on the write calls and it is recorded in the history.

Register one from the command line:

```bash
curl -X POST http://localhost:3000/api/agents \
  -H 'content-type: application/json' \
  -H 'x-actor: robert.harkin' \
  -d '{
    "name": "Accounts Payable Orchestrator 2",
    "description": "Approves and schedules supplier payments inside a bounded envelope.",
    "version": "2.3.0",
    "organisationId": "CBA-123",
    "authorisationServerId": "480a9a34-22c2-4c24-b13b-a5ea51b808aa",
    "roles": ["cba.oidc.participant", "cba.agentic.member", "cba.agentic.ap.orchestrator"],
    "businessUnit": "Business Banking, Accounts Payable",
    "accountableOwner": "Kirsten Yeo, Accounts Payable Product",
    "environment": "sandbox",
    "capability": "supplier-payments",
    "repository": "https://github.com/commbank-agentic/ap-orchestrator",
    "sbom": "sbom/ap-orchestrator-2.3.0.cdx.json"
  }'
```

## Data model

One Mongo collection, `agents`, one document per registered agent:

```js
{
  softwareId: "accounts-payable-orchestrator-2",  // derived from the name, unique
  name, description, version, environment,
  organisationId, organisationName,                // the federation entity
  authorisationServerId, authorisationServerName,
  roles: ["cba.oidc.participant", …],              // requested
  businessUnit, owner, accountableOwner, capability,
  repository, sbom,                                // evidence, held here by reference
  status: "pending" | "approved" | "suspended",
  raidiam: {                                       // null until approved
    entityId, softwareStatementId, signingKid, transportKid,
    rolesGranted: [], statementStatus: "Active" | "Inactive",
    mode: "mock" | "live", payload, publishedAt
  },
  steps: [ { n, kind, message, detail, at } ],     // the deployment log
  history: [ { action, actor, note, at } ]
}
```

`kind` is one of `statement`, `certificate`, `role`, `verify` or `refused`.

A second collection, `cache`, holds the directory snapshot.

## Tests

```bash
npm install
node test/harness.js
```

18 checks covering role validation, the state machine, the published record, the
deployment log and the refused-write path. They stub the Mongo collections, so no
database is needed.

## Notes and limits

- There is **no authentication**. Anyone who can reach the port can approve and
  suspend agents. Fine for a demo on your own machine; add a reverse proxy with
  SSO before putting it anywhere shared.
- Keys are **recorded, not generated**. The log notes a signing and a transport
  key reference. It does not create real key material or call a vault, which is
  the TC-26 "no private key custody" question.
- Deployment is out of scope. This registers identities; it does not deploy
  workloads or talk to SPIRE.
- `AdditionalSoftwareMetadata` is capped at 252 characters, matching the limit on
  the live API. Everything else stays in the catalogue by reference.
- Mongo has no authentication in the compose file and the port is not published,
  so it is only reachable from the app container.
