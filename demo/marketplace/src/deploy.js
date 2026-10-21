'use strict';

const config = require('./config');
const raidiam = require('./raidiam');
const rig = require('./rig');
const vault = require('./vault');

/**
 * Deploying a Principal version: the marketplace's control plane work done for real, end to end - with no agent
 * provider. Raidiam hosts the version's identity, the KMS holds its one key, and PingFederate registers it itself.
 *
 *   1. statement     Raidiam: POST /organisations/{org}/softwarestatements - a federation-managed OpenID Federation
 *                    entity: Raidiam hosts and signs its Entity Configuration, at its own identifier, with the keys it
 *                    certified (jwks_uri) and automatic registration; related to PingFederate's authorisation server
 *   2. spiffe        Raidiam: the statement's AdditionalSoftwareMetadata - its SPIFFE ID spiffe://<td>/<label>, the
 *                    trust domain's bundle endpoint, and PingFederate as its attester - which Raidiam's authority
 *                    publishes as value policies, and PingFederate's attester reads
 *   3. bridge key    the KMS (OpenBao): bridge-<statement id>, created there and never exported; the vault makes its
 *                    CSR and signs it
 *   4. certificate   Raidiam: POST .../softwarestatements/{id}/certificates/rtssigning - the bridge key, which
 *                    Raidiam then publishes for the version (its keystore, the Entity Configuration's jwks_uri)
 *   5. role          Raidiam: POST .../softwarestatements/{id}/authorityclaims, one per role, from the
 *                    organisation's own claims (GET /organisations/{org}/authorityclaims)
 *   6. verify        read back: the statement, its certificates, its claims
 *   7. spire         a SPIRE entry: spiffe://<td>/<label> <- docker:label:app:<label>
 *   8. trust         wait until Raidiam serves its Entity Configuration and vouches for it. PingFederate registers it
 *                    at its first attested token request, from Raidiam - nobody registers it beforehand
 *
 * Each step's result is kept on the agent (its deploy field), so a deploy that stopped part way resumes where it
 * stopped rather than creating a second statement. deploy.slot holds the version's workload label.
 */

const now = () => new Date().toISOString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function recorder(prior) {
  const steps = [];
  const add = (kind, message, detail) =>
    steps.push({ n: (prior || 0) + steps.length + 1, kind, message, detail: detail || null, at: now() });
  return { steps, add };
}

function describe(err) {
  if (!err) return null;
  if (err.body) return JSON.stringify(err.body).slice(0, 600);
  return String(err.message || err).slice(0, 600);
}

/**
 * The agent's SPIFFE binding as Raidiam takes it: AdditionalSoftwareMetadata, which Raidiam's authority publishes as a
 * value policy on these openid_relying_party members (a leaf cannot set them itself), so PingFederate reads them from
 * the trust chain. Raidiam keeps at most 255 characters, counted on its own re-serialisation (", " and ": " between
 * members, as Python's json.dumps writes them) - and over it, answers 500 rather than a validation error. All five
 * members come to 258 or more, so spiffe_bundle_format is left out: the bundle endpoint serves a JWKS, which a consumer
 * assumes when the format is absent. One attester, PingFederate's, the agents' default.
 */
function spaced(value) {
  if (Array.isArray(value)) return `[${value.map(spaced).join(', ')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.entries(value).map(([k, v]) => `${JSON.stringify(k)}: ${spaced(v)}`).join(', ')}}`;
  }
  return JSON.stringify(value);
}

function spiffeMetadata(spiffeId) {
  const members = {
    spiffe_id: spiffeId,
    spiffe_trust_domain: spiffeId.split('/')[2],
    spiffe_bundle_endpoint: config.rig.spireBundleUrl,
    client_attesters: [config.rig.pfIssuer],
  };
  const length = spaced(members).length;
  if (length > 255) {
    throw Object.assign(new Error(`the SPIFFE metadata for ${spiffeId} is ${length} characters as Raidiam counts them; it keeps at most 255`), { status: 400 });
  }
  return JSON.stringify(members);
}

function statementBody(doc) {
  const site = `${config.rig.agentsSite}/${encodeURIComponent(doc.softwareId)}`;
  return {
    ClientName: doc.name,
    Description: doc.description || `Principal agent version ${doc.version}, deployed by the agent marketplace`,
    ClientUri: site,
    LogoUri: 'https://data.directory.cba.raidiam.io/logos/placeholder-logo.png',
    RedirectUri: [`${site}/callback`],
    Mode: 'Live',
    Environment: 'Sandbox',
    SoftwareVersion: String(doc.version || '1'),
    OpenidFederationEnabled: true,
    OpenidFederationEntityManagementType: config.raidiam.federationManaged,
    RequireSignedRequestObject: false,
    IdTokenSignedResponseAlgorithm: 'PS256',
    TokenEndpointAuthMethod: 'private_key_jwt',
    TlsClientCertificateBoundAccessTokens: false,
    RelatedAuthorisationServer: doc.authorisationServerId || config.rig.authorisationServerId,
  };
}

/** The identifier Raidiam gives a federation-managed statement: its ClientId when that is one, else Raidiam's pattern. */
function managedEntityId(statement, ssId) {
  const id = statement.ClientId || '';
  return /^https:\/\//.test(id) ? id.replace(/\/$/, '') : `${config.rig.managedEntityBase}/${ssId}`;
}

const P = config.raidiam.paths;

async function publish(doc, save) {
  const d = { ...(doc.deploy || {}) };
  const { steps, add } = recorder((doc.steps || []).length);
  const org = doc.organisationId;
  const keep = async () => save({ deploy: d });

  try {
    // 1. The software statement, federation-managed.
    if (!d.softwareStatementId) {
      d.payload = statementBody(doc);
      const created = await raidiam.call('POST', P.softwareStatements, { orgId: org }, d.payload);
      d.softwareStatementId = created.SoftwareStatementId || created.softwareStatementId || created.id;
      if (!d.softwareStatementId) throw Object.assign(new Error('Raidiam answered with no SoftwareStatementId'), { body: created });
      await keep();
    }
    if (!d.entityId) {
      const back = await raidiam.call('GET', P.softwareStatement, { orgId: org, ssId: d.softwareStatementId });
      d.entityId = managedEntityId(back, d.softwareStatementId);
      d.slot = `agent-${d.softwareStatementId.slice(0, 8)}`;
      d.spiffeId = `spiffe://${config.rig.trustDomain}/${d.slot}`;
      add('statement', `software statement ${d.softwareStatementId} in ${org}: Raidiam hosts its Entity Configuration at ${d.entityId}`,
        `${back.OpenidFederationEntityManagementType}, private_key_jwt, related to PingFederate`);
      await keep();
    }

    // 2. Its SPIFFE binding, on the statement.
    if (!d.spiffeMetadata) {
      const set = await setSpiffeMetadata(org, d.softwareStatementId, d.spiffeId);
      if (!set.matches) throw Object.assign(new Error('Raidiam did not keep the SPIFFE metadata'), { body: set });
      d.spiffeMetadata = true;
      add('statement', `SPIFFE binding on the statement: ${d.spiffeId}, attested by PingFederate (${config.rig.pfIssuer})`,
        set.additionalSoftwareMetadata);
      await keep();
    }

    // 3 + 4. The bridge key, in the KMS, certified by Raidiam. A certificate already on the statement - uploaded in the
    // Raidiam website, when the API refused - is found by its public key.
    d.certificates = d.certificates || {};
    if (!d.certificates.bridge) {
      const mine = await vault.bridgeKey(d.softwareStatementId, true);
      const certs = await raidiam.call('GET', `${P.softwareStatement}/certificates`, { orgId: org, ssId: d.softwareStatementId });
      const found = (certs || []).find((c) => c.Status === 'Active' && c.n === mine.n);
      if (found) {
        d.certificates.bridge = { kid: found.kid };
        add('certificate', `bridge key certified by Raidiam as ${found.keyType}, kid ${found.kid}`);
        await keep();
      }
    }
    if (!d.certificates.bridge) {
      d.csrs = { bridge: await vault.bridgeCsr(d.softwareStatementId, org) };
      add('certificate', `the KMS created ${vault.keyName(d.softwareStatementId)} (rsa-2048, not exportable) and made its CSR `
        + `(CN=${d.softwareStatementId}); the private key never leaves the KMS`);
      try {
        const cert = await raidiam.call('POST', P.certificates,
          { orgId: org, ssId: d.softwareStatementId, type: 'rtssigning' }, d.csrs.bridge, 'application/x-pem-file');
        d.certificates.bridge = { kid: cert.kid || cert.Kid || cert.CertificateOrKeyId || null };
        add('certificate', `bridge key certified by Raidiam as rtssigning${d.certificates.bridge.kid ? `, kid ${d.certificates.bridge.kid}` : ''}`);
      } catch (err) {
        if (err.status !== 403) throw err;
        add('refused', `Raidiam's API refused to certify the bridge key (403): upload its CSR in the Raidiam website instead - `
          + `software statement ${d.softwareStatementId}, certificates, rtssigning - then approve again to carry on`, describe(err));
        d.awaitingUpload = true;
        await keep();
        return { ok: false, steps, deploy: d, awaitingUpload: true };
      }
      await keep();
    }
    d.awaitingUpload = false;

    // 5. Roles, from the organisation's own authority claims.
    d.roles = d.roles || {};
    const wanted = (doc.roles || []).filter((r) => !d.roles[r]);
    if (wanted.length) {
      const orgClaims = await raidiam.call('GET', '/organisations/{orgId}/authorityclaims', { orgId: org });
      for (const role of wanted) {
        const claim = (orgClaims || []).find((c) => c.Role === role && c.Status === 'Active');
        if (!claim) {
          add('refused', `role ${role}: ${org} holds no active claim for it`);
          continue;
        }
        try {
          const made = await raidiam.call('POST', P.authorityClaims, { orgId: org, ssId: d.softwareStatementId }, {
            OrganisationAuthorisationDomainRoleClaimID: claim.OrganisationAuthorityClaimId,
            AuthorisationDomain: claim.AuthorisationDomain,
            Role: claim.Role,
            Status: 'Active',
          });
          d.roles[role] = made.SoftwareAuthorityClaimId || true;
          add('role', `granted ${role} (${claim.AuthorisationDomain})`,
            (claim.Metadata || []).map((m) => `${m.EntityType}.${m.ClaimName} ${m.PolicyOperator} ${JSON.stringify(m.Values || m.Value)}`).join('; ') || null);
          await keep();
        } catch (err) {
          add('refused', `role ${role} refused: ${err.message}`, describe(err));
        }
      }
    }

    // 6. Read back.
    const back = await raidiam.call('GET', P.softwareStatement, { orgId: org, ssId: d.softwareStatementId });
    const certs = await raidiam.call('GET', `${P.softwareStatement}/certificates`, { orgId: org, ssId: d.softwareStatementId });
    const claims = await raidiam.call('GET', P.authorityClaims, { orgId: org, ssId: d.softwareStatementId });
    const active = (claims || []).filter((c) => c.Status === 'Active').map((c) => c.Role);
    add('verify', `read back: ${back.ClientName} is ${back.Status}, ${back.OpenidFederationEntityManagementType}`);
    add('verify', `read back: ${(certs || []).filter((c) => c.Status === 'Active').length} active rtssigning certificate(s); roles ${active.join(', ') || 'none'}`);
    d.rolesActive = active;

    // 7. Its workload identity.
    if (!d.spire) {
      d.spire = await rig.spireEntry(d.spiffeId, d.slot);
      add('verify', `SPIRE entry ${d.spiffeId} <- docker:label:app:${d.slot} (${d.spire})`);
      await keep();
    }

    // 8. Trust established: Raidiam serves its Entity Configuration and vouches for it, with its bridge key.
    const st = await waitForTrust(d);
    d.trust = st;
    d.hosted = Boolean(st.raidiam.vouches);
    add(st.raidiam.served ? 'verify' : 'refused', st.raidiam.served
      ? `Raidiam serves its Entity Configuration at ${d.entityId}/.well-known/openid-federation`
      : `Raidiam does not serve its Entity Configuration yet: ${st.raidiam.error || 'pending'}`);
    add(st.raidiam.vouches ? 'verify' : 'refused', st.raidiam.vouches
      ? `Raidiam vouches for it, publishing its bridge key (kid ${st.raidiam.kids.bridge})`
      : `Raidiam does not vouch for it yet: ${st.raidiam.error || 'its bridge key is not published'}`);
    add('verify', 'PingFederate registers it from Raidiam at its first attested token request - nobody registers it beforehand');
    await keep();
    return { ok: true, steps, deploy: d };
  } catch (err) {
    add('refused', `deploy stopped: ${err.message}`, describe(err));
    await keep();
    return { ok: false, steps, deploy: d };
  }
}

const decode = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));

/**
 * Where the version stands, asked of the parties themselves: Raidiam (its Entity Configuration, the authority's statement
 * about it, its bridge key among the keys that configuration names) and PingFederate (its log: registered from the
 * federation on a verified attestation).
 */
async function trust(d) {
  const raidiamSide = { served: false, vouches: false, kids: {} };
  try {
    const ec = await fetch(`${d.entityId}/.well-known/openid-federation`, { signal: AbortSignal.timeout(15000) });
    if (!ec.ok) throw new Error(`its Entity Configuration answers ${ec.status}`);
    const conf = decode((await ec.text()).trim());
    raidiamSide.served = conf.iss === d.entityId;
    const authority = (process.env.AGENT_ENV_AUTHORITY || '').replace(/\/$/, '');
    const statement = await fetch(`${authority}/fetch?sub=${encodeURIComponent(d.entityId)}`, { signal: AbortSignal.timeout(15000) });
    if (!statement.ok) throw new Error(`the authority answers ${statement.status} for it`);
    const rp = (conf.metadata || {}).openid_relying_party || {};
    const jwks = rp.jwks || (rp.jwks_uri ? await (await fetch(rp.jwks_uri, { signal: AbortSignal.timeout(15000) })).json() : { keys: [] });
    const bridge = await vault.bridgeKey(d.softwareStatementId);
    const published = (jwks.keys || []).find((k) => bridge && k.n === bridge.n);
    raidiamSide.kids.bridge = published ? published.kid : null;
    raidiamSide.vouches = Boolean(published);
    if (!published) raidiamSide.error = 'its bridge key is not among the keys Raidiam publishes for it yet';
  } catch (err) {
    raidiamSide.error = err.message;
  }
  const log = await rig.docker(['exec', config.rig.pfContainer, 'sh', '-c',
    `grep -h "registered ${d.entityId} from the federation" /opt/out/instance/log/server.log | tail -1`]).catch(() => null);
  const line = ((log && log.stdout) || '').trim();
  return { raidiam: raidiamSide, pingfederate: { registered: Boolean(line), at: line ? line.slice(0, 23) : null } };
}

async function waitForTrust(d, limitMs = 120000) {
  const start = Date.now();
  let st = await trust(d);
  while (!st.raidiam.vouches && Date.now() - start < limitMs) {
    await sleep(5000);
    st = await trust(d);
  }
  return st;
}

async function setStatus(doc, status) {
  const d = doc.deploy;
  const current = await raidiam.call('GET', P.softwareStatement, { orgId: doc.organisationId, ssId: d.softwareStatementId });
  if (current.Status === status) return; // already so - and Raidiam refuses to re-send a suspended statement
  await raidiam.call('PUT', P.softwareStatement, { orgId: doc.organisationId, ssId: d.softwareStatementId },
    // Environment is required on an update, though not on create.
    { ...current, Environment: current.Environment || 'Sandbox', Status: status });
}

/** Suspension: the statement Suspended - Raidiam stops vouching for it - and a Shared Signals account-disabled. */
async function suspend(doc) {
  const { steps, add } = recorder((doc.steps || []).length);
  const d = doc.deploy;
  if (!d?.softwareStatementId) return { ok: false, steps: [{ n: 1, kind: 'refused', message: 'not deployed', at: now() }] };
  try {
    // Raidiam's status for this is Suspended (Inactive is not one its update schema accepts).
    await setStatus(doc, 'Suspended');
    add('statement', `software statement ${d.softwareStatementId} set to Suspended: no new trust from Raidiam`);
  } catch (err) {
    add('refused', `suspension refused at Raidiam: ${err.message}`, describe(err));
    return { ok: false, steps };
  }
  try {
    const streams = await rig.emit('https://schemas.openid.net/secevent/risc/event-type/account-disabled', d.entityId);
    add('statement', `Shared Signals: account-disabled for ${d.entityId}, to ${streams} stream(s) - the gateway refuses its tokens`);
  } catch (err) {
    add('refused', `signal not raised: ${err.message}`);
  }
  return { ok: true, steps };
}

async function reinstate(doc) {
  const { steps, add } = recorder((doc.steps || []).length);
  const d = doc.deploy;
  if (!d?.softwareStatementId) return { ok: false, steps: [{ n: 1, kind: 'refused', message: 'not deployed', at: now() }] };
  try {
    await setStatus(doc, 'Active');
    add('statement', `software statement ${d.softwareStatementId} set to Active`);
  } catch (err) {
    add('refused', `reinstatement refused at Raidiam: ${err.message}`, describe(err));
    return { ok: false, steps };
  }
  try {
    const streams = await rig.emit('https://schemas.openid.net/secevent/risc/event-type/account-enabled', d.entityId);
    add('statement', `Shared Signals: account-enabled for ${d.entityId}, to ${streams} stream(s)`);
  } catch (err) {
    add('refused', `signal not raised: ${err.message}`);
  }
  return { ok: true, steps };
}

/** A job run as this version (agent.py in a container SPIRE identifies as it). */
async function run(doc, job, options = {}) {
  const d = doc.deploy;
  if (!d?.slot) throw Object.assign(new Error('deploy it first'), { status: 409 });
  const extraEnv = {};
  if (options.attester) extraEnv.ATTESTER = options.attester;
  if (options.invoiceAmount) extraEnv.INVOICE_AMOUNT = String(options.invoiceAmount);
  // Another workload's container (label): SPIRE gives it that workload's SPIFFE ID, not this version's.
  return rig.runAgent({ label: options.label || d.slot, agentId: d.entityId, job, extraEnv });
}

async function status(doc) {
  const d = doc.deploy;
  if (!d?.entityId) return null;
  return { state: doc.status, ...(await trust(d)) };
}

/**
 * Sets the SPIFFE metadata on an existing statement - one the marketplace did not create, or one created before Raidiam
 * published these members. The whole record is sent back with it, as Raidiam's update requires (a save without the
 * field resets it), and read back.
 */
/** The same JSON, however it is spaced or ordered: Raidiam keeps the metadata re-serialised, its members reordered. */
function sameJson(a, b) {
  const sorted = (v) => (Array.isArray(v) ? v.map(sorted) : v && typeof v === 'object'
    ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])])) : v);
  try {
    return JSON.stringify(sorted(JSON.parse(a))) === JSON.stringify(sorted(JSON.parse(b)));
  } catch (err) {
    return false;
  }
}

async function setSpiffeMetadata(orgId, ssId, spiffeId) {
  const current = await raidiam.call('GET', P.softwareStatement, { orgId, ssId });
  const metadata = spiffeMetadata(spiffeId);
  await raidiam.call('PUT', P.softwareStatement, { orgId, ssId },
    { ...current, Environment: current.Environment || 'Sandbox', AdditionalSoftwareMetadata: metadata });
  const back = await raidiam.call('GET', P.softwareStatement, { orgId, ssId });
  return { softwareStatementId: ssId, clientId: back.ClientId, status: back.Status,
    additionalSoftwareMetadata: back.AdditionalSoftwareMetadata, matches: sameJson(back.AdditionalSoftwareMetadata, metadata) };
}

module.exports = { publish, suspend, reinstate, run, status, setSpiffeMetadata };
