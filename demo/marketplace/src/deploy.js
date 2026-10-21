'use strict';

const config = require('./config');
const raidiam = require('./raidiam');
const rig = require('./rig');

/**
 * Deploying a Principal version: the marketplace's control plane work done for real, end to end.
 *
 *   1. slot          the provider claims a Principal slot: <provider>/agent/<slot>, spiffe://<td>/<slot>
 *   2. statement     Raidiam: POST /organisations/{org}/softwarestatements - self-managed OpenID Federation entity,
 *                    ClientId = the slot's identifier, related to PingFederate's authorisation server
 *   3. csr           the provider: a CSR for its entity key and one for its bridge key, for that statement (the
 *                    private keys never leave it)
 *   4. certificate   Raidiam: POST .../softwarestatements/{id}/certificates/rtssigning, once per CSR
 *   5. role          Raidiam: POST .../softwarestatements/{id}/authorityclaims, one per role, from the
 *                    organisation's own claims (GET /organisations/{org}/authorityclaims)
 *   6. verify        read back: the statement, its certificates, its claims
 *   7. host          the provider publishes its Entity Configuration and registers it at PingFederate
 *   8. spire         a SPIRE entry: spiffe://<td>/<slot> <- docker:label:app:<slot>
 *   9. trust         wait until Raidiam vouches for its keys and PingFederate has registered it
 *
 * Each step's result is kept on the agent (its deploy field), so a deploy that stopped part way resumes where it
 * stopped rather than creating a second statement.
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
 * value policy on these five openid_relying_party members (a leaf cannot set them itself), so PingFederate reads them
 * from the trust chain. At most 255 characters, so one attester: PingFederate's, the agents' default.
 */
function spiffeMetadata(spiffeId) {
  const meta = JSON.stringify({
    spiffe_id: spiffeId,
    spiffe_trust_domain: spiffeId.split('/')[2],
    spiffe_bundle_endpoint: config.rig.spireBundleUrl,
    spiffe_bundle_format: 'jwks',
    client_attesters: [config.rig.pfIssuer],
  });
  if (meta.length > 255) {
    throw Object.assign(new Error(`the SPIFFE metadata for ${spiffeId} is ${meta.length} characters; Raidiam keeps at most 255`), { status: 400 });
  }
  return meta;
}

function statementBody(doc, d) {
  return {
    ClientName: doc.name,
    Description: doc.description || `Principal agent version ${doc.version}, deployed by the agent marketplace`,
    ClientId: d.entityId,
    ClientUri: d.entityId,
    LogoUri: 'https://data.directory.cba.raidiam.io/logos/placeholder-logo.png',
    RedirectUri: [`${d.entityId}/callback`],
    Mode: 'Live',
    Environment: 'Sandbox',
    SoftwareVersion: String(doc.version || '1'),
    AdditionalSoftwareMetadata: spiffeMetadata(d.spiffeId),
    OpenidFederationEnabled: true,
    OpenidFederationEntityManagementType: 'openid_entity_self_managed',
    RequireSignedRequestObject: false,
    IdTokenSignedResponseAlgorithm: 'PS256',
    TokenEndpointAuthMethod: 'private_key_jwt',
    TlsClientCertificateBoundAccessTokens: false,
    RelatedAuthorisationServer: doc.authorisationServerId || config.rig.authorisationServerId,
  };
}

const P = config.raidiam.paths;

async function publish(doc, save) {
  const d = { ...(doc.deploy || {}) };
  const { steps, add } = recorder((doc.steps || []).length);
  const org = doc.organisationId;
  const keep = async () => save({ deploy: d });

  try {
    // 1. A slot at the provider.
    if (!d.slot) {
      const slot = await rig.provider('POST', '/admin/versions/claim', { name: doc.name, version: doc.version });
      Object.assign(d, { slot: slot.slot, entityId: slot.entity_id, spiffeId: slot.spiffe_id });
      add('statement', `the provider claimed slot ${d.slot} for ${doc.name} ${doc.version}: ${d.entityId}`);
      await keep();
    }

    // 2. The software statement.
    if (!d.softwareStatementId) {
      d.payload = statementBody(doc, d);
      const created = await raidiam.call('POST', P.softwareStatements, { orgId: org }, d.payload);
      d.softwareStatementId = created.SoftwareStatementId || created.softwareStatementId || created.id;
      if (!d.softwareStatementId) throw Object.assign(new Error('Raidiam answered with no SoftwareStatementId'), { body: created });
      add('statement', `software statement ${d.softwareStatementId} in ${org}, client id ${d.entityId}`,
        'self-managed OpenID Federation entity, private_key_jwt, related to PingFederate');
      await keep();
    }

    // 3 + 4. CSRs from the provider, certified by Raidiam. Certificates already on the statement - uploaded in the
    // Raidiam website, when the API refused - are found by their public key.
    d.certificates = d.certificates || {};
    if (!d.certificates.entity || !d.certificates.bridge) {
      const mine = await rig.provider('GET', `/admin/versions/${d.slot}/keys`);
      const certs = await raidiam.call('GET', `${P.softwareStatement}/certificates`, { orgId: org, ssId: d.softwareStatementId });
      for (const name of ['entity', 'bridge']) {
        const found = (certs || []).find((c) => c.Status === 'Active' && c.n === mine[name].n);
        if (found && !d.certificates[name]) {
          d.certificates[name] = { kid: found.kid };
          add('certificate', `${name} key certified by Raidiam as ${found.keyType}, kid ${found.kid}`);
        }
      }
      await keep();
    }
    if (!d.certificates.entity || !d.certificates.bridge) {
      const csrs = await rig.provider('POST', `/admin/versions/${d.slot}/csr`,
        { softwareStatementId: d.softwareStatementId, organisationId: org });
      d.csrs = csrs;
      add('certificate', `the provider made CSRs for its entity key and its bridge key (CN=${d.softwareStatementId}); no private key leaves the provider - or, for a bridge key held in OpenBao, the vault`);
      for (const name of ['entity', 'bridge']) {
        if (d.certificates[name]) continue;
        try {
          const cert = await raidiam.call('POST', P.certificates,
            { orgId: org, ssId: d.softwareStatementId, type: 'rtssigning' }, csrs[name], 'application/x-pem-file');
          d.certificates[name] = { kid: cert.kid || cert.Kid || cert.CertificateOrKeyId || null };
          add('certificate', `${name} key certified by Raidiam as rtssigning${d.certificates[name].kid ? `, kid ${d.certificates[name].kid}` : ''}`);
          await keep();
        } catch (err) {
          if (err.status !== 403) throw err;
          add('refused', `Raidiam's API refused to certify the ${name} key (403): upload its CSR in the Raidiam website instead - `
            + `software statement ${d.softwareStatementId}, certificates, rtssigning - then approve again to carry on`,
            describe(err));
          d.awaitingUpload = true;
        }
      }
      await keep();
      if (!d.certificates.entity || !d.certificates.bridge) {
        return { ok: false, steps, deploy: d, awaitingUpload: true };
      }
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
    add('verify', `read back: ${back.ClientName} is ${back.Status}, client id ${back.ClientId}`);
    add('verify', `read back: ${(certs || []).filter((c) => c.Status === 'Active').length} active rtssigning certificate(s); roles ${active.join(', ') || 'none'}`);
    d.rolesActive = active;

    // 7. Hosted by the provider.
    if (!d.hosted) {
      await rig.provider('POST', `/admin/versions/${d.slot}/host`, { name: doc.name });
      d.hosted = true;
      add('verify', `the provider publishes its Entity Configuration at ${d.entityId}/.well-known/openid-federation, binding ${d.spiffeId} for PingFederate's attester`);
      await keep();
    }

    // 8. Its workload identity.
    if (!d.spire) {
      d.spire = await rig.spireEntry(d.spiffeId, d.slot);
      add('verify', `SPIRE entry ${d.spiffeId} <- docker:label:app:${d.slot} (${d.spire})`);
      await keep();
    }

    // 9. Trust established: Raidiam vouches for its keys, PingFederate has registered it.
    const status = await waitForTrust(d.slot);
    d.trust = status;
    add(status.raidiam?.vouches ? 'verify' : 'refused',
      status.raidiam?.vouches ? `Raidiam vouches for its entity key (kid ${status.raidiam.kids.entity})`
        : `Raidiam does not vouch for its keys yet: ${status.raidiam?.error || 'not in the authority statement'}`);
    add(status.pingfederate?.registered_until ? 'verify' : 'refused',
      status.pingfederate?.registered_until
        ? `registered at PingFederate until ${new Date(status.pingfederate.registered_until * 1000).toISOString()}`
        : `not registered at PingFederate yet: ${status.pingfederate?.error || 'pending'} - the provider retries every 30 s`);
    await keep();
    return { ok: true, steps, deploy: d };
  } catch (err) {
    add('refused', `deploy stopped: ${err.message}`, describe(err));
    await keep();
    return { ok: false, steps, deploy: d };
  }
}

async function waitForTrust(slot, limitMs = 120000) {
  const start = Date.now();
  let status = {};
  while (Date.now() - start < limitMs) {
    status = await rig.provider('GET', `/admin/versions/${slot}/status`).catch((e) => ({ error: e.message }));
    if (status.raidiam?.vouches && status.pingfederate?.registered_until) return status;
    await sleep(5000);
  }
  return status;
}

async function setStatus(doc, status) {
  const d = doc.deploy;
  const current = await raidiam.call('GET', P.softwareStatement, { orgId: doc.organisationId, ssId: d.softwareStatementId });
  if (current.Status === status) return; // already so - and Raidiam refuses to re-send a suspended statement
  await raidiam.call('PUT', P.softwareStatement, { orgId: doc.organisationId, ssId: d.softwareStatementId },
    // Environment is required on an update, though not on create.
    { ...current, Environment: current.Environment || 'Sandbox', Status: status });
}

/** Suspension: the statement Suspended, a Shared Signals account-disabled, the Entity Configuration withdrawn. */
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
  await rig.provider('POST', `/admin/versions/${d.slot}/withdraw`).then(
    () => add('verify', `the provider withdrew its Entity Configuration: its chain no longer resolves`),
    (err) => add('refused', `withdrawal at the provider failed: ${err.message}`));
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
  await rig.provider('POST', `/admin/versions/${d.slot}/host`, { name: doc.name }).then(
    () => add('verify', `the provider publishes its Entity Configuration again`),
    (err) => add('refused', `hosting at the provider failed: ${err.message}`));
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
  if (!d?.slot) return null;
  return rig.provider('GET', `/admin/versions/${d.slot}/status`);
}

/**
 * Sets the SPIFFE metadata on an existing statement - one the marketplace did not create, or one created before Raidiam
 * published these members. The whole record is sent back with it, as Raidiam's update requires (a save without the
 * field resets it), and read back.
 */
async function setSpiffeMetadata(orgId, ssId, spiffeId) {
  const current = await raidiam.call('GET', P.softwareStatement, { orgId, ssId });
  const metadata = spiffeMetadata(spiffeId);
  await raidiam.call('PUT', P.softwareStatement, { orgId, ssId },
    { ...current, Environment: current.Environment || 'Sandbox', AdditionalSoftwareMetadata: metadata });
  const back = await raidiam.call('GET', P.softwareStatement, { orgId, ssId });
  return { softwareStatementId: ssId, clientId: back.ClientId, status: back.Status,
    additionalSoftwareMetadata: back.AdditionalSoftwareMetadata, matches: back.AdditionalSoftwareMetadata === metadata };
}

module.exports = { publish, suspend, reinstate, run, status, setSpiffeMetadata };
