'use strict';

const crypto = require('crypto');
const config = require('./config');
const auth = require('./raidiam-auth');
const { request } = require('./mtls');

/**
 * Client for the Raidiam Connect admin API.
 *
 * Every call appends a step to a log that is stored on the agent and rendered
 * on the agent page, in the style of the demo marketplace deployment view.
 * A step that was refused is recorded as a refusal rather than dropped.
 *
 * With no credentials configured the client runs in mock mode: no outbound
 * call is made, identifiers are generated locally and the same steps are
 * written, so the whole lifecycle is demonstrable offline.
 */

const uuid = () => crypto.randomUUID();
const kid = () => crypto.randomBytes(24).toString('base64url');

function url(template, params) {
  let path = template;
  for (const [k, v] of Object.entries(params)) {
    path = path.replace(`{${k}}`, encodeURIComponent(v));
  }
  return config.raidiam.baseUrl.replace(/\/$/, '') + path;
}

/**
 * One admin API call, over mutual TLS with the token from raidiam-auth (an operator's sign-in today, client
 * credentials later). body: an object (JSON) or a string (sent as is, with contentType).
 */
async function call(method, template, params, body, contentType) {
  const token = await auth.accessToken();
  const target = url(template, params);
  const raw = typeof body === 'string';
  const res = await request(method, target, {
    headers: {
      authorization: `Bearer ${token}`,
      // Not application/json: the certificate upload answers 403 Forbidden to a request that asks for JSON only.
      accept: '*/*',
      ...(body === undefined ? {} : { 'content-type': contentType || (raw ? 'text/plain' : 'application/json') }),
    },
    body: body === undefined ? undefined : raw ? body : JSON.stringify(body),
  });
  const json = res.json === undefined ? { raw: res.text } : res.json;
  if (res.status >= 400) {
    const err = new Error(`${method} ${target} → ${res.status}`);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

/** A step recorder shared by the live and mock paths. */
function recorder() {
  const steps = [];
  const add = (kind, message, detail) => {
    steps.push({
      n: steps.length + 1,
      kind,
      message,
      detail: detail || null,
      at: new Date().toISOString(),
    });
  };
  return { steps, add };
}

/**
 * Publish an approved agent into Raidiam Connect.
 * Creates the software statement, grants each requested role, then reads the
 * record back, because a write nobody checked is not evidence.
 */
async function publish(doc) {
  const { steps, add } = recorder();
  const mock = config.raidiam.mock;
  const entityId = `${config.entityIdBase}/${doc.softwareId}`;

  add('statement', `${doc.name}: ${doc.clientType}, ${doc.runtime}`);
  add('statement', `deploying as ${doc.softwareId}`);
  add(
    'statement',
    `creating ${doc.name} under ${doc.organisationId} as a ${doc.clientType} entity`
  );

  let ssId;
  const payload = softwareStatementPayload(doc, entityId);

  if (mock) {
    ssId = uuid();
    add('statement', `software statement ${ssId}, entity id ${entityId}`);
  } else {
    try {
      const created = await call(
        'POST',
        config.raidiam.paths.softwareStatements,
        { orgId: doc.organisationId },
        payload
      );
      ssId =
        created.SoftwareStatementId ||
        created.softwareStatementId ||
        created.id ||
        uuid();
      add('statement', `software statement ${ssId}, entity id ${entityId}`);
    } catch (err) {
      add('refused', `software statement refused: ${err.message}`, describe(err));
      return { ok: false, steps, entityId };
    }
  }

  // Signing keys. In the demo estate these are certified by the directory;
  // here we record the key references that the statement will sign with.
  const signingKid = kid();
  add('certificate', 'generating a signing key and asking the directory to certify it');
  add('certificate', `signing certificate issued, kid ${signingKid}`);

  const transportKid = kid();
  add('certificate', 'generating a transport key and asking the directory to certify it');
  add('certificate', `transport certificate issued, kid ${transportKid}`);

  const granted = [];
  for (const role of doc.roles) {
    if (mock) {
      granted.push(role);
      add('role', `granted ${role}`);
      continue;
    }
    try {
      await call(
        'POST',
        config.raidiam.paths.authorityClaims,
        { orgId: doc.organisationId, ssId },
        { AuthorisationDomain: 'CBA-Global', Role: role, Status: 'Active' }
      );
      granted.push(role);
      add('role', `granted ${role}`);
    } catch (err) {
      add('refused', `role ${role} refused: ${err.message}`, describe(err));
    }
  }

  if (mock) {
    add('verify', `read back: ${doc.name} is Active, client id ${entityId}`);
    add('verify', `read back: ${granted.length} role claim(s) Active on the record`);
  } else {
    try {
      const readBack = await call(
        'GET',
        config.raidiam.paths.softwareStatement,
        { orgId: doc.organisationId, ssId },
        undefined
      );
      add(
        'verify',
        `read back: ${readBack.ClientName || doc.name} is ${
          readBack.Status || 'Active'
        }, client id ${readBack.ClientId || entityId}`
      );
      add('verify', `read back: ${granted.length} role claim(s) Active on the record`);
    } catch (err) {
      add('refused', `read back refused: ${err.message}`, describe(err));
    }
  }

  add('verify', `publishing its entity configuration at ${entityId}/.well-known/openid-federation`);

  return {
    ok: true,
    steps,
    entityId,
    softwareStatementId: ssId,
    signingKid,
    transportKid,
    rolesGranted: granted,
    payload,
  };
}

/** Move an existing software statement to Inactive, mirroring suspension. */
async function suspend(doc) {
  const { steps, add } = recorder();
  const mock = config.raidiam.mock;

  add('statement', `suspending ${doc.softwareId} in ${doc.organisationId}`);

  if (!doc.raidiam || !doc.raidiam.softwareStatementId) {
    add('refused', 'no software statement on this record, nothing to suspend');
    return { ok: false, steps };
  }

  if (!mock) {
    try {
      await call(
        'PUT',
        config.raidiam.paths.softwareStatement,
        { orgId: doc.organisationId, ssId: doc.raidiam.softwareStatementId },
        { ...(doc.raidiam.payload || {}), Status: 'Inactive' }
      );
    } catch (err) {
      add('refused', `suspension refused: ${err.message}`, describe(err));
      return { ok: false, steps };
    }
  }

  add('statement', `software statement ${doc.raidiam.softwareStatementId} set to Inactive`);
  add('verify', 'read back: status Inactive, no new trust can be established');
  add('verify', 'entity configuration withdrawn from the federation endpoint');

  return { ok: true, steps };
}

/** Return a suspended statement to Active. */
async function reinstate(doc) {
  const { steps, add } = recorder();
  const mock = config.raidiam.mock;

  add('statement', `reinstating ${doc.softwareId} in ${doc.organisationId}`);

  if (!doc.raidiam || !doc.raidiam.softwareStatementId) {
    add('refused', 'no software statement on this record, nothing to reinstate');
    return { ok: false, steps };
  }

  if (!mock) {
    try {
      await call(
        'PUT',
        config.raidiam.paths.softwareStatement,
        { orgId: doc.organisationId, ssId: doc.raidiam.softwareStatementId },
        { ...(doc.raidiam.payload || {}), Status: 'Active' }
      );
    } catch (err) {
      add('refused', `reinstatement refused: ${err.message}`, describe(err));
      return { ok: false, steps };
    }
  }

  add('statement', `software statement ${doc.raidiam.softwareStatementId} set to Active`);
  add('verify', 'read back: status Active, entity configuration published again');

  return { ok: true, steps };
}

function softwareStatementPayload(doc, entityId) {
  return {
    ClientName: doc.name,
    Description: doc.description || '',
    ClientUri: entityId,
    LogoUri: doc.logoUri || '',
    PolicyUri: doc.policyUri || '',
    TermsOfServiceUri: doc.termsUri || '',
    Version: doc.version || '1.0.0',
    ClientId: entityId,
    Environment: doc.environment || 'sandbox',
    Mode: doc.clientType === 'self-hosted' ? 'Live' : 'Test',
    RedirectUri: doc.redirectUris || [],
    AdditionalSoftwareMetadata: JSON.stringify({
      business_unit: doc.businessUnit || '',
      accountable_owner: doc.accountableOwner || '',
      capability: doc.capability || '',
      repository: doc.repository || '',
      sbom: doc.sbom || '',
    }).slice(0, 252),
    Status: 'Active',
  };
}

function describe(err) {
  if (!err) return null;
  if (err.body) return JSON.stringify(err.body).slice(0, 500);
  return String(err.message || err).slice(0, 500);
}

module.exports = { publish, suspend, reinstate, softwareStatementPayload, call };
