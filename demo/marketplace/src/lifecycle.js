'use strict';

const { agents } = require('./db');
const raidiam = require('./raidiam');
const config = require('./config');

const STATES = ['pending', 'approved', 'suspended'];

// What each state may become next.
const TRANSITIONS = {
  pending: ['approved'],
  approved: ['suspended'],
  suspended: ['approved'],
};

function slug(name) {
  return String(name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48);
}

/** softwareId is the deployed name, e.g. ap-orchestrator-2-19. */
async function mintSoftwareId(name) {
  const base = slug(name) || 'agent';
  const existing = await agents()
    .find({ softwareId: { $regex: `^${base}(-\\d+)?$` } })
    .project({ softwareId: 1 })
    .toArray();
  if (!existing.length) return base;
  let n = 2;
  const taken = new Set(existing.map((e) => e.softwareId));
  while (taken.has(`${base}-${n}`)) n += 1;
  return `${base}-${n}`;
}

function entry(action, actor, note) {
  return { action, actor: actor || 'marketplace', note: note || null, at: new Date().toISOString() };
}

async function create(input, actor) {
  const softwareId = await mintSoftwareId(input.name);
  const doc = {
    softwareId,
    name: input.name,
    description: input.description || '',
    version: input.version || '1.0.0',
    organisationId: input.organisationId,
    organisationName: input.organisationName || '',
    authorisationServerId: input.authorisationServerId || '',
    authorisationServerName: input.authorisationServerName || '',
    roles: Array.isArray(input.roles) ? input.roles : [],
    clientType: input.clientType || 'self-hosted',
    runtime: input.runtime || 'redirect runtime',
    environment: input.environment || 'sandbox',
    businessUnit: input.businessUnit || '',
    owner: input.owner || '',
    accountableOwner: input.accountableOwner || '',
    capability: input.capability || '',
    repository: input.repository || '',
    sbom: input.sbom || '',
    redirectUris: (input.redirectUris || []).filter(Boolean),
    status: 'pending',
    raidiam: null,
    steps: [],
    history: [entry('registered', actor, 'registered in the marketplace')],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  await agents().insertOne(doc);
  return doc;
}

async function transition(softwareId, next, actor) {
  const doc = await agents().findOne({ softwareId });
  if (!doc) {
    const err = new Error('agent not found');
    err.status = 404;
    throw err;
  }
  if (!STATES.includes(next)) {
    const err = new Error(`unknown state: ${next}`);
    err.status = 400;
    throw err;
  }
  if (!TRANSITIONS[doc.status].includes(next)) {
    const err = new Error(`cannot move from ${doc.status} to ${next}`);
    err.status = 409;
    throw err;
  }

  let result;
  let note;

  if (next === 'approved' && doc.status === 'pending') {
    result = await raidiam.publish(doc);
    note = result.ok ? 'approved and published to Raidiam Connect' : 'approval failed at the control plane';
  } else if (next === 'suspended') {
    result = await raidiam.suspend(doc);
    note = result.ok ? 'suspended, status updated in Raidiam Connect' : 'suspension failed at the control plane';
  } else if (next === 'approved' && doc.status === 'suspended') {
    result = await raidiam.reinstate(doc);
    note = result.ok ? 'reinstated, status updated in Raidiam Connect' : 'reinstatement failed at the control plane';
  }

  const steps = [...(doc.steps || []), ...(result.steps || [])];

  // A failed control-plane call leaves the marketplace state unchanged: the
  // record should never claim an identity exists when the write was refused.
  if (!result.ok) {
    await agents().updateOne(
      { softwareId },
      {
        $set: { steps, updatedAt: new Date().toISOString() },
        $push: { history: entry(`${next}-failed`, actor, note) },
      }
    );
    const err = new Error(note);
    err.status = 502;
    err.steps = result.steps;
    throw err;
  }

  const set = {
    status: next,
    steps,
    updatedAt: new Date().toISOString(),
  };

  if (next === 'approved' && doc.status === 'pending') {
    set.raidiam = {
      entityId: result.entityId,
      softwareStatementId: result.softwareStatementId,
      signingKid: result.signingKid,
      transportKid: result.transportKid,
      rolesGranted: result.rolesGranted,
      payload: result.payload,
      mode: config.raidiam.mock ? 'mock' : 'live',
      publishedAt: new Date().toISOString(),
      statementStatus: 'Active',
    };
  } else if (doc.raidiam) {
    set.raidiam = {
      ...doc.raidiam,
      statementStatus: next === 'suspended' ? 'Inactive' : 'Active',
      lastChangedAt: new Date().toISOString(),
    };
  }

  await agents().updateOne(
    { softwareId },
    { $set: set, $push: { history: entry(next, actor, note) } }
  );

  return agents().findOne({ softwareId });
}

async function list(filter = {}) {
  const query = {};
  if (filter.status && STATES.includes(filter.status)) query.status = filter.status;
  if (filter.organisationId) query.organisationId = filter.organisationId;
  return agents().find(query).sort({ createdAt: -1 }).toArray();
}

const get = (softwareId) => agents().findOne({ softwareId });

/** Agents that hold a record in Raidiam Connect. */
const instances = () =>
  agents()
    .find({ 'raidiam.softwareStatementId': { $exists: true, $ne: null } })
    .sort({ 'raidiam.publishedAt': -1 })
    .toArray();

async function remove(softwareId) {
  const doc = await agents().findOne({ softwareId });
  if (!doc) {
    const err = new Error('agent not found');
    err.status = 404;
    throw err;
  }
  if (doc.status === 'approved') {
    const err = new Error('suspend the agent before removing it from the catalogue');
    err.status = 409;
    throw err;
  }
  await agents().deleteOne({ softwareId });
  return { ok: true };
}

module.exports = { STATES, TRANSITIONS, create, transition, list, get, instances, remove };
