'use strict';

/**
 * Exercises the real lifecycle, Raidiam client and HTTP routes against an
 * in-memory stand-in for the Mongo collections, so the logic can be verified
 * without a database running.
 */

const path = require('path');
const assert = require('assert');
const Module = require('module');

// --- in-memory collection ---------------------------------------------------

function matches(doc, query) {
  return Object.entries(query).every(([k, v]) => {
    const actual = k.split('.').reduce((o, part) => (o == null ? o : o[part]), doc);
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      if ('$exists' in v && (actual !== undefined) !== v.$exists) return false;
      if ('$ne' in v && actual === v.$ne) return false;
      if ('$regex' in v && !new RegExp(v.$regex).test(String(actual ?? ''))) return false;
      return true;
    }
    return actual === v;
  });
}

function apply(doc, update) {
  if (update.$set) {
    for (const [k, v] of Object.entries(update.$set)) doc[k] = v;
  }
  if (update.$push) {
    for (const [k, v] of Object.entries(update.$push)) {
      doc[k] = [...(doc[k] || []), v];
    }
  }
}

function collection() {
  const rows = [];
  const cursor = (list) => ({
    sort(spec) {
      const [[k, dir]] = Object.entries(spec);
      list = [...list].sort((a, b) => {
        const av = k.split('.').reduce((o, p) => (o == null ? o : o[p]), a) ?? '';
        const bv = k.split('.').reduce((o, p) => (o == null ? o : o[p]), b) ?? '';
        return (av < bv ? -1 : av > bv ? 1 : 0) * dir;
      });
      return cursor(list);
    },
    project() { return cursor(list); },
    async toArray() { return list.map((d) => JSON.parse(JSON.stringify(d))); },
  });

  return {
    async createIndexes() {},
    async createIndex() {},
    find(query = {}) { return cursor(rows.filter((d) => matches(d, query))); },
    async findOne(query = {}) {
      const hit = rows.find((d) => matches(d, query));
      return hit ? JSON.parse(JSON.stringify(hit)) : null;
    },
    async insertOne(doc) {
      if (rows.some((d) => d.softwareId && d.softwareId === doc.softwareId)) {
        throw new Error('duplicate key');
      }
      rows.push(JSON.parse(JSON.stringify(doc)));
      return { insertedId: doc.softwareId || rows.length };
    },
    async updateOne(query, update, opts = {}) {
      const hit = rows.find((d) => matches(d, query));
      if (hit) { apply(hit, update); return { modifiedCount: 1 }; }
      if (opts.upsert) {
        const doc = { ...query };
        apply(doc, update);
        rows.push(doc);
        return { upsertedCount: 1 };
      }
      return { modifiedCount: 0 };
    },
    async deleteOne(query) {
      const i = rows.findIndex((d) => matches(d, query));
      if (i >= 0) { rows.splice(i, 1); return { deletedCount: 1 }; }
      return { deletedCount: 0 };
    },
    _rows: rows,
  };
}

// --- stub the db module before anything requires it -------------------------

const agentsCol = collection();
const cacheCol = collection();

const dbPath = path.join(__dirname, '..', 'src', 'db.js');
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  const resolved = (() => {
    try { return Module._resolveFilename(request, parent, isMain); } catch { return request; }
  })();
  if (resolved === dbPath) {
    return {
      connect: async () => ({}),
      db: () => ({}),
      agents: () => agentsCol,
      cache: () => cacheCol,
      close: async () => {},
    };
  }
  return originalLoad.apply(this, arguments);
};

// Force mock mode and keep the directory offline so the seed is used.
process.env.RAIDIAM_MOCK = 'true';
process.env.DIRECTORY_PARTICIPANTS_URL = 'http://127.0.0.1:9/unreachable';

const express = require('express');
const api = require('../src/routes/api');
const lifecycle = require('../src/lifecycle');

// --- run --------------------------------------------------------------------

(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api', api);
  app.use((err, req, res, next) => {
    res.status(err.status || 500).json({ error: err.message });
  });

  const server = app.listen(0);
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  const call = async (method, p, body) => {
    const res = await fetch(base + p, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, json: await res.json().catch(() => ({})) };
  };

  const checks = [];
  const check = (name, fn) => checks.push([name, fn]);

  check('entities load from the bundled snapshot', async () => {
    const { status, json } = await call('GET', '/api/entities');
    assert.strictEqual(status, 200);
    assert.strictEqual(json.source, 'snapshot');
    assert.ok(json.entities.length >= 4, 'expected at least 4 organisations');
    const cba = json.entities.find((e) => e.organisationId === 'CBA-123');
    assert.ok(cba, 'CBA-123 present');
    assert.ok(cba.roles.some((r) => r.role === 'cba.agentic.ap.orchestrator'));
    assert.ok(cba.authorisationServers.some((a) => a.name === 'CommBiz Identity Platform'));
    // Roles must be de-duplicated.
    const names = cba.roles.map((r) => r.role);
    assert.strictEqual(names.length, new Set(names).size, 'roles de-duplicated');
  });

  check('registering requires a known organisation', async () => {
    const { status, json } = await call('POST', '/api/agents', {
      name: 'Bad Org Agent', organisationId: 'NOPE', roles: ['cba.oidc.participant'],
    });
    assert.strictEqual(status, 400);
    assert.match(json.error, /unknown organisation/);
  });

  check('registering rejects a role the entity does not hold', async () => {
    const { status, json } = await call('POST', '/api/agents', {
      name: 'Wrong Role Agent', organisationId: 'CBA-ASB', roles: ['cba.agentic.ap.orchestrator'],
    });
    assert.strictEqual(status, 400);
    assert.match(json.error, /not held by CBA-ASB/);
  });

  check('registering requires at least one role', async () => {
    const { status } = await call('POST', '/api/agents', {
      name: 'No Roles', organisationId: 'CBA-123', roles: [],
    });
    assert.strictEqual(status, 400);
  });

  let softwareId;

  check('an agent registers as pending', async () => {
    const { status, json } = await call('POST', '/api/agents', {
      name: 'Accounts Payable Orchestrator 2',
      description: 'Approves and schedules supplier payments inside a bounded envelope.',
      version: '2.3.0',
      organisationId: 'CBA-123',
      authorisationServerId: '480a9a34-22c2-4c24-b13b-a5ea51b808aa',
      roles: ['cba.oidc.participant', 'cba.agentic.member', 'cba.agentic.ap.orchestrator'],
      businessUnit: 'Business Banking, Accounts Payable',
      accountableOwner: 'Kirsten Yeo, Accounts Payable Product',
      environment: 'sandbox',
      capability: 'supplier-payments',
      repository: 'https://github.com/commbank-agentic/ap-orchestrator',
      sbom: 'sbom/ap-orchestrator-2.3.0.cdx.json',
    });
    assert.strictEqual(status, 201);
    assert.strictEqual(json.status, 'pending');
    assert.strictEqual(json.softwareId, 'accounts-payable-orchestrator-2');
    assert.strictEqual(json.organisationName, 'CBA-Payments');
    assert.strictEqual(json.authorisationServerName, 'CommBiz Identity Platform');
    assert.strictEqual(json.raidiam, null, 'nothing published while pending');
    softwareId = json.softwareId;
  });

  check('a second agent of the same name gets a distinct id', async () => {
    const { json } = await call('POST', '/api/agents', {
      name: 'Accounts Payable Orchestrator 2',
      organisationId: 'CBA-123',
      roles: ['cba.oidc.participant'],
    });
    assert.strictEqual(json.softwareId, 'accounts-payable-orchestrator-2-2');
  });

  check('suspending a pending agent is refused', async () => {
    const { status, json } = await call('POST', `/api/agents/${softwareId}/suspend`);
    assert.strictEqual(status, 409);
    assert.match(json.error, /cannot move from pending to suspended/);
  });

  check('approving publishes to the control plane', async () => {
    const { status, json } = await call('POST', `/api/agents/${softwareId}/approve`);
    assert.strictEqual(status, 200);
    assert.strictEqual(json.status, 'approved');
    assert.ok(json.raidiam, 'raidiam record written');
    assert.ok(json.raidiam.softwareStatementId, 'software statement id present');
    assert.strictEqual(
      json.raidiam.entityId,
      `https://marketplace.demo.cba.raidiam.io/agents/${softwareId}`
    );
    assert.strictEqual(json.raidiam.statementStatus, 'Active');
    assert.deepStrictEqual(json.raidiam.rolesGranted, [
      'cba.oidc.participant', 'cba.agentic.member', 'cba.agentic.ap.orchestrator',
    ]);
    assert.ok(json.raidiam.signingKid, 'signing key recorded');

    const kinds = json.steps.map((s) => s.kind);
    assert.ok(kinds.includes('statement'), 'statement steps');
    assert.ok(kinds.includes('certificate'), 'certificate steps');
    assert.ok(kinds.includes('role'), 'role steps');
    assert.ok(kinds.includes('verify'), 'verify steps');
    assert.ok(!kinds.includes('refused'), 'no refusals in the happy path');
    // Steps are numbered from 1 with no gaps.
    json.steps.forEach((s, i) => assert.strictEqual(s.n, i + 1));

    // The additional metadata bag has a hard 252 character ceiling.
    assert.ok(json.raidiam.payload.AdditionalSoftwareMetadata.length <= 252);
  });

  check('approving twice is refused', async () => {
    const { status } = await call('POST', `/api/agents/${softwareId}/approve`);
    assert.strictEqual(status, 409);
  });

  check('an approved agent cannot be removed', async () => {
    const { status, json } = await call('DELETE', `/api/agents/${softwareId}`);
    assert.strictEqual(status, 409);
    assert.match(json.error, /suspend the agent before removing/);
  });

  check('the instances page lists the published identity', async () => {
    const { status, json } = await call('GET', '/api/instances');
    assert.strictEqual(status, 200);
    assert.strictEqual(json.count, 1);
    assert.strictEqual(json.instances[0].softwareId, softwareId);
  });

  check('suspending sets the statement Inactive', async () => {
    const before = (await call('GET', `/api/agents/${softwareId}`)).json.steps.length;
    const { status, json } = await call('POST', `/api/agents/${softwareId}/suspend`);
    assert.strictEqual(status, 200);
    assert.strictEqual(json.status, 'suspended');
    assert.strictEqual(json.raidiam.statementStatus, 'Inactive');
    assert.ok(json.steps.length > before, 'suspension appended steps');
    // The identity reference survives suspension.
    assert.ok(json.raidiam.softwareStatementId);
  });

  check('reinstating returns the statement to Active', async () => {
    const { status, json } = await call('POST', `/api/agents/${softwareId}/approve`);
    assert.strictEqual(status, 200);
    assert.strictEqual(json.status, 'approved');
    assert.strictEqual(json.raidiam.statementStatus, 'Active');
  });

  check('history records every decision', async () => {
    const { json } = await call('GET', `/api/agents/${softwareId}`);
    const actions = json.history.map((h) => h.action);
    assert.deepStrictEqual(actions, ['registered', 'approved', 'suspended', 'approved']);
  });

  check('filtering by status works', async () => {
    const { json } = await call('GET', '/api/agents?status=pending');
    assert.strictEqual(json.count, 1, 'one pending agent remains');
  });

  check('a failed control-plane write leaves the state unchanged', async () => {
    // Suspend a record whose raidiam reference has been wiped: the client
    // refuses, and the marketplace status must not move.
    const { json: made } = await call('POST', '/api/agents', {
      name: 'Broken Link Agent', organisationId: 'CBA-123', roles: ['cba.oidc.participant'],
    });
    await call('POST', `/api/agents/${made.softwareId}/approve`);
    const row = agentsCol._rows.find((d) => d.softwareId === made.softwareId);
    row.raidiam.softwareStatementId = null;

    const { status } = await call('POST', `/api/agents/${made.softwareId}/suspend`);
    assert.strictEqual(status, 502);

    const after = (await call('GET', `/api/agents/${made.softwareId}`)).json;
    assert.strictEqual(after.status, 'approved', 'status unchanged after a refused write');
    assert.ok(
      after.steps.some((s) => s.kind === 'refused'),
      'the refusal is visible in the log'
    );
    assert.ok(
      after.history.some((h) => h.action === 'suspended-failed'),
      'the failure is in the history'
    );
  });

  check('404 for an unknown agent', async () => {
    const { status } = await call('GET', '/api/agents/does-not-exist');
    assert.strictEqual(status, 404);
  });

  check('config reports mock mode', async () => {
    const { json } = await call('GET', '/api/config');
    assert.strictEqual(json.raidiamMode, 'mock');
  });

  let failed = 0;
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log(`  ok   ${name}`);
    } catch (err) {
      failed += 1;
      console.log(`  FAIL ${name}\n       ${err.message}`);
    }
  }

  server.close();
  console.log(`\n${checks.length - failed}/${checks.length} checks passed`);
  process.exit(failed ? 1 : 0);
})();
