'use strict';

const express = require('express');
const lifecycle = require('../lifecycle');
const directory = require('../directory');
const config = require('../config');
const auth = require('../raidiam-auth');
const raidiam = require('../raidiam');
const deploy = require('../deploy');
const scenarios = require('../scenarios');
const evidence = require('../evidence');
const objectives = require('../objectives');
const { agents } = require('../db');

const router = express.Router();

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

router.get(
  '/config',
  wrap(async (req, res) => {
    res.json({
      raidiamMode: config.raidiam.mock ? 'mock' : 'live',
      auth: config.raidiam.mock ? null : auth.status(),
      baseUrl: config.raidiam.mock ? null : config.raidiam.baseUrl,
      entityIdBase: config.entityIdBase,
      directoryUrl: config.directory.participantsUrl,
    });
  })
);

// The directory session: who is signed in to Raidiam, and until when.
router.get('/auth', (req, res) => res.json(auth.status()));
router.post('/auth/logout', (req, res) => {
  auth.signOut();
  res.json(auth.status());
});

// Read-only passthrough to Raidiam's admin API with the current session, for checking what the control plane
// holds (GET /api/raidiam/organisations/CBA-123/softwarestatements/<id>). Writes go through the lifecycle only.
router.get(
  /^\/raidiam\/(.+)$/,
  wrap(async (req, res) => {
    const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    res.json(await raidiam.call('GET', `/${req.params[0]}${query}`, {}));
  })
);

router.get(
  '/entities',
  wrap(async (req, res) => {
    const result = await directory.entities({ force: req.query.refresh === 'true' });
    res.json(result);
  })
);

router.get(
  '/agents',
  wrap(async (req, res) => {
    const docs = await lifecycle.list({
      status: req.query.status,
      organisationId: req.query.organisationId,
    });
    res.json({ agents: docs, count: docs.length });
  })
);

router.get(
  '/agents/:softwareId',
  wrap(async (req, res) => {
    const doc = await lifecycle.get(req.params.softwareId);
    if (!doc) return res.status(404).json({ error: 'agent not found' });
    res.json(doc);
  })
);

router.post(
  '/agents',
  wrap(async (req, res) => {
    const body = req.body || {};
    const missing = ['name', 'organisationId'].filter((f) => !body[f]);
    if (missing.length) {
      return res.status(400).json({ error: `missing required field(s): ${missing.join(', ')}` });
    }
    if (!Array.isArray(body.roles) || body.roles.length === 0) {
      return res.status(400).json({ error: 'select at least one role' });
    }

    // Roles must exist on the chosen organisation in the directory.
    const { entities } = await directory.entities();
    const org = entities.find((e) => e.organisationId === body.organisationId);
    if (!org) {
      return res.status(400).json({ error: `unknown organisation: ${body.organisationId}` });
    }
    const available = new Set(org.roles.map((r) => r.role));
    const unknown = body.roles.filter((r) => !available.has(r));
    if (unknown.length) {
      return res
        .status(400)
        .json({ error: `role(s) not held by ${org.organisationId}: ${unknown.join(', ')}` });
    }

    body.organisationName = org.name;
    if (body.authorisationServerId) {
      const as = org.authorisationServers.find((a) => a.id === body.authorisationServerId);
      body.authorisationServerName = as ? as.name : '';
    }

    const doc = await lifecycle.create(body, req.get('x-actor') || 'marketplace');
    res.status(201).json(doc);
  })
);

router.post(
  '/agents/:softwareId/approve',
  wrap(async (req, res) => {
    const doc = await lifecycle.transition(
      req.params.softwareId,
      'approved',
      req.get('x-actor') || 'marketplace'
    );
    res.json(doc);
  })
);

router.post(
  '/agents/:softwareId/suspend',
  wrap(async (req, res) => {
    const doc = await lifecycle.transition(
      req.params.softwareId,
      'suspended',
      req.get('x-actor') || 'marketplace'
    );
    res.json(doc);
  })
);

// A scenario run as a deployed Principal version (agent.py, in a container SPIRE identifies as that version), judged
// against what it should do and recorded on the agent as evidence. Body: {scenario} (src/scenarios.js).
router.post(
  '/agents/:softwareId/run',
  wrap(async (req, res) => {
    const doc = await lifecycle.get(req.params.softwareId);
    if (!doc) return res.status(404).json({ error: 'agent not found' });
    const scenario = scenarios.SCENARIOS.find((x) => x.id === (req.body || {}).scenario);
    if (!scenario) return res.status(400).json({ error: `unknown scenario: ${(req.body || {}).scenario}` });
    const startedAt = Date.now();
    const out = await deploy.run(doc, scenario.job, scenario);
    const endedAt = Date.now();
    const record = {
      scenario: scenario.id, title: scenario.title, job: scenario.job, objectives: scenario.objectives,
      expected: scenario.expect, passed: scenarios.judge(scenario, out.result),
      outcome: out.result.outcome, refusedAt: out.result.refused_at || null, reason: out.result.reason || null,
      steps: out.result.steps || {}, log: out.log, status: doc.status, at: new Date().toISOString(),
    };
    try {
      record.evidence = await evidence.collect(doc, record, startedAt, endedAt);
    } catch (err) {
      record.evidence = { error: `evidence not collected: ${err.message}` };
    }
    delete record.steps.attest?.artefact; // kept in the evidence pack, not on the agent record
    delete record.steps.token?.artefact;
    for (const step of Object.values(record.steps)) {
      if (step) delete step.exchange; // also kept in the evidence pack only
    }
    await agents().updateOne({ softwareId: doc.softwareId }, { $push: { runs: { $each: [record], $slice: -100 } } });
    res.json(record);
  })
);

// A deploy's CSRs, for uploading in the Raidiam website when its API will not certify them (PEM).
router.get(
  '/agents/:softwareId/csr/:name',
  wrap(async (req, res) => {
    const doc = await lifecycle.get(req.params.softwareId);
    const pem = doc?.deploy?.csrs?.[req.params.name];
    if (!pem) return res.status(404).json({ error: 'no CSR for that key on this deploy' });
    res.type('application/x-pem-file')
      .set('content-disposition', `attachment; filename="${doc.deploy.slot}-${req.params.name}-${doc.deploy.softwareStatementId}.csr"`)
      .send(pem);
  })
);

// Sets an existing statement's SPIFFE metadata (src/deploy.js setSpiffeMetadata): {softwareStatementId, spiffeId,
// organisationId?}. A write to Raidiam with the operator's session.
router.post(
  '/raidiam-spiffe-metadata',
  wrap(async (req, res) => {
    const { softwareStatementId, spiffeId, organisationId } = req.body || {};
    if (!softwareStatementId || !/^spiffe:\/\/[^/]+\/.+/.test(spiffeId || '')) {
      return res.status(400).json({ error: 'softwareStatementId and a spiffe:// spiffeId are required' });
    }
    res.json(await deploy.setSpiffeMetadata(organisationId || process.env.RAIDIAM_ORGANISATION_ID || 'CBA-123',
      softwareStatementId, spiffeId));
  })
);

router.get('/scenarios', (req, res) => res.json({ scenarios: scenarios.SCENARIOS, actions: scenarios.ACTIONS }));

// Every PoC objective and the evidence for it (src/objectives.js).
router.get('/objectives', wrap(async (req, res) => res.json(await objectives.compute())));

// Evidence packs (src/evidence.js): the list, one pack as JSON (a download), and whether it still holds.
router.get('/evidence', wrap(async (req, res) => res.json({ packs: await evidence.list(req.query.softwareId) })));
router.get(
  '/evidence/:id',
  wrap(async (req, res) => {
    const row = await evidence.get(req.params.id);
    if (!row) return res.status(404).json({ error: 'no such evidence pack' });
    res.set('content-disposition', `attachment; filename="evidence-${row.seq}-${row.softwareId}-${row.pack.run.scenario}.json"`)
      .json({ sha256: row.sha256, pack: row.pack });
  })
);
router.get('/evidence/:id/verify', wrap(async (req, res) => res.json(await evidence.verify(req.params.id))));

// Where the deployed version stands: hosted and vouched for by Raidiam, registered by PingFederate at its first token.
router.get(
  '/agents/:softwareId/status',
  wrap(async (req, res) => {
    const doc = await lifecycle.get(req.params.softwareId);
    if (!doc) return res.status(404).json({ error: 'agent not found' });
    res.json((await deploy.status(doc)) || { state: 'not deployed' });
  })
);

router.delete(
  '/agents/:softwareId',
  wrap(async (req, res) => {
    res.json(await lifecycle.remove(req.params.softwareId));
  })
);

router.get(
  '/instances',
  wrap(async (req, res) => {
    const docs = await lifecycle.instances();
    res.json({ instances: docs, count: docs.length });
  })
);

module.exports = router;
