'use strict';

const express = require('express');
const lifecycle = require('../lifecycle');
const directory = require('../directory');
const config = require('../config');
const auth = require('../raidiam-auth');
const raidiam = require('../raidiam');
const deploy = require('../deploy');
const scenarios = require('../scenarios');
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
    const out = await deploy.run(doc, scenario.job, scenario);
    const record = {
      scenario: scenario.id, title: scenario.title, job: scenario.job, objectives: scenario.objectives,
      expected: scenario.expect, passed: scenarios.judge(scenario, out.result),
      outcome: out.result.outcome, refusedAt: out.result.refused_at || null, reason: out.result.reason || null,
      steps: out.result.steps || {}, log: out.log, status: doc.status, at: new Date().toISOString(),
    };
    await agents().updateOne({ softwareId: doc.softwareId }, { $push: { runs: { $each: [record], $slice: -100 } } });
    res.json(record);
  })
);

router.get('/scenarios', (req, res) => res.json({ scenarios: scenarios.SCENARIOS, actions: scenarios.ACTIONS }));

// Every PoC objective and the evidence for it: the deployed versions' lifecycle actions and scenario runs, and the
// harness's last report (python harness.py --report reports/latest.json, mounted at /rig/reports).
router.get(
  '/objectives',
  wrap(async (req, res) => {
    const docs = await agents().find({ kind: 'principal' }).toArray();
    const evidence = Object.fromEntries(Object.keys(scenarios.OBJECTIVES).map((tc) => [tc, []]));
    const add = (tcs, item) => tcs.forEach((tc) => evidence[tc] && evidence[tc].push(item));
    for (const doc of docs) {
      for (const h of doc.history || []) {
        const action = h.action === 'approved' ? (doc.history.some((x) => x.action === 'suspended' && x.at < h.at) ? 'reinstate' : 'deploy')
          : h.action === 'suspended' ? 'suspend' : null;
        const failed = h.action.endsWith('-failed');
        const base = failed ? (h.action.startsWith('approved') ? 'deploy' : 'suspend') : action;
        if (!base) continue;
        add(scenarios.ACTIONS[base].objectives, { source: 'marketplace', agent: doc.softwareId, what: base,
          passed: !failed, note: h.note, proves: scenarios.ACTIONS[base].proves, at: h.at });
      }
      for (const r of doc.runs || []) {
        if (!r.scenario) continue;
        add(r.objectives || [], { source: 'marketplace', agent: doc.softwareId, what: r.title, passed: r.passed,
          note: r.passed ? `${r.outcome}${r.refusedAt ? ` at ${r.refusedAt}` : ''}` : `expected ${JSON.stringify(r.expected)}, got ${r.outcome}${r.refusedAt ? ` at ${r.refusedAt}` : ''}: ${r.reason || ''}`.slice(0, 240),
          at: r.at });
      }
    }
    let harness = null;
    try {
      harness = JSON.parse(require('fs').readFileSync('/rig/reports/latest.json', 'utf8'));
      for (const row of harness.checks || []) {
        add(row.objectives || [], { source: 'harness', agent: harness.agent, what: row.check,
          passed: row.status === 'pass', skipped: row.status === 'skip', note: row.detail, proves: row.proves, at: harness.at });
      }
    } catch { /* no report yet */ }
    const objectives = Object.entries(scenarios.OBJECTIVES).map(([tc, title]) => {
      const items = evidence[tc].filter((i) => !i.skipped);
      const latest = {};
      for (const i of items) {
        const k = `${i.source}|${i.agent}|${i.what}`;
        if (!latest[k] || latest[k].at < i.at) latest[k] = i;
      }
      const current = Object.values(latest);
      const state = current.some((i) => !i.passed) ? 'failing' : current.length ? 'evidenced'
        : scenarios.DOCUMENTARY[tc] ? 'documentary' : 'not yet';
      return { objective: tc, title, state, documentary: scenarios.DOCUMENTARY[tc] || null,
        evidence: current.sort((x, y) => (y.at || '').localeCompare(x.at || '')) };
    });
    res.json({ objectives, harness: harness ? { at: harness.at, agent: harness.agent, attester: harness.attester,
      passed: (harness.checks || []).filter((c) => c.status === 'pass').length,
      failed: (harness.checks || []).filter((c) => c.status === 'fail').length } : null });
  })
);

// Where the deployed version stands: hosted by the provider, vouched for by Raidiam, registered at PingFederate.
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
