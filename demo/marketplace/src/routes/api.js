'use strict';

const express = require('express');
const lifecycle = require('../lifecycle');
const directory = require('../directory');
const config = require('../config');
const auth = require('../raidiam-auth');
const raidiam = require('../raidiam');

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
