'use strict';

const path = require('path');
const express = require('express');
const config = require('./config');
const db = require('./db');
const api = require('./routes/api');

async function main() {
  await db.connect();

  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/healthz', (req, res) => res.json({ ok: true }));
  app.use('/api', api);

  const pub = path.join(__dirname, '..', 'public');
  app.use(express.static(pub));

  // Pretty URLs for the four pages.
  const page = (file) => (req, res) => res.sendFile(path.join(pub, file));
  app.get('/', page('index.html'));
  app.get('/new', page('new.html'));
  app.get('/instances', page('instances.html'));
  app.get('/agents/:softwareId', page('agent.html'));

  app.use((err, req, res, next) => {
    const status = err.status || 500;
    if (status >= 500) console.error('[error]', err);
    res.status(status).json({ error: err.message || 'internal error', steps: err.steps });
  });

  app.listen(config.port, () => {
    console.log(`[server] agent marketplace on http://localhost:${config.port}`);
    console.log(`[server] raidiam mode: ${config.raidiam.mock ? 'mock' : 'live'}`);
  });
}

main().catch((err) => {
  console.error('[fatal]', err);
  process.exit(1);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    await db.close().catch(() => {});
    process.exit(0);
  });
}
