'use strict';

const path = require('path');
const express = require('express');
const config = require('./config');
const db = require('./db');
const api = require('./routes/api');
const auth = require('./raidiam-auth');

async function main() {
  await db.connect();

  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/healthz', (req, res) => res.json({ ok: true }));

  // Signing in to Raidiam (src/raidiam-auth.js). The redirect URI registered on the directory client is
  // https://localhost:8443/cb: the agent provider's gateway (Kong) on 8443 passes /cb through to here.
  app.get('/auth/login', async (req, res, next) => {
    try {
      res.redirect(await auth.startLogin());
    } catch (err) {
      next(err);
    }
  });
  app.get('/cb', async (req, res) => {
    try {
      await auth.completeLogin(req.query);
      res.redirect(`${config.raidiam.afterLogin}/?signedIn=1`);
    } catch (err) {
      console.error('[auth]', err.message);
      res.redirect(`${config.raidiam.afterLogin}/?signInError=${encodeURIComponent(err.message.slice(0, 300))}`);
    }
  });

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
    res.status(status).json({ error: err.message || 'internal error', steps: err.steps, body: err.body, signIn: err.signIn });
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
