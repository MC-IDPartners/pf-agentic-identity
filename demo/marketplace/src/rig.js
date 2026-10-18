'use strict';

const fs = require('fs');
const https = require('https');
const { execFile } = require('child_process');
const config = require('./config');

/**
 * The rig around the marketplace: the agent provider's admin API (Principal version slots), SPIRE (registration
 * entries, through the Docker socket), the agent image (a job run as a deployed version) and PingFederate's Shared
 * Signals transmitter (lifecycle events).
 */

const rig = config.rig;

function docker(args, { timeout = 600000, env } = {}) {
  return new Promise((resolve) => {
    execFile('docker', args, { timeout, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, ...(env || {}) } },
      (err, stdout, stderr) => resolve({ code: err ? err.code || 1 : 0, stdout: String(stdout), stderr: String(stderr) }));
  });
}

/** The provider's admin API (inside the compose network only). */
async function provider(method, path, body) {
  const res = await fetch(rig.providerAdmin + path, {
    method,
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(30000),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`provider ${method} ${path} → ${res.status}: ${json.error_description || json.error || ''}`);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

/** A SPIRE registration entry: spiffeId for containers labelled app=<label>. Returns 'exists' or 'created'. */
async function spireEntry(spiffeId, label) {
  const server = ['exec', rig.spireServer, '/opt/spire/bin/spire-server'];
  const shown = await docker([...server, 'entry', 'show', '-spiffeID', spiffeId]);
  if (shown.stdout.includes(`docker:label:app:${label}`)) return 'exists';
  const made = await docker([...server, 'entry', 'create', '-spiffeID', spiffeId, '-parentID', rig.spireParent,
    '-selector', `docker:label:app:${label}`]);
  if (made.code) throw new Error(`SPIRE refused the entry: ${(made.stderr || made.stdout).trim().slice(-300)}`);
  return 'created';
}

async function removeSpireEntry(spiffeId) {
  const server = ['exec', rig.spireServer, '/opt/spire/bin/spire-server'];
  const shown = await docker([...server, 'entry', 'show', '-spiffeID', spiffeId]);
  for (const [, id] of shown.stdout.matchAll(/Entry ID\s*:\s*(\S+)/g)) {
    await docker([...server, 'entry', 'delete', '-entryID', id]);
  }
}

/** The environment every agent run gets: AGENT_ENV_<NAME> in the marketplace's own environment, as <NAME>. */
function agentEnv() {
  return Object.fromEntries(Object.entries(process.env)
    .filter(([k]) => k.startsWith('AGENT_ENV_')).map(([k, v]) => [k.slice('AGENT_ENV_'.length), v]));
}

/**
 * Runs agent.py <job> as a deployed version: a container labelled app=<label> (so SPIRE issues it that version's
 * SPIFFE ID), with its own state volume (its own instance key), on the rig's network. Returns the AGENT_RESULT and
 * the output's tail.
 */
async function runAgent({ label, agentId, job, extraEnv = {} }) {
  const env = { ...agentEnv(), AGENT_ID: agentId, ...extraEnv };
  const name = `marketplace-run-${label}-${Date.now()}`;
  const create = await docker(['create', '--name', name, '--label', `app=${label}`, '--network', rig.network,
    '-v', `${rig.spireSocketsVolume}:/run/spire/sockets`, '-v', `${rig.statePrefix}${label}-state:/state`,
    ...Object.keys(env).flatMap((k) => ['-e', k]), '--entrypoint', 'python', rig.agentImage, 'agent.py', job],
  { env, timeout: 60000 });
  if (create.code) throw new Error(`docker create: ${create.stderr.trim().slice(-300)}`);
  try {
    for (const [from, to] of [[rig.certsDir, '/certs'], [rig.fedDir, '/fed']]) {
      const cp = await docker(['cp', `${from}/.`, `${name}:${to}`], { timeout: 60000 });
      if (cp.code) throw new Error(`docker cp ${from}: ${cp.stderr.trim().slice(-300)}`);
    }
    const run = await docker(['start', '-a', name], { timeout: 600000 });
    const out = run.stdout + run.stderr;
    const line = out.split('\n').reverse().find((l) => l.startsWith('AGENT_RESULT '));
    const result = line ? JSON.parse(line.slice('AGENT_RESULT '.length)) : { outcome: 'error', reason: 'no AGENT_RESULT line' };
    return { result, log: out.split('\n').filter((l) => l.startsWith('[')).slice(-40) };
  } finally {
    await docker(['rm', '-f', name], { timeout: 60000 });
  }
}

function pfRequest(method, path, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body);
    const req = https.request(rig.pfUrl + path, {
      method,
      headers: { ...headers, ...(payload ? { 'content-length': payload.length } : {}) },
      ca: fs.existsSync(`${rig.certsDir}/pf-runtime-tls-ca.crt`) ? fs.readFileSync(`${rig.certsDir}/pf-runtime-tls-ca.crt`) : undefined,
      timeout: 20000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json;
        try { json = JSON.parse(text); } catch { json = undefined; }
        resolve({ status: res.statusCode, text, json });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function emitterSecret() {
  try {
    const line = fs.readFileSync(rig.secretsFile, 'utf8').split('\n').find((l) => l.startsWith('TF_VAR_ssf_emitter_client_secret='));
    return line ? line.split('=').slice(1).join('=').trim() : '';
  } catch {
    return '';
  }
}

/**
 * A Shared Signals event about an agent, raised at PingFederate's transmitter as its operator
 * (conformance-ssf-emitter): every stream - the gateway's PEP among them - receives it. Returns the stream count.
 */
async function emit(eventType, agentId) {
  const secret = emitterSecret();
  if (!secret) throw new Error(`no TF_VAR_ssf_emitter_client_secret in ${rig.secretsFile}`);
  const tok = await pfRequest('POST', '/as/token.oauth2', {
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: 'conformance-ssf-emitter',
      client_secret: secret, scope: 'ssf.provision' }).toString(),
  });
  if (tok.status !== 200) throw new Error(`the transmitter's token: ${tok.status} ${tok.text.slice(0, 200)}`);
  const res = await pfRequest('POST', '/ssf/events:emit', {
    headers: { authorization: `Bearer ${tok.json.access_token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ event_type: eventType, event: {}, subject: { format: 'iss_sub', iss: rig.pfIssuer, sub: agentId } }),
  });
  if (res.status >= 300) throw new Error(`events:emit ${res.status} ${res.text.slice(0, 200)}`);
  return (res.json || {}).count || 0;
}

module.exports = { docker, provider, spireEntry, removeSpireEntry, runAgent, emit };
