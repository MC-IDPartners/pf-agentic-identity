'use strict';

const crypto = require('crypto');
const config = require('./config');
const raidiam = require('./raidiam');
const rig = require('./rig');
const { db } = require('./db');
const scenarios = require('./scenarios');

/**
 * Evidence packs: one per scenario run, collected when the run ends and kept as it was.
 *
 * A pack holds the run (scenario, expectation, verdict, the agent's own record and narration), the artefacts it
 * used (the attestation and the token, decoded, their signatures left out so they cannot be replayed), each MCP call
 * it made - the JSON-RPC request and the resource's or agent's response or error (capped, with the response's
 * SHA-256) - and what
 * independent witnesses recorded in the seconds it took:
 *   - the gateway's policy enforcement point (coaz-pep): each decision, with its principal and reason;
 *   - PingFederate (the OpenID Federation modules' log lines): the attestation issued and verified, registrations;
 *   - Raidiam: the authority's subordinate statement about the agent at that moment (public), and - with an operator
 *     session - the software statement and its roles read back.
 *
 * Each pack carries the SHA-256 of its canonical JSON and the previous pack's, so they form a chain: a pack changed
 * afterwards no longer matches its hash, and one removed breaks the chain. The chain is held in the marketplace's own
 * database, so it shows tampering with packs, not with the database as a whole - for that, keep the published
 * hashes (each pack and the objectives report print them) somewhere the marketplace cannot write.
 */

const FORMAT = 'agentic-idam-poc evidence pack v1';
const evidence = () => db().collection('evidence');

/** JSON with keys sorted at every level: the same content always hashes the same. */
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().filter((k) => value[k] !== undefined)
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value === undefined ? null : value);
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

async function logs(container, since, until, keep, limit) {
  const out = await rig.docker(['logs', '--timestamps', '--since', since, '--until', until, container], { timeout: 60000 });
  if (out.code) return { container, error: (out.stderr || out.stdout).trim().slice(-200), lines: [] };
  const lines = (out.stdout + out.stderr).split('\n').filter((l) => l.trim() && keep(l))
    .map((l) => l.replace(/\/opt\/out\/instance\/log\/server\.log:\s*/, ''));
  return { container, since, until, lines: lines.slice(-limit), truncated: lines.length > limit ? lines.length - limit : 0 };
}

function claims(jwt) {
  const p = jwt.split('.')[1];
  return JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
}

/** The authority's statement about the agent, as anyone would fetch it: is it vouched for, with what. */
async function authorityStatement(entityId) {
  const authority = (process.env.AGENT_ENV_AUTHORITY || '').replace(/\/$/, '');
  if (!authority || !entityId) return { error: 'no authority or entity id' };
  const url = `${authority}/fetch?sub=${encodeURIComponent(entityId)}`;
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(20000) });
    const text = (await res.text()).trim();
    if (!res.ok) return { url, status: res.status, vouched: false, body: text.slice(0, 200) };
    const c = claims(text);
    const rp = (c.metadata_policy || {}).openid_relying_party || {};
    return {
      url, status: res.status, vouched: true, iss: c.iss, sub: c.sub, iat: c.iat, exp: c.exp,
      kids: (c.jwks?.keys || []).map((k) => k.kid),
      authorization_details_types: rp.authorization_details_types || null,
      grant_types: rp.grant_types || null,
      trust_marks: (c.trust_marks || []).map((t) => (typeof t === 'string' ? claims(t).id : t.id || t.trust_mark_type)),
      sha256: sha256(text),
    };
  } catch (err) {
    return { url, error: err.message };
  }
}

async function statementReadBack(doc) {
  const ssId = doc.deploy?.softwareStatementId;
  if (!ssId) return { note: 'not deployed by this marketplace' };
  const P = config.raidiam.paths;
  try {
    const st = await raidiam.call('GET', P.softwareStatement, { orgId: doc.organisationId, ssId });
    const roles = await raidiam.call('GET', P.authorityClaims, { orgId: doc.organisationId, ssId });
    return {
      softwareStatementId: ssId, Status: st.Status, ClientId: st.ClientId, ClientName: st.ClientName,
      SoftwareVersion: st.SoftwareVersion,
      roles: (roles || []).map((r) => ({ Role: r.Role, Status: r.Status, AuthorisationDomain: r.AuthorisationDomain })),
    };
  } catch (err) {
    return { softwareStatementId: ssId, note: err.signIn ? 'no Raidiam session at the time: sign in to include the read-back' : err.message };
  }
}

/**
 * Collect, hash and keep the pack for one run. Returns {id, sha256}.
 */
async function collect(doc, record, startedAt, endedAt) {
  const since = new Date(startedAt - 3000).toISOString();
  const until = new Date(endedAt + 3000).toISOString();
  const entityId = doc.deploy?.entityId || doc.raidiam?.entityId;
  const [gateway, pingfederate, authority, statement] = await Promise.all([
    logs(config.rig.coazContainer, since, until, (l) => l.includes('[PEP') || l.includes('ssf:') || l.includes('refused'), 300),
    logs(config.rig.pfContainer, since, until, (l) => l.includes('com.pingidentity.ps.oidf'), 200),
    authorityStatement(entityId),
    statementReadBack(doc),
  ]);
  const steps = record.steps || {};
  const scenario = scenarios.SCENARIOS.find((s) => s.id === record.scenario);
  const previous = await evidence().find().sort({ seq: -1 }).limit(1).next();
  const id = crypto.randomUUID();
  const pack = {
    format: FORMAT,
    id,
    seq: (previous?.seq || 0) + 1,
    previous: previous ? { id: previous._id, sha256: previous.sha256 } : null,
    collectedAt: new Date().toISOString(),
    agent: {
      softwareId: doc.softwareId, name: doc.name, version: doc.version, statusAtRun: doc.status,
      entityId, softwareStatementId: doc.deploy?.softwareStatementId || null, slot: doc.deploy?.slot || null,
      spiffeId: doc.deploy?.spiffeId || null, organisationId: doc.organisationId,
    },
    run: {
      scenario: record.scenario, title: record.title, proves: scenario?.proves || null, job: record.job,
      objectives: record.objectives, expected: record.expected, passed: record.passed, outcome: record.outcome,
      refusedAt: record.refusedAt, reason: record.reason, startedAt: new Date(startedAt).toISOString(),
      endedAt: new Date(endedAt).toISOString(), narration: record.log,
    },
    artefacts: {
      attestation: steps.attest?.artefact || null,
      accessToken: steps.token?.artefact || null,
      exchanges: Object.entries(steps).filter(([, v]) => v && v.exchange).map(([step, v]) => ({
        step, to: v.agent || v.endpoint || null, tool: v.tool || null, ...v.exchange })),
      delegations: ['accounts', 'payments'].filter((s) => steps[s]).map((s) => ({
        step: s, principalToken: steps[s].principal_token || null, delegation: steps[s].delegation || null,
        decision: steps[s].decision || null })),
    },
    agentRecord: Object.fromEntries(Object.entries(steps).map(([k, v]) => [k, Object.fromEntries(
      Object.entries(v || {}).filter(([kk]) => !['artefact', 'principal_token', 'exchange'].includes(kk)))])),
    witnesses: { gateway, pingfederate, raidiam: { authorityStatement: authority, softwareStatement: statement } },
  };
  const hash = sha256(canonical(pack));
  await evidence().insertOne({ _id: id, seq: pack.seq, softwareId: doc.softwareId, at: pack.collectedAt, sha256: hash, pack });
  return { id, sha256: hash };
}

async function get(id) {
  return evidence().findOne({ _id: id });
}

/** Does the pack still match its hash, and does the chain hold around it? */
async function verify(id) {
  const row = await get(id);
  if (!row) return { found: false };
  const intact = sha256(canonical(row.pack)) === row.sha256;
  const prev = row.pack.previous ? await get(row.pack.previous.id) : null;
  const next = await evidence().findOne({ 'pack.previous.id': id });
  return {
    found: true, id, seq: row.seq, sha256: row.sha256, intact,
    previousLinked: row.pack.previous ? Boolean(prev && prev.sha256 === row.pack.previous.sha256) : true,
    nextLinked: next ? next.pack.previous.sha256 === row.sha256 : null,
  };
}

async function list(softwareId) {
  return evidence().find(softwareId ? { softwareId } : {}).project({ pack: 0 }).sort({ seq: -1 }).toArray();
}

module.exports = { collect, get, verify, list, canonical, sha256 };
