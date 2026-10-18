'use strict';

const fs = require('fs');
const { agents } = require('./db');
const scenarios = require('./scenarios');

/**
 * Every PoC objective and the evidence for it: the deployed versions' lifecycle actions and scenario runs (each run
 * linked to its evidence pack), and the harness's last report (python harness.py --report reports/latest.json,
 * mounted at /rig/reports). The latest result of each piece of evidence counts.
 */
async function compute() {
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
          evidence: r.evidence || null,
          note: r.passed ? `${r.outcome}${r.refusedAt ? ` at ${r.refusedAt}` : ''}` : `expected ${JSON.stringify(r.expected)}, got ${r.outcome}${r.refusedAt ? ` at ${r.refusedAt}` : ''}: ${r.reason || ''}`.slice(0, 240),
          at: r.at });
      }
    }
    let harness = null;
    try {
      harness = JSON.parse(fs.readFileSync('/rig/reports/latest.json', 'utf8'));
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
    return { objectives, harness: harness ? { at: harness.at, agent: harness.agent, attester: harness.attester,
      passed: (harness.checks || []).filter((c) => c.status === 'pass').length,
      failed: (harness.checks || []).filter((c) => c.status === 'fail').length } : null };
  }

module.exports = { compute };
