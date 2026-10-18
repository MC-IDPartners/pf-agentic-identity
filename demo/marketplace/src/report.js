'use strict';

/**
 * Printable pages for evidence: one run's pack, and the objectives report. Self-contained HTML (no scripts, inline
 * styles), so a browser's "Print to PDF" makes the document to hand over.
 */

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const json = (v) => `<pre>${esc(JSON.stringify(v, null, 2))}</pre>`;
const verdict = (passed) => `<span class="v ${passed ? 'pass' : 'fail'}">${passed ? 'PASS' : 'FAIL'}</span>`;

const STYLE = `
  body { font: 14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color: #1a1a1a; margin: 32px auto; max-width: 1000px; padding: 0 16px; }
  h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 28px 0 8px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
  .sub { color: #555; margin: 0 0 16px; }
  table { border-collapse: collapse; width: 100%; } th, td { text-align: left; vertical-align: top; padding: 5px 8px; border-bottom: 1px solid #e3e3e3; }
  th { width: 210px; color: #444; font-weight: 600; }
  pre, .lines { font: 12px/1.4 ui-monospace, Consolas, monospace; background: #f6f6f6; padding: 10px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
  .v { font: 600 12px ui-monospace, monospace; padding: 2px 8px; border-radius: 3px; }
  .v.pass { background: #e3f4e8; color: #17603a; } .v.fail { background: #fbe4e4; color: #8a1c1c; } .v.none { background: #eee; color: #555; }
  .hash { font: 12px ui-monospace, Consolas, monospace; word-break: break-all; }
  .note { color: #555; font-size: 13px; }
  @media print { body { margin: 0; } h2 { break-after: avoid; } pre, .lines { break-inside: avoid-page; } a { color: inherit; } }
`;

function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style></head><body>${body}</body></html>`;
}

function lines(w) {
  if (!w) return '<p class="note">not collected</p>';
  if (w.error) return `<p class="note">not collected: ${esc(w.error)}</p>`;
  if (!w.lines.length) return `<p class="note">no lines from ${esc(w.container)} between ${esc(w.since)} and ${esc(w.until)}</p>`;
  return `<p class="note">${esc(w.container)}, ${esc(w.since)} to ${esc(w.until)}${w.truncated ? ` (${w.truncated} earlier lines left out)` : ''}</p>
    <div class="lines">${w.lines.map(esc).join('\n')}</div>`;
}

function renderPack(row, check) {
  const p = row.pack;
  const r = p.run;
  const a = p.agent;
  const auth = p.witnesses.raidiam.authorityStatement || {};
  const st = p.witnesses.raidiam.softwareStatement || {};
  return page(`Evidence ${p.seq}: ${r.title}`, `
    <h1>${esc(r.title)} ${verdict(r.passed)}</h1>
    <p class="sub">Evidence pack ${esc(p.seq)} · ${esc(a.name)} ${esc(a.version)} (${esc(a.softwareId)}) · ${esc(r.startedAt)}</p>

    <h2>The run</h2>
    <table>
      <tr><th>Objectives</th><td>${esc((r.objectives || []).join(', '))}</td></tr>
      <tr><th>What it shows</th><td>${esc(r.proves || '')}</td></tr>
      <tr><th>Expected</th><td>${esc(r.expected?.outcome)}${r.expected?.refusedAt ? ` at ${esc(r.expected.refusedAt)}` : ''}</td></tr>
      <tr><th>Outcome</th><td>${esc(r.outcome)}${r.refusedAt ? ` at ${esc(r.refusedAt)}` : ''}${r.reason ? ` - ${esc(r.reason)}` : ''}</td></tr>
      <tr><th>Agent</th><td>${esc(a.entityId)}<br>statement ${esc(a.softwareStatementId || '—')}, SPIFFE ID ${esc(a.spiffeId || '—')}, status at run: ${esc(a.statusAtRun)}</td></tr>
      <tr><th>Started, ended</th><td>${esc(r.startedAt)} → ${esc(r.endedAt)}</td></tr>
    </table>

    <h2>The Trust Controller at the time (Raidiam)</h2>
    <table>
      <tr><th>Authority's statement</th><td>${auth.vouched ? `vouched for: issued ${esc(new Date(auth.iat * 1000).toISOString())}, expires ${esc(new Date(auth.exp * 1000).toISOString())}` : `not vouched for (${esc(auth.status || auth.error || '')})`}<br><span class="note">${esc(auth.url || '')}</span></td></tr>
      ${auth.vouched ? `<tr><th>Keys it publishes</th><td class="hash">${esc((auth.kids || []).join(', '))}</td></tr>
      <tr><th>Capabilities granted</th><td>${esc(JSON.stringify(auth.authorization_details_types))}</td></tr>
      <tr><th>Grant types</th><td>${esc(JSON.stringify(auth.grant_types))}</td></tr>
      <tr><th>Trust marks</th><td>${esc((auth.trust_marks || []).join(', ') || '—')}</td></tr>
      <tr><th>Statement SHA-256</th><td class="hash">${esc(auth.sha256)}</td></tr>` : ''}
      <tr><th>Software statement</th><td>${st.Status ? `${esc(st.Status)}, ${esc(st.ClientName)} ${esc(st.SoftwareVersion || '')}, roles: ${esc((st.roles || []).filter((x) => x.Status === 'Active').map((x) => x.Role).join(', '))}` : esc(st.note || '—')}</td></tr>
    </table>

    <h2>The artefacts</h2>
    <p class="note">Decoded, signatures left out: none of this can be replayed as the credential. The SHA-256 is of the
      token as issued, to match it against logs.</p>
    ${p.artefacts.attestation ? `<h3>Client attestation</h3>${json(p.artefacts.attestation)}` : '<p class="note">no attestation in this run</p>'}
    ${p.artefacts.accessToken ? `<h3>Access token</h3>${json(p.artefacts.accessToken)}` : ''}
    ${(p.artefacts.delegations || []).map((d) => `<h3>Delegation: ${esc(d.step)}</h3>${json(d)}`).join('')}

    <h2>What the agent recorded</h2>
    ${json(p.agentRecord)}
    <div class="lines">${(r.narration || []).map(esc).join('\n')}</div>

    <h2>The gateway (policy enforcement point)</h2>
    ${lines(p.witnesses.gateway)}

    <h2>PingFederate</h2>
    ${lines(p.witnesses.pingfederate)}

    <h2>Integrity</h2>
    <table>
      <tr><th>This pack's SHA-256</th><td class="hash">${esc(row.sha256)}</td></tr>
      <tr><th>Previous pack</th><td class="hash">${p.previous ? `${esc(p.previous.id)}<br>${esc(p.previous.sha256)}` : 'none (the first)'}</td></tr>
      <tr><th>Checked now</th><td>${check.intact ? 'the pack matches its hash' : '<strong>the pack no longer matches its hash</strong>'};
        ${check.previousLinked ? 'linked to the previous pack' : '<strong>the link to the previous pack is broken</strong>'}${check.nextLinked === false ? '; <strong>the next pack does not link to this one</strong>' : ''}</td></tr>
      <tr><th>Collected</th><td>${esc(p.collectedAt)}, ${esc(p.format)}</td></tr>
    </table>
    <p class="note">The SHA-256 is over the pack's canonical JSON (keys sorted): download it from /api/evidence/${esc(p.id)}
      and recompute to check it independently.</p>`);
}

function renderObjectives(data, hash) {
  const state = { evidenced: 'pass', failing: 'fail' };
  return page('PoC objectives: evidence report', `
    <h1>PoC objectives: evidence report</h1>
    <p class="sub">Agentic IDAM - Trust Controller PoC Objectives (10 July 2026) · generated ${esc(data.generatedAt)}</p>
    <table>
      <tr><th>Evidenced</th><td>${data.objectives.filter((o) => o.state === 'evidenced').length} of ${data.objectives.length}</td></tr>
      <tr><th>Failing</th><td>${data.objectives.filter((o) => o.state === 'failing').length}</td></tr>
      <tr><th>Documentary</th><td>${data.objectives.filter((o) => o.state === 'documentary').length}</td></tr>
      <tr><th>Harness</th><td>${data.harness ? `${esc(data.harness.passed)} passed, ${esc(data.harness.failed)} failed - ${esc(data.harness.at)}` : 'no report'}</td></tr>
      <tr><th>This report's SHA-256</th><td class="hash">${esc(hash)}</td></tr>
    </table>
    ${data.objectives.map((o) => `
      <h2>${esc(o.objective)} ${o.state === 'evidenced' || o.state === 'failing' ? `<span class="v ${state[o.state]}">${esc(o.state)}</span>` : `<span class="v none">${esc(o.state)}</span>`}</h2>
      <p>${esc(o.title)}</p>
      ${o.evidence.length ? `<table>${o.evidence.map((e) => `<tr><td style="width:60px">${verdict(e.passed)}</td>
        <td><strong>${esc(e.what)}</strong> · ${esc(e.source)}${e.agent ? ` · ${esc(e.agent)}` : ''} · ${esc(e.at || '')}
        ${e.note ? `<br><span class="note">${esc(String(e.note).slice(0, 300))}</span>` : ''}
        ${e.evidence?.id ? `<br><a href="/evidence/${esc(e.evidence.id)}">evidence pack</a> <span class="hash">${esc(e.evidence.sha256)}</span>` : ''}</td></tr>`).join('')}</table>`
        : `<p class="note">${esc(o.documentary || 'no evidence yet')}</p>`}`).join('')}`);
}

module.exports = { renderPack, renderObjectives };
