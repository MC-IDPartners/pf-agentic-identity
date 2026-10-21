'use strict';

const crypto = require('crypto');
const fs = require('fs');
const { execFile } = require('child_process');
const config = require('./config');

/**
 * The bridge keys, in the KMS (OpenBao's transit engine): created when a version is deployed, never exported. The
 * marketplace may create keys and have the vault make their CSRs, never sign with them - PingFederate's token is the
 * one that signs (../../openbao/setup.py). A key is named for the client it authenticates, bridge-<statement id>, the
 * name PingFederate's bridge template gives a Raidiam-hosted agent, so enrolling one needs no change at PingFederate.
 */

function token() {
  return fs.readFileSync(config.rig.openbaoTokenFile, 'utf8').trim();
}

async function bao(method, path, body, ok = [200, 204]) {
  const res = await fetch(config.rig.openbaoAddr + path, {
    method,
    headers: { 'X-Vault-Token': token(), 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(15000),
  });
  const text = await res.text();
  if (!ok.includes(res.status)) throw new Error(`OpenBao ${method} ${path}: ${res.status} ${text.slice(0, 200)}`);
  return { status: res.status, body: text ? JSON.parse(text) : {} };
}

const keyName = (softwareStatementId) => `bridge-${softwareStatementId}`;

/** The bridge key's public half as a JWK ({kty, n, e}), creating the key (rsa-2048, not exportable) when asked. */
async function bridgeKey(softwareStatementId, create = false) {
  const path = `/v1/transit/keys/${keyName(softwareStatementId)}`;
  let { status, body } = await bao('GET', path, null, [200, 404]);
  if (status === 404) {
    if (!create) return null;
    await bao('POST', path, { type: 'rsa-2048', exportable: false });
    ({ body } = await bao('GET', path));
  }
  const latest = body.data.keys[String(body.data.latest_version)];
  return crypto.createPublicKey(latest.public_key).export({ format: 'jwk' });
}

/** A CSR template with this subject, signed by a throwaway key: the vault keeps the subject and signs with its own key. */
function template(subject) {
  return new Promise((resolve, reject) => {
    execFile('openssl', ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', '/dev/null', '-subj', subject,
      '-outform', 'PEM'], { timeout: 30000 }, (err, stdout, stderr) => (err ? reject(new Error(stderr || err.message)) : resolve(stdout)));
  });
}

/** The bridge key's CSR, made and signed inside the vault, for the statement (CN) in the organisation (OU). */
async function bridgeCsr(softwareStatementId, organisationId, organisation) {
  await bridgeKey(softwareStatementId, true);
  const csr = await template(`/C=GB/O=${organisation || 'CBA Trust Framework'}/OU=${organisationId}/CN=${softwareStatementId}`);
  const { body } = await bao('POST', `/v1/transit/keys/${keyName(softwareStatementId)}/csr`, { csr });
  return body.data.csr;
}

module.exports = { bridgeKey, bridgeCsr, keyName };
