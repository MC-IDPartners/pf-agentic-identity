'use strict';

const fs = require('fs');
const https = require('https');
const tls = require('tls');
const config = require('./config');

/**
 * HTTPS with the directory client's transport certificate: Raidiam's matls-* hosts (PAR, token, admin API) want
 * mutual TLS, and Node's fetch has no way to present a client certificate, so this is plain https.request.
 */

let tlsOptions;

function options() {
  if (tlsOptions !== undefined) return tlsOptions;
  const { transportCertPath, transportKeyPath, caPath } = config.raidiam;
  tlsOptions = {};
  if (transportCertPath && fs.existsSync(transportCertPath)) tlsOptions.cert = fs.readFileSync(transportCertPath);
  if (transportKeyPath && fs.existsSync(transportKeyPath)) tlsOptions.key = fs.readFileSync(transportKeyPath);
  // The public roots plus the directory's own chain (server-chain.pem), whichever signs its hosts.
  if (caPath && fs.existsSync(caPath)) tlsOptions.ca = [...tls.rootCertificates, fs.readFileSync(caPath, 'utf8')];
  return tlsOptions;
}

/** request(method, url, {headers, body}) -> {status, headers, text, json} */
function request(method, url, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : Buffer.from(body);
    const req = https.request(
      url,
      {
        method,
        headers: { ...headers, ...(payload ? { 'content-length': payload.length } : {}) },
        ...options(),
        timeout: config.raidiam.timeoutMs,
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json;
          try {
            json = text ? JSON.parse(text) : {};
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error(`${method} ${url} timed out`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const form = (data) => new URLSearchParams(data).toString();

module.exports = { request, form, options };
