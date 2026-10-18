'use strict';

const crypto = require('crypto');
const fs = require('fs');
const config = require('./config');
const { request, form } = require('./mtls');

/**
 * The marketplace's token for Raidiam's admin API.
 *
 *   authorization_code (today)  an operator signs in: PAR with a signed request object and PKCE, the browser
 *                               login, a signed (JARM, query.jwt) response to the redirect URI, then the code at
 *                               the token endpoint. Scope directory:website - the directory's own website scope,
 *                               the only one Raidiam lets a person's session use to manage statements.
 *   client_credentials (later)  the marketplace as itself, scope directory:management, once Raidiam allows that
 *                               scope for client credentials. Nothing else changes: RAIDIAM_GRANT switches it.
 *
 * Either way the client authenticates with private_key_jwt (its rtssigning key) over mutual TLS (its rtstransport
 * certificate). Tokens are held in memory only; a restart means signing in again.
 */

const ASSERTION = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const pending = new Map(); // state -> {verifier, nonce, at}
let tokens = null; // {accessToken, refreshToken, expiresAt, idClaims, grant}
let discovery = null;
let signingKey = null;

const b64url = (buf) => Buffer.from(buf).toString('base64url');

async function metadata() {
  if (discovery) return discovery;
  const res = await request('GET', `${config.raidiam.issuer}/.well-known/openid-configuration`);
  if (res.status !== 200 || !res.json) throw new Error(`Raidiam's discovery document: ${res.status}`);
  const d = res.json;
  const mtls = d.mtls_endpoint_aliases || {};
  discovery = {
    issuer: d.issuer,
    authorization: d.authorization_endpoint,
    jwks: d.jwks_uri,
    par: mtls.pushed_authorization_request_endpoint || d.pushed_authorization_request_endpoint,
    token: mtls.token_endpoint || d.token_endpoint,
  };
  return discovery;
}

function key() {
  if (!signingKey) signingKey = crypto.createPrivateKey(fs.readFileSync(config.raidiam.signingKeyPath));
  return signingKey;
}

/** A PS256 JWT signed with the client's rtssigning key, under the kid Raidiam publishes for it. */
function sign(claims, audience) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'PS256', kid: config.raidiam.signingKid, typ: 'JWT' };
  const body = { ...claims, iss: config.raidiam.clientId, aud: audience, jti: crypto.randomUUID(), iat: now, exp: now + 300 };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(body))}`;
  const sig = crypto.sign('sha256', Buffer.from(input), {
    key: key(),
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });
  return `${input}.${b64url(sig)}`;
}

function clientAuth(issuer) {
  return {
    client_id: config.raidiam.clientId,
    client_assertion_type: ASSERTION,
    client_assertion: sign({ sub: config.raidiam.clientId }, issuer),
  };
}

async function post(url, data) {
  return request('POST', url, {
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: form(data),
  });
}

/** Verifies a JWT from the directory (the JARM response, the ID token) against its published keys. */
async function verify(jwt, audience) {
  const m = await metadata();
  const [h, p, s] = jwt.split('.');
  const header = JSON.parse(Buffer.from(h, 'base64url'));
  const res = await request('GET', m.jwks);
  const jwk = (res.json?.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error(`no key ${header.kid} in ${m.jwks}`);
  const pss = header.alg.startsWith('PS');
  const ok = crypto.verify(
    `sha${header.alg.slice(2)}`,
    Buffer.from(`${h}.${p}`),
    { key: crypto.createPublicKey({ key: jwk, format: 'jwk' }), ...(pss ? { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: Number(header.alg.slice(2)) / 8 } : {}) },
    Buffer.from(s, 'base64url')
  );
  if (!ok) throw new Error('the directory signature did not verify');
  const claims = JSON.parse(Buffer.from(p, 'base64url'));
  const now = Date.now() / 1000;
  if (claims.iss !== m.issuer) throw new Error(`issuer ${claims.iss}, not ${m.issuer}`);
  const aud = [].concat(claims.aud || []);
  if (audience && !aud.includes(audience)) throw new Error(`audience ${aud}, not ${audience}`);
  if (claims.exp && claims.exp < now - 30) throw new Error('expired');
  return claims;
}

/** Step 1: PAR, then the URL to send the operator's browser to. */
async function startLogin() {
  const m = await metadata();
  const verifier = b64url(crypto.randomBytes(48));
  const state = b64url(crypto.randomBytes(16));
  const nonce = b64url(crypto.randomBytes(16));
  const params = {
    response_type: 'code',
    client_id: config.raidiam.clientId,
    scope: config.raidiam.loginScope,
    redirect_uri: config.raidiam.redirectUri,
    state,
    nonce,
    code_challenge_method: 'S256',
    code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()),
    response_mode: 'query.jwt',
  };
  const res = await post(m.par, {
    response_type: 'code',
    request: sign({ ...params, nbf: Math.floor(Date.now() / 1000) }, m.issuer),
    ...clientAuth(m.issuer),
  });
  if (res.status !== 201 || !res.json?.request_uri) {
    throw Object.assign(new Error(`Raidiam refused the sign-in request (PAR): ${res.status} ${res.text.slice(0, 300)}`), { status: 502 });
  }
  for (const [s, v] of pending) if (Date.now() - v.at > 10 * 60000) pending.delete(s);
  pending.set(state, { verifier, nonce, at: Date.now() });
  const q = new URLSearchParams({ client_id: config.raidiam.clientId, request_uri: res.json.request_uri });
  return `${m.authorization}?${q}`;
}

/** Step 3: the redirect (query.jwt) - verify the response, then the code for tokens. */
async function completeLogin(query) {
  if (!query.response) {
    throw Object.assign(new Error(`no response in the redirect: ${JSON.stringify(query).slice(0, 200)}`), { status: 400 });
  }
  const m = await metadata();
  const claims = await verify(query.response, config.raidiam.clientId);
  if (claims.error) throw Object.assign(new Error(`Raidiam: ${claims.error} ${claims.error_description || ''}`), { status: 400 });
  const login = pending.get(claims.state);
  if (!login) throw Object.assign(new Error('unknown or expired sign-in (state)'), { status: 400 });
  pending.delete(claims.state);
  const res = await post(m.token, {
    grant_type: 'authorization_code',
    code: claims.code,
    redirect_uri: config.raidiam.redirectUri,
    code_verifier: login.verifier,
    ...clientAuth(m.issuer),
  });
  if (res.status !== 200 || !res.json?.access_token) {
    throw Object.assign(new Error(`token request refused: ${res.status} ${res.text.slice(0, 300)}`), { status: 502 });
  }
  let idClaims = null;
  if (res.json.id_token) {
    idClaims = await verify(res.json.id_token, config.raidiam.clientId);
    if (idClaims.nonce !== login.nonce) throw Object.assign(new Error('ID token nonce mismatch'), { status: 400 });
  }
  keep(res.json, 'authorization_code', idClaims);
  return status();
}

function keep(body, grant, idClaims) {
  tokens = {
    accessToken: body.access_token,
    refreshToken: body.refresh_token || tokens?.refreshToken || null,
    expiresAt: Date.now() + (body.expires_in || 300) * 1000,
    scope: body.scope || null,
    idClaims: idClaims || tokens?.idClaims || null,
    grant,
  };
}

async function refresh() {
  const m = await metadata();
  const res = await post(m.token, { grant_type: 'refresh_token', refresh_token: tokens.refreshToken, ...clientAuth(m.issuer) });
  if (res.status !== 200 || !res.json?.access_token) {
    tokens = null;
    return false;
  }
  keep(res.json, 'authorization_code');
  return true;
}

async function clientCredentials() {
  const m = await metadata();
  const res = await post(m.token, { grant_type: 'client_credentials', scope: config.raidiam.scope, ...clientAuth(m.issuer) });
  if (res.status !== 200 || !res.json?.access_token) {
    throw Object.assign(new Error(`client credentials refused: ${res.status} ${res.text.slice(0, 300)}`), { status: 502 });
  }
  keep(res.json, 'client_credentials');
}

/** The current access token, refreshed or fetched as the grant allows; else "sign in" (401). */
async function accessToken() {
  if (tokens && tokens.expiresAt > Date.now() + 30000) return tokens.accessToken;
  if (config.raidiam.grant === 'client_credentials') {
    await clientCredentials();
    return tokens.accessToken;
  }
  if (tokens?.refreshToken && (await refresh())) return tokens.accessToken;
  tokens = null;
  throw Object.assign(new Error('sign in to Raidiam first (the control centre has no directory session)'), { status: 401, signIn: true });
}

function status() {
  return {
    grant: config.raidiam.grant,
    signedIn: Boolean(tokens && tokens.expiresAt > Date.now()),
    refreshable: Boolean(tokens?.refreshToken),
    expiresAt: tokens ? new Date(tokens.expiresAt).toISOString() : null,
    scope: tokens?.scope || (config.raidiam.grant === 'client_credentials' ? config.raidiam.scope : config.raidiam.loginScope),
    who: tokens?.idClaims ? tokens.idClaims.email || tokens.idClaims.name || tokens.idClaims.sub : null,
    clientId: config.raidiam.clientId,
    redirectUri: config.raidiam.redirectUri,
  };
}

function signOut() {
  tokens = null;
}

module.exports = { startLogin, completeLogin, accessToken, status, signOut };
