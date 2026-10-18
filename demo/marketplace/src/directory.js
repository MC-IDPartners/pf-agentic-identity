'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');
const { cache } = require('./db');

const SEED = path.join(__dirname, '..', 'seed', 'participants.json');
const KEY = 'directory:participants';

function readSeed() {
  try {
    return JSON.parse(fs.readFileSync(SEED, 'utf8'));
  } catch (err) {
    console.error('[directory] seed unreadable:', err.message);
    return [];
  }
}

/** Reduce the participants export to what the marketplace needs. */
function shape(participants) {
  return participants
    .filter((o) => o && o.OrganisationId)
    .map((o) => ({
      organisationId: o.OrganisationId,
      name: o.OrganisationName,
      legalEntityName: o.LegalEntityName,
      status: o.Status,
      country: o.CountryOfRegistration,
      city: o.City,
      registrationNumber: o.RegistrationNumber,
      authorisationServers: (o.AuthorisationServers || [])
        .filter((a) => a && a.CustomerFriendlyName)
        .map((a) => ({
          id: a.AuthorisationServerId,
          name: a.CustomerFriendlyName,
          description: a.CustomerFriendlyDescription || '',
          issuer: a.Issuer || null,
          discovery: a.OpenIDDiscoveryDocument || null,
          status: a.Status,
        })),
      roles: (o.OrgDomainRoleClaims || [])
        .filter((r) => r && r.Role && r.Status === 'Active')
        .map((r) => ({
          role: r.Role,
          type: r.RoleType || 'Federation',
          domain: r.AuthorisationDomain || 'CBA-Global',
        }))
        // The directory can repeat a role across claims; show each once.
        .filter((r, i, all) => all.findIndex((x) => x.role === r.role) === i)
        .sort((a, b) => a.role.localeCompare(b.role)),
    }))
    .sort((a, b) => a.organisationId.localeCompare(b.organisationId));
}

/**
 * Entities available to register under. Served from the Mongo cache when
 * fresh, refreshed from the live directory when stale, and falling back to
 * the bundled snapshot when the directory cannot be reached.
 */
async function entities({ force = false } = {}) {
  const now = Date.now();
  const maxAge = config.directory.cacheMinutes * 60 * 1000;

  if (!force) {
    const hit = await cache().findOne({ key: KEY });
    if (hit && now - new Date(hit.fetchedAt).getTime() < maxAge) {
      return { entities: hit.value, source: hit.source, fetchedAt: hit.fetchedAt };
    }
  }

  let value;
  let source;
  try {
    const res = await fetch(config.directory.participantsUrl, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(20000),
    });
    if (!res.ok) throw new Error(`status ${res.status}`);
    value = shape(await res.json());
    source = 'live';
    console.log(`[directory] refreshed ${value.length} organisations from the directory`);
  } catch (err) {
    console.warn(`[directory] live fetch failed (${err.message}), using bundled snapshot`);
    const existing = await cache().findOne({ key: KEY });
    if (existing) {
      return { entities: existing.value, source: existing.source, fetchedAt: existing.fetchedAt };
    }
    value = shape(readSeed());
    source = 'snapshot';
  }

  const fetchedAt = new Date().toISOString();
  await cache().updateOne(
    { key: KEY },
    { $set: { key: KEY, value, source, fetchedAt } },
    { upsert: true }
  );
  return { entities: value, source, fetchedAt };
}

module.exports = { entities };
