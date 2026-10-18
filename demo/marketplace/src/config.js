'use strict';

const bool = (v, def = false) => {
  if (v === undefined || v === '') return def;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
};

const config = {
  port: Number(process.env.PORT || 3000),

  mongo: {
    url: process.env.MONGO_URL || 'mongodb://mongo:27017',
    db: process.env.MONGO_DB || 'agent_marketplace',
  },

  // Public participants export. No credentials needed.
  directory: {
    participantsUrl:
      process.env.DIRECTORY_PARTICIPANTS_URL || 'https://data.directory.cba.raidiam.io',
    // How long a fetched snapshot stays fresh, in minutes.
    cacheMinutes: Number(process.env.DIRECTORY_CACHE_MINUTES || 60),
  },

  // Raidiam Connect admin API. Leave the credentials unset to run in mock mode.
  raidiam: {
    // When true, no outbound calls are made: the lifecycle is simulated and
    // every step is still written to the deployment log.
    mock: bool(process.env.RAIDIAM_MOCK, !process.env.RAIDIAM_CLIENT_ID),

    baseUrl: process.env.RAIDIAM_BASE_URL || 'https://matls-api.directory.cba.raidiam.io',
    tokenUrl:
      process.env.RAIDIAM_TOKEN_URL || 'https://matls-auth.directory.cba.raidiam.io/token',
    clientId: process.env.RAIDIAM_CLIENT_ID || '',
    clientSecret: process.env.RAIDIAM_CLIENT_SECRET || '',
    scope: process.env.RAIDIAM_SCOPE || 'directory:software',

    // Optional mutual TLS material, as file paths mounted into the container.
    certPath: process.env.RAIDIAM_CERT_PATH || '',
    keyPath: process.env.RAIDIAM_KEY_PATH || '',
    caPath: process.env.RAIDIAM_CA_PATH || '',

    // Endpoint templates. Override if your tenant differs.
    paths: {
      softwareStatements:
        process.env.RAIDIAM_PATH_SOFTWARE_STATEMENTS ||
        '/organisations/{orgId}/softwarestatements',
      softwareStatement:
        process.env.RAIDIAM_PATH_SOFTWARE_STATEMENT ||
        '/organisations/{orgId}/softwarestatements/{ssId}',
      authorityClaims:
        process.env.RAIDIAM_PATH_AUTHORITY_CLAIMS ||
        '/organisations/{orgId}/softwarestatements/{ssId}/authorityclaims',
    },

    timeoutMs: Number(process.env.RAIDIAM_TIMEOUT_MS || 20000),
  },

  // Base used to mint entity ids for agents, mirroring the demo marketplace.
  entityIdBase:
    process.env.ENTITY_ID_BASE || 'https://marketplace.demo.cba.raidiam.io/agents',
};

module.exports = config;
