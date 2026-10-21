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

  // Raidiam Connect admin API. Leave RAIDIAM_CLIENT_ID unset to run in mock mode.
  raidiam: {
    // When true, no outbound calls are made: the lifecycle is simulated and
    // every step is still written to the deployment log.
    mock: bool(process.env.RAIDIAM_MOCK, !process.env.RAIDIAM_CLIENT_ID),

    // A Principal version's statement: federation-managed, so Raidiam hosts and signs its Entity Configuration.
    federationManaged: process.env.RAIDIAM_FEDERATION_MANAGED || 'openid_entity_federation_managed',

    // authorization_code: an operator signs in (scope directory:website) - until Raidiam allows
    // directory:management for client_credentials, which needs no sign-in (src/raidiam-auth.js).
    grant: process.env.RAIDIAM_GRANT || 'authorization_code',
    issuer: process.env.RAIDIAM_ISSUER || 'https://auth.directory.cba.raidiam.io',
    baseUrl: process.env.RAIDIAM_BASE_URL || 'https://matls-api.directory.cba.raidiam.io',
    // The directory client: its id (Raidiam's openid_relying_party URL), its rtssigning key for private_key_jwt
    // (and the kid Raidiam publishes for it), and its rtstransport certificate for mutual TLS.
    clientId: process.env.RAIDIAM_CLIENT_ID || '',
    signingKeyPath: process.env.RAIDIAM_SIGNING_KEY_PATH || '/directory-client/signing.key',
    signingKid: process.env.RAIDIAM_SIGNING_KID || '',
    transportCertPath: process.env.RAIDIAM_CERT_PATH || '/directory-client/transport.crt',
    transportKeyPath: process.env.RAIDIAM_KEY_PATH || '/directory-client/transport.key',
    caPath: process.env.RAIDIAM_CA_PATH || '/directory-client/ca.pem',
    // Registered on the directory client exactly as written.
    redirectUri: process.env.RAIDIAM_REDIRECT_URI || 'https://localhost:8443/cb',
    loginScope: process.env.RAIDIAM_LOGIN_SCOPE || 'openid directory:website',
    scope: process.env.RAIDIAM_SCOPE || 'directory:management',
    // Where the browser lands after signing in: the control centre itself.
    afterLogin: process.env.MARKETPLACE_URL || 'http://localhost:3000',

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
      certificates:
        process.env.RAIDIAM_PATH_CERTIFICATES ||
        '/organisations/{orgId}/softwarestatements/{ssId}/certificates/{type}',
    },

    timeoutMs: Number(process.env.RAIDIAM_TIMEOUT_MS || 20000),
  },

  // The rig around the marketplace (src/rig.js): the KMS, SPIRE, the agent image, PingFederate.
  rig: {
    // Where Raidiam hosts a federation-managed relying party: <base>/<statement id>, when its ClientId does not say.
    managedEntityBase: process.env.RAIDIAM_MANAGED_ENTITY_BASE || 'https://rp.directory.cba.raidiam.io/openid_relying_party',
    // A version's page, for its statement's ClientUri and RedirectUri (Raidiam requires them; nothing redirects there).
    agentsSite: process.env.AGENTS_SITE || 'https://host.docker.internal:8443/marketplace/agents',
    trustDomain: process.env.TRUST_DOMAIN || 'example.org',
    // The KMS (src/vault.js): OpenBao, and the enrolment token - create bridge keys and their CSRs, never sign.
    openbaoAddr: process.env.OPENBAO_ADDR || 'http://openbao:8200',
    openbaoTokenFile: process.env.OPENBAO_TOKEN_FILE || '/openbao/enrolment.token',
    authorisationServerId: process.env.AUTHORISATION_SERVER_ID || '9b0983ce-781e-4f58-8620-0a752aafa054',
    spireServer: process.env.SPIRE_SERVER_CONTAINER || 'spire-spire-server-1',
    spireParent: process.env.SPIRE_PARENT_ID || 'spiffe://example.org/spire/agent/x509pop/agent1',
    spireBundleUrl: process.env.SPIRE_BUNDLE_URL || 'https://host.docker.internal:8445/keys',
    agentImage: process.env.AGENT_IMAGE || 'spire-workload-agent:latest',
    network: process.env.RIG_NETWORK || 'spire-workload_default',
    spireSocketsVolume: process.env.SPIRE_SOCKETS_VOLUME || 'spire_spire-agent-sockets',
    statePrefix: process.env.STATE_VOLUME_PREFIX || 'marketplace-',
    certsDir: process.env.RIG_CERTS_DIR || '/rig/certs',
    fedDir: process.env.RIG_FED_DIR || '/rig/fed',
    secretsFile: process.env.RIG_SECRETS_FILE || '/rig/secrets.env',
    pfUrl: process.env.PF_URL || 'https://host.docker.internal:9031',
    // Witnesses for the evidence packs (src/evidence.js): the gateway's PEP and PingFederate, by container name.
    coazContainer: process.env.COAZ_PEP_CONTAINER || 'spire-workload-coaz-pep-1',
    pfContainer: process.env.PF_CONTAINER || 'pf-agentic-identity',
    pfIssuer: process.env.PF_ISSUER || 'https://bottle-platonic-parted.ngrok-free.dev',
  },

  // Base used to mint entity ids for agents, mirroring the demo marketplace.
  entityIdBase:
    process.env.ENTITY_ID_BASE || 'https://marketplace.demo.cba.raidiam.io/agents',
};

module.exports = config;
