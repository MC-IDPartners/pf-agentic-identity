'use strict';

/**
 * What the control centre proves, and how: the PoC objectives (Agentic IDAM - Trust Controller PoC Objectives,
 * 10 July 2026; the same list as ../spire-workload/objectives.py), the scenarios a deployed Principal version runs,
 * and the lifecycle actions - each mapped to the objectives it evidences.
 */

const OBJECTIVES = {
  'TC-01': 'Marketplace registration triggers the Agent Identity workflow from a manifest',
  'TC-02': 'The Trust Controller governs Agent Identity approval, suspension and withdrawal',
  'TC-03': 'Token flow with an Agent Identity trust check before access to a protected resource',
  'TC-04': 'An Agent lifecycle event (suspension, retirement) revokes or disables its Agent Identities',
  'TC-05': 'Publishing, updating and withdrawing OpenID Federation entity configuration for Agent Identities',
  'TC-06': 'The marketplace as the Agent registry, separate from Agent Identity and trust authority',
  'TC-07': 'Orchestration across Agent workflow events and Agent Identity workflows',
  'TC-08': 'Policy enforcement for Agent Identity trust decisions (claims, attributes, context, risk)',
  'TC-09': 'Federation bridge for existing authorisation servers: chain resolution, metadata, onboarding',
  'TC-10': 'The Trust Controller as authoritative source; IdPs consume it for clients and token issuance',
  'TC-11': 'The OpenID Federation target state: native federation, standards deviations explicit',
  'TC-12': 'Overlay compatibility with the enterprise authorisation server landscape',
  'TC-13': 'Deployment model options and CBA boundary implications',
  'TC-14': 'Identity and authentication controls for users, services and integrations',
  'TC-15': 'Secure configuration and hardening of PoC components',
  'TC-16': 'Vulnerability identification and remediation',
  'TC-17': 'Network protection, segmentation and isolation',
  'TC-18': 'Security logging: authentication, access, workflow triggers, trust decisions, policy changes',
  'TC-19': 'Observability and monitoring to operate and investigate',
  'TC-20': 'Data protection and recovery for PoC data and trust artefacts',
  'TC-21': 'Recoverability and rebuild of the PoC environment',
  'TC-22': 'Support, operating model and vendor enablement',
  'TC-23': 'Commercial and procurement implications',
  'TC-24': 'Implementation gaps and internal build effort',
  'TC-25': 'Agent Identity metadata and external evidence (manifest, ownership, keys, SBOM ...)',
  'TC-26': 'Cryptographic assurance with enterprise-managed keys, no private-key custody in the Trust Controller',
  'TC-27': 'A governed, versioned capability envelope, consumed by IdPs, PDPs, gateways',
  'TC-28': 'Automated workload identity registration and SPIFFE/SPIRE attestation',
};

// Documentary objectives: evidenced by documents (raidiam/PROTECTED-ENVIRONMENTS.md, the READMEs), not by a run.
const DOCUMENTARY = {
  'TC-13': 'raidiam/PROTECTED-ENVIRONMENTS.md: the outbound-only deployment model',
  'TC-15': 'PROTECTED-ENVIRONMENTS.md lists the rig\'s development shortcuts',
  'TC-16': 'vulnerability management - documentary',
  'TC-17': 'network design - documentary; the rig runs one Docker network',
  'TC-20': 'data protection and backup - documentary',
  'TC-22': 'support and operating model - documentary',
  'TC-23': 'commercials - documentary',
  'TC-24': 'gap register in the READMEs (act as a string, explicit registration, bridge slots ...)',
};

/**
 * Scenarios a deployed version runs (agent.py in a container SPIRE identifies as it). expect: what passing is.
 * when: the lifecycle state it is meant for.
 */
const SCENARIOS = [
  {
    id: 'act', title: 'Acts as itself', job: 'get-balance', when: 'approved',
    expect: { outcome: 'ok' }, objectives: ['TC-03', 'TC-09', 'TC-10', 'TC-27', 'TC-28'],
    proves: 'attested on SPIRE\'s word by PingFederate\'s attester, its envelope read from Raidiam, the resource found through the federation, a DPoP-bound token, the call allowed by the gateway and the PDP',
  },
  {
    id: 'a2a', title: 'Has agents act on its behalf', job: 'pay-invoice', when: 'approved',
    expect: { outcome: 'ok' }, objectives: ['TC-03', 'TC-08', 'TC-10', 'TC-27'],
    proves: 'the Accounts and Payments agents found through the federation by capability, each exchanging its token (RFC 8693: sub = this version, act = the agent), each hop bound to its own instance key',
  },
  {
    id: 'over-limit', title: 'An invoice over the policy limit', job: 'pay-invoice', invoiceAmount: 1500, when: 'approved',
    expect: { outcome: 'refused', refusedAt: 'payments' }, objectives: ['TC-08'],
    proves: 'PingAuthorize denies a 1500 payment at the Payments agent\'s gateway, before the agent acts',
  },
  {
    id: 'outside-envelope', title: 'A job outside its envelope', job: 'loan-balance', when: 'approved',
    expect: { outcome: 'refused', refusedAt: 'envelope' }, objectives: ['TC-27', 'TC-08'],
    proves: 'lending_read is not among the capabilities its Raidiam roles grant: refused before a request is built',
  },
  {
    id: 'impostor', title: 'Another workload claims to be it', job: 'get-balance', label: 'my-workload', when: 'approved',
    expect: { outcome: 'refused', refusedAt: 'attest' }, objectives: ['TC-28', 'TC-03'],
    proves: 'a container SPIRE identifies as spiffe://example.org/my-workload gets no attestation as this version',
  },
  {
    id: 'provider-attests', title: 'Attested by the agent provider instead', job: 'get-balance', attester: 'provider', when: 'approved',
    expect: { outcome: 'ok' }, objectives: ['TC-12', 'TC-28'],
    proves: 'the provider\'s /attest, trusted by PingFederate through the provider\'s chain - attestation is pluggable',
  },
  {
    id: 'while-suspended', title: 'Tries to act while suspended', job: 'get-balance', when: 'suspended',
    expect: { outcome: 'refused' }, objectives: ['TC-02', 'TC-04'],
    proves: 'with its statement Suspended, its Entity Configuration withdrawn and account-disabled signalled, it cannot act',
  },
];

// The lifecycle actions and what each one evidences, when it succeeds.
const ACTIONS = {
  deploy: {
    objectives: ['TC-01', 'TC-05', 'TC-06', 'TC-07', 'TC-09', 'TC-10', 'TC-25', 'TC-26', 'TC-28'],
    proves: 'approving it in the marketplace created its statement, certified CSRs from the provider (no private key left the provider), granted its roles, published its Entity Configuration, registered its SPIFFE ID, and PingFederate registered it through the federation',
  },
  suspend: {
    objectives: ['TC-02', 'TC-04', 'TC-05'],
    proves: 'suspension set its statement Suspended in Raidiam, raised account-disabled, and withdrew its Entity Configuration',
  },
  reinstate: {
    objectives: ['TC-02', 'TC-05'],
    proves: 'reinstatement returned its statement to Active and published its Entity Configuration again',
  },
};

function judge(scenario, result) {
  const e = scenario.expect;
  if (result.outcome !== e.outcome) return false;
  if (e.refusedAt && result.refused_at !== e.refusedAt) return false;
  return true;
}

module.exports = { OBJECTIVES, DOCUMENTARY, SCENARIOS, ACTIONS, judge };
