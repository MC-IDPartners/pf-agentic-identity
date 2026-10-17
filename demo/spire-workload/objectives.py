"""The CBA Agentic IDAM Trust Controller PoC objectives (TC-01..TC-28, "Agentic IDAM - Trust Controller PoC
Objectives - FINAL", 10 July 2026), and how harness.py's checks evidence them.

In the rig's terms: Raidiam is the Trust Controller (the federation's authority and anchor, publishing the Agent
Identities' trust material - statements, keys, capability envelopes, trust marks); the agent marketplace is the Agent
registry; PingFederate is the Identity-layer Client Representation; SPIRE is the Workload-layer Representation; Kong +
coaz-pep is the gateway/PEP; PingAuthorize is the PDP; the agent provider (entity-host) hosts the agents' Entity
Configurations and attests their instances.
"""
import re

OBJECTIVES = {
    "TC-01": ("Marketplace registration triggers the Agent Identity workflow from a manifest", "Governance control strength"),
    "TC-02": ("The Trust Controller governs Agent Identity approval, suspension and withdrawal", "Strategic architecture fit"),
    "TC-03": ("Token flow with an Agent Identity trust check before access to a protected resource", "Integration fit"),
    "TC-04": ("An Agent lifecycle event (suspension, retirement) revokes or disables its Agent Identities", "Governance control strength"),
    "TC-05": ("Publishing, updating and withdrawing OpenID Federation entity configuration for Agent Identities", "Integration fit"),
    "TC-06": ("The marketplace as the Agent registry, separate from Agent Identity and trust authority", "Strategic architecture fit"),
    "TC-07": ("Orchestration across Agent workflow events and Agent Identity workflows", "Delivery fit"),
    "TC-08": ("Policy enforcement for Agent Identity trust decisions (claims, attributes, context, risk)", "Governance control strength"),
    "TC-09": ("Federation bridge for existing authorisation servers: chain resolution, metadata, onboarding", "Compatibility fit"),
    "TC-10": ("The Trust Controller as authoritative source; IdPs consume it for clients and token issuance", "Integration fit"),
    "TC-11": ("The OpenID Federation target state: native federation, standards deviations explicit", "Strategic architecture fit"),
    "TC-12": ("Overlay compatibility with the enterprise authorisation server landscape", "Compatibility fit"),
    "TC-13": ("Deployment model options and CBA boundary implications", "Deployment model fit"),
    "TC-14": ("Identity and authentication controls for users, services and integrations", "Security / risk fit"),
    "TC-15": ("Secure configuration and hardening of PoC components", "Security / risk fit"),
    "TC-16": ("Vulnerability identification and remediation", "Security / risk fit"),
    "TC-17": ("Network protection, segmentation and isolation", "Security / risk fit"),
    "TC-18": ("Security logging: authentication, access, workflow triggers, trust decisions, policy changes", "Security / risk fit"),
    "TC-19": ("Observability and monitoring to operate and investigate", "Delivery fit"),
    "TC-20": ("Data protection and recovery for PoC data and trust artefacts", "Security / risk fit"),
    "TC-21": ("Recoverability and rebuild of the PoC environment", "Delivery fit"),
    "TC-22": ("Support, operating model and vendor enablement", "Delivery fit"),
    "TC-23": ("Commercial and procurement implications", "Commercial / procurement fit"),
    "TC-24": ("Implementation gaps and internal build effort", "Delivery fit"),
    "TC-25": ("Agent Identity metadata and external evidence (manifest, ownership, keys, SBOM ...)", "Governance control strength"),
    "TC-26": ("Cryptographic assurance with enterprise-managed keys, no private-key custody in the Trust Controller", "Security / risk fit"),
    "TC-27": ("A governed, versioned capability envelope, consumed by IdPs, PDPs, gateways", "Integration fit"),
    "TC-28": ("Automated workload identity registration and SPIFFE/SPIRE attestation", "Integration fit"),
}

# Objectives the harness cannot evidence by running the rig, and why - for the coverage summary.
OUT_OF_SCOPE = {
    "TC-13": "documentary: deployment options (see raidiam/PROTECTED-ENVIRONMENTS.md for the outbound-only model)",
    "TC-15": "documentary: hardening baseline; the rig's dev-only shortcuts are listed in PROTECTED-ENVIRONMENTS.md",
    "TC-16": "documentary: vulnerability management",
    "TC-17": "documentary: network design; the rig runs one Docker network",
    "TC-20": "documentary: data protection and backup",
    "TC-22": "documentary: support and operating model",
    "TC-23": "documentary: commercials",
    "TC-24": "documentary: gap register (README's limitations: act as a string, explicit registration, ...)",
    "TC-25": "partly: the marketplace's manifest metadata (owner, SBOM, repository) is not yet wired in",
    "TC-02": "approval evidenced (Raidiam's verified statement and envelope); suspension and withdrawal through the "
             "Trust Controller need the marketplace on Raidiam's live control plane - signals stand in today",
    "TC-01": "needs the marketplace on Raidiam's live control plane (registration -> software statement)",
    "TC-06": "needs the marketplace on Raidiam's live control plane",
    "TC-07": "needs the marketplace on Raidiam's live control plane",
}

STAGES = {
    "preflight": ("Is everything the trust flow depends on up, and does the Trust Controller (Raidiam) vouch for the "
                  "agent - its keys and its capability envelope - and serve the provider its configuration?",
                  ["TC-05", "TC-09", "TC-10", "TC-21", "TC-26", "TC-27"]),
    "spire": ("The Workload-layer Representation: a SPIRE registration entry binding the agent's SPIFFE ID to the "
              "containers allowed to run it.", ["TC-28"]),
    "run": ("The Principal acting as itself: attested on SPIRE's word, its envelope read from the Trust Controller, the "
            "resource found through the federation, a token bound to its instance, the call allowed after the trust "
            "checks.", ["TC-03", "TC-09", "TC-10", "TC-27", "TC-28"]),
    "negatives": ("What must be refused: another workload, a capability outside the envelope, no token, a suspended "
                  "agent.", ["TC-03", "TC-04", "TC-08", "TC-14", "TC-27", "TC-28"]),
    "gateway": ("The enforcement point in front of the resource: signature, DPoP sender-constraint, the PDP's "
                "allow/deny - each refusal observable and explainable.", ["TC-03", "TC-08", "TC-14", "TC-18"]),
    "signals": ("Lifecycle propagation: Shared Signals events reach the gateway and change what it allows, measured "
                "in seconds; one instance can be withdrawn without its agent.", ["TC-04", "TC-28"]),
    "a2a": ("Agents calling agents: the Principal finds sub-agents through the federation by capability; each acts "
            "on its behalf by token exchange (sub, act), bound to its own instance; policy and signals apply at every "
            "hop.", ["TC-03", "TC-04", "TC-08", "TC-10", "TC-27"]),
}

# check (regex on its text) -> (objectives, what passing it proves)
CHECKS = [
    (r" is running$", ["TC-21", "TC-19"], "the component is up; the environment is rebuilt from compose and scripts"),
    (r"^PingFederate answers", ["TC-09", "TC-12"],
     "the existing authorisation server (PingFederate, with the OpenID Federation modules) is the token issuer"),
    (r"^Raidiam vouches for the agent's entity key", ["TC-02", "TC-05", "TC-10", "TC-26"],
     "the Trust Controller's signed statement publishes the agent's public key; the private key never leaves the "
     "agent's owner - the Trust Controller holds none"),
    (r"^Raidiam grants the agent capabilities", ["TC-02", "TC-27", "TC-08"],
     "the capability envelope comes from the Trust Controller (roles -> authorization_details_types), independent of "
     "OAuth scopes and of the client's runtime configuration"),
    (r"^the provider serves the agent's Entity Configuration", ["TC-05", "TC-11"],
     "the Agent Identity is published as a standard OpenID Federation Entity Configuration"),
    (r"^the agent is registered at PingFederate", ["TC-09", "TC-10"],
     "the authorisation server's local client representation is built from the federation's trust material "
     "(chain resolved and validated, policy applied), not configured by hand"),
    (r"^entry spiffe://", ["TC-28"], "the workload identity is registered programmatically (spire-server API)"),
    (r"^the run completed", ["TC-03"], "the whole token flow, trust checks included, ends in access"),
    (r"^attested by the provider", ["TC-28", "TC-26"],
     "the agent provider vouches for this running instance, signing with a key the Trust Controller publishes for it"),
    (r"^attested as this agent", ["TC-28"], "the attested instance is bound to the Agent Identity's client"),
    (r"^SPIRE identified the container", ["TC-28"],
     "the SPIFFE ID comes from SPIRE's attestation of the container, not from anything the agent claims"),
    (r"is in the envelope", ["TC-27", "TC-08"], "the job's capability is inside the envelope the Trust Controller grants"),
    (r"^found the resource through the federation", ["TC-10", "TC-11"],
     "discovery by capability through the federation, the resource's chain verified to the pinned anchor"),
    (r"^token for this agent, for the resource", ["TC-03", "TC-09"],
     "the token traces to the approved Agent Identity (client_id) and is audience-restricted to the resource"),
    (r"^the token is bound to this instance's key", ["TC-03", "TC-14"],
     "the token is DPoP-bound (cnf.jkt) to the attested instance key: useless to anyone else"),
    (r"^the resource allowed the call", ["TC-03", "TC-08"],
     "access granted only after gateway, PDP and the resource's own federation check"),
    (r"refused at /attest", ["TC-28", "TC-03"], "a workload SPIRE does not bind to the agent gets no attestation"),
    (r"^a job outside the envelope", ["TC-27", "TC-08"], "a capability the Trust Controller did not grant is refused"),
    (r"refuses a call with no token", ["TC-14", "TC-03"], "no anonymous access"),
    (r"^a suspended agent is refused", ["TC-04", "TC-01", "TC-07"], "marketplace suspension -> identity withdrawal"),
    (r"not signed by PingFederate", ["TC-03", "TC-14"], "only the authorisation server's tokens are honoured"),
    (r"^the PDP permits", ["TC-08", "TC-03"], "the PDP's allow, with the decision traceable to the agent"),
    (r"^DPoP:", ["TC-03", "TC-14"], "sender-constrained tokens: a stolen or replayed credential does not work"),
    (r"^the PDP denies", ["TC-08", "TC-03"], "the PDP's deny is observable (COAZ -32401) and stops the call at the gateway"),
    (r"^decisions are logged", ["TC-18", "TC-19"],
     "every trust decision at the gateway is logged with its principal and reason, traceable to this run"),
    (r"before any signal", ["TC-04"], "the baseline: the agent works"),
    (r"^session-revoked", ["TC-04"], "a lifecycle signal invalidates existing credentials within the agreed tolerance"),
    (r"^account-disabled", ["TC-04"], "suspension prevents new trust being established"),
    (r"^account-enabled", ["TC-04"], "reinstatement restores it"),
    (r"one instance disabled|another instance|instance works again", ["TC-04", "TC-28"],
     "withdrawal of one runtime instance (its key) without affecting the Agent Identity's other instances"),
    (r"^pay-invoice completed", ["TC-03", "TC-10"], "the multi-agent flow completes end to end"),
    (r"found through the federation by capability", ["TC-10", "TC-27"],
     "agents are discovered by the capabilities the Trust Controller publishes for them"),
    (r"acted for the Principal", ["TC-03", "TC-10"],
     "delegation is explicit in the token: sub = the Principal, act = the acting agent (RFC 8693)"),
    (r"for its resource and bound to its own instance key", ["TC-03", "TC-14"],
     "each hop's token is audience-restricted and bound to that hop's own attested instance"),
    (r"checked both agents", ["TC-08", "TC-27"],
     "the resource checks every agent in the chain against the envelope: no capability laundering through delegation"),
    (r"over the policy's limit", ["TC-08"], "the PDP's limit applies at the first hop, before the sub-agent acts"),
    (r"Payments agent disabled|Accounts agent still answers", ["TC-04"],
     "one agent's suspension takes it out of the chain while the others carry on"),
]


def classify(check: str):
    for pattern, tcs, why in CHECKS:
        if re.search(pattern, check):
            return tcs, why
    return [], ""
