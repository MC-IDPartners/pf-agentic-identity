# Token exchange (RFC 8693) for agent-to-agent delegation (../gateway/README.md, "Agents calling agents"): a sub-agent
# - the Accounts or Payments agent - was called by another agent with a token for itself; it exchanges that token
# for one for the resource it calls next. The subject token is one this PingFederate issued: validated here against
# its own JWKS and issuer. The issued token's sub is the subject token's (the calling agent), its act the sub-agent
# (resource.tf), and it is bound to the sub-agent's own instance key (DPoP combined mode at the token endpoint).
#
# Federated clients are registered automatically, so no client can be given a processor policy of its own: this one
# is PingFederate's default. Authored when the profile has delegated resources (resource.tf).

resource "pingfederate_idp_token_processor" "pf_access_token" {
  count = length(local.rig_delegated) > 0 ? 1 : 0

  processor_id = "pfAccessTokenProc"
  name         = "This PingFederate's access tokens (token-exchange subject tokens)"
  plugin_descriptor_ref = {
    id = "org.sourceid.wstrust.processor.jwt.JWTTokenProcessor"
  }
  configuration = {
    fields = [
      # Its own JWKS, over the container's plain loopback listener.
      { name = "JWKS Endpoint URI", value = "http://localhost:9080/pf/JWKS" },
      { name = "Issuer", value = var.pf_base_url },
      { name = "Expiry Tolerance", value = "0" },
    ]
  }
  attribute_contract = {
    core_attributes     = [{ name = "sub" }]
    extended_attributes = [{ name = "client_id" }]
  }
}

resource "pingfederate_oauth_token_exchange_processor_policy" "agent_delegation" {
  count = length(local.rig_delegated) > 0 ? 1 : 0

  policy_id            = "agentDelegation"
  name                 = "Agent-to-agent delegation"
  actor_token_required = false

  attribute_contract = {
    extended_attributes = []
  }

  processor_mappings = [
    {
      subject_token_type      = "urn:ietf:params:oauth:token-type:access_token"
      subject_token_processor = { id = pingfederate_idp_token_processor.pf_access_token[0].processor_id }
      attribute_contract_fulfillment = {
        "subject" = { source = { type = "SUBJECT_TOKEN" }, value = "sub" }
      }
    }
  ]
}

resource "pingfederate_oauth_token_exchange_processor_settings" "this" {
  count = length(local.rig_delegated) > 0 ? 1 : 0

  default_processor_policy_ref = { id = pingfederate_oauth_token_exchange_processor_policy.agent_delegation[0].id }
}
