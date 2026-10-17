# The raidiam profile's resources (../raidiam/README.md, "The agent-r flow"; ../gateway/README.md): MCP servers and
# agents inside the protected network, each a federation entity whose oauth_resource metadata names this PingFederate.
# A client asks for a token for one with RFC 8707's resource parameter, which PingFederate answers only from a token
# manager listing that resource's URI (otherwise invalid_target) - so one manager per resource, each stamping its own
# audience. Authored for each resource up.sh is given (RAIDIAM_RESOURCE_ID, RAIDIAM_PAYMENTS_RESOURCE_ID,
# RAIDIAM_HOSTED_AGENTS).
#
# Two ways to a token for a resource:
#   client credentials  an agent acting as itself: sub = the client
#   token exchange      a sub-agent acting for the agent that called it (RFC 8693, token-exchange.tf): sub = that
#                       agent, from the subject token; act = {sub: the sub-agent}. The act is a literal per resource
#                       - its one calling agent - because PingFederate 13 refuses an OGNL mapping that builds `act`
#                       (ognl_expression_invalid_attribute; idp-agentic-demo's token-exchange.tf has the history).

variable "rs_accounts_resource" {
  description = "rs-accounts' identifier (TF_VAR_rs_accounts_resource; up.sh: RAIDIAM_RESOURCE_ID)"
  type        = string
  default     = ""
}

variable "rs_payments_resource" {
  description = "rs-payments' identifier (TF_VAR_rs_payments_resource; up.sh: RAIDIAM_PAYMENTS_RESOURCE_ID)"
  type        = string
  default     = ""
}

variable "accounts_agent_resource" {
  description = "The Accounts agent's identifier - a resource other agents call, and rs-accounts' delegated caller"
  type        = string
  default     = ""
}

variable "payments_agent_resource" {
  description = "The Payments agent's identifier - a resource other agents call, and rs-payments' delegated caller"
  type        = string
  default     = ""
}

locals {
  # manager id => (resource URI, the agent that calls it by token exchange, if any)
  rig_resources = { for id, r in {
    rsAccountsJwt     = { uri = var.rs_accounts_resource, actor = var.accounts_agent_resource, name = "rs-accounts" }
    rsPaymentsJwt     = { uri = var.rs_payments_resource, actor = var.payments_agent_resource, name = "rs-payments" }
    accountsAgentJwt  = { uri = var.accounts_agent_resource, actor = "", name = "the Accounts agent" }
    paymentsAgentJwt  = { uri = var.payments_agent_resource, actor = "", name = "the Payments agent" }
  } : id => r if r.uri != "" }
  rig_delegated = { for id, r in local.rig_resources : id => r if r.actor != "" }
}

resource "pingfederate_oauth_access_token_manager" "rig" {
  for_each = local.rig_resources

  manager_id = each.key
  name       = "JWT access tokens for ${each.value.name}"

  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }

  configuration = {
    fields = [
      { name = "Token Lifetime", value = "10" },
      { name = "Use Centralized Signing Key", value = "true" },
      { name = "JWS Algorithm", value = "PS256" },
      { name = "Issuer Claim Value", value = var.pf_base_url },
      # The resource checks that a token is meant for it.
      { name = "Audience Claim Value", value = each.value.uri },
      { name = "Type Header Value", value = "at+jwt" },
      # iat: a Shared Signals session-revoked refuses the tokens issued before it (../gateway/README.md), so a
      # token has to say when it was issued; without it the PEP refuses every token of a revoked agent.
      { name = "Include Issued At Claim", value = "true" },
    ]
    tables = []
  }

  # The manager a request naming this resource gets.
  selection_settings = {
    resource_uris = [each.value.uri]
  }

  attribute_contract = {
    extended_attributes = [
      { name = "sub", multi_valued = false },
      { name = "act", multi_valued = false },
    ]
  }
}

# Client credentials: the agent acting as itself, so the subject is the client and there is no actor.
resource "pingfederate_oauth_access_token_mapping" "rig_client" {
  for_each = local.rig_resources

  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.rig[each.key].id }
  context                  = { type = "CLIENT_CREDENTIALS" }

  attribute_contract_fulfillment = {
    "sub" = { source = { type = "CONTEXT" }, value = "ClientId" }
    "act" = { source = { type = "NO_MAPPING" } }
  }
}

# Token exchange: the subject is the agent whose token was exchanged; the actor is the sub-agent that exchanged it.
resource "pingfederate_oauth_access_token_mapping" "rig_delegated" {
  for_each = local.rig_delegated

  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.rig[each.key].id }
  context = {
    type        = "TOKEN_EXCHANGE_PROCESSOR_POLICY"
    context_ref = { id = pingfederate_oauth_token_exchange_processor_policy.agent_delegation[0].id }
  }

  attribute_contract_fulfillment = {
    "sub" = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject" }
    # Byte-exact JSON, not jsonencode(): the provider diffs the raw value against what PingFederate stores.
    "act" = { source = { type = "TEXT" }, value = "{\"sub\":\"${each.value.actor}\"}" }
  }
}
