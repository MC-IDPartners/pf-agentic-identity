# The raidiam profile's resource server (demo/spire-workload's rs-accounts; ../raidiam/README.md, "The agent-r
# flow"): an MCP resource inside the protected network, a federation entity of its own whose oauth_resource
# metadata names this PingFederate as its authorisation server. An agent asks for a token for it with RFC 8707's
# resource parameter, which PingFederate answers only from a token manager that lists the resource's URI - without
# one the request is invalid_target. Authored only when up.sh is given RAIDIAM_RESOURCE_ID.

variable "rs_accounts_resource" {
  description = "The resource server's identifier (its Entity Identifier) - TF_VAR_rs_accounts_resource; up.sh sets it from RAIDIAM_RESOURCE_ID"
  type        = string
  default     = ""
}

resource "pingfederate_oauth_access_token_manager" "rs_accounts" {
  count = var.rs_accounts_resource != "" ? 1 : 0

  manager_id = "rsAccountsJwt"
  name       = "Accounts resource JWT access tokens"

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
      { name = "Audience Claim Value", value = var.rs_accounts_resource },
      { name = "Type Header Value", value = "at+jwt" },
    ]
    tables = []
  }

  # The token manager a request naming this resource gets.
  selection_settings = {
    resource_uris = [var.rs_accounts_resource]
  }

  attribute_contract = {
    extended_attributes = [
      { name = "sub", multi_valued = false },
    ]
  }
}

# Client credentials: the agent acting as itself, so the subject is the client.
resource "pingfederate_oauth_access_token_mapping" "rs_accounts_client" {
  count = var.rs_accounts_resource != "" ? 1 : 0

  access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.rs_accounts[0].id }
  context                  = { type = "CLIENT_CREDENTIALS" }

  attribute_contract_fulfillment = {
    "sub" = { source = { type = "CONTEXT" }, value = "ClientId" }
  }
}
