# The gateway's PEP as a Shared Signals receiver (../gateway/README.md, "Shared Signals"): coaz-pep polls a stream
# from this PingFederate's SSF transmitter, so an agent revoked by a signal (session-revoked, account-disabled) is
# refused at the gateway at once, not when caches and registrations run out. private_key_jwt with its own key
# (../gateway/gen-keys.sh); ssf.manage only - it can manage its own stream and poll it, nothing else.
# Authored only when the key exists.

locals {
  pep_ssf_jwks = "${path.module}/../keys/gateway/pep-ssf.public.jwks.json"
}

resource "pingfederate_oauth_client" "pep_ssf_receiver" {
  count = fileexists(local.pep_ssf_jwks) ? 1 : 0

  client_id = "rig-pep-ssf-receiver"
  name      = "Gateway PEP - Shared Signals receiver"

  grant_types = ["CLIENT_CREDENTIALS"]

  client_auth = {
    type                                  = "PRIVATE_KEY_JWT"
    token_endpoint_auth_signing_algorithm = "PS256"
    enforce_replay_prevention             = true
  }
  jwks_settings = {
    jwks = jsonencode(jsondecode(file(local.pep_ssf_jwks)))
  }

  restrict_scopes  = true
  exclusive_scopes = ["ssf.manage"]

  default_access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.jwt.id }

  depends_on = [
    pingfederate_oauth_server_settings.this,
    pingfederate_oauth_access_token_mapping.client,
  ]
}
