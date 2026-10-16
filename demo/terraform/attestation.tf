# The raidiam profile's attestation client: a SPIRE workload authenticating with attest_jwt_client_auth
# (demo/spire-workload, AUTH_MODE=attestation; ../raidiam/README.md). Authored only when up.sh sets
# TF_VAR_spire_attestation_client, which it does for PF_PROFILE=raidiam with SPIRE_BUNDLE_FILE.
#
# Two halves, both in this client:
#   - the attester's: which SPIFFE IDs are instances of it, the SPIRE bundle their JWT-SVIDs verify against,
#     the ceiling on what they may ask for, and the key the attester signs their attestations with
#     (docs/configuration/issuance-client-properties.md).
#   - the token endpoint's: PRIVATE_KEY_JWT against the bridge's public key. The token-endpoint filter checks the
#     attestation and its proof of possession, then signs a private_key_jwt for this client with the bridge's
#     private half (OIDF_BRIDGE_SIGNING_KEYS) - which is what PingFederate itself authenticates.
#
# Keys from ../keys/raidiam/ (git-ignored; ../raidiam/gen-keys.sh, import-spire-bundle.sh). The attester's private
# key is inline (attestation_signing_jwk) - development only; production names an OpenBao key
# (attestation_signing_key_ref) instead.

variable "spire_attestation_client" {
  description = "Author the SPIRE attestation client (TF_VAR_spire_attestation_client; up.sh sets it for PF_PROFILE=raidiam with SPIRE_BUNDLE_FILE)"
  type        = bool
  default     = false
}

variable "spire_attestation_client_id" {
  description = "The attestation client's id - the sub of every attestation its instances get"
  type        = string
  default     = "spire-workload"
}

variable "spire_trust_domain" {
  description = "The SPIFFE trust domain whose JWT-SVIDs the attester accepts for this client"
  type        = string
  default     = "example.org"
}

variable "spire_instance_spiffe_ids" {
  description = "SPIFFE IDs (a trailing * matches a path prefix) whose holders are instances of this client"
  type        = list(string)
  default     = ["spiffe://example.org/*"]
}

variable "spire_entitlement" {
  description = "The ceiling on the authorization_details an instance may be attested for, as JSON"
  type        = string
  default     = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\",\"APAC\",\"AMER\"]}]"
}

locals {
  raidiam_keys = "${path.module}/../keys/raidiam"
  # try(): read only when the client is authored, so validate (and a rig without the profile) needs no keys.
  spire_bridge_jwks  = try(file("${local.raidiam_keys}/bridge-${var.spire_attestation_client_id}.public.jwks.json"), "{}")
  spire_bundle_jwks  = try(file("${local.raidiam_keys}/spire-bundle.jwks.json"), "{}")
  spire_attester_jwk = try(file("${local.raidiam_keys}/attester-signing.private.jwk.json"), "")
}

resource "pingfederate_oauth_client" "spire_workload" {
  count = var.spire_attestation_client ? 1 : 0

  client_id   = var.spire_attestation_client_id
  name        = "SPIRE workload (client attestation)"
  description = "attest_jwt_client_auth; attestations issued by this PingFederate from SPIFFE JWT-SVIDs"

  grant_types = ["CLIENT_CREDENTIALS"]

  client_auth = {
    type                                  = "PRIVATE_KEY_JWT"
    token_endpoint_auth_signing_algorithm = "ES256"
  }
  jwks_settings = {
    jwks = jsonencode(jsondecode(local.spire_bridge_jwks))
  }

  default_access_token_manager_ref = { id = pingfederate_oauth_access_token_manager.jwt.id }

  extended_parameters = {
    attestation_evidence      = { values = ["spiffe-jwt"] }
    attestation_trust_domain  = { values = [var.spire_trust_domain] }
    attestation_spiffe_bundle = { values = [jsonencode(jsondecode(local.spire_bundle_jwks))] }
    attestation_instances     = { values = [jsonencode([for id in var.spire_instance_spiffe_ids : { spiffe_id = id }])] }
    attestation_entitlement   = { values = [jsonencode(jsondecode(var.spire_entitlement))] }
    # The attester's issuer is PingFederate's own, which is also the audience the JWT-SVID must carry.
    attestation_issuer     = { values = [var.pf_base_url] }
    attestation_issued_ttl = { values = ["300"] }
    # sensitive(): a private key, kept out of the plan's output (it still lands in the git-ignored state and archive).
    attestation_signing_jwk = { values = [sensitive(local.spire_attester_jwk)] }
  }

  lifecycle {
    precondition {
      condition     = local.spire_bridge_jwks != "{}" && local.spire_bundle_jwks != "{}" && local.spire_attester_jwk != ""
      error_message = "keys/raidiam/ lacks the bridge key, the SPIRE bundle or the attester key: run raidiam/gen-keys.sh and raidiam/import-spire-bundle.sh (up.sh does, for PF_PROFILE=raidiam with SPIRE_BUNDLE_FILE)."
    }
  }

  depends_on = [pingfederate_oauth_server_settings.this, pingfederate_extended_properties.federation]
}
