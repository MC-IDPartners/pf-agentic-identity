# PingFederate's OAuth/OIDC signing key, certified by Raidiam (../raidiam/pf-signing.sh): an organisation-level
# server_signing certificate, as CBA's authorisation servers hold theirs. The federation module signs PingFederate's
# Entity Configuration with PingFederate's current OAuth signing key; with the keys PingFederate generates and rotates
# itself, Raidiam has never seen that key, and its resolver refuses PingFederate's chain ("the subordinate statement
# does not contain the key used to sign the subject entity's Entity Configuration"). Static keys make this one active,
# published under Raidiam's kid (the certificate's x5t#S256, kid.txt). Access tokens and ID tokens sign with it too.
#
# Authored only when keys/raidiam/pf-signing/signing.p12 exists (pf-signing.sh import). Rotation is a manual,
# certified step: a new CSR, a new certificate, a re-author.

locals {
  pf_signing_dir = "${path.module}/../keys/raidiam/pf-signing"
  pf_signing     = fileexists("${local.pf_signing_dir}/signing.p12")
}

resource "pingfederate_keypairs_signing_key" "raidiam" {
  count = local.pf_signing ? 1 : 0

  key_id    = "pf-raidiam-signing"
  file_data = filebase64("${local.pf_signing_dir}/signing.p12")
  format    = "PKCS12"
  # Only guards the file in the git-ignored keys directory; pf-signing.sh writes it.
  password = "changeit"
}

resource "pingfederate_keypairs_oauth_openid_connect" "this" {
  count = local.pf_signing ? 1 : 0

  static_jwks_enabled       = true
  rsa_active_cert_ref       = { id = pingfederate_keypairs_signing_key.raidiam[0].id }
  rsa_publish_x5c_parameter = true
  # PingFederate publishes the key once more per algorithm, its kid suffixed with the algorithm (<kid>_RS256), and
  # the federation module signs (OIDF_FEDERATION_SIGNING_ALG, RS256) under that one - which Raidiam does not know.
  # So the RS256 key id is Raidiam's kid itself, and the generic one something else, so the two cannot collide.
  rsa_active_key_id = "pf-raidiam-signing"
  rsa_algorithm_active_key_ids = [
    { key_id = trimspace(file("${local.pf_signing_dir}/kid.txt")), rsa_alg_type = "RS256" },
  ]
}
