# OpenBao for the rig: the bridge keys (attest_jwt_client_auth's per-client signing keys) in its transit engine,
# never exported. File storage on a volume, so the keys Raidiam certifies survive a restart; one unseal key, kept
# with the root token in ../keys/openbao/ (git-ignored) by setup.py. Plain HTTP on the compose network and the host -
# a development shortcut (../raidiam/PROTECTED-ENVIRONMENTS.md).
storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr      = "http://openbao:8200"
disable_mlock = true
ui            = false
