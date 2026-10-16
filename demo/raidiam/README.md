# The raidiam profile: PingFederate in Raidiam's federation, with SPIFFE client attestation

`PF_PROFILE=raidiam ./up.sh` runs the rig as an OpenID Provider in Raidiam's CBA federation, with client
attestation switched on. [`../spire-workload`](../spire-workload) then gets a token from it in three ways:

| `AUTH_MODE` | The workload authenticates with | Who builds the trust chain | Client in PingFederate |
|---|---|---|---|
| `attestation` | `attest_jwt_client_auth`: a JWT-SVID from its SPIRE agent, exchanged at PingFederate's attester for a client attestation | none: no federation | `spire-workload`, authored by [`../terraform/attestation.tf`](../terraform/attestation.tf) |
| `federation` | `private_key_jwt` with its trust chain in the assertion's `trust_chain` header | **the workload**, from Raidiam's fetch endpoints | registered automatically at the token endpoint (OpenID Federation 1.0 §12.1) |
| `federation-discovery` | its Entity Configuration alone at `/federation/register`, then `private_key_jwt` with no chain | **PingFederate**, following `authority_hints` to Raidiam's authority and anchor | registered explicitly (§12.2) |

Why the third one registers explicitly: 0.7.0's token endpoint registers a client it has never seen only from a
chain it is handed (`RegistrationService$TokenChannel.discoversUnknownClients()` is `false`). The authorization
and PAR endpoints and `/federation/register` resolve one themselves. Once registered, the token endpoint
renews an automatic registration by discovery; an explicit one ends with its chain (a day at most), and the
workload registers again on its next run.

Everything here is **development only**. The production profile refuses the mock attester (`oidf.mock.attesters`)
and inline keys (`OIDF_BRIDGE_SIGNER_BACKING=config`, `attestation_signing_jwk`).

## What it adds to the rig

| File | What |
|---|---|
| [`../vars.raidiam.env`](../vars.raidiam.env) | Federation and automatic registration on, Raidiam's anchor pinned, attestation on with the bridge keys |
| [`../docker-compose.raidiam.yml`](../docker-compose.raidiam.yml) | Mounts the trusted attester's key and the bridge keys; sets `oidf.mock.attesters` through `JAVA_OPTS` |
| [`../terraform/attestation.tf`](../terraform/attestation.tf) | The `spire-workload` attestation client, authored only with `SPIRE_BUNDLE_FILE` |
| [`gen-keys.sh`](gen-keys.sh) | The attester's signing key and the client's bridge key (EC P-256), in `keys/raidiam/` |
| [`import-spire-bundle.sh`](import-spire-bundle.sh) | The JWT-SVID keys of a SPIRE bundle, for `attestation_spiffe_bundle` |
| [`render-runtime-keys.sh`](render-runtime-keys.sh) | The two mounted files, for the issuer |

All key material is in `keys/raidiam/`, git-ignored like the rest of `keys/`.

## Running it

**1. Raidiam.** The rig names one federation: the CBA trust anchor and authority in `vars.raidiam.env` and
`../spire-workload/docker-compose.yml`. For the federation flows you need, under that authority:

- an authorisation server whose `Issuer` is `PF_BASE_URL`. Raidiam validates the issuer by fetching its
  discovery document, so it must be reachable from the internet while you save the record (ngrok, say);
- a software statement whose `ClientId` is the workload's Entity Identifier (`ENTITY_ID`, by default
  `https://localhost/agent/my-workload`). The `ClientId` can't be changed afterwards. Its `rtssigning` key must be
  the workload's entity key, certified through a CSR:
  `docker compose run --rm workload python workload.py csr "/C=GB/O=<framework org>/OU=<org id>/CN=<software statement id>"`
  with the key in `../spire-workload/keys/entity.jwk`.

**2. SPIRE.** A SPIRE server and agent, a registration entry for the workload
(`docker:label:app:my-workload` → `spiffe://example.org/my-workload`), and the server's trust bundle:

```sh
docker exec <spire-server> /opt/spire/bin/spire-server bundle show -format spiffe > spire-bundle.json
```

**3. The rig.**

```sh
PF_PROFILE=raidiam SPIRE_BUNDLE_FILE=$PWD/spire-bundle.json \
PF_BASE_URL=https://<your public issuer> ./up.sh
```

`PF_RIG_NAME`, `PF_PORT_*` and `PF_AUTHOR_*_PORT` run it beside another rig, as for any profile.

**4. The workload**, from `../spire-workload` (`PF_PORT_HTTPS` if the rig isn't on 9031):

```sh
docker compose run --rm workload                                    # attestation
docker compose run --rm -e AUTH_MODE=federation workload            # chain in the assertion
docker compose run --rm -e AUTH_MODE=federation-discovery workload  # PingFederate resolves the chain
```

The two federation flows register the same client id and run in either order: each one's registration replaces
the other's.

PingFederate binds a JWT-SVID to the first instance key that presents it. The SPIRE agent hands back the same SVID
until it nears expiry (its JWT-SVID TTL, five minutes by default), so a second attestation run inside that window
is refused with `instance_attestation_bound` - replay protection, not a fault. Run it again once SPIRE has
issued a fresh SVID.

### What the workload works around

`client-attestation-sdk` (1.1.0 and 1.2.0) predates two 0.6.0 changes in PingFederate's attester, and
`workload.py` adjusts for both:

- the attester's challenge endpoint (`/federation/attestation/challenge`) takes GET, and the SDK POSTs to it.
  The attester requires no challenge unless its document says `challenge_required`, so the workload drops
  the advertised endpoint then, and mints without one;
- the instance-key proof must carry `exp` as well as `iat`; the workload signs it with both.

## On Windows (Git Bash)

- **Terraform's plugin handshake.** Antivirus that intercepts TLS on loopback (Avast, for one) breaks Terraform's
  mTLS to its own provider: `Failed to load plugin schemas ... x509: certificate signed by unknown authority`.
  `export TF_DISABLE_PLUGIN_TLS=1` before `./up.sh`.
- **`COMPOSE_FILE`.** Docker on Windows splits it on `;`. `up.sh` sets `COMPOSE_PATH_SEPARATOR=:` for this profile;
  set it yourself for `docker-compose.rar-plugin.yml`.
- `gen-keys.sh` and `export.sh` work around Git Bash's path rewriting and `unzip`'s globbing themselves.
