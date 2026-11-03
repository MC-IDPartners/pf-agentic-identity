# The PingFederate image build

PF 13.1.3 plus this repo's modules, assembled into a runnable image. This is the **capability made
runnable** - it belongs here, beside the code it packages. To run it on this machine, configured,
use [`../conformance/up.sh`](../demo/README.md); this page is about the image itself.

This directory builds an image; it deploys nothing. [`conformance/`](../demo/README.md) is the
one consumer in this repo: it authors the PF configuration as Terraform, exports the archive, composes
the build context and runs the image with `docker compose`. A deployment elsewhere composes its own
context from this directory plus its own archive and variables, and keeps whatever its platform needs in
its own repo.

## The PingFederate version

`build/pf-version.env` is the one place the PingFederate version is written down: the image tag and its
digest, the SDK version the reactor compiles against, and the product version the Terraform provider is
told. `tools/pf-version-check.py` checks that the other places which name the version agree with it -
the Dockerfile's `FROM` line among them, which has to stay a literal. Moving to another PingFederate
release starts with that file, and the modules move with it: build them against the new SDK and stage
them again. `assemble-pf-runtime-war.sh` refuses jars built for the other servlet namespace, and
`tools/pf-linkcheck.py` finds a PingFederate member the new release no longer has - both before
anything boots.

## Two profiles

An image is built for one of two **staging profiles**, and says which in a label.

| Profile | Module jars | For |
|---|---|---|
| `production` (the default) | the jars `stage-modules.sh` lists in `ENTRIES` and names in `modules/MANIFEST`: `oidf.jar`, `attestation-issuer`, `ssf`, and the libraries they need, `platform` and `platform-pf` among them | every deployment |
| `conformance` | those and `pf.plugins.ciba-sim.jar`, plus `/opt/ciba-sim`, the directory the simulator keeps its decisions in (`0700`, owned by PingFederate's user) | the conformance rig, for the suite's FAPI-CIBA plan |

The `MANIFEST` is the list: this page, the Dockerfile and the showcase point at it rather than count the jars,
so a package that stages another jar edits `ENTRIES` and nothing else. To see what an image carries, read the
`MANIFEST` in the build context, or list `server/default/deploy/*.jar` in the image.

The CIBA simulator is an approval oracle keyed by nothing but an `auth_req_id`
(plugins/ciba-sim), so it is never staged into a production image, and
even in a conformance one it runs only under `OIDF_DEPLOYMENT_PROFILE=development`. The profile is chosen
twice, and the two must agree: `stage-modules.sh --profile <p>` writes it into `MANIFEST`, and
`docker build --build-arg STAGING_PROFILE=<p>` hands it to the assembler, which refuses a `modules/` staged
for the other one. A third value is refused by both. The image records it as the label
`io.github.dphhyland.pf-agentic-identity.staging-profile`:

```sh
docker inspect --format '{{index .Config.Labels "io.github.dphhyland.pf-agentic-identity.staging-profile"}}' <image>
```

Verified 2026-09-27 on 13.1.3, before `rar-model` joined the staged jars (S1b): a production build had the then
eight jars in `server/default/deploy` and in the war's `WEB-INF/lib`, no `pf.plugins.ciba-sim.jar` and no
`/opt/ciba-sim`; a conformance build had nine and the directory as `drwx------ ping`. With `rar-model` it is nine
and ten: 0.4.0's release dry run staged the production nine and its rig the conformance ten (2026-09-27, see
[docs/releases/0.4.0.md](../docs/releases/0.4.0.md#what-we-verified)). Also verified before S1b: a production
`modules/` built with `STAGING_PROFILE=conformance` fails at the assembler, and `STAGING_PROFILE=staging` fails
at the first `RUN`. The conformance image booted
through `conformance/up.sh`: the token endpoint answered, a bare `POST /ciba-sim/decision` was a 400 and
not a 404 (every check in the simulator's gate passed on the running PF), a recorded decision appeared in
`/opt/ciba-sim` as a `0600` file, and the PingFederate JVM had `Umask: 0077` and the profile in its
environment. With `platform` and `platform-pf` (plan item F-1), verified 2026-09-28 on 13.1.3: the production
stage was 11 jars and the conformance stage 12, the assembler accepted both `MANIFEST`s against the stock war,
and the conformance image booted through `conformance/up.sh` with both jars in `server/default/deploy` and the
war's `WEB-INF/lib`, and its discovery, SSF and federation endpoints answering 200.

## What is here, and what you must supply

Tracked:

| Path | Purpose |
|---|---|
| `Dockerfile` | stock `pingidentity/pingfederate:13.1.3` + the staged modules, merged into `pf-runtime.war` at the **root** context (single classloader), with eight filters registered over PF's own endpoints in its `web.xml` - the list, and the order they must run in, is in `filters.xml`. `--build-arg STAGING_PROFILE=production\|conformance` (default `production`); targets `builder`, `capability` and `deployment` (the default) - see [Building](#building) |
| `stage-modules.sh` | copies the reactor's module jars into `modules/` - the production profile's by default, and the CIBA simulator as well for `--profile conformance` - and writes the v2 `MANIFEST`, which names each one; and copies the war assembler into `assembler/` |
| `filters.xml` | the filters registered in `pf-runtime.war`'s `web.xml`: each one's class and paths, the order pairs that must hold between them, and why |
| `assemble-pf-runtime-war.sh` | merges `modules/` into the stock war and registers what `filters.xml` declares, after checking `modules/` against `MANIFEST` and the profile; also used inside the image build. A wrapper round the war assembler, which does the checking - see [The war assembler](#the-war-assembler) |
| `pf-entrypoint.sh` | the boot shim: refuses to start without the licence agreement accepted or with a plain listener in production, checks, decrypts and places the archive, drops the identity from the environment, hands over to the base image |
| `pf-healthcheck.sh` | the image's `HEALTHCHECK`: PingFederate's heartbeat and this repository's live endpoint - see [The healthcheck](#the-healthcheck) |
| `test-entrypoint.sh` | exercises the entrypoint's and the healthcheck's decisions with PingFederate stubbed out; `--image <image>` runs it inside a built image |
| `overlay/config-store/` | the drop-in deployer's settings, PingFederate's own defaults - see [The drop-in deployer's settings](#the-drop-in-deployers-settings); not secret |

You supply, per deployment (all git-ignored - see `.gitignore`):

| Path | What it is |
|---|---|
| `modules/` | output of `stage-modules.sh`; do not hand-populate it |
| `assembler/` | output of `stage-modules.sh` too: `war-assembler.jar`, from `build/war-assembler` |
| `data.zip.age` | the PF configArchive for **your** environment, **age-encrypted**. A configArchive is a plain zip that *contains* `pf.jwk` - the master key that decrypts every secret in it, next to the system keys, both keystores and the admin password hash. Encrypted, it is safe in git and safe in an image layer. |
| `data.zip` | the same thing **unencrypted**. Transitional, and refused at boot unless `OIDF_DEPLOYMENT_PROFILE=development` - see below. |
| `overlay/pf.jwk`, `overlay/pingfederate-system-keys.xml` | staged **only** on the plaintext path, and redundant since the entrypoint takes both keys from inside the archive on either path. Phase 3 (plan item R-I3) removes the plaintext path and them with it. |

## Consuming a release, rather than copying jars

Tagging `v<version>` publishes a checksummed set of these artifacts as a GitHub Release — the module
set, `oidf.war`, the plugin jars, `SHA256SUMS`, and a `PROVENANCE.txt` naming the commit that built
them. Maven artifacts also go to GitHub Packages under `com.pingidentity.ps.oidf`, though that requires
authentication even for public reads, so the release assets are the auth-free path.

**Pull a release and record what you pulled.** The alternative — copying jars out of a sibling checkout
— is how a consumer came to be running module code from before the 2026-08-15 split-package unwind,
with none of the security work in it, and nothing anywhere recording that it was behind.

```sh
gh release download v<version> -R ID-Partners/pf-agentic-identity -D vendor/   # releases to 0.6.0 are mirrored there, checksums unchanged
( cd vendor && sha256sum -c SHA256SUMS )      # verify before use
grep -E '^(commit|tag):' vendor/PROVENANCE.txt >> VENDORED.txt   # record it
```

For PingFederate 13.1.3 that is v0.3.0 or later. Every v0.1.x release is a `javax.servlet` build for
13.0.x, and moving from one means moving PingFederate in the same change.

`modules/` is **eight separate jars** in a production stage, which is what a release is, and nine in a
conformance stage (v0.3.0's release set was the nine of the one-profile script). If you are copying a
single `pf-oidf-modules.jar`, you are on the pre-unwind artifact shape that this build no longer produces.

## Building

The Dockerfile has three targets. `deployment` is the last, so a `docker build` with no `--target` builds it, as
it did before the targets existed (plan item R-CI6, taking R-I3's targets ahead of Phase 3).

| Target | What it is | Needs in the context |
|---|---|---|
| `builder` | assembles `pf-runtime.war` from the stock war, `modules/` and `filters.xml`; nothing ships from it but the war | `modules/`, `assembler/`, `filters.xml`, `assemble-pf-runtime-war.sh` |
| `capability` | the image with no configuration archive: the assembled war and the module jars in `server/default/deploy`, the entrypoint, age. What Build's image job builds, tests and scans. Run without `PF_ARCHIVE_FILE` naming a mounted archive it boots an empty PingFederate (the entrypoint logs `no config archive present` and carries on), so do not deploy it as it is | the same, and `pf-entrypoint.sh` |
| `deployment` (the default) | `capability` plus the configuration archive and `overlay/config-store/`: what a deployment runs | the same, and `data.zip.age` or `data.zip`, and `overlay/` |

```sh
mvn -q -DskipTests package                              # from the repo root
build/pingfederate/stage-modules.sh                     # -> modules/ + MANIFEST, assembler/; --profile conformance for a rig
docker build --target capability -t pf-oidf:capability build/pingfederate    # no archive needed
# stage your data.zip.age and overlay/ into build/pingfederate/, then:
docker build -t pf-oidf build/pingfederate              # --build-arg STAGING_PROFILE=conformance for a rig
```

The `deployment` image is the one the single-stage Dockerfile built. Checked 2026-09-28 on 13.1.3, for both
profiles, from one context with a placeholder archive: every file in the two images has the same path, type,
mode, owner, size and sha256 - the assembled war included - and the labels, environment, user and entrypoint
are the same, except for what the build itself stamps: `/etc/shadow`'s last-changed day for `klogd`, three
fontconfig caches and `/var/log/apk.log`, which apk writes on each run (see F-0220 for why it rewrites so much),
and `/tmp/hsperfdata_root`, which the JVM left in the image when the assembler ran there and now leaves in
`builder`. The `deployment` target still refuses a context with neither archive in it, and `capability` builds
from one with no archive and no `overlay/`. From 0.6.0 no stage that ships runs apk (see
[What the image leaves to you](#what-the-image-leaves-to-you)), so the fontconfig caches, `/etc/shadow` and
`apk.log` are the base image's in every build.

CI passes three build arguments for the OCI labels: `OCI_VERSION` (the root pom's version), `OCI_REVISION` (the
commit, `GITHUB_SHA`) and `OCI_CREATED` (the build time, RFC 3339 UTC). A local build that passes none is labelled
`unknown`, `unknown` and an empty time. The reactor build passes the commit too, as `-Doidf.build.commit=...`,
which platform-pf writes into its manifest as `Build-Commit`: `/agentic-identity/info` and the start-up banner
read it from there (F-0190), and a build that passes nothing says `unknown`, which they report as null.

From another repo, point the script at a sibling checkout:

```sh
PF_AGENTIC_IDENTITY_HOME=../pf-agentic-identity ../pf-agentic-identity/build/pingfederate/stage-modules.sh
```

`STAGE_DEST` redirects where the jars land, if you are composing a context elsewhere; the assembler goes to
`assembler/` beside it. A context composed elsewhere needs `Dockerfile`, `assemble-pf-runtime-war.sh`,
`filters.xml`, `pf-entrypoint.sh`, `pf-healthcheck.sh`, `modules/`, `assembler/` and `overlay/config-store/`
from here.

## Staging from a release

`stage-from-release.sh` writes the same `modules/` and `assembler/` as `stage-modules.sh`, from a published
release's assets instead of from the reactor: no Maven and no git, so a tree without the source (the public one)
can build the image. The Dockerfile, the war assembler and `conformance/compose-context.sh` cannot tell the two
stages apart; both write the `MANIFEST` and stage the assembler through `stage-lib.sh`.

```sh
build/pingfederate/stage-from-release.sh 0.6.1                          # production, fetched and cached
build/pingfederate/stage-from-release.sh --profile conformance 0.6.1    # a rig: the CIBA simulator too
build/pingfederate/stage-from-release.sh --profile conformance dist/    # a directory of a release's assets
```

What it checks before anything is staged:

- **Every file against `SHA256SUMS`.** A version is fetched from
  `https://github.com/<PFAI_RELEASE_REPO>/releases/download/v<version>/`: `SHA256SUMS` first, then every file it
  lists, with `curl -q -fsSL --retry 3` over https only (redirects too) and no credentials (release assets are
  anonymous, `GH_TOKEN` is never sent, and `-q` keeps a `~/.curlrc` from adding a header or a `.netrc`). Each
  name `SHA256SUMS` lists must be a plain file name - no slash, no leading dot - or nothing is fetched. Nothing
  is staged unless every file verifies. A directory source is held to the same check, and a file
  in it that `SHA256SUMS` does not list is refused.
- **The release's `MANIFEST`.** It must be a `MANIFEST/2` production header; exactly the jars it lists are staged,
  under its sections, each with the digest it gives, and the new `MANIFEST` keeps the release's commit.
- **A war assembler.** `war-assembler-<version>.jar` has been a release asset from 0.6.1, the first release this
  script can stage. An older release has none, and is refused with that message: build it from its source.

**The cache.** A fetched version is kept in `.release/<version>/` beside the script (git-ignored), with the URL
it came from in `.release/<version>/.source`, and reused only while it still verifies against its `SHA256SUMS`
and was fetched from the URL asked for now: a copy from a mirror or a local test server is fetched again rather
than taken for the release. A release that is refused is not left there.

**The two profiles.** `production` (the default) stages the release's `MANIFEST` and nothing else. `conformance`
adds the CIBA simulator, which a release carries as `demo-only-ciba-sim.jar` so that nothing globbing
`pf.plugins.*` deploys it, under its own name, `pf.plugins.ciba-sim.jar` (plugins/ciba-sim).
The production profile never stages it. The release name is a label, not a guard: PingFederate 13.1.3 loads the
jar from `server/default/deploy` under either name ([U-0460](../docs/findings.md#u-0460)).

| Setting | Default | What it does |
|---|---|---|
| the argument | `PFAI_RELEASE` from `release.env` beside the script | a version (`0.6.1`; a leading `v` is dropped) or a directory of release assets. The public tree has a `release.env`; this repository does not, so here the argument is required |
| `PFAI_RELEASE_REPO` | `release.env`'s, else `ID-Partners/pf-agentic-identity` | the repository whose releases are fetched |
| `PFAI_RELEASE_BASE_URL` | `https://github.com/$PFAI_RELEASE_REPO/releases/download` | the URL the `v<version>/` directories sit under: a mirror, or a local server in a test |
| `STAGE_DEST` | `modules/` beside the script | as for `stage-modules.sh`; `assembler/` goes beside it |

Build's image job proves the equivalence on every change: it assembles a release's assets from the build with
`tools/ci/assemble-dist.sh` (what `release.yml` publishes), stages both profiles from them, and holds each stage
to the one the image was built from - every jar byte for byte, the `MANIFEST` but for its `built=` time, and the
assembler. Then `test-stage-from-release.sh` serves fixture releases on 127.0.0.1 and checks that a tampered jar,
a jar `SHA256SUMS` does not list, a `SHA256SUMS` naming a missing file, a release with no war assembler and an
unknown profile are each refused, and that no request carries an `Authorization` header.

## Scanning the image

Build's `image` job (`.github/workflows/build.yml`) builds `capability` for both profiles on every pull request
and push to main, and a release needs it green (`.github/required-checks.txt`). It:

- runs the war assembler against PingFederate's own `pf-runtime.war`, from the image `build/pf-version.env` pins,
  so `StockWarGoldenTest` holds the assembled `web.xml` to the shell assembler's byte for byte (U-0185);
- builds each profile's `capability` image, checks its profile label and runs `test-entrypoint.sh --image` in it;
- checks each image's OCI labels (this build's version and commit, an RFC 3339 build time), that it declares 9031
  and 9999 and nothing else, that its healthcheck is `pf-healthcheck.sh`, that it leaves the licence agreement at
  the base image's `NO` and the plain listener at `-1`, that PingFederate's `run.properties` template sets no
  `oidf.*` property and its `log4j2.xml` names none of this repository's loggers, that the image's own `log4j2.xml`
  differs from PingFederate's only in `server.log`'s pattern, which prints `%X{httprequestid}` (F-0395), that there are no mock attesters
  and no bash, and that platform-pf's manifest in the image carries the commit;
- holds every file, link and directory under `/bin`, `/sbin`, `/lib`, `/usr`, `/etc` and `/var` to the base
  image's, byte for byte, apart from `age`, `age-keygen` and age's licence (F-0220), and PgJDBC's licences (F-0330),
  and checks that PgJDBC is in `server/default/lib`;
- builds the default target from a placeholder archive, and checks that it refuses a context with none;
- writes a syft SBOM of each image (SPDX JSON, the `image-sbom` artefact) and scans it with grype, and scans the
  base image the same way (the reports are the `image-scan` artefact, the verdicts are in the job summary).

**What fails and what does not.** `tools/ci/image-scan-gate.py` sorts each finding by where it comes from. It is
PingFederate's when the base image's scan has the same vulnerability in the same package at the same version:
PingFederate's jars (which the assembled war carries too), its Java runtime, the tools Ping installs. Those are
reported and never fail the build, because they are not ours to fix: a PingFederate version bump is what fixes
them, and the job's summary lists them for the day the bump is chosen. Everything else is ours - the jars
`stage-modules.sh` stages, anything the assembler adds to the war, the `age` binaries the Dockerfile builds -
and a HIGH or CRITICAL finding there fails the job. A finding in one of our jars is ours even when
PingFederate ships the same library at the same version with the same finding: the gate reads each profile's
`modules/MANIFEST` (`--ours-manifest`) and a finding found inside a jar it names, loose in `server/default/deploy`
or inside the war, is ours, since a PingFederate bump would fix PingFederate's copy and leave ours.

A finding of ours that cannot be fixed yet is accepted in `.github/grype.yaml`, one entry per vulnerability,
package and version, each with its reason; the summary lists every accepted finding and names an entry that no
longer matches. On 2026-10-11 one thing is accepted: two advisories in the SSH code of the `golang.org/x/crypto`
v0.55.0 that age 1.3.2 is built with, as its go.sum pins it (F-0285). Until 0.6.0 the Dockerfile's `apk add`
reinstalled every base package, because the base image has no apk database (F-0220), so a scan reported the base
image's own Alpine packages - zlib's CVE-2026-85091 among them - as ours; it no longer runs apk, and those
packages are PingFederate's again.

The scanner and the SBOM generator come from `tools/ci/install-lint-tools.sh` at pinned versions and checksums
(grype 0.119.0, syft 1.52.0). The job fetches grype's vulnerability database once and scans the base and both
images against that one copy (`GRYPE_DB_AUTO_UPDATE=false`). The database is the day's, so the job can fail on a day
nothing here changed: a new advisory against something of ours. Read the summary, then fix it or accept it with a
reason. The same scan by hand, after building `capability` as above:

```sh
tools/ci/install-lint-tools.sh /tmp/scan grype syft
. build/pf-version.env
/tmp/scan/syft scan "docker:$PF_IMAGE@$PF_IMAGE_DIGEST" -o syft-json=base.syft.json
/tmp/scan/syft scan docker:pf-oidf:capability -o syft-json=image.syft.json
/tmp/scan/grype sbom:base.syft.json -c .github/grype.yaml -o json --file base.grype.json
/tmp/scan/grype sbom:image.syft.json -c .github/grype.yaml -o json --file image.grype.json
python3 tools/ci/image-scan-gate.py --image image.grype.json --base base.grype.json \
  --ours-manifest build/pingfederate/modules/MANIFEST
```

The service images plan item R-CI6 also names - device-enrolment, the adapter and the SPIRE reader - do not
exist yet: plan item R-I8 makes them in Phases 5 and 6, and they join the job then. Booting the image needs a
licence, and waits for R-CI7 (Phase 4).

## The war assembler

`assemble-pf-runtime-war.sh` is a wrapper: `build/war-assembler`, a JDK-only jar
the reactor builds and `stage-modules.sh` stages into `assembler/`, reads the stock `web.xml` with the JDK's DOM
and applies `filters.xml` (plan item R-I5). Besides the `MANIFEST` guard and the namespace guard, it refuses a war
in which a declared filter does not have exactly one `<filter>` and one `<filter-mapping>` over exactly its
declared paths, an order pair does not hold, a declared path is one the stock `web.xml` does not serve, the root
is `metadata-complete="true"`, or a declared filter's or listener's class is in no jar - and it prints each
path's filter chain, PingFederate's own filters included:

```
chain /as/token.oauth2 (controller): RuntimeServiceSetFilter > proxyFilter > ... > servletRequestCleanupFilter > Fapi2Profile > OAuthErrorDescription > OidfAutoRegistration > ClientAttestationAuth > noCacheFilter
```

In the image build it runs on the base image's own Java 21; outside Docker the script needs Java 17 or later.
Verified 2026-09-28 on 13.1.3: it wrote the same `web.xml` as the shell script it replaced, byte for byte, for
both profiles, and the same war again from its own output; the production and conformance images built with it
carry the same seven filters in the same order as before. The evidence, and why it is a jar rather than a
source-launched file, are in its README.

From 0.7.0 the war is reproducible from its stage (F-0450): every staged jar's entry carries one time,
2000-01-01T00:00:00 - the poms' `project.build.outputTimestamp` - instead of the jar's file time, so copying a stage again, or assembling in another time zone, gives the same bytes.
On 2026-10-08 two production stagings four seconds apart assembled against 13.1.3's stock war gave one sha256,
`8ed83174...`. The reference stacks ([reference/](../demo/reference/README.md)) build target `capability` with the
production profile from a stage of their own, so they never overwrite the rig's `modules/`.

## The MANIFEST guard

`stage-modules.sh` writes `modules/MANIFEST`, version 2, and so does `stage-from-release.sh`
([Staging from a release](#staging-from-a-release)); both write it with `stage-lib.sh`'s `pfai_write_manifest`, so
the two cannot drift apart:

```
MANIFEST/2 profile=production built=2026-09-27T09:28:26Z commit=a440bc5f88d1
[servlets]
ca43ec7a6863eba7e8c1f0cd5a4c59135a2f9796ea9c513c0043ef83593c61fa  oidf.jar
729ab2b32f47280a274c3bf29e464724caa4471c1d064d7ec5ec4e4c93b64d51  attestation-issuer-0.4.0-SNAPSHOT.jar
...
[libs]
...
```

One header line - the format, the profile, when it was staged and from which commit (`-dirty` when tracked
files had uncommitted changes; `unknown` outside a git checkout; from a release, the commit its own `MANIFEST`
names); a `[section]` per module group
(`servlets`, `libs`, and `plugins` in a conformance stage); and one `<sha256>  <file>` line per jar, in
`sha256sum`'s own format, so the directory can be checked by hand:

```sh
grep -E '^[0-9a-f]{64}  ' modules/MANIFEST | ( cd modules && sha256sum -c )
```

`assemble-pf-runtime-war.sh` (the war assembler, since R-I5) refuses to build unless the header is a v2 header whose profile is the one it
was told (its fifth argument, `production` when omitted), every named jar is present with the digest it was
staged with, and no other jar is in the directory. A v1 `MANIFEST` - bare filenames, no header - is refused
too: it came from an older `stage-modules.sh`, and the jars beside it from some other tree. Hand-copying
jars into `modules/` is how modules have gone missing before, and a war that is missing one does not fail
at build - it 500s at first use, in production. The guard turns that into a build failure, and the digests
catch the jar that was rebuilt or swapped after staging, which a list of names could not.

Verified 2026-09-27 against the 13.1.3 stock war: both profiles assemble; a profile mismatch either way, a
v1 file, a jar with one byte appended, a stray jar, a missing jar and a third profile value are each
refused, and no output war is left behind.

**Reading a MANIFEST elsewhere.** Anything that counted the module set by counting lines - the release
workflow builds `PROVENANCE.txt` that way - counts the header and the sections as well from this version.
Count the digest lines instead: `grep -cE '^[0-9a-f]{64}  ' MANIFEST`.

> **Licensing is DevOps-fetched - no `pingfederate.lic` is baked or staged.** The image does not accept Ping
> Identity's licence agreement for you: set `PING_IDENTITY_ACCEPT_EULA=YES` at run time, or the entrypoint stops
> the boot. The base image's boot hook pulls a fresh evaluation licence when `PING_IDENTITY_DEVOPS_USER` +
> `PING_IDENTITY_DEVOPS_KEY` are present in the environment. Eval licences are short-lived (~7 days) and
> re-fetched only at container start. Or mount a licence file of your own at
> `/opt/in/instance/server/default/conf/pingfederate.lic`: the hook fetches nothing when the server already has one,
> and the DevOps variables are then not needed ([the top-level README](../README.md#licensing-pingfederate)). Mount
> it; never `COPY` it into an image built from this one.

## The archive at boot

`pf-entrypoint.sh` runs before the base image's own `bootstrap.sh`, and does these things in this order:

1. `umask 077`, before anything is written - the decrypted archive, the keys, and every file the base
   image's hooks go on to copy are readable by PingFederate's user alone.
2. Refuses to start unless `PING_IDENTITY_ACCEPT_EULA` is `YES` or `Y`, in any case - the base image's own
   reading, which its licence hook applies only when it fetches an evaluation licence - and refuses a plain
   HTTP listener (`PF_RUN_PF_HTTP_PORT` of 0 or more, `-0` included) unless
   `OIDF_DEPLOYMENT_PROFILE=development`. Both come before the archive is touched.
3. Chooses the archive: `PF_ARCHIVE_FILE` if set, else `data.zip.age` in the drop-in directory, else
   `data.zip` there. Encrypted and plain are told apart by content, not by name: an age file starts with
   `age-encryption.org/v1`, or with `-----BEGIN AGE ENCRYPTED FILE-----` when it was made with `age -a`.
   An archive, or a `PF_ARCHIVE_AGE_KEY_FILE`, that exists but PingFederate's uid cannot read is refused as
   that, with the uid and the file's mode and owner. Until 0.7.0 an unreadable archive failed the content test
   and was reported as plaintext: C-7's first run on a Linux runner (2026-10-08) bind-mounted a host file that
   was `0600` to uid 1000 into a container running as 9031, which Docker Desktop's file sharing had hidden.
4. If `PF_ARCHIVE_SHA256` is set, checks the archive against it - before it is decrypted or imported.
5. Decrypts an encrypted archive with the identity from `PF_ARCHIVE_AGE_KEY_FILE`, or, only when that is
   unset, from `PF_ARCHIVE_AGE_KEY`. The inline identity reaches `age` on a pipe, never a temporary file
   or an argument; the file is the operator's, read and left alone. The ciphertext is left where it is, so
   every start of the container decrypts it again, a restart included, and every start needs the identity
   (F-0313: until 0.6.0 the first start removed a ciphertext baked into the drop-in directory - one mounted
   through `PF_ARCHIVE_FILE` was always kept - and a restart in production then refused the plaintext the first
   start had written).
6. Refuses a plaintext archive unless `OIDF_DEPLOYMENT_PROFILE=development`. Production is the default
   when the variable is unset, and what any other value counts as.
7. Extracts `pf.jwk` and `pingfederate-system-keys.xml` from inside the archive, on either path.
8. Removes `PF_ARCHIVE_AGE_KEY` and `PF_ARCHIVE_AGE_KEY_FILE` from the environment and hands over. Nothing
   downstream - the base image's hooks, PingFederate, a shell in the container - sees the identity.

| Variable | Default | What it does | When it's wrong |
|---|---|---|---|
| `PF_ARCHIVE_FILE` | `data.zip.age`, else `data.zip`, in the drop-in directory | The archive to boot from - a mounted secret, usually. It wins over an archive baked into the image, which is left where it is | Not a file: `FATAL: PF_ARCHIVE_FILE=... is not a file`, no boot. There but unreadable to the container's uid (a bind-mounted host file keeps the host's owner and mode on Linux): `FATAL: the config archive ... exists but cannot be read by uid 9031 (gid 0): it is -rw------- owner 1000:1001`. Ciphertext may be `0644`; or hand the uid its own copy |
| `PF_ARCHIVE_AGE_KEY_FILE` | unset | Path to the age identity, as a mounted secret file. **Preferred**: it is never in the container's metadata. Read at every start, restarts included, so keep it mounted | Set but missing: `FATAL: ... does not exist` - no fall-through to the inline key. There but unreadable to the container's uid: `FATAL: PF_ARCHIVE_AGE_KEY_FILE=... exists but cannot be read by uid ...`, with its mode and owner - hand the uid a `0400` copy (the reference stacks do it on a tmpfs) rather than widen the host file. Wrong identity: `FATAL: could not decrypt the config archive`, and no plaintext is left behind |
| `PF_ARCHIVE_AGE_KEY` | unset | The identity itself, read only when `_FILE` is unset. Gone from the process environment before PingFederate starts, but still in `docker inspect` - the reason to prefer the file | Wrong: as above. Neither set for an encrypted archive: `FATAL: ... neither PF_ARCHIVE_AGE_KEY_FILE nor PF_ARCHIVE_AGE_KEY is set` |
| `PF_ARCHIVE_SHA256` | unset (no check) | The archive's SHA-256 in hex, any case, of the file as shipped - the ciphertext for an encrypted archive | Mismatch: `FATAL: ... does not match PF_ARCHIVE_SHA256`, before anything is decrypted. Not 64 hex digits: `FATAL: PF_ARCHIVE_SHA256 is not a hex SHA-256` |
| `PING_IDENTITY_ACCEPT_EULA` | the base image's `NO` | `YES` or `Y`, in any case, accepts Ping Identity's licence agreement. Until 0.6.0 the image set `YES` for everyone who ran it | Anything else: `FATAL: PING_IDENTITY_ACCEPT_EULA is '...': set PING_IDENTITY_ACCEPT_EULA=YES at run time`, before anything else |
| `PF_RUN_PF_HTTP_PORT` | `-1` (off) | PingFederate's plain HTTP runtime listener, `pf.http.port`, which the Dockerfile has the base image's `run.properties` template read from this variable. A negative number other than `-0` is off. A port, `0` and `-0` included, turns it on, with a warning, in development only | A port in production: `FATAL: PF_RUN_PF_HTTP_PORT=... opens PingFederate's plain HTTP listener, which is refused ...`. Not a whole number: `FATAL: PF_RUN_PF_HTTP_PORT is '...', not a whole number` |
| `OIDF_DEPLOYMENT_PROFILE` | unset, which is `production` | `development` lets a plaintext archive boot and the plain listener open, each with a warning. Read here in shell by `is_development`, which applies the Java modules' rule (libs/platform's `DeploymentProfile`): `development` in any case, trimmed as Java's `String.trim` trims. `DeploymentProfileShellTest` runs one table through both (F-0161, closed in 0.6.0; the entrypoint did not trim before) | Unset, `production` or anything else with a plaintext archive: `FATAL: a plaintext archive (...) is refused when OIDF_DEPLOYMENT_PROFILE is production` |
| `PF_DATA_DIR`, `PF_BOOTSTRAP` | `/opt/in/instance/server/default/data`, `/opt/bootstrap.sh` | Where the archive and keys go, and what to hand over to. `test-entrypoint.sh` points both at a scratch directory and a stub | - |

Once per environment, by whoever owns the deployment:

```sh
age-keygen -o identity.txt          # keep the identity in a password manager + a sealed service secret
age -r "$(grep -o 'age1[a-z0-9]*' identity.txt)" -o data.zip.age data.zip
sha256sum data.zip.age              # -> PF_ARCHIVE_SHA256, if you want the boot to check it
shred -u data.zip                   # the plaintext has no further use

# then, on the service: mount identity.txt as a secret file and set
PF_ARCHIVE_AGE_KEY_FILE=/run/secrets/pf-archive-identity   # or PF_ARCHIVE_AGE_KEY=<the identity>, second best
```

**Only one secret.** `pf.jwk` is deliberately *not* supplied separately: it comes out of the archive
after decryption, so the running key is by construction the one the archive was encrypted under.
Supplying them separately is how an archive and a key drift apart, and a PF whose key does not match
its archive fails in a way that reads like data corruption. From this version the plaintext path takes
its keys from the archive as well; the `overlay/` keys it used to rely on are the same files.

### Where the plaintext lives

Earlier versions of this page and of the script said the archive was decrypted "into a tmpfs-backed
path". It never was; nothing mounted one. What happens, read from the 13.1.3 base image's scripts on
2026-09-27: the entrypoint writes `data.zip` to the drop-in directory under `PF_DATA_DIR` and the two key
files beside it, on the container's writable layer; the base image's `entrypoint.sh` then copies everything
under `/opt/in` to `/opt/staging` (`apply_local_server_profile`) and hook `07-apply-server-profile.sh` copies
that into `/opt/out/instance`, both with a plain `cp` of every file. So for the life of the container the
plaintext archive and `pf.jwk` exist in three places on that layer, each `0600` because of the umask - seen
on the rig 2026-09-27, where the drop-in deployer had also renamed its copy under `/opt/out` to
`data.zip.<date>` after importing it, and left it there. What the entrypoint guarantees is narrower, and
holds: none of them is in an image layer, and the identity that unlocked them is in none of those places
either.

**Every start decrypts.** The entrypoint keeps the ciphertext, and each start - the first, and every restart
that keeps the container's writable layer: `docker restart`, a restart policy, a node reboot - decrypts it
again over the plaintext the last start wrote. The plaintext is therefore never what a later start boots from:
while the ciphertext is there it is chosen, and a plaintext archive is chosen only when no ciphertext is, which
production refuses whoever wrote it. So no marker file tells the entrypoint's plaintext from an operator's, and
there is none to forge. The base image's bootstrap copies the kept `data.zip.age` to `/opt/staging` and
`/opt/out` beside the plaintext; PingFederate's drop-in deployer ignores it, deploying `data.zip` only (read
from the 13.1.3 `DataDeployer`, which asks for one zipped data file, and seen on the rig on 2026-10-01). On a
restart the bootstrap's run plan is `RESTART` and it copies nothing into `/opt/out`, so PingFederate starts on
the configuration it imported the first time and the fresh plaintext is not imported again. The plaintext
copies outlive the start that needed them, as they did before; that adds nothing a reader of the writable layer
lacks, because `/opt/out/instance/server/default/data` holds, for as long as PingFederate runs, the same
`pf.jwk` in the clear, the same system keys and the configuration the archive was exported from, at the same
`0600`.

To keep them off the node's disk as well, mount a tmpfs over `/opt/out`, the runtime instance the
bootstrap builds there from `/opt/server` (519 MB on 13.1.3) and where PingFederate also writes its logs -
so size it:

```sh
docker run ... --tmpfs /opt/out:rw,exec,size=2g,uid=9031,gid=0,mode=0770 ...
```

A restart empties that tmpfs, and the bootstrap then treats it as a first start: it copies the instance into
`/opt/out` again and PingFederate imports the archive again, which only works because the ciphertext is still
there to decrypt (seen on the rig on 2026-10-01).

Pass `exec` explicitly. On 2026-09-27, with it left out of the mount options, the runtime's `run.sh` failed
with `Permission denied` before PingFederate started (exit 126, after the licence had been fetched); with it
in, the boot described under "Verified" below came up with `/opt/out` a 2 GB tmpfs, 569 MB used. With
`PF_ARCHIVE_FILE` pointing at a mounted secret, the drop-in copy under
`/opt/in` can go on a tmpfs too (`--tmpfs /opt/in/instance/server/default/data/drop-in-deployer`), leaving
the extracted keys under `PF_DATA_DIR` and the `/opt/staging` copy on the writable layer: `/opt/staging`
holds the hooks and cannot be a mount, and `PF_DATA_DIR` holds the image's `config-store/` overlay. Plan
item R-I3 (Phase 3) revisits the layout.

**Verified.** 2026-08-21 on the 13.0.3 base image: the entrypoint failed closed with a missing identity and
with a wrong one, and a `docker save` layer scan of an image built this way found **no** key material,
against a plaintext-built control that found four files - a control that matters, because an earlier
version of the same scan reported "clean" for both images and was simply broken. 2026-09-27 on 13.1.3:
the base image is alpine 3.24.1 with `age` 1.3.1, and `test-entrypoint.sh --image` ran its 42 checks inside
an image built from this Dockerfile, as the `ping` user, and again in the base image with GNU grep beside
busybox's - every refusal above, the file-over-variable preference, an archive armored with `age -a` taken
for encrypted and not for plaintext, `umask 077` reaching the process the entrypoint hands over to, both
identity variables absent from its environment, and the inline identity in no file under the test's work
directory and in none written to a temp directory during the run. That last check is proved live by two
more that plant the identity in both places and find it; its first version passed whatever the entrypoint
wrote, because the image's busybox grep rejected an option it used. The same day, on a real boot: the
rig's image started from an age-encrypted archive named by `PF_ARCHIVE_FILE` on a read-only mount, the
identity from `PF_ARCHIVE_AGE_KEY_FILE`, `PF_ARCHIVE_SHA256` set, under `OIDF_DEPLOYMENT_PROFILE=production`,
first on the writable layer and then with `/opt/out` on the tmpfs above. Both times the entrypoint logged
the integrity match, the decrypt and both extractions; PingFederate answered on the token endpoint; the
JVM's `/proc/<pid>/environ` held `PF_ARCHIVE_FILE` and `PF_ARCHIVE_SHA256` and neither identity variable,
and the identity's text was nowhere in it; `Umask: 0077`; both mounted files were untouched; and the
simulator's endpoint, jar present, answered 404.

**Verified, 0.6.0.** 2026-09-29 on 13.1.3, both profiles' `capability` images built with no configuration of
their own: `test-entrypoint.sh --image` ran 68 checks inside the conformance rig's image, the licence-agreement
refusals, the plain-listener refusals and the healthcheck's decisions among them. The rig (`conformance/up.sh`,
its `vars.env` accepting the agreement and turning the listener on) booted, imported its archive with
`ForceUnsupportedImport` false, answered discovery on 9031 and the heartbeat on the plain listener, printed the
commit in its start-up banner, and was healthy by the image's own healthcheck.

**Verified, F-0313.** 2026-10-01 on 13.1.3, on the conformance rig's image rebuilt with `data.zip.age` in the
drop-in directory, `OIDF_DEPLOYMENT_PROFILE=production` and the identity from `PF_ARCHIVE_AGE_KEY_FILE`: with the
entrypoint as main had it at e377dbae the first start served and `docker restart` stopped at once with `FATAL: a
plaintext archive (/opt/in/instance/server/default/data/drop-in-deployer/data.zip) is refused when
OIDF_DEPLOYMENT_PROFILE is production`; with this one the restart decrypted again, answered 200 on
`/pf/heartbeat.ping` and `/agentic-identity/health/live` and was healthy by the image's healthcheck, and a restart
with `/opt/out` on the tmpfs above imported the archive again and served the same. `test-entrypoint.sh --image` has
restart cases for both profiles: ten of its checks fail against that entrypoint.

**The layer trap.** Staging the key and deleting it in a later `RUN` does *not* remove it: the earlier
layer still carries it and `docker save` yields it. The plaintext path demonstrably does this. Only
never putting it in a layer works.

> **Transitional.** A plaintext `data.zip` still builds, and boots under `OIDF_DEPLOYMENT_PROFILE=development`
> with a loud warning, so the rig is not broken between now and the master-key rotation. The rig's archive is
> plaintext, so plan item R-I3's package (0.6.0) kept that branch and the `overlay/` key handling; they go when the
> rig boots from an encrypted archive.

## What the image leaves to you

Until 0.6.0 the image carried configuration that belongs to a deployment. It carries none of it now (plan item
R-I3); each is yours to set at run time, and the rig in `conformance/` sets the ones it needs in `vars.env`.

| What | Until 0.6.0 | Now | To have it back |
|---|---|---|---|
| Ping Identity's licence agreement | `ENV PING_IDENTITY_ACCEPT_EULA=YES` | the base image's `NO`; the entrypoint stops the boot until you accept it | `PING_IDENTITY_ACCEPT_EULA=YES` |
| PingFederate's plain HTTP listener | on, port 9080, in every image | off (`PF_RUN_PF_HTTP_PORT=-1`), and refused in production | `PF_RUN_PF_HTTP_PORT=9080` with `OIDF_DEPLOYMENT_PROFILE=development`. PingFederate's own template warns that turning it on "is not recommended" and needs the secure session cookie off in `session-cookie-config.xml`; in production, terminate TLS in front of 9031 instead |
| This repository's loggers | `DEBUG` for `com.pingidentity.ps.oidf`, written into `log4j2.xml` | PingFederate's `log4j2.xml` as shipped: they inherit its root, `INFO`. From 0.7.0 that file is the one control - no level is set in code - and every line ends with `ctx[tid=.. rid=.. traceparent=..]` ([docs/operator/logging.md](../docs/operator/logging.md)) | a `log4j2.xml` of your own, in a server profile or a mount, by logger name: `com.pingidentity.ps.oidf`, `com.pingidentity.ps.oidf.<family>.event.<category>`, `au.com.idpartners.gm` |
| `ForceUnsupportedImport` | `true` in `overlay/` | `false`, PingFederate's default | see [The drop-in deployer's settings](#the-drop-in-deployers-settings) |
| Required attestation claims | `oidf.attestation.required.claims=workload` in `run.properties` | none, the code's default | `OIDF_ATTESTATION_REQUIRED_CLAIMS=workload` (or the system property) |
| Mock attesters | `oidf-mock-attesters.json` copied from the build context when present, and `oidf.mock.attesters` pointed at it | not read from the context and not set | development only: mount the file and set the system property `oidf.mock.attesters` to its path yourself, through `JAVA_OPTS` or a server profile's `run.properties`. The settings catalogue classes it forbidden in production |

The labels, the ports and the healthcheck are the image's own, and describe it rather than configure it:

- OCI labels `org.opencontainers.image.{title,description,source,version,revision,created,licenses}`, with the
  version, commit and build time CI passes (see [Building](#building)). `revision` is the commit, the same one
  `/agentic-identity/info` reports.
- `EXPOSE 9031 9999`: the runtime and admin ports, as the base image declares them. Nothing for 9080.
- `HEALTHCHECK`, below.

The base image has no apk database (`/lib/apk/db` holds no installed file), so an `apk add` there reinstalls the
whole of its Alpine userland at the day's versions (F-0220). age is built from its 1.3.2 module source in the
`age-build` stage, with a Go toolchain pinned by digest (`golang:1.27.2-alpine3.24`), and `go install` checks the
module and every dependency against the Go checksum database; the image gets the two binaries and age's licence
and no Go. Until 0.7.0 it was age's own release binary, built with go1.27.0, whose standard library failed the
image scan (F-0708). So a build of the image fetches the golang image from Docker Hub and age's source from
`proxy.golang.org`, checked against `sum.golang.org`, where it used to fetch age from GitHub. bash is gone from
the image: `pf-entrypoint.sh` and `pf-healthcheck.sh` are `sh` scripts, and bash is installed only in the
`builder` stage, for the war assembler's wrapper. Build's image job holds the image's system files to the base
image's apart from age and PgJDBC's licences.

### PostgreSQL's JDBC driver

From 0.7.0 the image carries PgJDBC, PostgreSQL's JDBC driver ([F-0330](../docs/findings.md#f-0330)). The stock
image has none: on 2026-10-06 the pinned digest had `h2.jar`, `hsqldb.jar` and `spring-jdbc.jar` in
`server/default/lib` and no jar anywhere holding `org/postgresql/Driver.class`. Every store here is PostgreSQL
([docs/operator/database.md](../docs/operator/database.md)), and both ways to reach it need the driver:

- a PingFederate JDBC data store on PostgreSQL (`OIDF_SSF_DATA_STORE_ID`, `OIDF_AUTHORITY_DATA_STORE_ID`, the instance
  registry's data store), whose pool PingFederate builds with the driver class the data store names;
- a direct URL in development (`OIDF_SSF_JDBC_URL`, `OIDF_AUTHORITY_JDBC_URL`, the instance registry's "JDBC URL"),
  which platform's `DataSources` opens with `Class.forName("org.postgresql.Driver")`.

The Dockerfile's `pgjdbc` stage downloads `postgresql-<version>.jar` from Maven Central and checks it against the
sha256 it records (taken on 2026-10-06 and cross-checked with Central's own `.sha1`) before anything reads it. The
jar goes to `/opt/in/instance/server/default/lib/`, which the base image's bootstrap copies to
`/opt/out/instance/server/default/lib/` at every start, as it does `deploy/`: there PingFederate's engine and the
webapp both see it. It is never in `modules/`, which goes into `pf-runtime.war`. The version is the one the
reactor's tests run on, `bom/pom.xml`'s `version.postgresql` (42.7.13); `tools/pf-version-check.py` fails when the
Dockerfile's `PGJDBC_VERSION` is another, so a Dependabot bump of the BOM fails the build until the Dockerfile's
version and its sum move with it. The licence is BSD-2-Clause, and so are the four OnGres libraries the jar bundles
(SCRAM and SASLprep): the image carries the jar's `LICENSE` and its `licenses/` folder at
`/usr/local/share/licenses/pgjdbc/`, and the `org.opencontainers.image.licenses` label names BSD-2-Clause.

To use a different driver build, put your own jar in `server/default/lib` through a server profile; two copies of
`org.postgresql.Driver` on the same classpath are a classloading accident waiting to happen, so remove this one
(`postgresql-42.7.13.jar`) when you do.

### The drop-in deployer's settings

`overlay/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml` sets the three settings the drop-in
deployer reads, to the values PingFederate 13.1.3 ships in its own copy of the file (read from the pinned image,
2026-09-29). What each does, read from that version's `DataDeployer` class with `javap` the same day:

- `ForceImport` (`true`): when an archive from another PingFederate version is upgraded on import and the upgraded
  data fails validation, the import goes on and is logged as completed; `false` stops it with "Data integrity
  validation failed during upgrade".
- `ReencryptArchive` (`false`): the archive's secrets are not re-encrypted under the running master key on import.
  The entrypoint makes the running key the archive's own (`pf.jwk` comes out of the archive), so there is nothing
  to re-encrypt.
- `ForceUnsupportedImport` (`false`; `true` until 0.6.0): when the archive's version check fails, the drop-in
  deployer refuses the archive and logs the reason as an error; `true` logs it as a warning and imports anyway.
  So an archive PingFederate does not support importing now stops at the import rather than loading into a
  version it was not made for. Export the archive from the PingFederate version the image runs. The rig's
  archive, exported from 13.1.3, imported with it `false` on 2026-09-29 ("Config archive import completed
  successfully").

### The healthcheck

`pf-healthcheck.sh` is healthy when PingFederate's own liveness check (`/opt/liveness.sh`, the base image's
healthcheck, run unchanged) passes and `/pf/heartbeat.ping` and `/agentic-identity/health/live` both answer 200
over the runtime port (`PF_ENGINE_PORT`, or `PF_RUN_PF_HTTPS_PORT` over it, as the base image's hooks have it). An
admin node (`OPERATIONAL_MODE=CLUSTERED_CONSOLE`) serves no runtime, so its liveness check alone decides. The timings
are the base image's: every 31 seconds, 29 to answer, 241 to start, 7 failures to be unhealthy.

**Live, not ready.** The plan asked for heartbeat and ready. `/agentic-identity/health/ready` answers 503 while an
enabled component is not ready, and some of those states are not ones a restart fixes: a PingFederate that is its
own trust anchor is not ready until its keys are pinned, and they can only be pinned once it serves its entity
configuration (F-0192). Docker does nothing with an unhealthy container by itself, but orchestrators replace one,
so a healthcheck on ready would restart such a node for ever. On the rig on 2026-09-29 the container was healthy
with heartbeat and live at 200 while ready answered 503.

To route on ready, point the load balancer's or orchestrator's readiness probe at
`/agentic-identity/health/ready` on 9031 - a Kubernetes `readinessProbe` with `httpGet` and `scheme: HTTPS`, say -
and keep the image's healthcheck, or a liveness probe on `/agentic-identity/health/live`, for restarts.
[docs/operator/health.md](../docs/operator/health.md) says what each answers.

## Testing the entrypoint

```sh
build/pingfederate/test-entrypoint.sh                        # here: needs age, age-keygen, zip, unzip
build/pingfederate/test-entrypoint.sh --image <built image>  # the same inside the image, which has them
```

Each case boots the entrypoint from a fresh data directory under `env -i`, with the base image's
`bootstrap.sh` replaced by a stub that records its environment, umask, working directory and arguments,
and asserts on what was written, what was refused and what PingFederate would have seen. One check sweeps
the work directory and the temp directories for the inline identity, and two more plant it there so the
sweep is known to fail when it should. The healthcheck's cases run `pf-healthcheck.sh` with `curl` and the base
liveness check stubbed. Build's image job runs it inside both profiles' `capability` images on every pull request
(plan item R-CI6). Every script in this directory is shellcheck-clean (0.11.0, 2026-09-27).

Because the modules sit at the **root** context, their endpoints have no `/oidf` prefix - the challenge endpoints
are `/federation/attestation-challenge` and `/federation/attestation/challenge`, and `/.well-known/ssf-configuration` is at root.
Repoint any `/oidf/*` consumers accordingly.
