# OpenSteer pins for the protocol-7 release

This audit covers OpenSteer commit `269afa7268c92ee19876fd124410146959fab86b` on branch `cv2-opensteer`. The
OpenSteer checkout was read only. Angle-bracketed values below are deliberately
unissued placeholders; they must be replaced from the published release
evidence and must never be guessed.

## Finding

No real PortableFS release version, artifact digest, or image digest is checked
into the OpenSteer repository at this commit. The only literal PortableFS image
digest in the tree is the synthetic test value at
`apps/control-plane/src/cloud/kubernetes-managed-deployment-provider.test.ts:30`
(`registry.test/portablefs@sha256:${"6".repeat(64)}`). It is a fixture and must
not be changed for a release.

Managed Cloud reads its production pins from an external strict JSON template.
`apps/control-plane/src/config.ts:170` declares
`OPENSTEER_CLOUD_TEMPLATE_PATH`, lines 318-323 turn it into the cloud
configuration, and `apps/control-plane/src/server/runtime.ts:59` reads that
file at control-plane startup. Therefore there is no tracked file in
`opensteer-cv2` that can be edited to consume the release. The pin change must
be one reviewed commit in the repository that owns the production template,
followed by a control-plane restart and reconciliation. If that template is
managed only as a secret or an untracked host file, the claimed one-commit
change is not currently possible; first put its non-secret release fields under
reviewed configuration ownership.

## Managed Cloud production template

The template schema is in
`apps/control-plane/src/cloud/kubernetes-managed-deployment-resources.ts:116-155`.
Every container image must end in a full digest (`:93-98`). Make these three
edits in the external JSON file named by `OPENSTEER_CLOUD_TEMPLATE_PATH` in the
same commit:

| Field and source | Current literal | Exact protocol-7 edit |
| --- | --- | --- |
| `filesImage`, schema line 120; consumed by the Files sidecar at line 671 | Not present in this repository; read the deployed template | Set to `us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases/portablefs-files@sha256:<UNISSUED_V7_FILES_IMAGE_MANIFEST_DIGEST>` |
| `portableFsMountImage`, schema line 142; consumed at lines 331, 355, 529, and 977 | Not present in this repository; read the deployed template | Set to `<MATERIALIZER_IMAGE_REPOSITORY>@sha256:<UNISSUED_V7_MATERIALIZER_IMAGE_MANIFEST_DIGEST>` where that immutable image was built from the verified v7 release capsule |
| `portableFsMountSha256`, schema line 143; verified at line 352 and passed to the Runner at line 715 | Not present in this repository; read the deployed template | Set to `sha256:<UNISSUED_V7_HOSTED_BIN_PORTABLEFS_SHA256>` for the exact `/opensteer-portablefs-release/hosted/bin/portablefs` member of the published capsule |

The release workflow publishes the component as
`us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases/portablefs-files@sha256:<digest>`
and the aggregate as
`us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases/portablefs-release@sha256:<digest>`.
The aggregate `portablefs-release` image is a scratch capsule, not the value for
`portableFsMountImage`. OpenSteer documents this constraint at
`apps/control-plane/src/cloud/README.md:30-36`: the materializer must contain a
shell, `sha256sum`, and the capsule's `hosted/bin/portablefs` at
`/portablefs/portablefs`. Infrastructure must build and publish that
materializer and report its image digest separately.

The init container checks `portableFsMountSha256`, copies the binary to the
Runner's private executable volume, and sets mode 0555
(`kubernetes-managed-deployment-resources.ts:348-359`). The Runner receives the
same digest without the `sha256:` prefix as
`OPENSTEER_PORTABLEFS_MOUNT_SHA256` (`:62-83`) and its container entrypoint
checks the installed file. The image digest and binary digest bind different
objects and neither can substitute for the other.

These are live release fields. Only placement is retained in each operation's
encrypted snapshot (`kubernetes-managed-deployment-resources.ts:192-211`); the
provider combines that placement with the current template at reconcile time
(`:227-244` and
`kubernetes-managed-deployment-provider.ts:199-211`). A control-plane process
that has not restarted still holds the old parsed template in memory.

The following adjacent values are deployment identity, routing, and trust, not
release pins. Do not change them merely to adopt protocol 7:

- `portableFsManagerUrl` and `portableFsManagerCidrs`, schema lines 144-145;
- `portableFsManagerCa`, `portableFsManagerCertificate`,
  `portableFsManagerPrivateKey`, and `portableFsProductPrivateKey`, schema lines
  146-149 and Secret projection lines 407-410;
- `portableFsProductIssuer` and `portableFsServiceId`, schema lines 150-151.

Rotate those values only through their own identity or endpoint procedure. The
Host receives their paths and identities at lines 616-645, and the teardown job
receives the same contract at lines 1034-1061.

## Self-hosted and local OpenSteer

Self-hosted production values also live outside the repository. The checked-in
files expose the inputs but contain no current release literal:

| Repository source | Current literal | Exact deployed-config edit |
| --- | --- | --- |
| `deploy/self-host/config.env.example:71` | `OPENSTEER_PORTABLEFS_ARTIFACT_PATH=/absolute/path/to/pinned/portablefs` | Set `OPENSTEER_PORTABLEFS_ARTIFACT_PATH=<ABSOLUTE_PATH_TO_EXTRACTED_V7_PORTABLEFS>` |
| `deploy/self-host/config.env.example:72` | `OPENSTEER_PORTABLEFS_SHA256=replace-with-64-lowercase-hex-characters` | Set `OPENSTEER_PORTABLEFS_SHA256=<UNISSUED_V7_HOSTED_BIN_PORTABLEFS_SHA256>` without a `sha256:` prefix |
| `deploy/self-host/config.env.example:55` | `OPENSTEER_PORTABLEFS_SOURCE_DIR=/absolute/path/to/steerlabs/portablefs` | Point the deployed value at a clean checkout of `<V7_SOURCE_COMMIT>` so the Files image is built from the same release commit |

`deploy/self-host/compose.runner-portablefs-linux.yaml:29-30,54-59` binds and
checks the mount binary. `deploy/self-host/compose.portablefs.yaml:27-31` builds
`portablefs-files` from `OPENSTEER_PORTABLEFS_SOURCE_DIR`. Recreate the Runner
and Files services together after changing all three values. Editing either
Compose file would weaken the existing pin mechanism and is not part of the
release update.

The local development stack also has no version literal to edit. It records the
exact clean PortableFS source commit in `.opensteer/portablefs/local/deployment.json`
(`scripts/portablefs-local.ts:197-236`), derives its Manager and cell image tag
from that commit plus the local deployment files (`:307-316`), and builds the
client release under a commit-keyed directory (`:328-365`). Point
`OPENSTEER_PORTABLEFS_SOURCE_DIR` at the clean v7 commit and run the existing
local setup. Do not hand-edit the generated deployment JSON or image tag.
`deploy/portablefs-local/compose.yaml:5,32,59` consumes the generated
`PORTABLEFS_LOCAL_IMAGE_TAG`; `deploy/portablefs-local/Containerfile:13-19`
embeds the same generated release identity in the Manager and cell binaries.
Those are consumers of the source-commit pin, not additional release values to
edit.

## Desktop release inputs

Desktop packaging is another external pin surface, although it is outside the
requested production Linux path. No current value is checked in. For a Desktop
build that carries PortableFS, set these build inputs together:

- `OPENSTEER_PORTABLEFS_RELEASE_VERSION=0.4.1`;
- `OPENSTEER_PORTABLEFS_INSTALLER_SOURCE=<PATH_TO_V7_INSTALL_SH>` from the same
  PortableFS source commit;
- `OPENSTEER_PORTABLEFS_INSTALLER_SHA256=<UNISSUED_V7_INSTALL_SH_SHA256>`.

`apps/desktop/scripts/prepare-release-resources.ts:240-273` validates the stable
version and installer digest and writes them into the signed resource set.
Runtime environment variables cannot override that identity in a packaged app
(`apps/desktop/src/config.ts:162-176`). No OpenSteer workflow in this commit
supplies these build values, so the owner of the Desktop release job must update
them where that job is configured. The packaged release writes the exact
version and installer digest at
`apps/desktop/scripts/prepare-release-resources.ts:187-196`, and the Mac setup
passes that version to the installer as `PORTABLEFS_VERSION` at
`apps/desktop/src/releases/portablefs-setup.ts:398-416`. Every Mac client for a
volume must install the resulting v7 Desktop/PortableFS release during the same
maintenance cutover; changing the Linux template does not update Macs.

## Sources that do not carry a release pin

`packages/workspace-portablefs` contains no PortableFS image, binary digest,
release version, or authority wire-major pin. Its `v1` literals are other frozen
contracts: the Manager HTTP API prefix and product-authorization format at
`src/control-plane.ts:55-59`, and the mount capability envelope at
`src/schemas.ts:22-26`. They must not be renamed to `v7`.

The Runner's required feature
`hosted-automatic-mount-reauthorization-v2` at
`apps/runner/src/workspace/workspace-mount-registry.ts:40,147-162` is the hosted
enrollment contract, not the Authority protocol major. It already gates Runner
readiness and also must not be changed to `v7`.

## Kernel pin and proof

Protocol 7 requires a Runner kernel at least Linux 5.10 and a negotiated FUSE
protocol of 7.31 or newer. The audited OpenSteer template has only a
`fuseResourceName`; it has no node image, kernel version, node-pool selector, or
runtime-class field. The absence is stated directly in
`docs/portablefs-coherence-v2/design.md:214` and
`docs/portablefs-coherence-v2/opensteer-integration.md:113-116`. The only kernel
floor elsewhere in this repository is the unrelated seccomp compatibility
floor of 4.8 (`deploy/container/compile-seccomp-profile.mjs:78-93`).

The same configuration commit that moves the three artifact pins must therefore
pin the managed Runner node pool to a concrete image/kernel satisfying Linux
5.10+ and record that exact kernel as qualification evidence. This change
cannot be named as an OpenSteer file edit because node-pool configuration is not
in `opensteer-cv2`. Before promotion, run
`portablefs mount-check --strategy fuse --probe-mount --json` on that node and
require `kernelProbe.protocolMajor == 7` and
`kernelProbe.protocolMinor >= 31`, matching the production E2B smoke check in
PortableFS `deploy/opensteer/e2b-release.mjs:83-117`.

There is also no shipped OpenSteer or PortableFS runtime metric that reports
active write delegations. The apparent `active_delegations` name occurs only as
a Go benchmark result in PortableFS
`vcs/internal/volumeserver/coherence_benchmark_test.go:227`; it is not exported
by `/metrics`. The production metric inventory in
`vcs/internal/authoritymetrics/metrics.go:196-241` has active sessions, FSKit
write staging, fsync, visibility barriers, and fences, but no delegation gauge
or grant counter. A rollout document must not cite `active_delegations` as a
runtime metric. The requested active-delegation metric check requires instrumentation
to ship first and blocks promotion until then. Real two-mount qualification
provides functional evidence but does not supply the missing operational
metric.

## One-change-set procedure after publication

1. Record `<V7_SOURCE_COMMIT>`, `0.4.1`, the immutable
   `portablefs-files` digest, the aggregate `portablefs-release` digest, the
   capsule's `hosted/bin/portablefs` SHA-256, and the materializer image digest
   from release evidence.
2. In the repository that owns the production cloud template and node pool,
   make one commit changing exactly `filesImage`, `portableFsMountImage`,
   `portableFsMountSha256`, and the concrete Runner node image/kernel pin.
3. Preserve the Manager URL, CIDRs, CA, client identity, product signing key,
   product issuer, and service ID unless a separately planned rotation requires
   them. Validate every image as `@sha256:<64 lowercase hex>` and the binary as
   `sha256:<64 lowercase hex>`.
4. Attach the release evidence to the commit. Prove that the Files image and
   mount binary came from the same `<V7_SOURCE_COMMIT>` and that the materializer
   contains exactly the recorded binary digest.
5. Merge that commit only inside the protocol-7 maintenance window. Restart the
   control plane so it rereads `OPENSTEER_CLOUD_TEMPLATE_PATH`, reconcile every
   managed deployment, and verify the pinned kernel and FUSE 7.31+ probe before
   admitting work.

The PortableFS production workflow is a separate path: it rebuilds the hosted
bundle and E2B client from the exact promoted PortableFS commit. Staging instead
consumes the published aggregate `portablefs-release` capsule through
`opensteer-infra`. Neither path supplies the external OpenSteer Managed Cloud
template automatically.
