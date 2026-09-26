# Protocol 7 fleet rollout

Release candidate: **0.4.1**, product generation v3, authority major **7**,
ALPN `portablefs-authority-v7`. Major 6 cannot attach. Upgrade every Authority,
every Linux mount, the files gateway, and every Mac client on each volume in
one maintenance window. A rolling mixed-major upgrade is not supported.

This is a preparation runbook, not deployment evidence. The G6 entries in
[integration.md](integration.md) record a full local gate, complete Linux soak,
and baseline for the earlier G6 tree. The subsequent `20f12da` ownership and
mount-lifetime changes require qualification on that exact release commit.
Publication, production kernel proofs, and live staging/Mac tests remain release
prerequisites.

## Inputs and stop conditions before scheduling

Use one immutable PortableFS source commit for all components. Tag that exact
commit `v0.4.1` after review and complete CI. `release.yml` publishes
`portablefs_0.4.1_linux_{amd64,arm64}.tar.gz`,
`portablefs-server_0.4.1_linux_{amd64,arm64}.tar.gz`, their offline attestation
bundles and `checksums.txt`, plus
`portablefs_0.4.1_darwin_universal_app.zip` and its checksum. Each Linux client
archive contains exactly `portablefs` and `portablefsd`; the server archive
contains `portablefs-authority`.

The Mac CLI, Go daemon, and Swift extension must come from the same commit.
The native Go suite checks the production Resolve frame against the shared
pfslocal golden; Swift decodes it through the shipping parser. Local protocol
1.15 does not permit mixing a major-6 parser with a major-7 daemon. Publish and
install the complete signed/notarized app, never a replacement daemon alone.

Xcode project defaults remain development settings. Release packaging reads
`VERSION`, passes `MARKETING_VERSION` explicitly to the single universal archive,
and checks the resulting host app, extension, service, CLI, and daemon versions
before publication. The release-trust gate checks this effective packaging
boundary and consistent project defaults; it does not require release work to
rewrite the Swift projects.

The 2026-09-16 REL Xcode settings preflight found that the shipping app pinned
SwiftProtobuf 1.29.0 while `swift/PortableFSKit/Package.swift` required exact
1.38.1. Commit `20f12da` aligned the app and Kit lockfiles at 1.38.1 and made
the app packager require resolved package versions. Passing native Swift tests
and matching lockfiles do not prove that the shipping app archives under locked
resolution. Verify that archive for the exact release commit before publication.

`files-image.yml` on `main` publishes the verified files image followed by the
aggregate capsule under
`us-west1-docker.pkg.dev/opensteer-admin/portablefs-releases`:
`portablefs-files:sha-<full-commit>` and `portablefs-release:sha-<full-commit>`.
Resolve both to immutable digests. The capsule's `release.json` binds the
source commit, hosted release ID, client SHA-256, and files image digest.
Hosted identity remains `pfs-hosted-YYYYMMDD-<12-commit-hex>`; it is not the
SemVer or authority major. Preserve those artifact names and verifiers.

The production promotion workflow rebuilds the hosted bundle from its exact
successful promotion commit and adds that client to a digest-pinned Runner
image. It does not consume the staging capsule pin. Its promotion tree must
match a reviewed `main` tree. If a merge gives production a different commit
identity, record its distinct hosted ID/digests and prove the tree equality;
do not claim that differently stamped binaries have the same digest.

Complete the [OpenSteer pin sheet](opensteer-pins.md) in one reviewed consumer
configuration commit after publication. No real artifact pin is checked into
`opensteer-cv2`: its control plane loads the external JSON file named by
`OPENSTEER_CLOUD_TEMPLATE_PATH`. Commit the pin change in that configuration
owner, not in an invented OpenSteer source file. Build the Runner containing the completion-barrier
integration, then update `OPENSTEER_RUNNER_IMAGE` in PortableFS's
`.github/workflows/deploy-opensteer-production.yml` to that published image's
exact digest. A prior Runner image is not evidence that completion handling
exists. Staging activation belongs exclusively to `opensteer-infra`; do not
point `deploy-production.sh` at `opensteer-staging`.

Pin the runner node/VM kernel and boot image in the infrastructure owner before
rollout. OpenSteer currently pins neither. Require kernel **5.10 or newer**
and negotiated **FUSE 7.31 or newer**; an OCI userspace image digest does not
pin the host kernel. Record `uname -r`, boot image identity, and the FUSE INIT
probe from the actual E2B runner. Run the F10 resident-page/private-mapping
invalidation and root FSYNCDIR delivery proofs on that exact kernel. A newer
version string alone is insufficient. Runner completion must hold a mount-root
directory descriptor from run start through completion, sandbox exit, and
detach, fsync it, and fail/restart affected work on loss or stale handles.

Keep the prior verified capsule/files/client digests, prior hosted bundle, and
prior OpenSteer configuration pin as a prepared revert commit. Verify they remain retrievable
before maintenance. This reduces recovery preparation time; it does not create
a mixed-major or automatic rollback path.

## Ordered production procedure

1. **Qualify and publish.** Require final full CI for the chosen runtime tree,
   the production-kernel proofs, the deployed staging corpus including its
   second-capability remount phase, and live FSKit qualification where Macs
   participate. Publish the tag artifacts and files/capsule images above.
   Verify checksums, attestations, signed app identity, capsule `release.json`,
   and source identities. Abort on a missing artifact or mismatched identity.

2. **Prepare consumers and stop admissions.** Review the OpenSteer configuration pin commit,
   updated Runner digest, all Mac app packages, canonical production cell
   inventory, and files-gateway image digest. Close new run/sandbox creation,
   scheduled jobs, new mount issuance, and files requests through the product's
   maintenance controls. The existing deploy script has no admission lock;
   repeated drains do not replace one. Finish active runs with their root
   barriers, then cleanly unmount every external Linux and Mac client. Stop
   old files-gateway instances and verify zero old sessions/processes. E2B
   drain covers only running/paused sandboxes with
   `opensteer_provider_identity` metadata, so inventory and fence any other
   holder separately. Abort if complete mount absence cannot be established.

3. **Build the production candidate.** Promote the reviewed main tree through
   a PR to `opensteer-production`; its successful `ci` workflow triggers the
   protected, serialized deployment. It builds/verifies the hosted bundle,
   builds the commit-tagged E2B candidate, and runs
   `node deploy/opensteer/e2b-release.mjs smoke TEMPLATE RELEASE_ID`.
   Require the exact hosted client version and a completed FUSE INIT of at
   least 7.31. This smoke has no Authority and proves no authority negotiation.

4. **Preflight every host and restart the Manager.** The workflow calls
   `deploy/opensteer/deploy-production.sh` with the reviewed inventory,
   release directory, candidate tag, evidence directory, SDK root, GCP project,
   and E2B key. The script transfers and verifies the bundle on every host
   before activation. It activates the Manager host first, stopping/starting
   `portablefs-manager.service`, and converges every exact cell declaration.
   A co-located `manager-cell` host also restarts its cell services now.
   Require `manager-cells.json` and the initial release plan to match the entire
   reviewed inventory; unknown cells or conflicts abort the deployment.

5. **Restart cell services.** The script activates each remaining cell host;
   the activator stops agents before helpers, swaps the release symlink and
   systemd units, reloads systemd, then starts helpers before agents. Units are
   `portablefs-cell-helper@<cell>.service` and
   `portablefs-cell-agent@<cell>.service`. For every cell, require
   `cell-authority-state.sh verify-control-release CELL RELEASE_ID` and
   `manager-api.sh wait-cell-release CELL RELEASE_ID 300` to pass. These prove
   process executable provenance and the Manager's healthy observation, not
   merely the symlink. Discover all volumes from the Manager and validate
   placements and capacity; never use a hand-maintained subset.

6. **Drain and fence old Authorities.** For volumes needing restart, the script
   drains all identified OpenSteer E2B sandboxes (`pre-restart.json`), calls
   `manager-api.sh restart VOLUME RELEASE_ID`, drains again
   (`strict-fence.json`), and waits for each old Authority's service, listener,
   and cgroup to disappear. It submits the SHA-256 of that evidence through
   `manager-api.sh strict-fence`. This is a Manager-directed volume restart,
   not an ad hoc `systemctl restart portablefs-authority@...`.
   Never submit sandbox-only evidence while external mounts remain; step 2's
   independent absence proof is mandatory. A drain kills processes; complete
   buffered work before it or explicitly fail the interrupted runs.

7. **Verify new generations and promote the client.** Require each expected
   generation to reach READY with `manager-api.sh wait-ready VOLUME GENERATION
   300`, then `cell-authority-state.sh wait-release VOLUME RELEASE_ID 300`.
   Revalidate the complete volume/cell inventories and capacity report.
   Only then does the script assign E2B `default` to the tested candidate and
   drain again (`post-promotion.json`). Keep admissions closed throughout;
   require empty remaining sandbox IDs in every drain receipt. Retain the
   workflow evidence and its hashes (GitHub retention is 90 days).

8. **Activate the remaining consumers.** Deploy the reviewed OpenSteer configuration pin
   commit and its verified files image through OpenSteer's release owner;
   restart the OpenSteer control plane to reread its template, reconcile managed
   deployments, and require all old gateway replicas gone before admitting
   requests. Check each
   running gateway imageID against the published digest, then verify health and
   an authenticated listing/read on a disposable volume while a Linux writer
   holds a file open. Install the complete same-commit Mac app on every Mac
   before any remount. Upgrade external Linux binaries as well. The production
   script performs none of these external client/gateway updates.

9. **Run fresh attachment and completion checks.** Create disposable sandboxes
   explicitly from the promoted candidate, attach every frontend type using
   fresh credentials, and run the commands below. Test Linux peers together;
   test a Mac separately because every attached Mac excludes other writers.
   Require root-barrier completion and remount durability, a cacheless gateway
   peer read, expected Mac writer exclusion, and absence of writeback loss.
   The active-delegation metric gate below must also be available and pass.

10. **Reopen admissions.** Confirm no old client, gateway, Authority generation,
    or template remains eligible to serve. Record the source commit, release
    IDs, all image/client digests, node kernel/image identity, pin commit,
    generation receipts, and test logs. Reopen files traffic and new runs only
    after every check passes. Any failure keeps the maintenance window closed.

## Commands and evidence

On a disposable Linux canary, use the exact verified hosted binary and fresh
Manager-issued credentials. Variables below name reviewed non-secret paths
and endpoint identifiers; keep the capability in `PORTABLEFS_MOUNT_TOKEN`.

```bash
pfs=/opt/opensteer/portablefs/portablefs
"$pfs" version --json
uname -r
"$pfs" mount-check --strategy fuse --probe-mount --json
"$pfs" mount "$VOLUME_ID" "$MOUNT_PATH" \
  --addr "$AUTHORITY_ADDR" --strategy fuse \
  --data-plane-transport tls-private-ca \
  --data-plane-server-name "$AUTHORITY_SERVER_NAME" \
  --data-plane-ca "$AUTHORITY_CA" \
  --client-cert "$CLIENT_CERT" --client-key "$CLIENT_KEY" --json
"$pfs" mounts --json
"$pfs" doctor --json
```

A successful **fresh `portablefs mount ... --json` from the verified protocol-7
artifact**, followed by real I/O, proves it passed exact v7 TLS/Hello/Activate:
that code has no v6 fallback. Match its authorization session to the Authority's
successful `activate` log and its exact-release process. `version` alone proves
only artifact identity. `mounts`/`doctor` do not expose a negotiated-major field
in this snapshot; `mount-check.kernelProbe.protocolMajor` is the independent
kernel FUSE major, **not Authority protocol 7**. For a Mac, use the same direct
credentials with `--strategy fskit` and the paired signed app.

Open the root before work and retain that descriptor until fsync, for example
on the disposable Linux canary:

```bash
python3 - "$MOUNT_PATH" <<'PY'
import os, sys
root = sys.argv[1]
fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
try:
    with open(os.path.join(root, 'release-canary'), 'xb') as output:
        output.write(b'protocol-7-release-canary\n')
    os.fsync(fd)
finally:
    os.close(fd)
PY
```

Run the full `deploy/opensteer/staging-qualification.sh` corpus on a disposable
staging volume with its documented `--mount-token-command` for fresh remount
authorization. A skipped phase 9 is not a pass for durability. Test gateway
reads against that volume's known canary bytes using OpenSteer's authenticated
files interface; a healthy HTTP process alone proves no Authority attachment.

**Delegation and subscription telemetry.** The Authority's `/metrics` endpoint
exports `portablefs_authority_delegations{volume,state}` with the bounded states
`reserved`, `active`, `recalling`, and `retiring`. Retiring records still hold
storage/read pins and continue consuming the grant budget. Capacity reserved
before CREATE has its own `portablefs_authority_delegation_capacity_reservations`
gauge. `portablefs_authority_subscription_horizons` counts retained horizons,
including fenced horizons until their normal expiry sweep; it is not a count of
currently healthy clients.

`portablefs_authority_delegation_recalls_total{volume,outcome}` and
`portablefs_authority_delegation_breaks_total{volume,outcome}` distinguish
`completed` from `lost` acknowledgments. Loss includes budget expiry, horizon
expiry, or session retirement; it does not by itself establish lost file bytes.
Subscription cold replacements and expirations appear separately as
`portablefs_authority_subscription_resets_total` and
`portablefs_authority_subscription_expirations_total`. The bounded stream's
retained size is `portablefs_authority_change_log_entries`.

Protocol-7 control operations, `barrier`, and `wait_visibility` have dedicated
`opcode` labels in the existing RPC request and latency series. None of these
series labels an inode, pathname, session, or grant.

The Linux mount's existing `renewal.*` JSON log records include a `writeback`
snapshot: dirty and retained bytes/entries, pending admissions and closes,
flushing/scheduled identities, tracked state, durability lag, and loss sequence.
Sampling follows enrollment renewal events; it adds no timer or per-I/O logging.
The counters are diagnostic snapshots, not atomic durability receipts. A root
barrier remains the completion proof.

Before promotion, hold an uncontended Linux writer open and require a positive
`portablefs_authority_delegations{state="active"}` for the canary volume. Close
and barrier, wait for release completion, then prove it returns to baseline.
Sample recall/break outcomes during conflicting access and ensure the canary's
barrier latency fits the deployment's budget. Unit and kernel tests establish
the implementation; this exact deployed-artifact scrape remains a rollout gate.

## Abort and recovery

Abort before changing hosts for missing publication/provenance, failed CI or
kernel proofs, an unpinned kernel, missing completion handling, unavailable
delegation telemetry, incomplete holder inventory, or inability to close
admissions. Abort during cutover for any helper failure, unexpected cell or
volume state, failed drain/absence proof, wrong executable/image digest,
missing READY generation, or template identity mismatch. Never override strict
fencing to continue. During canaries, a refused handshake, stale read, failed
root barrier, writeback-drop report, or unexpected coherence/storage error
keeps admissions closed.

There is **no rollback except forward promotion**. Once activation succeeds,
do not repoint one host, restore one old image, or move `default` back to a
protocol-6 client. The activator can restore a symlink during a failed local
transaction; this is not fleet rollback. Keep the previous artifact digest
ready and the previous OpenSteer pin as a revert commit, but use them only as
reviewed recovery inputs to a new coordinated promotion after checking wire
and persisted-state compatibility. Reverting only the pin cannot make v6
clients attach to v7 Authorities, recover lost buffered writes, or prove old
mount absence. If the known-good runtime must be restored, it needs a new
reviewed forward release and the same complete drain/fence procedure; until
then the fleet remains in maintenance.

## REL verification receipt

On 2026-09-16, `bash scripts/verify-local.sh` passed in **default mode**,
including Darwin Foundation/cgo and static Linux builds/vet, the vulnerability
scan, native Go and race suites, the physical-reply seam, and all 345 enumerated
Swift tests. Both requested workflow checks passed:

```bash
node scripts/check-workflow-pins.mjs .github/workflows
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.10 .github/workflows/*.yml
```

The gate also passed release trust, deployment inventory, registry tests, and
architecture scans. An isolated Xcode settings check confirmed effective
`MARKETING_VERSION=0.4.0` and build 400 for the app and extension; it was not
a signed archive. The app lockfile mismatch observed in this dated receipt was
resolved later by `20f12da` and still requires archive verification as above.
The first invocation stopped at the old source-default
version check; the complete repeat passed after the release policy checked the
packager's VERSION override and exact output versions instead. REL made no
product-code or OpenSteer changes and performed no publication or deployment.
This default run did not execute either privileged Linux suite, the optional
package-manager workload, live FSKit mounts, or the deployed staging corpus.
It does not replace the runtime owner's final full gate.
