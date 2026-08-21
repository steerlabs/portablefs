# Protocol-5 hosted qualification — 2026-08-16

Status: **historical qualification receipt for the retired protocol-5 stack;
not evidence for protocol 6**.

This receipt records the final clean-source validation of the protocol-5
hosted migration. It distinguishes demonstrated behavior from platform or
product boundaries; a compile, mocked mount, or fallback path is not counted as
a live result.

## Exact source and artifacts

- Source commit and deployed code revision:
  `759873f63b520658cfe7f22ec8c7dc001f789e8d`.
- Branch: `codex/protocol5-hosted-gcp`; pushed to `origin`, not merged.
- Hosted release ID: `pfs-hosted-20260816-759873f63b52`.
- Linux arm64 release archive SHA-256:
  `37978cadf2e8607ea97f9f8f7aae1c413dfdd25660b6257b35106c3e9d736e96`.
- Linux client SHA-256:
  `a98e497ff12e05ea6002cfd583bb92e8f92a4de8b0d6266bd3a7d1fbe8d01f2c`.
- Linux mount helper SHA-256:
  `b5c5ffb6486663d966c8548b6b0a610aefdc396a94a0c1dc354f8642f94f89c7`.
- Universal macOS development archive SHA-256:
  `bf733052138077cbd578616ab60c630637bd74cc606d85eedbbbdec6288add1a`.

Both embedded macOS Go executables report version `0.2.6`, revision
`759873f63b520658cfe7f22ec8c7dc001f789e8d`, and `vcs.modified=false`.
The app, extension, CLI, and daemon all contain arm64 and x86_64 slices.

## Hosted control plane and storage

The isolated arm64 VZ reference cell ran the exact
`6.12.100-pfs-strict` kernel, patch SHA-256 values
`096d01915824d909316498fdc9de9252730ac4292294fd421a7fa4b24fffa417`,
`2534c6889f73d02bd2166791298da6e1a8a7689e92166bbf6fd74945c19cc786`,
and `eb7cddd8726ecc40a0e8fa210aab9694f8e65dbda63f341dd9b2fe94d60bba9f`.

The final hosted volume was `READY` at authority generation 7 with a recorded
prior-strict-mount fence. Manager, UUID-scoped cell agent, privileged helper,
authority service, and authority socket were all active. The running authority
resolved through `/opt/portablefs/current` to the exact hosted release above.
The volume used a dedicated XFS filesystem mounted with project quotas,
`nodev,nosuid,noexec,noatime`; project 51001 had a 4 GiB block limit and
250,000-inode limit. No strict FUSE mounts were left behind after validation.

The running kernel ended with taint 0, initialized lockdep, and no KASAN,
BUG/WARNING, circular-lock, deadlock, XFS corruption/shutdown, use-after-free,
or out-of-bounds report.

## Linux results

- `scripts/verify-local.sh`: passed build, vet, vulnerability scan, Go normal
  and race suites, maintained go-fuse normal and race seams, release trust and
  stale-architecture scans, Python Swift seams, and all 342 unique Xcode-native
  tests.
- Privileged XFS/FUSE gate: all 49 required service-identity tests and both
  required root-boundary wrappers passed. Root oracles proved delayed-INIT,
  overlay lower/upper, and loop-backing refusal.
- Cross-mount matrix: 22 pass, 0 fail, one declared skip. The skip is remote
  `chown`, which is outside the single-principal volume model.
- Package-manager matrix: npm and yarn both passed on one shared tree while a
  second strict mount continuously enumerated and read it. pnpm and bun were
  declared unavailable and were not downloaded or silently substituted.
- The final live syscall probe passed create/read/positioned write/append,
  `fsync`, chmod, rename, hardlink, symlink, `MAP_PRIVATE`, copy-file-range,
  truncate, and unlink. The exact setxattr refusal described below was also
  asserted.
- A two-mount concurrent append test produced 8,000/8,000 unique records with
  identical final hashes and no torn or lost record.
- Session reauthorization advanced the live deadline without detaching or
  replacing the session.

Evidence log SHA-256 values:

- local verification:
  `a5ded34c5c809d00aac95aafd9d52c263ef64f0c352a0b6f5d1ea4a16a9f3eb8`;
- privileged integration:
  `70e9cf12406d98c628b08f691f3842ac8d473da7611711704809dea29eb08f49`;
- package-manager matrix:
  `a13a4ac2e53cc834b6a6bb2978120be855fb6ca08128dd429a08af0611e215bd`;
- coherence matrix:
  `8a6e7cab9c2d2399e48c5e2668e161dfd89424e14e27b866fb7b9e2fb5137691`.

## Performance evidence

The maintained go-fuse fix classifies in-memory read results before acquiring
or growing a splice pipe. Descriptor-backed results retain zero-copy. Against
the immediately preceding exact build in an otherwise identical live A/B, the
64 MiB read median improved from 262.919 to 333.041 MiB/s (26.7%) and splice
warnings fell from 1,024 to zero. A separate final run on the loaded diagnostic
VM measured a 200.8 MiB/s median. These are diagnostic observations, not a
service SLO.

The five-run protocol-5 workload in `docs/performance.md` remains the stable
cross-operation baseline: one-mount acknowledged 64 MiB writes were 158.5
MiB/s and reads were 105.9 MiB/s. Historical Archil figures are directional
only because no current Archil endpoint was in scope; an apples-to-apples
competitive claim is therefore not made.

## macOS result and hard boundary

On macOS 26.5 with Xcode 26.6, all 342 FSKit/AppCore tests passed and the exact
commit produced a validated universal app archive. The client pipeline's
previous ten-run 20 MiB write-plus-read median remained about 0.047 seconds
(about 851 MiB/s of verified pipeline traffic); that is not an end-to-end
mounted-filesystem result.

A cache-correct production FSKit mount was not and cannot honestly be admitted
on the current public SDK. macOS 26 lacks namespace, inode-attribute, and data
cache invalidation primitives required by protocol 5. SDK 27 adds a data-cache
operation but still lacks the namespace and inode-attribute invalidation needed
for exact peer repair. PortableFS therefore rejects current macOS production
mounts before Attach. It does not poll, disable caching, weaken coherence, or
pretend a development adapter is production support.

The production path was also exercised against the live generation-7 hosted
volume, not only in unit tests. A fresh manager-issued, single-use authorization
was passed to the exact universal macOS CLI. On macOS 26.5 it returned the
unsupported-FSKit error before authority Attach, created no kernel mount or
mount record, and left the authorization unconsumed. The same authorization
then mounted successfully through the exact Linux FUSE client.

That proof was repeated while the Linux mount completed 300 fsync-and-rename
cycles. The simultaneous macOS attempt refused in 0.00 seconds without
disturbing the writer; its still-unused authorization then admitted a second
strict FUSE peer. The two Linux peers subsequently produced 1,000/1,000 unique
atomic append records with identical hashes and immediate bidirectional name
and byte visibility. Both mounts detached cleanly, both temporary enrollments
were revoked, and the hosted kernel ended with zero strict mounts, taint 0, and
zero kernel failure-scan matches.

The two macOS admission-attempt logs are retained in local qualification
evidence with SHA-256 values
`297d567136fc17c21134a8ba99c1254eaac180b983be3c4ef04d3af5a9aae30a`
and `ee58b7fff0215c394c7257ad06d261ff21de23d31f6487cd3ccc6bda835c87c2`.

## Post-qualification macOS 26 best-effort addendum

After the exact Linux qualification above, product policy changed to admit the
existing SDK-26 synchronous-repair implementation as a named best-effort tier.
This addendum does not alter the historical Linux receipt or claim that macOS
26 meets the exact Linux cache contract.

The updated signed development app mounted the same hosted protocol-5 volume on
macOS 26.5 while the exact Linux 6.12.100 client remained attached. The mounted
matrix passed create, read, write, positioned write, `fsync`, rename, links,
truncate shrink/extend, negative lookup, multi-megabyte SHA verification,
immediate Mac-to-Linux visibility, and Linux-to-Mac visibility for a newly
created file. Writable xattrs returned Darwin `EOPNOTSUPP` as declared.

With the authority, Linux client, and signed Mac app rebuilt from the same
writer-lease source, five 64 MiB Mac durable-write runs measured a 128.2 MiB/s
median; five earlier
`F_NOCACHE` reads measured 71.1 MiB/s with exact digest verification. The Linux
peer's pre-lease diagnostic measured 100.8 MiB/s median durable writes with the
Mac attached. Under the frozen lease, Linux writes returned `EBUSY` in 0.3–1.4
ms without touching XFS. After clean Mac unmount, Linux took ownership and
measured 120.9 MiB/s writes and 135.3 MiB/s reads; a fresh Mac remount saw the
exact Linux file and SHA-256. Direct XFS in the same guest measured 3033.7
MiB/s. These are local hosted-reference measurements, not service SLOs.

A Linux truncate of a file already cached by the Mac exposed the SDK-26 limit:
FSKit rejected the synthetic repair callback, so PortableFS fenced the Mac
instead of accepting unproven state. The post-qualification architecture now
gives an active macOS 26 mount the compatibility writer lease. Linux peers may
read but receive `EBUSY` for visible mutation until the Mac cleanly unmounts;
the mutation is refused before XFS apply. macOS 26 also exposes neither cross-
machine lock callbacks nor authority append intent. Exact concurrent shared
mutation, distributed locks, and atomic cross-client append remain Linux-only.

The matched stack also ran 100 Mac atomic fsync+rename replacements while the
Linux peer made 3,000 enumerate-and-read observations. Linux completed 2,996
and returned four transient `ESTALE` results (99.87% success), with zero torn
or mismatched generations. Both mounts remained healthy and 1,000 subsequent
observations passed. This is an explicit macOS-26 best-effort boundary: the
client reports the stale observation and does not silently retry or fall back.
Normal create/read/write/pwrite/fsync/chmod/rename/truncate/link/symlink/unlink
and negative-lookup tests all passed with exact cross-mount state.

The source and documentation changes for this addendum are committed separately
from the historical `759873f63b52` qualification receipt. The original receipt
continues to identify the exact Linux source and binaries it qualified.

## Explicit product boundaries

- Writable xattrs remain `EOPNOTSUPP`: XFS attribute-fork blocks are not
  charged to the volume project quota, so accepting writes would violate the
  aggregate storage boundary. Read/list/remove remain in the defined profile.
- Cross-principal ownership changes are outside the single-principal volume
  model.
- This qualification ran the complete hosted product locally in the isolated
  reference cell. It did not deploy or mutate a GCP production/staging project.
- Any change to the source revision, private kernel ABI, patch bytes, storage
  mutation contract, or publication lifecycle requires requalification.
