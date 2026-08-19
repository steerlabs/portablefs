# Cross-mount coherence matrix

PortableFS's central Linux claim is one authoritative volume mounted through
several stock-kernel FUSE clients with write-through, lease-coherent semantics.
This is the black-box instrument that verifies it. macOS invocations are
qualification runs and do not establish production FSKit support.

```bash
scripts/coherence-matrix-linux.sh                      # Linux, two kernel FUSE mounts
scripts/coherence-matrix-macos.sh --mount-a A --mount-b B   # macOS, two mounts on one Mac
scripts/coherence-matrix-macos.sh --mount-a A \
  --remote user@second-mac --remote-mount B            # macOS/macOS
scripts/coherence-matrix-macos.sh --mount-a A \
  --remote user@linux-peer --remote-mount B \
  --remote-binary /path/to/linux/pfs-coherence-matrix  # mixed macOS/Linux
```

Both scripts run the same named cases through the same driver
(`vcs/test/coherence/cmd/pfs-coherence-matrix`), so a Linux result and a macOS
result are directly comparable line for line. A case that is green on one
platform and red on the other is a frontend defect on the red one, not a
difference in what was measured.

## What it is

The driver is black box. It talks to two mountpoints through ordinary syscalls
and nothing else: no access to the frontend's internals, no injected kernel, no
in-process fixture. It cannot pass because a fake agreed with itself.

The mounts are ordinary OS processes started by the script, which is what makes
the last case possible at all. A mount that lives inside a test binary cannot be
killed uncleanly, so "a dead participant must not break the survivor" can only
be asserted when the mounts are separate processes.

The Linux script provisions a real XFS cell with project quotas through the
production provisioner, mints credentials with the production capability signer
(`volumecap.Sign`), and starts the real `portablefs-authority` and two real
`portablefs-mount-v3` processes. Nothing about the stack is simulated.

## Assertions are on the real quantity

* Content is compared against the bytes a descriptor actually returns when read
  to EOF. Never against `stat.Size`; the two have been observed to disagree, and
  when they do, the readable bytes are what a program gets.
* The namespace is compared against the entries `readdir` actually enumerates.
* An atomic replacement is compared against the inode number the *other* mount
  resolves, not against content alone, because a stale binding can serve the
  right bytes from the wrong inode.
* Nothing polls or retries. The correct answer is the first answer. Names,
  attributes, clean data, and directory enumerations may be cached only under
  authority leases; a conflicting mutation completes peer discharge before its
  result is published. A case that needed a settling delay
  would be reporting a defect, not a timing artefact.

## Falsifiability

A green matrix is only worth something if a red one is reachable, so a run
proves that before it reports anything. The Linux script runs three phases:

1. **Disjoint-namespace control.** The second root is an ordinary directory that
   is not the volume. Every case must fail. A case that can pass without the two
   roots sharing a filesystem is not measuring coherence.
2. **First-success stale-view control.** One mount replays the first successful
   `stat`, `lstat`, `readdir`, `readfile`, or `readlink` answer for each path --
   exactly the defect class the hand-run macOS matrix found: mode bits that
   never change, an atomic replacement that keeps resolving the old inode, or
   an EOF that never moves. Every case declared pathname-stale-sensitive must
   fail. Stateful descriptor behavior and the attach-time route contract are
   intentionally outside this fault model and keep their direct assertions.
3. **The real matrix.**

If a control does not produce a case's declared result, the job fails. A case
that has stopped detecting its relevant injected breakage must not be trusted
until it is fixed.

Both controls are also runnable by hand anywhere:

```bash
pfs-coherence-matrix --a DIR --b OTHER_DIR       # disjoint: everything must fail
pfs-coherence-matrix --a DIR --b DIR --self-check-stale
pfs-coherence-matrix --a DIR --b DIR             # one coherent directory: everything must pass
```

## Expectations, skips and exit status

Exit status is zero only when every case reached its **declared** status.

* A failure is a failure. There is no aggregate "pass except platform".
* A platform limitation that is genuinely expected must be declared by name with
  a stated reason: `--expect <case>=FAIL:<reason>`.
* A declared expectation that stops failing is reported as an unexpected pass
  and fails the run, so the list cannot rot into a blanket excuse.
* A case that cannot be honestly asserted skips with a stated reason and a
  nonzero exit unless the skip was declared. A quiet pass is never an option.

## The cases

| case | what it asserts |
| --- | --- |
| `remote_create_visible` | a file created on one mount is visible and readable on the other with no polling |
| `remote_unlink_name_gone` | a name unlinked on one mount stops resolving on the other, including reopen |
| `remote_unlink_open_fd_posix` | an fd open across a remote unlink keeps reading and writing the unlinked inode |
| `atomic_replace_new_inode` | create-temp/write/rename-over is observed on the other mount as the new inode with the new bytes |
| `rename_old_gone_new_present_same_inode` | after a remote rename the old name is gone, the new name resolves, and the inode is unchanged |
| `remote_chmod_visible` | mode bits changed on one mount are observed on the other, not served from a stale attribute cache |
| `remote_chown_visible` | an ownership change made on one mount is observed on the other |
| `remote_utimes_visible` | timestamps set on one mount are observed exactly on the other |
| `remote_truncate_grow_readable_eof` | a remote grow is observed as readable bytes to the new EOF, not only as a larger stat size |
| `remote_truncate_shrink_readable_eof` | a remote shrink is observed as a shorter readable EOF, not a stale tail |
| `dir_listing_reflects_remote_creates_and_deletes` | an enumeration on one mount reflects creates and deletes performed on the other |
| `concurrent_writers_distinct_files` | both mounts writing distinct files concurrently lose nothing and both see the full result |
| `concurrent_same_file_append_atomicity` | negative `O_APPEND` gate; a separate syscall-level gate must track the unobservable `RWF_APPEND` blocker |
| `concurrent_same_file_overwrite_integrity` | concurrent whole-record overwrites of one file leave one writer's record, never a mixture |
| `hardlink_visible_same_inode` | a hard link made on one mount is observed on the other as the same inode with the right link count |
| `symlink_visible_and_resolves` | a symlink created and atomically replaced on one mount is observed on the other with its exact current target and bytes |
| `deep_nesting` | a deep tree created and rewritten on one mount is fully traversable and mutable from the other |
| `open_after_unlink_cross_mount_contents` | a descriptor held across a remote unlink *and* a remote replacement keeps reading the original bytes, while the same mount's path resolves the replacement |
| `rename_over_open_fd` | a remote rename-over leaves the open descriptor on the displaced inode's bytes and the name on the replacement's inode and bytes |
| `same_dir_concurrent_mutations` | both mounts running create/rename/unlink storms in the *same* directory finish in bounded time, wedge no mount, and leave both mounts enumerating the identical surviving set |
| `local_route_isolation` | a route-configured directory is machine-local: each mount resolves its own root inode, files created under it never cross mounts, one name holds different bytes on each machine, and shared siblings stay coherent across a peer's change |
| `routes_revision_mismatch` | an attach carrying a stale routing revision is refused with both revisions and the volume's canonical rules, and adopting them lets the same capability attach on exactly the second attempt |
| `peer_loss_does_not_break_surviving_mount` | one mount dying uncleanly must not stop the other mount from serving |

### `same_dir_concurrent_mutations` permits no fencing

Two mounts mutating one directory is the directory-inode-lock contention case.
The frontend reports a blocked repair only when its exact cached-binding and
parked-directory registries prove the cycle, while racing reads leave Stabilize
at apply rather than holding the directory lock until COMPLETE. The case still
records how many participants were fenced (observed as `ENOTCONN` from the
revoked mount), but the allowed count is zero: fencing either healthy mount is a
regression.

The case also fails if a storm does not complete within its stated bound, if
either mount stops serving, or if the mounts disagree about the exact surviving
names or bytes.

### The two route cases are enabled by an admin ApplyRoutes call

`scripts/coherence-matrix-linux.sh` installs a real declaration
(`PORTABLEFS_ROUTE_RULES`, default `node_modules/`) between provisioning and
mounting, through `pfs-coherence-routes --apply-file`. That is the only way it
can arrive: the authority owns `.portablefs/local-dirs` and refuses mount
mutation of it, so the declaration comes through the admin `ApplyRoutes` call
under a capability minted with the `admin` claim. That capability is minted
separately and never given to a mount — `admin` implies write, but write
deliberately does not imply `admin`, because changing this file changes what
every other machine can see.

Both mounts then attach with no route flags at all and adopt the volume's
declaration through the refusal, and each is given its own `--local-backing`
directory. So every run also exercises the production attach path rather than a
shape configured only for the harness.

`local_route_isolation` keeps its own **support probe**: if the route root
resolves to the same inode on both mounts it is being served from the shared
volume, and the case skips loudly rather than failing for a reason that has
nothing to do with routing.

The separate privileged FUSE suite owns the exact zero-RPC assertion. Its
server-side handler classifies every request that crosses the wire and excludes
only clock-driven keepalive, visibility and reclaim traffic;
`TestGraftedSubtreeReachesTheAuthorityZeroTimes` and the real-workload graft
tests require a zero delta. The cross-process matrix does not infer that claim
from whole-process `/proc` I/O, because unrelated keepalives can move that proxy
during an otherwise entirely local routed window.

### How a mount learns the routing it must declare

A mount has to put the volume's routing revision **on** its attach request, so a
mount that has never seen the volume appears to need a session in order to learn
what it must say to get one. It does not read the declaration first: a volume
capability is single use, and a pre-session read that succeeded would spend it
and leave the real attach with nothing to present.

The authority breaks the circle on the refusal instead. The routing check runs
*before* the capability is verified, so a refusal for a revision mismatch costs
no capability, and the refusal carries the volume's active canonical rules. So
the flow is one attach and at most one more:

1. attach with the empty rule set — which is also exactly what a volume with no
   declaration runs, so the common case is a single attach with no retry;
2. on a routing refusal, adopt the rules the refusal carried, check that they
   hash to the revision the authority calls active, and attach again **on the
   same capability**;
3. a second refusal is a real disagreement and is surfaced verbatim.

`routes_revision_mismatch` asserts exactly that contract, including the attempt
count, using a client that does *not* adopt — because the mount binary adopts by
itself, and a refusal nobody declines to adopt is a refusal nobody has observed.

### The authority has no production per-RPC counter (unmet observability gate)

Nothing in the production authority exports a request count. The
package-manager instrument therefore records clearly labelled whole-process
`/proc` byte and scheduling proxies, but never uses them for pass/fail. Exact
graft RPC assertions stay in the privileged server-side counting harness until
the authority exports a request-class counter that is independent of keepalive
and visibility traffic.

`remote_chown_visible` skips on PortableFS v3. The volume model is deliberately
single-principal, so the volume itself refuses a chown to another principal with
`EPERM` and there is no ownership change to observe. If multiple POSIX
principals are ever supported, the case becomes assertable and must be enabled.

## macOS

`scripts/coherence-matrix-macos.sh` does not mount anything itself. It accepts
paths created by an explicitly stamped qualification build and stays out of the
daemon lifecycle. A green run characterizes that adapter and OS only; it does
not promote FSKit past the protocol-6 primitive gate.

It refuses to run against ordinary directories. A directory on the boot volume
is perfectly coherent with itself, so a run like that would print a wall of
green that means nothing.

Everything it cannot honestly assert is skipped with a loud message and a
nonzero exit. The remote peer may be macOS or Linux; its driver must be built
for that host, and its mount type is validated with the remote OS's native
mount inventory. If the peer is unavailable, no case ran, so nothing was
demonstrated, and the output says exactly that.

## Configuration

Linux (`scripts/coherence-matrix-linux.sh`):

| variable | default | meaning |
| --- | --- | --- |
| `PORTABLEFS_ATOMIC_REPLACE_ROUNDS` | `20` | rounds of the atomic replacement case |
| `PORTABLEFS_ALT_GID` | `200002` | supplementary GID for the ownership case |
| `PORTABLEFS_CACHED_NAME_CAPACITY` | `65536` | transitional admission bound used by both harness sides |
| `PORTABLEFS_REPAIR_BUDGET` | `15s` | transitional recall/repair wall bound used by both harness sides |
| `PORTABLEFS_ROUTE_RULES` | `node_modules/` | the declaration installed through admin `ApplyRoutes` before either mount attaches |
| `PORTABLEFS_LOCAL_ROUTE` | `node_modules` | the directory name `local_route_isolation` drives; must be matched by the rules above |
| `PORTABLEFS_CASE_TIMEOUT` | `8m` | driver per-case wall bound; larger than `same_dir_concurrent_mutations`' own 3m storm bound so the case reports a deadlock rather than the outer guillotine |

macOS (`scripts/coherence-matrix-macos.sh`): `PFS_MATRIX_BIN`,
`PFS_EXPECT_FSTYPE`, `PFS_ALT_GID`, `PFS_FENCE_COMMAND`, `PFS_MATRIX_JSON`.

## Package-manager reality check

`scripts/package-manager-matrix.sh` is a different instrument in the same
container. The matrix above proves POSIX semantics one operation at a time; this
one asks whether a real dependency installer survives the worst configuration a
user can hand PortableFS.

It runs `npm ci`, `pnpm install`, `yarn install` and `bun install` on a **shared**
volume path with **no machine-local route** over `node_modules` — deliberately
the shape the product asks users to avoid — while the second mount enumerates and
reads the same tree throughout.

It asserts exactly three things and thresholds nothing:

1. the installer exited zero;
2. the tree is visible from the *other* mount with the same entry count and the
   same bytes;
3. both mounts still serve afterwards.

Wall time and the authority's work counters are **recorded into a table**, not
gated. A timing threshold in CI turns a shared runner's bad afternoon into a red
build, and a number nobody can act on gets raised until it never fires again.

The fixture is hermetic: six tiny packages the script generates and `npm pack`s
itself, installed from local tarballs, with no registry contacted and nothing
compiled. A registry outage can never be mistaken for a filesystem defect.

A package manager whose binary is not in the image **skips loudly and is named in
the table**. The script never downloads a package manager to improve its own
coverage; `pnpm` and `bun` are not packaged by Debian, so on the stock CI image
those two rows are skips until the image ships them or `PORTABLEFS_PNPM_BIN` /
`PORTABLEFS_BUN_BIN` point at them. `npm` is the one exception that fails the
whole script rather than skipping, because it packs the fixture every other
manager consumes.
