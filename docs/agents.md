# Agent Workspaces

> **Frozen v2 document.** The branch and write-back behavior below is not part
> of PortableFS v3. The current ordinary-directory contract is
> [authoritative XFS](./xfs-authority-architecture.md).

How to run coding agents (Claude Code, Codex, custom harnesses) on PortableFS
volumes. This is the long-form companion to
[../skills/portablefs/SKILL.md](../skills/portablefs/SKILL.md) — the skill is the
self-contained file you hand to an agent; this document explains the patterns and
why they work.

The model in one paragraph: a volume is a workspace that lives in the network. One
authority owns its live state, so every mount — laptop, server, sandbox — sees the
same ordered filesystem, coherently. Accepted writes flow into the authority
journal and immutable commits automatically; `fsync` and clean unmount are the
explicit cross-machine durability boundaries. Every commit is forkable. Machines
are disposable after that barrier; the workspace is not.

## Continuity: The Workspace Outlives The Session

An agent run today is usually welded to the machine it started on: laptop sleeps,
SSH drops, sandbox recycles — work gone or stranded. On PortableFS the machine is
just a viewport:

```bash
# day 1, laptop: start the agent in a mounted workspace
portablefs create refactor-auth
portablefs mount refactor-auth ~/work
cd ~/work && git clone git@github.com:acme/api . && claude

# Before handing work to another machine, fsync or cleanly unmount. That
# makes the accepted local tail durable at the authority; history cuts then
# capture it continuously.

# day 1, later, a server: pick up mid-run
portablefs mount refactor-auth /srv/work
cd /srv/work    # same files, same git state, same half-finished edit
```

Two things make this safe rather than merely convenient:

- **Write acceptance and durability are separate.** A contended,
  write-through operation is durable at the authority when it returns. A
  write under a delegation (the adaptive write-back engine —
  [writeback-engine.md](./writeback-engine.md)) is immediately visible on the
  writing mount, then reaches local physical durability on the 5 ms / 4 MiB
  group-sync. A complete power loss inside that small window may lose the
  recent un-fsynced tail, just as on a normal filesystem. `fsync`,
  synchronize, and clean unmount force the local WAL and make the
  accepted tail durable at the authority. Those are the handoff boundaries
  for Git, SQLite, and cross-machine continuation; `close(2)` alone is not.
- **There is no stale handover, because there is no second truth.** Both
  mounts are windows onto the same live authority. A peer that reads a
  subtree another mount holds delegated waits for the holder to drain
  (milliseconds when the holder is alive) and then sees the exact
  accepted bytes — never a stale snapshot. If the holder vanished with a
  locally durable, unshipped tail, peers get a retryable error rather than
  silently old data until exact replay completes (or an operator explicitly
  discards it as data loss). The practical habit: end an agent run with
  `fsync`/unmount (or any barrier) before abandoning the machine, and the
  whole workspace is authority-durable.

For scheduled or resumable agents, make the mount the first step of the job and the
unmount the last; the workspace carries all state between runs, including
`.git`, caches, and SQLite files.

## Fork-Per-Attempt: Parallel Agents Without Interference

When you want N agents trying the same task, do not point N writers at one branch.
Fork the workspace N times — forks are cheap (metadata plus deduplicated content)
and completely independent:

```bash
#!/usr/bin/env bash
set -euo pipefail

base=refactor-auth
attempts=3

portablefs snapshot "$base" --name fanout-base

for i in $(seq 1 "$attempts"); do
  portablefs fork "$base" --snapshot fanout-base --name "attempt-$i"
done

# one runner per fork: mount "attempt-$i" on its own machine or sandbox and start
# the agent there (see Sandbox Integration below), e.g.
#   portablefs mount attempt-1 /srv/attempt-1 && (cd /srv/attempt-1 && codex ...)

# when the agents finish, compare each result through its runner's mount
for i in $(seq 1 "$attempts"); do
  echo "== attempt-$i =="
  (cd "/srv/attempt-$i" && npm test 2>&1 | tail -3)
  portablefs history "attempt-$i" --json
done
```

Pick the winner and keep working in that volume (or diff it against the base and
apply the patch wherever you like). The losing attempts remain browsable history —
`portablefs history attempt-2` shows exactly what that agent did, checkpoint by
checkpoint, which is often as valuable as the winning diff.

This pattern also covers "checkpoint before something scary": snapshot, let the
agent proceed on the live branch, and fork the snapshot only if you need to recover
or compare.

## Compute Near The Volume

Mounting needs the platform transport (the FSKit extension on macOS, FUSE on
Linux — see [fskit-mount.md](./fskit-mount.md)) and a machine you control. Plenty of
agent situations need a minimal container or remote sandbox. Give that runner a
short-lived mount credential and mount inside its isolation boundary. The Volume
API itself never runs tenant commands. Content search remains available without a
mount:

```bash
portablefs mount myagent /workspace
(cd /workspace && git log --oneline -10)
portablefs grep myagent "raise NotImplementedError" --json
```

Under the hood grep is `POST /v1/volumes/:id/grep`. On a live branch it scans
an immutable HistoryCut of the current live state, minted or reused per call.
The old `/exec` route is a permanent `410 VOLUME_EXEC_RETIRED` contract. See
[api.md](./api.md).

Two properties to design around:

- Grep sees an **exact snapshot of the state as of the call** — not a stale
  checkpoint — but capturing it costs a few seconds of setup per call on a live
  branch. For "inspect what the agent did" that is fine; for a tight polling
  loop running commands every few seconds, or "read the byte another process
  wrote 100 ms ago", mount instead.
- Runner commands read and write through the same mounted, ordered authority as
  every interactive workload. Isolate each runner at the OS/container/VM
  boundary and give it only a short-lived volume-scoped credential.

## Multi-Agent Collaboration On One Branch

The default is one exclusive writer per branch, and fork-per-attempt is the right
tool for parallel *attempts*. But genuine collaboration — several agents working
different subtrees of one shared workspace — is supported through shared attaches
plus delegations (checkout/checkin):

- A shared writer claims a file or subtree before committing changes to it
  (`checkout`); conflicting claims are refused (`VOLUME_DELEGATION_BUSY`) rather
  than merged; `checkin` releases the claim.
- Disjoint delegated changes from different writers merge cleanly onto the branch
  head; overlapping changes are rejected with `VOLUME_MERGE_CONFLICT` — readers
  never observe half-applied states.
- Live mounted writers get this coordination from the VCS data plane (`fsio
  checkout`/`checkin`); direct API clients must claim explicitly.

The mechanics — attach modes, `rootPath` scoping, force-revoking stale delegations —
are specified in the checkout section of [api.md](./api.md); read that before
building a multi-writer harness. The rules of thumb: partition the tree so each
agent owns a subtree (`src/service-a` vs `src/service-b`); claim directories, not
individual files, when an agent will touch many; and if you find yourself wanting
two agents in the same files at the same time, you almost always want forks and a
merge step instead.

## Keep Per-Machine Dependencies Local

Dependency trees and build caches are platform-specific: a `node_modules`
installed by a Linux sandbox must never be executed by the macOS laptop that
mounts the same volume, and neither should pay to sync it. Declare those
directories as machine-local dirs (grafts) and each machine keeps its own:

```bash
portablefs mount myagent ~/work --local-dir node_modules --local-dir .venv
```

Better, declare them once in the repository so every machine that mounts gets
the same behavior with no flags:

```bash
cat > ~/work/.portablefs/local-dirs <<'EOF'
# per-machine dirs: served from local disk, never synced
node_modules
.venv
target
EOF
```

Linux FUSE and macOS FSKit mounts both union this declaration with the
explicit/persisted `--local-dir` set. Pass `--no-local-dirs` to clear the
persisted set and ignore the declaration for a particular mount; see
[fskit-mount.md](./fskit-mount.md).

Inside a graft everything behaves like a local filesystem at local-disk speed
(`npm install`, `npm ci`, `cargo build`). The graft shadows any same-named
directory that exists on the volume, `rm -rf` plus recreate works normally, and
a `mv` across the boundary falls back to copy+delete (EXDEV), exactly like a
bind mount. Grafted content survives unmount/remount on the same machine but
never travels: it is not in checkpoints, forks, or other machines' mounts —
which also means each machine must install its own dependencies once. Use
`--exclude 'node_modules/'` at `adopt` time for the same reason: keep the
volume free of per-machine state from the start.

## Sandbox Integration

Any Linux sandbox that can run a static binary can mount a workspace — see
"Quickstart B" in the [README](../README.md). The sequence is: mint an access
lease (endpoint + scoped token) from the authority manager, copy the static
`portablefs` CLI into the sandbox, mount, run the agent. Sandboxes never hold
long-lived credentials: access tokens are scoped to one authority instance
and expire.

Sandboxes that cannot mount at all need a different isolated runner with a
supported mount boundary; PortableFS deliberately does not fall back to running
tenant commands inside its storage/control plane.
