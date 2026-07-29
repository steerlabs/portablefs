---
name: portablefs
description: "Durable, branchable, mountable workspaces for agents. Use when you need workspace continuity across machines/sessions, to fork a workspace for parallel attempts, to inspect workspace history, or to run commands against a PortableFS volume without mounting."
---

# PortableFS Workspaces

PortableFS gives you a workspace that is a place in the network, not a folder on one
machine. Everything you need is the `portablefs` CLI and this file. Every command
accepts `--json` for machine-readable output; parse that instead of scraping text.

## Concepts

- **Volume**: a workspace — one live filesystem plus its entire committed history.
  Volume ids are client-chosen names (`[A-Za-z0-9_-]{1,220}`), so `myagent` is an id.
- **Branch**: an independent line of history inside a volume; the default is `main`.
  Commands take `--branch <name>`; `portablefs branch <volumeId> <name>` creates one.
- **Snapshot**: a named, immutable checkpoint of a branch at a commit.
- **Fork**: a new volume created from a snapshot; it diverges freely and never
  affects the original.
- **Authority**: the single server that owns the live state of an active branch. All
  mounts of that branch talk to it, so every machine sees the same ordered state —
  no sync, no merge, no conflict copies.
- **Mount**: a real POSIX filesystem view of a branch on this machine. **Exec/grep**:
  run a command or search server-side against an exact snapshot of the branch, no mount.
- Acknowledged writes are durable and checkpointed into history automatically (every
  few seconds). There is no save, commit, or push step for you to run.

## Setup And Login

Credentials live in `~/.config/portablefs/config.json`. Environment variables
override the config file: `PORTABLEFS_API_URL`, `PORTABLEFS_API_TOKEN`,
`PORTABLEFS_MANAGER_URL`, `PORTABLEFS_MANAGER_TOKEN`. Flags (`--api-url`,
`--api-token`, `--manager-url`, `--manager-token`, on every command) override both.

```bash
portablefs login --url https://api.example.com --token $TENANT_TOKEN \
  --manager-url https://manager.example.com --manager-token $MANAGER_TOKEN
portablefs version       # confirms the CLI works
portablefs ls --json     # lists volumes; confirms auth works
```

`--manager-url` defaults to the server URL and `--manager-token` to the API token,
so a combined deployment needs only `--url` and `--token`. `portablefs logout`
clears stored credentials.

## Mount vs Exec: Choose Deliberately

**Mount** when you need full POSIX: builds, `git`, test suites, SQLite, editors,
long-lived agent sessions. A mount is a normal directory; every tool works
unchanged, and hot reads run at local page-cache speed.

Write mode is adaptive and has no mount flag: the authority delegates
uncontended scopes for local-WAL acknowledgments and keeps contended paths
write-through. `fsync`, close, synchronize, and normal unmount remain real
authority-durability barriers. Use `--local-dir` for machine-specific build
trees such as `node_modules`, `.venv`, or `target`.

**Exec/grep** when you need one-shot answers and cannot or should not mount: no
FUSE in this environment, a quick inspection of another workspace, or comparing
forks. `exec` materializes an exact snapshot of the branch server-side, runs your
command near the data, and returns output; `grep` searches the same snapshot. On a
live branch the snapshot is captured at the moment of the call — every acknowledged
write is included — at the cost of a few seconds of setup per call; tight loops
should mount instead.

## Golden Paths

### Adopt an existing directory into a workspace

`adopt` imports a local directory into a new volume without mounting anything —
it hashes files locally, uploads only content the server does not already have,
and commits one manifest. The source directory is never modified.

```bash
portablefs adopt ~/dev/myrepo --name myagent --json
# {"volumeId":"myagent","branch":"main","commitId":"cmt_...","treeHash":"sha256:...",
#  "files":1204,"dirs":211,"symlinks":3,"bytes":48211003,"skipped":0,
#  "uploadedBlobs":980,"dedupedBlobs":224}
```

Everything is included by default — `.git`, untracked files, `.env` — because the
workspace IS the working directory. Skip paths with repeatable `--exclude`
globs or a `.portablefsignore` file; preview with `--dry-run`; add
`--mount <path>` to mount immediately after import. Re-running against an
existing volume name fails with a clear error (choose another `--name`).

### Create and mount a workspace

```bash
portablefs create myagent --json
# {"volumeId":"myagent","tenantId":"local","branch":"main",
#  "headCommitId":"cmt_1a2b...","treeHash":"sha256:..."}

portablefs mount myagent ~/work --json
# {"ok":true,"pid":52114,"strategy":"fuse","mountPath":"/home/user/work",
#  "volumeId":"myagent","branch":"main"}

cd ~/work
# ... work normally: git clone, edit, build, run tests ...
```

Writes are durable when acked and checkpoint automatically. When done on this
machine: `portablefs umount ~/work`. Unmounting loses nothing.

### Inspect state and history

```bash
portablefs status myagent --json
# {"volumeId":"myagent","branch":"main","headCommitId":"cmt_51ab...",
#  "treeHash":"sha256:...","activeLeases":1,"activeDelegations":0}

portablefs history myagent --limit 20 --json
# {"commits":[
#   {"id":"cmt_51ab...","treeHash":"sha256:...","createdAtMs":1751500449000,
#    "mutationCount":42,"byteCount":18734,"parentCommitId":"cmt_40aa..."},
#   ...]}
```

`activeLeases` > 0 means the branch currently has a writer. Every checkpoint the
workspace ever produced is in `history` — use it to see what an agent did and when.

### Snapshot before something risky

```bash
portablefs snapshot myagent --name before-rebase --json
# {"snapshot":{"id":"snp_77cd...","volumeId":"myagent","commitId":"cmt_51ab...",
#              "name":"before-rebase","createdAt":1751500449000}}
portablefs snapshots myagent --json
```

Snapshots are metadata-only (cheap) and immutable. Fork one to recover or compare.

### Fork for N parallel attempts, then compare

Forks are the correct way to run multiple writing agents from one starting point:

```bash
portablefs snapshot myagent --name fanout-base
for i in 1 2 3; do
  portablefs fork myagent --snapshot fanout-base --name "attempt-$i" --json
done
# {"volumeId":"attempt-1","branch":"main","headCommitId":"cmt_...","snapshotId":"snp_..."}

# run one agent per fork — mount each on its own machine/sandbox, or use exec:
portablefs exec attempt-1 -- sh -c 'npm ci && npm test'
portablefs exec attempt-2 -- sh -c 'npm ci && npm test'

# compare outcomes without mounting anything:
portablefs grep attempt-1 "FAIL" --json
portablefs history attempt-2 --json
```

(`fork` without `--snapshot` snapshots the branch head for you.) Pick the winner
and keep working in it; the losers cost only their unique bytes (content is
deduplicated), and their history explains every attempt.

### One-shot commands without a mount

```bash
portablefs exec myagent -- git log --oneline -5
portablefs exec myagent --timeout 120s -- sh -c 'ls -la && cat package.json'
# --json returns {"stdout":"...","stderr":"...","exitCode":0,...}; the CLI's own
# exit code mirrors the remote command's.

portablefs grep myagent "TODO" --dir src --json
# {"matches":[{"file":"src/planner.ts","line":214,"text":"// TODO: retry budget"}],
#  "stoppedReason":"completed","durationMs":2,"headCommitId":"cmt_51ab..."}
# exit code follows grep(1): 0 = matches, 1 = none.
```

`exec` is read-only by default; pass `--write` to commit the command's filesystem
changes back to the branch. Prefer a mount for anything interactive or multi-step.

## Continuity: Resume On A New Machine

The workspace outlives every machine. To continue exactly where work stopped —
yours or another agent's:

```bash
portablefs login --url <api-url> --token $TENANT_TOKEN   # once per machine
portablefs mount myagent ~/work
cd ~/work    # identical state: same files, same git repo, same everything
```

A laptop closing, a sandbox being destroyed, or a session ending does not lose
state: every acknowledged write was already durable. There is no lock to steal
either — all mounts of a branch attach to the same live authority, so the new
machine reads and writes immediately, alongside any mounts that still exist.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `login` fails 401/403 | Wrong or admin-scoped token | Use a tenant token for the API. Check `PORTABLEFS_API_TOKEN` is not overriding a fresh `login` with a stale value. |
| Commands fail: connection refused | Wrong URL or stack not running | Check the URL in `~/.config/portablefs/config.json` and any `PORTABLEFS_API_URL` override; `portablefs ls` to retest. |
| `mount` says "no authority manager configured" | Manager coordinates unset | Re-run `login` with `--manager-url`/`--manager-token`, set the `PORTABLEFS_MANAGER_*` envs, or mount directly with `--addr <host:port> --mount-token <token>`. |
| `mount` on macOS fails with FSKit extension guidance | The PortableFS FSKit extension is not registered on this machine | Install PortableFS.app and enable its File System Extension under System Settings → General → Login Items & Extensions, then retry. macOS mounts always use the FSKit strategy (`"strategy":"fskit"` in the JSON output); Linux mounts use FUSE. |
| `exec --write` refuses on a live branch | Live branches take writes only through their single ordered authority | Write through a mount (`portablefs mount`). Read-only `exec` and `grep` always work — they run against an exact snapshot of the live state. |
| `mount` on Linux: fusermount3 not found | FUSE tools missing | Install the `fuse3` package, or fall back to `portablefs exec`. |
| Mountpoint errors (`Transport endpoint is not connected`, "already mounted") | Stale mount from a dead daemon | `portablefs mounts` lists mounts and marks dead ones `stale`; run `portablefs umount <path>` for the stale entry, then remount. |
| A direct write attach fails with a busy-lease error | The branch's live authority holds the exclusive write lease while mounts are active | Make the change through a mount. `portablefs status --json` shows `activeLeases`. |
| `exec` killed by signal | Remote command exceeded `--timeout` (default 60s) | Raise `--timeout`, split the command, or mount and run locally. |
| `grep` exits 1 with no output | No matches (grep semantics) | Not an error; broaden the pattern or drop `--dir`. |

## Safety Notes

- **One exclusive writer per branch by default.** One live authority holds the
  branch's write lease; competing write attaches (another authority, `exec
  --write` against a mounted branch) are rejected, not merged. Mounts of that
  branch all write through the one authority.
- **Fork for parallel attempts.** N agents attempting the same task means N forks,
  one per agent — never N agents interleaving writes on one branch.
- **Never point two writing agents at the same branch paths** unless the
  deployment has set up delegations (subtree checkout/checkin) partitioning the
  tree between them. Without delegation claims on disjoint subtrees, concurrent
  same-file writes behave like a normal shared filesystem: ordered by the
  authority, last writer wins.
- **History is durable and visible.** Everything written becomes part of
  checkpoint history that `history`/`fork` can reach. Do not write secrets into a
  workspace you would not put in a repository.
- Reads never block on writers: mounting read-heavy tooling alongside one writer
  is always safe.
