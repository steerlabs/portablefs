# PortableFS

Your agent's workspace is a place in the network, not a folder on one machine.

PortableFS is a live, durable, branchable network filesystem for AI agent workspaces.
Mount the same volume from a laptop, a server, and a sandbox at the same time: one
ordered authority serves every mount, pushes cache invalidations, and gives real
read-after-write coherence — `git` and SQLite work. Every acknowledged write is
committed to a fenced PostgreSQL journal before ack and flows into immutable,
forkable history on object storage. Close your laptop; the agent working on a server keeps going. Fork a workspace
to fan out parallel agent attempts; time-travel through everything an agent did. It is
open source, self-hostable, and built for teams running coding agents (Claude Code,
Codex) that need continuity, forking, and history for agent workspaces.

## The Demo

Thirty seconds, two machines, one workspace:

```bash
# laptop
portablefs mount myagent ~/work
cd ~/work && claude    # agent edits files, runs git, builds

# server (same volume, same instant)
portablefs mount myagent /srv/work
tail -f /srv/work/agent.log   # sees the laptop's writes live — one authority, no sync delay
# (every mount — FSKit on macOS, FUSE on Linux — gets push invalidation)

# close the laptop. The mount disappears; the workspace does not.
# The agent on the server keeps working. Every acked write was already
# durably journaled and flows into immutable history automatically.

# fork the workspace to try three approaches in parallel
portablefs fork myagent --name attempt-1
portablefs fork myagent --name attempt-2
portablefs fork myagent --name attempt-3

# and time-travel through everything the agent did
portablefs history myagent
```

This is the difference from everything that looks similar:

- Unlike sync tools (Dropbox, Mutagen): one ordered authority decides the filesystem
  state. There is no eventual merge, no conflict copies, no "which machine won".
- Unlike sandbox filesystems (E2B, Modal): the workspace outlives any machine, and it
  mounts on your laptop too, not only inside the vendor's sandbox.
- Unlike proprietary cloud filesystem services: open source and self-hostable,
  and branching plus durable history work together — fork any checkpoint, mount it live.

## Install The CLI

```bash
curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs-oss/main/scripts/install.sh | sh
# or
brew install steerlabs/tap/portablefs
```

The installer verifies release checksums before installing (Linux and macOS,
amd64 and arm64). Binaries also ship on the GitHub releases page.

## Quickstart A: Local Stack In 2 Minutes

Requires Docker and Docker Compose. This starts Postgres (metadata plus the fenced
journal in one database), the Volume API (filesystem blob storage and history
serving), the authority manager in journal-native production mode, and the history
worker that materializes checkpoint history:

```bash
./scripts/quickstart.sh
```

The script runs `docker compose -f docker-compose.quickstart.yml up`, generates
per-install tokens (persisted to `.env.quickstart`, reused on rerun), provisions a
local tenant, and prints the exact login command for this install. Paste the
login command it prints, then the golden path (illustrative tokens — use the
printed ones):

```bash
portablefs login --url http://127.0.0.1:8787 --token <tenant-token> \
  --manager-url http://127.0.0.1:8788 --manager-token <manager-token>

portablefs adopt ~/dev/myrepo --name myagent   # import an existing repo (no mount needed)
portablefs mount myagent ~/work                # mount it live
# (macOS: install PortableFS.app and enable its File System Extension once —
#  see docs/fskit-mount.md; Linux: needs fuse3, e.g. `apt install fuse3`)
cd ~/work                                      # run agents, git, builds — normal files
# single-writer machine doing builds/installs? add --fast: writes batch and
# flush every 250ms (~25x faster small-file storms; fsync stays a real
# durability barrier — see docs/performance.md)

portablefs grep myagent "TODO" --dir src  # bounded server-side content search
portablefs history myagent                # every checkpoint the agent produced
portablefs fork myagent --name attempt-1  # branch the whole workspace
```

`adopt` imports everything under the directory — including `.git` and untracked
files, because the whole point is that your working state travels — hashes content
locally, uploads only blobs the server does not already have, and commits one
manifest. The source directory is never modified. Use `--exclude 'node_modules/'`
to keep per-machine build state out of the import, `--dry-run` to preview, and
`--mount` to mount immediately after import. `portablefs create` still makes an
empty volume. The mount-time counterpart of `--exclude` is
`portablefs mount --local-dir node_modules` (or a `.portablefs/local-dirs` file
in the repo): those directories are served from machine-local disk on every
machine that mounts, so installs run at local speed and platform-specific
artifacts never travel through the volume — see
[docs/agents.md](./docs/agents.md).

To serve volumes to your other machines from an always-on box (a Mac Mini over
Tailscale is the classic setup), run `./scripts/quickstart.sh --tailnet` and follow
[docs/home-server.md](./docs/home-server.md).

The CLI stores credentials in `~/.config/portablefs/config.json`; the
`PORTABLEFS_API_URL`, `PORTABLEFS_API_TOKEN`, `PORTABLEFS_MANAGER_URL`, and
`PORTABLEFS_MANAGER_TOKEN` environment variables override it. Agents using
PortableFS should read [skills/portablefs/SKILL.md](./skills/portablefs/SKILL.md).

## Quickstart B: Mount Into A Sandbox

Any Linux sandbox that can run a static binary can join a workspace. No kernel modules
beyond FUSE, no vendor integration:

```bash
# on your machine: mint a mount session for the sandbox
# (teamId is the volume's tenant id — "local" on the quickstart stack)
curl -X POST "$PORTABLEFS_MANAGER_URL/v1/mount-sessions" \
  -H "authorization: Bearer $PORTABLEFS_MANAGER_TOKEN" \
  -H "content-type: application/json" \
  -d '{"volumeId":"myagent","branch":"main","teamId":"local"}'
# -> { "mountSession": { "endpoint": { "authorityUrl": "host:2050", ... }, "token": "...", ... } }

# inside the sandbox: copy in the portablefs CLI (or the static portablefs-mount binary), then
portablefs mount myagent /workspace --addr <endpoint.authorityUrl> --mount-token <token>
# or: VCS_AUTH_TOKEN=<token> ./portablefs-mount -addr <endpoint.authorityUrl> -mount /workspace
```

The sandbox now shares the live workspace with every other mount. When the sandbox is
destroyed, the workspace — and its full history — remains.

## Architecture

```text
agent machine A              agent machine B              agent machine C
Codex / Claude Code          shell / Git / SQLite         build / tests
      |                            |                            |
      | FUSE / FSKit / CSI / bind-mounted custom protocol       |
      v                            v                            v
                  stable PortableFS volume endpoint
                                  |
                                  v
        one disposable VCS authority per active volume@branch
                                  |
                 fenced PostgreSQL journal (pfj/pfm/pfh)
                                  |
                 live working tree + cache + delegations
                                  |
                 async HistoryCuts -> immutable history
                                  |
           Postgres metadata + S3-compatible content-addressed blobs
```

- `vcs/`: the Go data plane. One VCS authority owns the live working tree for an
  active volume, serves mounts over a custom protocol (Linux FUSE client in
  `vcs/cmd/mount`, the `portablefsd` daemon behind the macOS FSKit
  extension, NFSv3 compat), and journals every mutation
  durably before acking — to the fenced Postgres journal in production
  ([docs/journal.md](./docs/journal.md)), to a crash-safe local file WAL in
  development. `vcs/cmd/history-worker` materializes journaled history cuts into
  content-addressed history objects ([docs/history.md](./docs/history.md)).
- `apps/volume-api`: the TypeScript control plane for volumes, branches, snapshots,
  forks, commits, content-addressed blobs, history serving, leases, delegations, and
  bounded server-side `grep`, over Postgres and S3-compatible (or filesystem) blob
  storage.
- `apps/authority-manager`: resolves `teamId + volumeId + branch` to a live authority
  endpoint and mount credential. Production mode spawns one disposable journal child
  per active branch behind one TCP/TLS router and serves access leases, so products
  and sandboxes see one stable address.
- `apps/volume-worker`: garbage collection, compaction, and integrity checks.

The full contract lives in [docs/architecture.md](./docs/architecture.md).

## Guarantees

- **Single active authority.** One VCS holds the fenced journal claim for an active
  volume@branch. Every mount connects to that authority; nothing maintains its own
  local truth. A second claimant fences the first in the database — there is no
  promotion protocol and no split-brain window.
- **Live multi-client coherence.** Mounts share one working tree. The authority pushes
  invalidations, so hot reads are page-cache fast and cross-machine read-after-write is
  exact — `git` and SQLite behave.
- **Write durability.** A writable VCS commits every mutation to its durable log
  before acking: the fenced, synchronously replicated PostgreSQL journal in
  production ([docs/journal.md](./docs/journal.md)), a crash-safe local file WAL in
  development. Authorities are disposable: on failure a replacement claims the
  journal and cold-replays — no acknowledged write is lost.
- **Exact sessions.** Mount sessions are journaled with receipts, so a reconnecting
  client replays in-flight mutations exactly once — never lost, never doubled.
- **Automatic history.** The journal is cut asynchronously into immutable
  HistoryCuts ([docs/history.md](./docs/history.md)): replicated, verified,
  content-addressed checkpoint states off the write path. Users never think about
  checkpoints during normal agent runs.
- **Immutable history.** Committed trees, snapshots, branches, and forks live in
  Postgres metadata and content-addressed storage. Fork any snapshot into a new
  live volume; nothing rewrites history.
- **Fail closed in production.** `VCS_PRODUCTION=1` requires the remote journal and
  its policy-verified durability evidence, and refuses local WALs, implicit temp
  files, and unauthenticated network-reachable data ports.

## What PortableFS Is Not

- **Not a sync tool.** There are no per-machine replicas that merge later. One ordered
  authority serves the active volume; disconnected offline editing is out of scope.
- **Not eventually consistent.** Connected clients observe authority-ordered state.
  If you want conflict-copy semantics, use a sync tool.
- **A single-writer-authority model.** One logical authority per active volume decides
  ordering. Concurrent writers use normal filesystem semantics plus delegations —
  never active-active multi-master, never silent merges of two writers' bytes.
- **NFS is compatibility only.** The custom mount protocol is the production data
  plane; NFSv3 exists for zero-install local workflows, not production coherence.

## Documentation

- [docs/architecture.md](./docs/architecture.md) — root invariants and contracts
- [docs/journal.md](./docs/journal.md) and [docs/history.md](./docs/history.md) — the fenced journal and HistoryCut planes
- [docs/api.md](./docs/api.md) — Volume API routes
- [docs/authority-manager.md](./docs/authority-manager.md) — authority resolution, production mode, access leases
- [docs/self-hosting.md](./docs/self-hosting.md) — production deployment guide
- [docs/home-server.md](./docs/home-server.md) — always-on home server (Mac Mini + Tailscale)
- [docs/fskit-mount.md](./docs/fskit-mount.md) — the macOS mount: `portablefsd` + the FSKit extension
- [docs/performance.md](./docs/performance.md) — benchmark harness, knobs, measured numbers
- [docs/agents.md](./docs/agents.md) — agent workspace patterns (continuity, fork-per-attempt)
- [docs/local-dev.md](./docs/local-dev.md) — development environment
- [docs/consistency-model.md](./docs/consistency-model.md) and [docs/failure-modes.md](./docs/failure-modes.md)
- [vcs/README.md](./vcs/README.md) — VCS runtime details, HA, TLS, performance
- [COMPATIBILITY.md](./COMPATIBILITY.md) — the stability contract (what you can pin)
- [CONTRIBUTING.md](./CONTRIBUTING.md) — how to contribute
- [skills/portablefs/SKILL.md](./skills/portablefs/SKILL.md) — the agent skill for using PortableFS

## Development

```bash
pnpm install
pnpm build
pnpm test
pnpm typecheck
pnpm verify
```

Useful focused commands:

```bash
pnpm vcs:build
pnpm vcs:test
pnpm vcs:test:race
pnpm verify:postgres
pnpm test:postgres
pnpm test:railway-bucket
pnpm bench:manifest-index
```

`pnpm test` covers the TypeScript workspaces and the Go VCS suite. Real Postgres,
Railway Bucket, and real-backend VCS tests are gated behind environment variables
documented in [docs/local-dev.md](./docs/local-dev.md) and
[docs/railway-buckets.md](./docs/railway-buckets.md). See
[CONTRIBUTING.md](./CONTRIBUTING.md) before opening a PR — changes to surfaces listed
in [COMPATIBILITY.md](./COMPATIBILITY.md) need explicit review.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
