# Your Mac Mini As An Always-On Workspace Server

A copy-paste guide to running PortableFS on a home server (a Mac Mini in the
examples, but any always-on Linux or macOS box works) and reaching it from your
laptop over Tailscale. The result: agent workspaces that live on the Mini, mount
live on any of your machines, keep working when your laptop is closed, and keep
full checkpoint history.

This guide uses the quickstart stack in tailnet mode. It is a single-node,
plaintext-TCP deployment with bearer tokens — right for a private tailnet or home
LAN, wrong for the public internet. For a hardened multi-node deployment with TLS
and replicated authorities, see [self-hosting.md](./self-hosting.md).
The quickstart declares this intentionally with
`PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE=plaintext` plus the production
plaintext authorization flag; clients learn that exact mode from each access
lease. No client infers plaintext from a missing CA.

## Prerequisites

- On the Mini: [Docker Desktop](https://www.docker.com/products/docker-desktop/)
  or [OrbStack](https://orbstack.dev/), and `git`.
- On both machines: [Tailscale](https://tailscale.com/), logged in to the same
  tailnet. (A trusted home LAN also works; use the Mini's LAN IP wherever this
  guide says Tailscale address.)
- The PortableFS CLI wherever you will type `portablefs` commands. Until the
  first tagged release, build from source (see the repository README's
  Development section). Once releases are published:

```bash
curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh
```

On Linux, the installer puts the verified CLI/daemon pair in an immutable,
content-addressed per-user release directory and atomically switches one CLI
activation link at `~/.local/bin/portablefs`. Before extraction, it verifies
GitHub build provenance against this repository's exact release workflow and
tag using the signed per-architecture bundle shipped with the release, plus the
release SHA-256 digest. This does not require a local GitHub login. On macOS, it
verifies the notarized `PortableFS.app`, installs it at
`~/Applications/PortableFS.app`, and links its embedded CLI at
`~/.local/bin/portablefs`.

## Server Setup (On The Mini)

```bash
git clone https://github.com/steerlabs/portablefs.git
cd portablefs
./scripts/quickstart.sh --tailnet
```

The script starts four services in Docker — Postgres (the metadata database and
the fenced journal in one), the volume API, the journal-backed authority manager
(production mode), and the history worker that materializes checkpoint history —
generates strong tokens (persisted to `.env.quickstart`, mode 0600 — rerunning
reuses them, deleting the file and rerunning rotates them), detects the Mini's
Tailscale IPv4 as the advertise address, and provisions a tenant. It ends by
printing a security warning and the exact commands for other machines, roughly:

```text
PortableFS quickstart stack is up (tailnet/LAN mode).

  volume API         http://100.101.102.103:8787
  authority manager  http://100.101.102.103:8788  (journal-backed, production mode)
  data-plane router  100.101.102.103:2050
  history worker     internal (materializes checkpoint history cuts)
  settings + tokens  .env.quickstart (0600; reused on rerun)

WARNING
  The data plane is plaintext TCP and every API uses static bearer tokens: ...

Set up another machine (laptop, desktop, second server):
  ...install one-liner, login command with the real tokens, adopt + mount...
```

To advertise a MagicDNS name (or a LAN IP) instead of the detected Tailscale IP,
pass it explicitly — mount clients dial exactly this address:

```bash
./scripts/quickstart.sh --tailnet --advertise-host mini.tail1234.ts.net
```

If macOS asks whether Docker may accept incoming network connections, allow it;
otherwise nothing outside the Mini can reach the stack.

## Laptop Setup

Install the CLI (one-liner above), then paste the login command the Mini printed.
With placeholders instead of the printed values:

```bash
portablefs login http://<mini-address>:8787 --token <tenant-token> \
  --manager-url http://<mini-address>:8788 --manager-token <manager-token>
```

`<mini-address>` is the advertise host the script chose or you passed
(Tailscale IP, MagicDNS name, or LAN IP). Credentials are saved to
`~/.config/portablefs/config.json`, so this is a one-time step per machine.

Import an existing project into a volume and mount it live:

```bash
portablefs adopt ~/dev/myrepo            # uploads the tree, commits one manifest;
                                         # ~/dev/myrepo itself is untouched
portablefs mount myrepo ~/dev/myrepo-live
```

`adopt` includes everything by default (`.git`, `node_modules`, dotfiles) because
the volume is a working directory, not a source archive; use `--exclude` or a
`.portablefsignore` file to trim it. The mount daemonizes: the command returns
and `~/dev/myrepo-live` stays served until `portablefs umount ~/dev/myrepo-live`.

On macOS, `mount` uses the PortableFS FSKit extension — POSIX-shaped semantics
within the documented FSKit boundaries (notably `O_APPEND` is not exposed and
cross-machine atomic append is not guaranteed; see
[consistency-model.md](./consistency-model.md#concurrent-appends)), one
transport, no fallback. One-time setup per Mac: install PortableFS.app and
enable its File System Extension in System Settings → General → Login Items &
Extensions (see [fskit-mount.md](./fskit-mount.md)). On Linux, one host-facts
observation selects exactly one FUSE mechanism before mounting: direct
`mount(2)` for a process with positive `CAP_SYS_ADMIN` evidence, otherwise an
exact trusted `fuse3` helper. That selection is persisted and revalidated; an
attempted mount never falls through to the other mechanism. A host that cannot
serve its platform's transport fails with guidance instead of degrading to
weaker semantics.

## Running Agents On The Mini

The point of the Mini is that agents run there, next to the workspace authority,
around the clock. Two ways to do it:

### (a) In A Linux Container

FUSE inside a Linux container works on Docker Desktop and OrbStack with
`--device /dev/fuse --cap-add SYS_ADMIN`. Run on the Mini:

```bash
docker run -it --rm \
  --device /dev/fuse --cap-add SYS_ADMIN \
  -e PORTABLEFS_API_URL=http://<mini-address>:8787 \
  -e PORTABLEFS_API_TOKEN=<tenant-token> \
  -e PORTABLEFS_MANAGER_URL=http://<mini-address>:8788 \
  -e PORTABLEFS_MANAGER_TOKEN=<manager-token> \
  ubuntu:24.04 bash

# inside the container:
apt-get update && apt-get install -y curl ca-certificates fuse3 tmux
curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh

mkdir -p /work
# Delegation is adaptive: uncontended writes batch locally, contended paths
# stay write-through, and fsync (git commit, SQLite) remains the explicit
# authority-durability barrier.
portablefs mount myrepo /work

# install your agent CLI of choice (claude, codex, ...), then run it in tmux
# so it survives your SSH/attach session ending:
tmux new -s agent
cd /work && claude    # or: codex
# detach with Ctrl-b d; the agent keeps running in the container
```

The CLI reads `PORTABLEFS_*` environment variables directly, so no `login` step
is needed in the container. The container dials the same advertised address as
every other machine; if that address is unreachable from containers on your
setup, re-run the quickstart with `--advertise-host <lan-ip-or-magicdns-name>`.

### (b) Directly On macOS With The FSKit Extension

Install PortableFS.app on the Mini and enable its File System Extension once
(System Settings → General → Login Items & Extensions, see
[fskit-mount.md](./fskit-mount.md)), then agents run as normal macOS
processes:

```bash
portablefs login http://<mini-address>:8787 --token <tenant-token> \
  --manager-url http://<mini-address>:8788 --manager-token <manager-token>
portablefs mount myrepo ~/agents/myrepo

brew install tmux
tmux new -s agent
cd ~/agents/myrepo && claude
```

The extension approval is a one-time toggle — FSKit is user-space, so no
kernel extension and no reboot. The container route avoids the app install;
the native route avoids Docker in the agent's path. Pick one.

## The Airport Flow

You are at the airport. On the laptop, you mount the workspace, steer the agent
for twenty minutes, run the agent's normal save/`fsync` boundary (or cleanly
unmount), and close the lid at boarding. The laptop's mount may disappear; the
authority-durable workspace does not — it lives on the Mini, where the agent
in tmux keeps reading and writing the same volume. Recent plain writes are
usually group-synced and flushed within milliseconds, but the explicit
barrier is what makes the handoff a guarantee. History cuts capture
authority-durable progress continuously.

After landing, you do not even need to re-mount to see what happened:

```bash
portablefs history myrepo                                  # cut-by-cut activity
(cd ~/dev/myrepo-live && git log --oneline -10)             # run through the mount
(cd ~/dev/myrepo-live && npm test 2>&1 | tail -5)
```

Re-mount (`portablefs mount myrepo ~/dev/myrepo-live`) whenever you want the
files themselves back on the laptop, exactly where the agent left them. See
[agents.md](./agents.md) for the continuity and fork-per-attempt patterns this
enables.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `portablefs mount` hangs or times out | The advertised router address is not reachable from this machine (mounts dial `<mini-address>:2050`, printed as "data-plane router") | Verify with `nc -vz <mini-address> 2050`. If it fails: check both machines are on the tailnet (`tailscale status`), and that the advertise host is right — re-run `./scripts/quickstart.sh --tailnet --advertise-host <reachable-address>` on the Mini |
| `login` fails with HTTP 401 | Token mismatch — usually the Mini's tokens were rotated (`.env.quickstart` deleted and the quickstart re-run) after this machine logged in | Read the current tokens from `.env.quickstart` on the Mini (or its printed output) and log in again |
| `mount` on a Mac fails with FSKit extension guidance | The PortableFS File System Extension is not installed or not enabled on this machine | Install PortableFS.app, enable its File System Extension under System Settings → General → Login Items & Extensions, and retry (see [fskit-mount.md](./fskit-mount.md)) |
| Nothing can connect to the Mini at all | macOS firewall blocked Docker's listener, or the prompt was dismissed | Allow incoming connections for Docker in System Settings -> Network -> Firewall, then `nc -vz <mini-address> 8787` from the laptop |
| `could not detect this machine's address` from the quickstart | No Tailscale and no detectable non-loopback IPv4 | Pass `--advertise-host <ip-or-hostname>` explicitly |

## Latency, Honestly

The volume's authority runs on the Mini, so filesystem operations are fast in
proportion to your distance from it. On the home LAN, mounts feel local. Over
Tailscale from a coffee shop or another city, every uncached metadata operation
and cold read pays the round trip to your home connection — browsing and edits
are fine, but a `npm install` or a full build through a remote mount will crawl.
Put the heavy work where the authority is: run agents, builds, and tests on the
Mini (or in isolated containers on it), and use the laptop to steer — mounts for
filesystem work, `grep` and `history` for bounded server-side reads. That split
is what this setup is for.

## See Also

- [self-hosting.md](./self-hosting.md) — production deployment: TLS, the
  journal-native authority manager, S3 blob storage, backups
- [local-dev.md](./local-dev.md) — developing PortableFS itself
- [agents.md](./agents.md) — agent workspace patterns on top of this setup
