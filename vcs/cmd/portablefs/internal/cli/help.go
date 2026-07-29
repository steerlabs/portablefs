package cli

import "strings"

func rootHelp() string {
	return `portablefs — live, durable, branchable network filesystems for agent workspaces

Your agent's workspace is a place in the network, not a folder on one machine.
Mount the same live volume from a laptop, a server, and a sandbox at once;
every change is continuously checkpointed; fork the volume to give each
parallel agent run its own isolated copy.

USAGE
  portablefs <command> [arguments] [flags]

QUICKSTART
  portablefs login                                            # hosted; or self-host: portablefs login <url>
  portablefs create my-workspace                              # volume + branch "main"
  portablefs mount my-workspace ~/work                        # live mount (returns; daemon keeps it served)
  ...agent reads and writes ~/work; every change checkpoints continuously...
  portablefs history my-workspace                              # what happened, commit by commit
  portablefs fork my-workspace --name agent-2                  # isolated copy for a second agent
  portablefs mount agent-2 ~/work-2

VOLUMES
  create <name>                create a volume (omit <name> for a generated id)
  adopt <dir>                  import an existing local directory into a new volume
  activate <volumeId>          resume an interrupted adopt (adopt runs this for you)
  ls                           list volumes with their branches
  rm <volumeId>                retire (delete) a volume — mounts detach as leases expire
  status <volumeId>            branch head, tree hash, active leases/delegations
  history <volumeId>           recent commits on a branch

DATA MANAGEMENT
  snapshot <volumeId>          durable point-in-time snapshot of a branch head
  snapshots <volumeId>         list snapshots
  branch <volumeId> <name>     new branch within the volume (from branch or snapshot)
  branches <volumeId>          list branches
  fork <volumeId>              new independent volume from a snapshot — give every
                               parallel agent run its own fork of the workspace

SEARCH (no mount needed)
  grep <volumeId> <pattern>    search a branch's file bytes server-side

MOUNTS (this machine)
  mount <volumeId> <path>      attach the live volume (FSKit on macOS, FUSE on Linux)
  umount <path>                sync and detach one mounted volume
  mounts                       list active mounts
  daemon stop                  atomically stop portablefsd only when no attach exists

SESSION
  login [URL]                  authenticate and save credentials (device flow or --token)
  logout                       remove saved credentials
  doctor                       environment health check (config, server, token, extension, mounts)
  version                      print the CLI version
  help [command]               this text, or detailed help for one command

FLAGS (every command)
  --json         machine-readable JSON output (recommended for agents)
  --profile      config profile to use (default: currentProfile)
  --api-url, --api-token, --manager-url, --manager-token
                 one-off connection overrides (highest precedence)

CONFIGURATION (precedence: flags > environment > config file)
  config file: ~/.config/portablefs/config.json (0600)

  environment variable        meaning
  PORTABLEFS_API_URL          volume API base URL
  PORTABLEFS_API_TOKEN        volume API bearer token
  PORTABLEFS_MANAGER_URL      authority manager URL (defaults to the API URL)
  PORTABLEFS_MANAGER_TOKEN    authority manager token (defaults to the API token)
  PORTABLEFS_MOUNT_TOKEN      data-plane token for mount --addr
  PORTABLEFS_TLS_CA           CA bundle for data-plane TLS (alias of VCS_TLS_CA)

Run ` + "`portablefs help <command>`" + ` for details and examples.
`
}

// commandHelp returns detailed, example-driven help for one command.
func commandHelp(name string) (string, bool) {
	texts := map[string]string{
		"login": `USAGE
  portablefs login [URL] [--url URL] [--token TOKEN] [--manager-url URL]
                   [--manager-token TOKEN] [--profile name] [--no-browser]
                   [--json]

Authenticate to a PortableFS server and save credentials to
~/.config/portablefs/config.json (0600). With --token the token is stored and
verified immediately. Without --token an OAuth-style device flow starts: the
CLI opens a one-click approval link in your browser (prefilled code) and polls
until an API key is minted. With --no-browser — or when no browser can start
(SSH, containers) — the link is printed instead; open it on any machine, or
type the code at the printed page.

EXAMPLES
  portablefs login                                             # hosted (portablefs.com), browser approval
  portablefs login https://api.example.com --token ttk_abc123  # self-host with a token
  portablefs login https://api.example.com                     # self-host, browser approval
  portablefs login https://api.example.com --no-browser        # print link only
  portablefs login http://127.0.0.1:8787 --token ttk_x --profile local
`,
		"logout": `USAGE
  portablefs logout [--profile name] [--json]

Remove the saved credentials for a profile (default: the current profile).
`,
		"daemon": `USAGE
  portablefs daemon stop

Atomically stop the per-user portablefsd only when it has no active or dormant
attach. The daemon first closes attach admission and persists its final idle
state; if any attach exists, the command fails without signaling or changing
the daemon. The installer never invokes this automatically.
`,
		"create": `USAGE
  portablefs create [name] [--tenant id] [--json]

Create a volume with a "main" branch. The name must match [A-Za-z0-9_-]{1,220};
omit it to let the server generate an id. --tenant is only for admin
credentials; tenant tokens create volumes in their own tenant automatically.

EXAMPLES
  portablefs create my-workspace
  portablefs create --json
`,
		"activate": `USAGE
  portablefs activate <volumeId> [--branch main] [--timeout 15m] [--json]

Finish entering an adopted volume into service after an interrupted
` + "`portablefs adopt`" + `. Idempotent and safe to re-run: an already-active
branch answers immediately. You rarely run this directly — adopt runs it
automatically as its final step, and prints this command if it is interrupted.

Under the hood it converts the committed head into the immutable journal base
and flips the branch into managed journal service, after which the volume can
be mounted.

EXAMPLES
  portablefs activate my-repo
  portablefs activate my-repo --branch main --timeout 30m
`,
		"adopt": `USAGE
  portablefs adopt <dir> [--name volumeName] [--branch main]
                   [--exclude pattern]... [--dry-run] [--mount path]
                   [--concurrency n] [--quiet] [--json]

Import an existing local directory into a new volume, without mounting
anything: scan the tree, upload the file contents, and commit one manifest.
The directory itself is untouched.

Everything is included by default — .git, node_modules, dotfiles — because the
volume is your working directory, not a source archive. Only unsupported node
types (sockets, FIFOs, device nodes) are skipped, with a warning. Symlinks are
preserved verbatim (the raw link target, never followed), empty directories
survive, and the executable bit is kept.

The volume name defaults to the directory basename, sanitized to
[A-Za-z0-9_-] (max 220 chars). If a volume with that name already exists the
command fails; pick another name with --name.

--exclude takes gitignore-style patterns (repeatable) matched against paths
relative to <dir>: "node_modules" matches at any depth, "/dist" only at the
root, "*.log" by basename, "build/" only directories, "a/**/b" across
segments, and "!keep.log" re-includes (last match wins). A .portablefsignore
file at the root of <dir> is read first, then --exclude patterns.

Identical file contents are uploaded once, and blobs the server already has
are skipped entirely (older servers without the probe route upload
everything). --dry-run scans and reports without any network calls.
--mount <path> mounts the new volume after a successful import.

EXAMPLES
  portablefs adopt ~/code/my-project
  portablefs adopt . --name scratch --exclude node_modules --exclude "*.log"
  portablefs adopt ~/data --dry-run
  portablefs adopt ~/code/api --mount ~/code/api-live
`,
		"ls": `USAGE
  portablefs ls [--limit n] [--json]

List volumes visible to the credential, with each volume's branches and their
head commits.
`,
		"rm": `USAGE
  portablefs rm <volumeId> [--yes] [--json]

Retire (delete) a volume — this cannot be undone. The volume immediately
disappears from listings and from every API surface (attach, grep,
branches, snapshots, and forks of its snapshots all answer the same not-found
an unknown volume gets), and its slot is freed for a new volume. Existing
live mounts are not force-detached: they lose access shortly afterwards as
their leases expire.

Without --yes, rm prints what will happen and requires the volume id to be
typed back to confirm — on an interactive terminal only. Non-interactive
callers (scripts, agents, pipes) must pass --yes explicitly; rm never
retires anything on an unconfirmed guess.

On success rm prints the retirement receipt: the volume id and the ISO8601
instant it left service.

EXAMPLES
  portablefs rm my-workspace           # interactive: type the id to confirm
  portablefs rm my-workspace --yes     # scripts and agents
  portablefs rm my-workspace --yes --json
`,
		"status": `USAGE
  portablefs status <volumeId> [--branch main] [--json]

Show a branch's state, whatever mode it is in — always cheap, even on huge
trees. While a branch is in its authoring phase the summary is the manifest
head: commit id, tree hash, and active lease/delegation counts. Once the
branch is served live (every cloud-created or adopted volume), status reports
the live-serving facts instead: the latest committed revision, the newest
ready snapshot (and any still being written), and this machine's mounts of
the branch with their health.
`,
		"history": `USAGE
  portablefs history <volumeId> [--branch main] [--limit 50] [--json]

List recent commits on a branch (newest first): id, time, mutation and byte
counts. Continuous checkpointing means this is effectively the workspace's
activity log. Servers without the commits route fall back to head + snapshots.
`,
		"snapshot": `USAGE
  portablefs snapshot <volumeId> [--name n] [--branch main] [--json]

Record an exact immutable revision of the branch; use snapshots as named
restore points and as fork/branch sources. On an authoring branch the
snapshot pins the committed head instantly. On a live branch the snapshot
captures the exact live state and materializes in the background — it lists
as pending until ready (` + "`portablefs snapshots <volumeId>`" + ` shows the state;
fork and branch wait for readiness automatically).

EXAMPLES
  portablefs snapshot my-workspace --name before-refactor
`,
		"snapshots": `USAGE
  portablefs snapshots <volumeId> [--branch name] [--json]

List snapshots for a volume (optionally filtered to one branch).
`,
		"branch": `USAGE
  portablefs branch <volumeId> <branchName> [--from-branch main]
                    [--from-snapshot nameOrId] [--json]

Create a branch inside the same volume, from another branch's current state
or from an existing snapshot (by name or id). If the source branch is served
live, its state is snapshotted first and the branch opens from that snapshot
once it is ready — progress prints while the snapshot is written. Branches
share history; mount any branch with
` + "`portablefs mount <volumeId> <path> --branch <branchName>`" + `.
`,
		"branches": `USAGE
  portablefs branches <volumeId> [--json]

List a volume's branches and their head commits.
`,
		"fork": `USAGE
  portablefs fork <volumeId> [--snapshot nameOrId] [--name newVolumeId]
                  [--branch main] [--json]

Fork a volume into a NEW independent volume — this is how you give every
parallel agent run its own workspace. Without --snapshot the branch state is
snapshotted right now (named fork-<unixms>) and that snapshot is forked; with
--snapshot an existing snapshot (by name or id) is forked. On a live branch
the snapshot is written in the background; fork waits for it (with progress)
before forking. Prints the new volume id.

Some servers cannot fork a live branch's snapshot into a new volume; the CLI
then hands you the equivalent same-volume command
(portablefs branch <volumeId> <name> --from-snapshot <id>).

EXAMPLES
  portablefs fork my-workspace --name agent-run-7
  portablefs fork my-workspace --snapshot before-refactor
`,
		"grep": `USAGE
  portablefs grep <volumeId> <pattern> [--dir path] [--branch main]
                  [--max 1000] [--json]

Search a branch's file bytes server-side (no mount, no download). On a live
branch the search runs against an exact snapshot of the current state,
captured (or reused) per call. Matches print as path:line:text. Exit code
0 = matches found, 1 = none (grep semantics).

EXAMPLES
  portablefs grep my-workspace "TODO" --dir src
`,
		"mount": `USAGE
  portablefs mount <volumeId> <mountPath> [--branch main]
                   [--local-dir rel]... [--no-local-dirs]
                   [--strategy auto|fskit|fuse] [--addr host:port]
                   [--mount-token t] [--foreground] [--json]

Attach the live volume at mountPath. The default resolves the volume's current
authority through the manager, mounts, and daemonizes — the command returns
and the mount persists (state under ~/.local/state/portablefs/mounts).
--foreground stays attached; Ctrl-C unmounts.

Write mode is not a mount property: the authority delegates write-back per
scope adaptively, so build/install-heavy workloads acknowledge locally at
local-disk speed while contended paths stay write-through. fsync(2) is
always a REAL local-sync plus authority-durability barrier. Plain write(2)
does not wait for physical local sync; the WAL group-sync normally runs
within 5 ms. Linux FUSE also acknowledges
peer invalidations after its kernel cache hook; macOS 26 FSKit has no such
hook, so reads served wholly from FSKit's kernel cache are outside the exact
peer-visibility claim. A WAL error fails later mutations until remount; it
never switches them to write-through. (The
retired --fast flag is an error: every mount is adaptive.)

--local-dir <rel> (repeatable) serves a workspace-relative directory —
node_modules, .venv, target — from machine-local disk instead of the volume:
installs run at local speed and platform-specific artifacts never travel
between machines. The set persists per volume+branch+mountPath, so a plain
remount reuses it; explicit flags win and update it; --no-local-dirs clears
it. On Linux (FUSE) a .portablefs/local-dirs file in the volume (one path
per line, # comments) is unioned in at mount time so a repo declares its
per-machine dirs once for every machine. See docs/agents.md.

There is ONE transport per platform, with no fallbacks: macOS mounts through
the PortableFS FSKit extension (install PortableFS.app and enable its File
System Extension under System Settings once; the CLI manages the portablefsd
daemon the extension talks to), and Linux mounts through FUSE (needs
fusermount3/fusermount, e.g. ` + "`apt install fuse3`" + `). A host that cannot serve
its platform's transport fails with guidance instead of degrading to a
weaker consistency model.

--addr mounts a VCS authority directly (skipping the manager); pass the data
plane token via --mount-token, PORTABLEFS_MOUNT_TOKEN, or VCS_AUTH_TOKEN. TLS
uses PORTABLEFS_TLS_CA / VCS_TLS_CA. FSKit extension coordinates (fs type,
daemon sockets, daemon binary) override via PORTABLEFS_FSKIT_TYPE,
PORTABLEFS_FSKIT_SOCKET, PORTABLEFS_FSKIT_CONTROL_SOCKET, and
PORTABLEFS_FSKIT_DAEMON.

EXAMPLES
  portablefs mount my-workspace ~/work
  portablefs mount my-workspace ~/work --local-dir node_modules
  portablefs mount my-workspace /tmp/w --branch experiment --foreground
  portablefs mount my-workspace /mnt/w --addr 127.0.0.1:2050 --mount-token tok
`,
		"umount": `USAGE
  portablefs umount <mountPath> [--force] [--json]

Unmount a portablefs mount and stop its daemon. A NORMAL unmount first runs
the full drain barrier — every accepted write is locally synced, reaches the authority, and
every live protocol subscriber acknowledges its invalidations — and FAILS
(mount stays attached, nonzero exit) if the drain cannot complete.

--force detaches without draining: the unshipped tail parks as a durable
recovery job (its ID is printed) and is verified and replayed on the next attach
of the same volume+branch. Use it when the authority is unreachable and you
need the mount gone NOW.

Uses the platform unmount tooling (umount/diskutil on macOS, fusermount3 on
Linux), then terminates the recorded daemon pid and removes the mount state.
A path with no recorded state gets a best-effort plain unmount with a warning.
`,
		"mounts": `USAGE
  portablefs mounts [--json]

List this machine's recorded mounts with their health: live (daemon serving),
stale (daemon gone; umount cleans up), or credential-expired (the daemon is
running but the server rejected its credentials — revoked or expired keys;
run ` + "`portablefs login`" + ` and remount). The same transition is logged once in
the mount's log file under ~/.local/state/portablefs/mounts/.
`,
		"doctor": `USAGE
  portablefs doctor [--profile name] [--json]

Read-only environment health check, in the spirit of brew doctor. Verifies,
in order: the config file parses (listing every profile's server and the
active one), the active server answers a cheap GET (an unauthenticated
401/404 still proves it is there), the saved token is still accepted, this
binary meets the server's advertised minimum CLI version, and — on macOS —
the FSKit extension registration state (via pluginkit, including the known
post-update staleness where the extension shows enabled but mounts fail),
portablefsd daemon health, and this machine's recorded mounts.

Each check prints PASS, FAIL, or SKIP with a one-line fix for every FAIL.
Exit code 1 if any check fails, 0 otherwise. Nothing is modified.

EXAMPLES
  portablefs doctor
  portablefs doctor --json
  portablefs doctor --profile work
`,
		"version": `USAGE
  portablefs version [--json]

Print the CLI version.
`,
	}
	if t, ok := texts[name]; ok {
		return t, true
	}
	if name == "help" {
		return rootHelp(), true
	}
	return "", false
}

// commandSummaries renders the one-line summary list (used by tests to keep
// help and the command table in sync).
func commandSummaries() string {
	var b strings.Builder
	for _, c := range commands() {
		b.WriteString(c.name)
		b.WriteString("\t")
		b.WriteString(c.summary)
		b.WriteString("\n")
	}
	return b.String()
}
