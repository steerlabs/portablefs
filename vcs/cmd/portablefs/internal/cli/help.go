package cli

import (
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
)

// localdirsConfigPath is the in-volume route declaration, named in help text
// exactly as the code reads it.
const localdirsConfigPath = localdirs.VolumeConfigPath

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
  mount <volumeId> <path>      attach the live volume through the v3 authority
                               (FSKit on macOS, FUSE on Linux; direct credentials
                               required — see help mount)
  umount <path>                sync and detach one mounted volume
  mounts                       list active mounts
  recovery list|resolve <path> inspect and resolve a mount's write-back recovery
                               jobs — the terminal ones block umount --force
  route <path>                 is this path machine-local or shared, and by which rule
  prune-local                  reclaim machine-local backing no route can reach
  daemon stop                  atomically stop portablefsd only when no attach exists
  mount-check                  inspect mount prerequisites (no network or mutation)

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
  PORTABLEFS_MOUNT_TOKEN      single-use volume mount capability for mount --addr

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
  portablefs daemon stop [--json]

Atomically stop the per-user portablefsd only when it has no live attach.
Credential-pending restart metadata does not block a clean stop because it
holds no live session, WAL handle, or frontend service. The daemon first
closes attach admission and persists its final idle state; if any live attach
exists, the command fails without signaling or changing the daemon. The
installer never invokes this automatically.
`,
		"lifecycle": `USAGE
  portablefs lifecycle hold-shared --json
  portablefs lifecycle hold-account-exclusive --json
  portablefs lifecycle identity --json

Internal app/installer coordination protocol. Acquires the fixed per-user
mount lifecycle shared guard, writes one versioned readiness line, and holds
the guard until stdin closes or the process receives SIGINT/SIGTERM.
The account-exclusive form additionally performs strict mount and daemon
attach inventory while held, then reports
{"schemaVersion":1,"held":true,"mounts":0,"attaches":0}; the app holds it
across atomic profile/config mutation.
Identity prints the linker-stamped FSKit app group for packaging validation;
portablefsd exposes the same JSON with ` + "`portablefsd -identity-json`" + `.
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
		"route": `USAGE
  portablefs route <path> [--json]

Explain one path: which mount serves it, whether it comes from machine-local
disk or from the shared volume, and exactly which rule decided that. When the
path is machine-local it also prints the route root, the backing directory on
this machine (with its size), and the revision of the rule set the mount
activated — the same revision the authority pins the mount to.

Routes are declared in the volume's ` + localdirsConfigPath + ` (one
directory rule per line: "node_modules/" at any depth, "/target/" only at the
volume root, '*' and '?' within one component, '**' across components). That
declaration is the only source of a volume's routing, and the revision printed
here is its hash — the value every machine mounting the volume must agree on.

EXAMPLES
  portablefs route ~/work/agent-app/node_modules/react
  portablefs route ~/work/src/main.go --json
`,
		"prune-local": `USAGE
  portablefs prune-local [--volume <volumeId>] [--dry-run] [--delete] [--json]

List — and, with --delete, remove — machine-local backing trees that no route
can reach any more: a directory whose rule was removed from the declaration,
or a whole volume's backing left behind after the volume was retired. Backing
is keyed by (volume, route root), so it deliberately survives unmount and
remount; this is the explicit step that frees it.

Dry-run is the DEFAULT: nothing is ever removed unless you pass --delete.
Removing a rule from the declaration never deletes data by itself.

EXAMPLES
  portablefs prune-local                       # what could be reclaimed
  portablefs prune-local --volume my-workspace
  portablefs prune-local --delete              # actually reclaim it
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
  portablefs mount <volumeId> <mountPath>
                   --addr host:port --mount-token t
                   --data-plane-transport tls-private-ca|tls-system-pki
                   --data-plane-server-name name [--data-plane-ca ca.pem]
                   --client-cert cert.pem --client-key key.pem
                   [--coherence strict|uncached] [--no-local-dirs]
                   [--strategy auto|fskit|fuse] [--foreground] [--json]

Attach the live volume at mountPath through the v3 authority stack, then
daemonize — the command returns and the mount persists (state under
~/.local/state/portablefs/mounts). --foreground stays attached; Ctrl-C
unmounts.

Every mount takes the direct v3 credential shape: the authority address
(--addr), a single-use volume mount capability (--mount-token or
PORTABLEFS_MOUNT_TOKEN), a verified TLS transport (--data-plane-transport
tls-system-pki with --data-plane-server-name, or tls-private-ca with that
name plus --data-plane-ca), and the manager-issued mutual-TLS client
identity (--client-cert/--client-key; the key must be chmod 600). v3
authority sessions are mutually authenticated TLS 1.3, so plaintext cannot
mount. The retained authority manager mints only v2 leases and cannot admit
a v3 session; a manager/lease-only invocation is refused with this shape
named, never silently mounted on the retired v2 engine. A v3 volume is
branchless: the retired --branch flag is an error.

There is no write-back cache: write(2) returns after the authority has
applied the bytes to XFS, and fsync waits for the authoritative server
descriptor. --coherence picks the kernel cache contract — strict (default:
names and attributes are cached and repaired through the authority's
synchronous visibility barrier) or uncached (cache nothing; Linux only).

Machine-local directories — node_modules, .venv, target — are served from
machine-local disk instead of the volume. WHICH directories is declared by
the volume in .portablefs/local-dirs (one directory rule per line,
# comments): the mount adopts the declaration at attach and the authority
refuses a mount whose routing revision is not the volume's active one, so
every machine routes identically. --local-dir is refused unconditionally — a
per-machine route would hide from this machine a directory its peers still
treat as shared — and --no-local-dirs refuses a declaring volume instead of
ignoring its topology. macOS does not yet join the route adoption protocol:
a volume that declares routes mounts from Linux.

There is ONE transport per platform, with no fallbacks: macOS mounts through
the PortableFS FSKit extension (install PortableFS.app and enable its File
System Extension under System Settings once; the CLI manages the portablefsd
daemon, which owns the authority session and never exposes credentials to
the extension), and Linux mounts through FUSE. A host that cannot serve its
platform's transport fails with guidance instead of degrading to a weaker
consistency model. FSKit daemon sockets override explicitly via
PORTABLEFS_FSKIT_SOCKET and PORTABLEFS_FSKIT_CONTROL_SOCKET.
PORTABLEFS_FSKIT_TYPE may only assert the signed release type. The daemon is
always the exact portablefsd sibling from the same installed release;
PORTABLEFS_FSKIT_DAEMON is rejected.

EXAMPLES
  portablefs mount my-workspace ~/work \
    --addr 10.0.0.7:2050 --mount-token "$CAP" \
    --data-plane-transport tls-private-ca --data-plane-server-name authority.internal \
    --data-plane-ca ca.pem --client-cert client.pem --client-key client.key
  portablefs mount my-workspace /mnt/w --addr 10.0.0.7:2050 \
    --data-plane-transport tls-system-pki --data-plane-server-name authority.example.com \
    --client-cert client.pem --client-key client.key --coherence uncached --foreground
`,
		"umount": `USAGE
  portablefs umount <mountPath> [--force] [--discard-record] [--json]

Unmount a portablefs mount and stop its daemon. A NORMAL unmount first runs
the full drain barrier — every accepted write is locally synced, reaches the authority, and
every live protocol subscriber acknowledges its invalidations — and FAILS
(mount stays attached, nonzero exit) if the drain cannot complete.

--force detaches without draining: the unshipped tail parks as a durable
recovery job (its ID is printed) and is verified and replayed on the next attach
of the same volume+branch. Use it when the authority is unreachable and you
need the mount gone NOW.

On macOS, portablefsd owns one frozen drain + exact FSKit kernel unmount +
durable attach-removal transaction. On Linux, unmount uses exactly the direct
or pinned-helper mechanism recorded when that mount was created; it never
switches mechanisms after a failure. The command then reconciles the exact
recorded process, resources, access lease, and mount state.
Missing state or missing drain proof fails closed; PortableFS never substitutes
an unverified plain unmount.

--discard-record is the terminal for BOOKKEEPING, not for a mount. It unmounts
nothing, signals nothing and parks nothing; it removes this path's mount record
and any incomplete operation intent, and only after proving all of: no kernel
mount exists at the path, the recorded mount owner is gone, the incomplete
operation's owner is gone, portablefsd holds no durable attach for the path, and
no live portablefsd owns an attach there. Any survivor is a refusal that names
the command owning it. Use it when an interrupted unmount left an intent (for
example phase "unmounting") that blocks new mounts at a path where nothing is
mounted. Never edit ~/.local/state/portablefs/mounts by hand.

Every probe of the mount path and every external unmount helper is bounded, so
umount always reaches a verdict even when the filesystem has stopped answering,
and no umount path — including --force — ever reads standard input.

If --force refuses because a recovery job is terminally conflict or corrupt,
that job is the blocker and "portablefs recovery resolve" is what clears it:

  portablefs recovery list <mountPath>
  portablefs recovery resolve <mountPath> --all-terminal
  portablefs umount --force <mountPath>
`,
		"recovery": `USAGE
  portablefs recovery list <mountPath> [--json]
  portablefs recovery resolve <mountPath> (--job <jobId> | --all-terminal)
                              [--reason TEXT] [--json]

Inspect and resolve the write-back RECOVERY JOBS of one mount's local store.

A recovery job holds the acknowledged writes a mount had not yet shipped to the
authority. Most jobs need nothing: the next attach of the same volume+branch
verifies and replays them. Two states do not — "conflict" and "corrupt" — and a
job in either of them BLOCKS "portablefs umount --force" and every
attach until an operator resolves it. That is what this command does.

  list     Reads every job in the mount's store: state, how much it still owes
           the authority, why it is stuck, and — for a blocking job — the exact
           resolve invocation. Takes no lock and changes nothing, so it works
           while a daemon still owns the store.

  resolve  Resolves the terminal jobs. It NEVER DELETES: the job's bytes are the
           only remaining copy of what was acknowledged, so they are MOVED to
           <store>/unreplayable/ and kept. It reports exactly what is lost — how
           many acknowledged records and bytes, and the scopes they were written
           under — and leaves that verdict on disk so it is re-reported on every
           later attach. It refuses any job that is NOT proven terminal (an
           active, parked, forced or replaying job has a future: the next attach
           replays it), any store a live engine still owns, and any stream whose
           recorded identity does not match the store.

           Name the job with --job (repeatable) or say --all-terminal. There is
           no default: quarantining acknowledged bytes is a data decision.

The resolution is OFFLINE — it contacts no authority — so the delegation grants
a resolved stream held are released by the next attach rather than immediately.
That is reported when it applies.

EXAMPLES
  portablefs recovery list ~/work
  portablefs recovery resolve ~/work --job wbj_3f2a1c --reason "disk lost, re-copied from backup"
  portablefs recovery resolve ~/work --all-terminal
`,
		"mounts": `USAGE
  portablefs mounts [--json]

List this machine's recorded mounts with their health: live (daemon serving),
stale (daemon gone; umount cleans up), or credential-expired (the daemon is
running but its ACCESS LEASE ended and cannot be renewed — expired, released,
revoked, or the account credential itself rejected). A lease is minted by a
mount, so remounting is what re-establishes one; run ` + "`portablefs login`" + `
first only when the saved account credential is the thing that was rejected.
The mount log under ~/.local/state/portablefs/mounts/ names which of the two
it was.
`,
		"mount-check": `USAGE
  portablefs mount-check [--strategy auto|fskit|fuse] [--json]

Inspect the current host's mount transport without contacting a server,
starting a daemon, or changing the machine. Transport selection is
deterministic: FSKit on macOS and FUSE on Linux. The result is one of:

  VERIFIED    a recorded live mount answered filesystem operations
  BLOCKED     a definite current prerequisite is absent
  UNVERIFIED  no definite blocker was found; only a real mount can prove it

Installed helpers, capabilities, app bundles, and PlugInKit inventory are
evidence, never proof. JSON output carries stable issue codes for installers
and other automation. BLOCKED exits 1; VERIFIED and UNVERIFIED exit 0.
`,
		"doctor": `USAGE
  portablefs doctor [--profile name] [--json]

Read-only environment health check, in the spirit of brew doctor. Verifies,
in order: the config file parses (listing every profile's server and the
active one), the active server answers a cheap GET (an unauthenticated
401/404 still proves it is there), the saved token is still accepted, this
binary meets the server's advertised minimum CLI version, and — on macOS —
the selected mount transport, FSKit PlugInKit inventory (which does not claim
enablement), portablefsd daemon health, and this machine's recorded mounts.

Each check prints PASS, FAIL, UNKNOWN, or SKIP with a one-line fix for every
definite FAIL. UNKNOWN is an honest unverified state and does not change the
exit code.
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
