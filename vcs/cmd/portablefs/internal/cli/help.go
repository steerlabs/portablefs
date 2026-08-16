package cli

import (
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
)

// localdirsConfigPath is the in-volume route declaration, named in help text
// exactly as the code reads it.
const localdirsConfigPath = localdirs.VolumeConfigPath

func rootHelp() string {
	return `portablefs — live, durable network filesystems for agent workspaces

Your agent's workspace is a place in the network, not a folder on one machine.
Mount the same live volume from a laptop, a server, and a sandbox at once; the
XFS authority is current-state truth for every one of them, and write(2) returns
only after the authority has applied the bytes.

USAGE
  portablefs <command> [arguments] [flags]

QUICKSTART
  portablefs mount my-workspace ~/work \
    --addr 10.0.0.7:2050 --mount-token "$PORTABLEFS_MOUNT_TOKEN" \
    --data-plane-transport tls-private-ca --data-plane-server-name authority.internal \
    --data-plane-ca ca.pem --client-cert client.pem --client-key client.key
  ...the agent reads and writes ~/work...
  portablefs umount ~/work

MOUNTS (this machine)
  mount <volumeId> <path>      attach the live volume through the v3 authority
                               (FSKit on macOS, FUSE on Linux; direct credentials
                               required — see help mount)
  reauthorize <path>           rotate a hosted mount's exact live authorization
  umount <path>                drain and detach one mounted volume
  mounts                       list this machine's mounts and their health
  route <path>                 is this path machine-local or shared, and by which rule
  prune-local                  reclaim machine-local backing no route can reach
  daemon stop                  stop an idle daemon (Linux; host-owned update only on macOS)
  mount-check                  inspect mount prerequisites (no network or mutation)

THIS MACHINE
  doctor                       health check (transport, extension, daemon, mounts)
  version                      print the CLI version
  help [command]               this text, or detailed help for one command

FLAGS (every command)
  --json         machine-readable JSON output (recommended for agents)

ENVIRONMENT
  PORTABLEFS_MOUNT_TOKEN      single-use volume mount capability for ` + "`mount --addr`" + `
                              or manager-issued live reauthorization capability

Run ` + "`portablefs help <command>`" + ` for details and examples.
`
}

// commandHelp returns detailed, example-driven help for one command.
func commandHelp(name string) (string, bool) {
	texts := map[string]string{
		"reauthorize": `USAGE
  PORTABLEFS_MOUNT_TOKEN=<manager-issued capability> portablefs reauthorize <mountPath>
    --client-cert renewed-client.pem --auth-expires-at-ms <unix-ms>
    --auth-sequence <positive-sequence> [--json]

Rotate the signed authorization and mutual-TLS certificate underneath one
exact live hosted mount. The manager binds the capability to the mount's
non-secret authorizationSessionId and assigns the exact next sequence. Linux
delivers it to the uid-owned mount supervisor over a private local socket;
macOS delivers it to portablefsd. The capability is accepted only through the
environment so it never appears in process arguments, and is never persisted.

This command does not mint credentials, broaden access, remount, or create a
replacement authority session. A mount created by an older CLI without an
authorizationSessionId must be mounted once with the current CLI. A mount
created with automatic Manager enrollment has one internal sequencer and
refuses this manual path.
`,
		"daemon": `USAGE
  portablefs daemon stop [--json]

On Linux, atomically stop the per-user portablefsd only when it has no live attach.
Credential-pending restart metadata does not block a clean stop because it
holds no live session, WAL handle, or frontend service. The daemon first
closes attach admission and persists its final idle state; if any live attach
exists, the command fails without signaling or changing the daemon. The
installer never invokes this automatically. On macOS portablefsd is an
always-running ServiceManagement agent, so this command refuses without
mutation; only the host-owned zero-mount update transaction may unregister it.
`,
		"lifecycle": `USAGE
  portablefs lifecycle hold-shared --json
  portablefs lifecycle hold-account-exclusive --json
  portablefs lifecycle hold-install-exclusive --json \
    [--expected-daemon-version <version> \
     --expected-daemon-sha256 <lowercase-sha256> \
     --expected-pfslocal-major <major> \
     --expected-pfslocal-minor <minor>]
  portablefs lifecycle identity --json

Internal app/installer coordination protocol. Acquires the fixed per-user
mount lifecycle shared guard, writes one versioned readiness line, and holds
the guard until stdin closes or the process receives SIGINT/SIGTERM.
The account-exclusive form additionally performs strict mount and daemon
attach inventory while held, then reports
{"schemaVersion":1,"held":true,"mounts":0,"attaches":0}; the app holds it
across atomic profile/config mutation.
The install-exclusive form nonblockingly acquires both the account-session and
mount-lifecycle exclusive guards, proves zero kernel mounts, mount records,
mount intents, durable daemon attaches, and live daemon attaches, then reports
one schema-1 ` + "`service-update`" + ` readiness frame. The macOS host keeps its
stdin open across the exact ServiceManagement unregister/register transaction;
closing stdin releases both guards.
When replacing a previously registered release, the host supplies all four
expected-daemon fields from its persisted, signature-validated registration
identity. A healthy old daemon must match that complete tuple before the CLI
reads its attach inventory. The four fields are all-or-none; omission is valid
only when no prior live daemon needs adoption.
Identity prints the linker-stamped FSKit app group for packaging validation;
portablefsd exposes the same JSON with ` + "`portablefsd -identity-json`" + `.
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
		"mount": `USAGE
  portablefs mount <volumeId> <mountPath>
                   --addr host:port --mount-token t
                   --data-plane-transport tls-private-ca|tls-system-pki
                   --data-plane-server-name name [--data-plane-ca ca.pem]
                   --client-cert cert.pem --client-key key.pem
                   [--manager-url https://manager --manager-server-name name
                    --manager-ca manager-ca.pem --mount-enrollment-id id
                    --mount-enrollment-cert enrollment.pem
                    --mount-enrollment-expires-at-ms ms
                    --authority-generation n --auth-expires-at-ms ms]
                   [--coherence strict] [--no-local-dirs]
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
mount. Standalone credentials may be supplied directly by the deployment. A
hosted product may additionally pass the complete Manager enrollment group
shown above. The Linux mount supervisor or macOS portablefsd then refreshes
short-lived grants inside the same authority session. The group is all-or-none,
has exactly one renewal owner, and never falls back to manual renewal. A v3
volume is branchless: the retired --branch flag is an error.

There is no PortableFS-managed or offline write-back layer. Linux direct-I/O
write(2) returns after the authority has applied the bytes to XFS. On macOS,
ordinary kernel page-cache writeback still applies: write(2) may return before
FSKit sends the write, while fsync/synchronize waits through the authority's
server descriptor. Protocol 5 has one coherence contract: names and attributes
are cached and repaired through the authority's synchronous visibility barrier.
--coherence may only be strict; legacy uncached mounts are rejected. Linux
implements the exact strict-cache contract. macOS 26 declares the named
macos26-synchronous-vfs-repair-v2 best-effort cache tier: authority ordering,
durability, source publication accounting, and terminal fencing remain exact,
but current FSKit cannot guarantee exact peer namespace or attribute cache
invalidation. While that Mac is mounted, it owns the compatibility writer lease;
other clients may read but visible mutations return EBUSY until the Mac cleanly
unmounts, and a second Mac compatibility writer is refused at attach. Under
extreme cross-client rename churn, a reader may receive a
transient ESTALE rather than torn data. The mount command reports the ownership
boundary before mounting.

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
System Extension under System Settings once; the host's launchd-managed
portablefsd owns the authority session and never exposes credentials to the
extension), and Linux mounts through FUSE. A host that cannot serve its
platform's transport fails with guidance instead of degrading to a weaker
consistency model. The FSKit frontend is fixed by the release's signed
app-group identity, while the unentitled CLI uses the fixed external private
control socket; PORTABLEFS_FSKIT_SOCKET and
PORTABLEFS_FSKIT_CONTROL_SOCKET are rejected. PORTABLEFS_FSKIT_TYPE may only
assert the signed release type. The daemon is
always the exact portablefsd sibling from the same installed release;
PORTABLEFS_FSKIT_DAEMON is rejected.

EXAMPLES
  portablefs mount my-workspace ~/work \
    --addr 10.0.0.7:2050 --mount-token "$CAP" \
    --data-plane-transport tls-private-ca --data-plane-server-name authority.internal \
    --data-plane-ca ca.pem --client-cert client.pem --client-key client.key
  portablefs mount my-workspace /mnt/w --addr 10.0.0.7:2050 \
    --data-plane-transport tls-system-pki --data-plane-server-name authority.example.com \
    --client-cert client.pem --client-key client.key --coherence strict --foreground
`,
		"umount": `USAGE
  portablefs umount <mountPath> [--force] [--discard-record] [--json]

Unmount a portablefs mount and stop its daemon. On macOS authority-v3, a NORMAL
unmount begins planned detach and first asks the kernel for an unforced unmount.
That pass invokes FSKit synchronize and the authority durability boundary. The
daemon accepts only success or the exact EBUSY produced after that sync pass;
EBUSY authorizes a second MNT_FORCE pass to revoke the retained mount-root vnode.
Exact mount-table absence is then delivered to the authority before local attach
removal. Any other first-pass failure leaves the mount attached.

--force skips the trustworthy unforced sync pass and revokes the exact mount
immediately. A v3 mount has no PortableFS-managed tail to park or replay, but
macOS kernel pages may still need the normal synchronize boundary. Use --force
only when that boundary is unavailable and the mount must be made unservable.

Legacy macOS attaches still use their frozen drain transaction. On Linux,
unmount uses exactly the direct
or pinned-helper mechanism recorded when that mount was created; it never
switches mechanisms after a failure. The command then reconciles the exact
recorded process, resources, and mount state.
Missing state or missing absence proof fails closed; PortableFS never substitutes
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
`,
		"mounts": `USAGE
  portablefs mounts [--json]

List this machine's recorded mounts with their health: live (daemon serving),
stale (daemon gone; umount cleans up), or credential-expired (the daemon is
running but this mount's credential ended). A v3 mount capability is single-use.
A hosted enrolled mount refreshes automatically before its safety cutoff.
Standalone hosted integrations can call portablefs reauthorize explicitly;
once the credential is already expired, a new capability and remount is
required. The mount log under
~/.local/state/portablefs/mounts/ carries the daemon's own reason.
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
	if text, ok := qualificationCommandHelp(name); ok {
		return text, true
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
