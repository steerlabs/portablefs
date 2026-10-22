# Linux workspace on macOS

Status: **unreleased and unsupported**. Stage 1a specifies the product and adds
paired control and suspension models. It does not run a VM or mount. Supported
release requires every qualification gate below, including the OPEN unfenced
host-sleep clock gate. Passing the controlled-pause model cannot close it.

## Execution and ownership

Workspace files, shells, tools, builds, editor backends and agents execute in
Linux. The Mac supplies the interface through SSH. The existing volume authority
remains the sole authority; the guest is a mount host using authority protocol
8 and the ordinary Linux frontend. No authority or coherence semantics change.

One signed `PortableFSWorkspaceService.app`, nested in PortableFS.app and
registered through SMAppService, will own one persistent VM per Mac user on its
main serial dispatch queue, which also runs the MainActor coordinator and
adapter entry points. Descriptor I/O runs on dedicated serial queues without
blocking the VM-owner queue. Power
adapters capture the continuous arrival timestamp before the actor hop. Closing
the menu app leaves that service running. Only this service receives the virtualization entitlement.
Workspace setup does not require the FSKit extension.

The selected guest is Debian 13 arm64 with a pinned 6.12 kernel, glibc, systemd,
OpenSSH and a development toolchain. The development image is pinned by
`deploy/linux-workspace/image.lock.json`; the builder records its actual kernel
configuration, package/source inventory and output hashes. Release attestation
and sealed-app insertion remain Stage 2 work. Use an immutable system
disk and sparse persistent ext4 data disk; keep home, editor installations,
guest identity and machine-local route backing on the data disk. Never share
the Mac home through virtiofs. Each volume mounts at `/workspaces/<volume-id>`;
an unmounted path must deny workspace-user access so a build cannot write into
an empty backing directory. One non-root guest user, UID/GID 1000, runs clients.
Every volume has its own daemon, session, key and route backing.

The pending defaults are 4 vCPUs/4 GiB for hosts with at least 16 GiB, otherwise
2 vCPUs/2 GiB, constrained by VZ limits, and a 64 GiB sparse data disk with
free-space checks. Change resources only while stopped. Editor requirements
and measured footprint must qualify these defaults before publication.

## Mount lifecycle

The guest supervisor owns membership and recovery above each mount daemon.
The daemon remains the sole session-renewal owner. Retain the shipping client's
require-remount policy on authority epoch change.

| Event | Required behavior |
| --- | --- |
| Network changes with the same live session | Reconnect both DATA and CONTROL using exact replay. Do not replace a mount solely because Wi-Fi changed. |
| Ten-second cache horizon expires | Deny new cache/delegation admission, finish withdrawal, then subscribe cold. Reconnecting transport grants no permission. |
| Session ends, authorization expires, or authority epoch changes | Terminalize the old mount, prove exact teardown, obtain fresh product authorization and initial renewal, then create a new mount instance. Never replay uncertain old mutations. The default lease is two minutes since renewal, not two minutes guaranteed after lid closure. |
| Withdrawal, kernel absence or authorization cannot be proved | Keep the volume unavailable with its reason and retained exact cleanup identities. Never mount over it or erase its inventory. |

Inventory must retain guest boot/incarnation, authority identity, volume,
mount incarnation, exact process-start and kernel-mount witnesses, session,
enrollment, route revision, cleanup phase and the old run's loss outcome.
A reusable numeric fusectl connection ID is not an exact retained witness.
Process exit and terminal authorization do not establish kernel absence.
Stage 1a models these identities and cleanup in memory. It retains up to 128
retired outcomes with monotonic, guest-incarnation-scoped sequence numbers.
The observer retains exact outcomes, then acknowledges through a sequence;
duplicate or older acknowledgements succeed without erasing newer outcomes. Full
capacity applies temporary replacement backpressure; acknowledgement frees it.
Crash-safe inventory and real cleanup remain pending.

A replacement at the same pathname cannot transfer old fd, cwd, mapping or lock
references. Old operations fail under the terminal contract. A shell must leave
its old cwd and enter the replacement; an editor must reconnect and reopen.
Expose explicit reopen actions and report holders that prevent cleanup. Do not
silently restart arbitrary processes or describe lazy unmount as recovery.
Preserve old barrier failures even if the new mount serves successfully.

## Stage 1c control boundary

The first Stage 1c unit adds control contracts and renewal ownership. Real
workspace Mount, Umount and Provision remain unavailable in the paired guest
transport. It does not enable managed mounts or qualify host sleep.

The existing random abstract mount socket retains ordinary reauthorization and
loss snapshots. Ordinary requests are bounded by `(32 << 10) + (256 << 10) +
4096` bytes; responses by 4096 bytes. Their handler/socket deadlines remain
30/35 seconds. Workspace requests and responses each have a 64 KiB bound.
Peers are classified before capacity reservation: the exact seeded root
UID/PID/start identity has two reserved connections, with separate phase and
observation lanes; same-UID ordinary clients retain eight connections and their
accepted renewal order. Workspace phases bypass that ordinary queue. Managed
manual renewal is explicitly refused: the automatic renewal owner is exclusive.
Loss observation remains available while closed. Ordinary peers are classified
by UID alone; only the seeded root PID requires a readable start witness.

Local workspace format 8 uses strict JSON keys and canonical string uint64s.
Its exact paired, unreleased contract is
[linux-workspace-local-control.md](./linux-workspace-local-control.md).
Prepare, Recover, Suspend and Cleanup acknowledge acceptance; observations
report actual lifecycle progress, including fixed install and removal slots.
Request IDs correlate socket attempts. They retain no encoded responses,
request history or execution high-water marks. One current job retains its
immutable start identity; older operations refuse as retired, and future
observations report not-accepted. A consumed action always refuses, including
when a later delivery carries fresh descriptors.

Acceptance reserves the real job/action state and moves received rights under
one short lock. Driver work, descriptor disposal, joins and socket I/O run
outside that lock. Prepare runs at most once per incarnation; Recover consumes
its exact Resume authorization once. Suspend and Cleanup close admission and
signal old work before returning occupied until that owner joins. Fixed slots
allow one install and voluntary removal followed by terminal escalation;
successful removal cannot reverse. Observations cannot publish actions or change
admission. Install completion remains distinct from prepared readiness, and
recorded removal remains distinct from final cleanup.

Socket attempts have a maximum 45-second budget. Losing or expiring a socket
cannot cancel accepted work or erase its resources and outcomes. Suspend alone
also carries a positive `drainBudgetNanos` of at most 15 seconds. Acceptance
captures its receipt-relative deadline after charging framing and admission
delay; retry allowances cannot extend it. Observation gets its own socket
budget after the drain expires. The host transaction retains its original
cold acknowledgment and pause deadlines. A fully framed current Suspend closes
admission and cancels a legal predecessor before its drain budget is checked.
If that budget is already spent, the start is refused after the predecessor
joins; the predecessor may remain failed. The root must escalate to Cleanup,
not retry recovery or treat refusal as withdrawal completion.

`AdmitFrame` owns the immediate admission invalidation for each authenticated,
fully framed Suspend or Cleanup, before checking lanes, remaining budget or
full hangup. A truncated full hangup remains transport loss; malformed
half-closed input closes admission. The hook does not write the supervisor's
memfd. Only actual owner-pipe EOF or process death takes permanent owner-loss
cleanup; full socket loss ends its waiter. These rules retain the later
closed-start gate and lifetime-pipe implementation as dependencies.

Only install-kernel carries rights: exactly two ordered descriptors, FUSE then
abort. Close-on-exec recvmsg accounts for all ancillary input. First delivery
requires the real driver's role/bootstrap validation; every rejected delivery
closes its received inventory. Acceptance transfers rights into the job without
adding copies. Later installs refuse action-consumed regardless of descriptor
identity. No KCMP support is required.

The root bootstrap owner records its one attempt before the mount syscall,
retains original descriptions and partial witness, and retransmits only copies
of those descriptions while child ownership remains unknown. Observing accepted
child ownership closes the redundant root FUSE copy; the original abort owner
survives through independent process-exit and kernel/source/alias-absence proof.
`ObserveAbsence` starts that observation only after the bootstrap and removal
owners settle. Its proof binds the exact process, kernel, source and target
alias inventory to this bootstrap owner. Finalize rejects unbound, foreign or
stale proofs, including observation overtaken by another removal action.
Death preserves uncertain inventory and blocks replacement. The control-boundary
tests use owned descriptors; actual device/bootstrap qualification still belongs
to the later protected-path driver.

One persistent renewer retains session, next sequence, installed deadline and
exact pending grant across Park/Resume/RefreshNow. Park prevents dispatch and
joins in-flight source/installation work and its synchronized policy
disposition. An old serving attempt cannot apply its cutoff to a later
Park/Resume interval. An unknown installation retries its same sequence and
bytes. A known remote success advances the sequence even when a later Close
suppresses readiness. Recording an installation that cannot be published
invalidates the prior proof; Readiness validates the exact returned proof's
session, permit, sequence and deadline. A permit-closed installation remains
recorded and can be republished under a later current permit after Park joins
its owner. An installation for a changed session is never publishable; Resume
cannot relabel it as belonging to the current session. Both outcomes invalidate
the older proof immediately. The managed installer itself rejects
missing or stale generation/serial permits. Hosted CLI readiness requires the
first successful installer and exact Manager/installed deadline equality;
explicit standalone readiness is not-required. Starting a goroutine or
exposing a socket provides no renewal evidence. Kernel termination and
SIGINT/SIGTERM cancel pre-kernel dial, attach and initial subscription
independently of the serving lifetime, and supervise the first renewal. Once
Activate may have committed, the shared authority client retains that attempt
under an independent bounded reconciliation lifetime. It rebinds the same
session and replays the exact Activate; startup cancellation joins before an
independently bounded exact Detach. Unresolved reconciliation returns explicit
transport uncertainty. An explicit attach disposition survives the shared
routing wrapper. Ordinary startup decides its clean verdict at the attach or
kernel-startup return boundary, before callers add diagnostic errors; a later
AttachReleased member elsewhere in an error tree cannot certify cleanup. Proven
exact release permits intent finalization and enrollment closure; possible
commitment or failed release
retains authority ownership, enrollment and cleanup debt. Cancellation, a nil
client and the absence of transport uncertainty cannot prove cleanup.

The shared client's worst-case attach settlement bound is approximately
`DialTimeout + 2 * CancelDrainTimeout`: initial negotiation, independent
activation reconciliation, then exact pre-publication release. Production uses
10 seconds for each budget, about 30 seconds total. Caller cancellation does
not shorten the latter two owners. `RecoverEpoch` uses the same attach bound.
The macOS FSKit initial attach runs through the CLI's 60-second daemon HTTP
client; the daemon sets no shorter handler deadline. Preflight's separate
10-second socket deadline follows completed attach and does not perform it.
FSKit frontend operations have a 50-second daemon admission budget and a longer
announced request deadline; the macOS data plane does not call RecoverEpoch.
These caller budgets accommodate the shared-client bound without adjustment.
A queued startup signal prevents publishing mounted readiness. The child bounds
startup at two minutes from entry, leaving rollback time inside the parent's
three-minute limit; renewal failure is delivered before detach retries finish.

Managed Resume republishes a recorded installation under the new permit only
while its deadline remains beyond the ordinary safety cutoff. It obtains no
new Manager sequence for that proof. RefreshNow means an immediate scheduling
decision: ordinary owners can refresh early; managed owners preserve the
normal mid-window Manager refresh time for a recorded install. Pending unknown
installs reconcile their exact sequence/body even past the previous
authorization deadline. Managed closed preparation retries transient failures
with bounded attempts and backoff until a definitive outcome or generation
cancellation; it grants no serving extension. This no-cutoff policy ends when
readiness is published in the current permission interval. Serving managed
owners and ordinary owners enforce the same safety cutoff, bounded attempt
deadline and retry cutoff. The future managed driver must Park its serving
renewal owner before the cutoff, or accept terminal cleanup and replacement
afterward. Park/Resume cannot revive a terminal owner, even when Manager
service returns. Readiness checks the cutoff synchronously, even before the
scheduling loop wakes. Park withdraws readiness before joining work; Resume
near expiry remains pending and recovers behind closed admission. All owners
invalidate readiness atomically on terminal denial or cutoff and before stop
observation. Malformed Manager grants and installed-deadline mismatches
terminate automatic renewal on Linux and macOS rather than retrying an
untrustworthy grant.

Paired status uses renewal states pending, installed with a positive sequence,
and explicit standalone not-required with sequence zero. Every status/cold
entry carries durability (`durable`, `lost`, `unresolved`), observation
(`observed`, `unobserved`), release (`released`, `expired`, `abandoned`,
`unresolved`) and counted cleanup debt. Initial unknown evidence is
unresolved/unobserved. Known loss remains separately cumulative and survives
failed or overtaken Prepare/Recover, cold completion, replacement and retirement.
Unknown observation cannot certify durability or release. Within an interval,
new evidence cannot erase a known disposition or reduce cleanup debt. Only a
successful admission publication starts fresh disposition evidence; failed Open
retains it. Cleanup debt and loss remain cumulative across intervals.

Close advances an exact serial even within one generation. It immediately denies
new admission and defeats delayed prepared publication; it does not retract an
already admitted operation. Completed withdrawal requires Suspend's joins.
Prepare/Recover belong to their generation, retry classified transient failures
with bounded attempts/backoff, and have no 45-second logical deadline. Only
current session/authorization validation, a functioning renewal owner and fresh
subscription evidence can authorize publication. A genuine failed Prepare or
Recover permanently ends serving preparation for that mount incarnation. The
terminal fact survives replacement of its job and cold transaction. Later
Suspend may withdraw state, but reports the retained failure instead of a new
cold recovery opportunity; exact Cleanup remains available. The Mount driver returns an explicit lifecycle disposition:
Completed requires successful publication and no error; Overtaken asserts only
job-overtaking cancellation, with no independent work or teardown failure;
Failed includes independent failures even when joined with cancellation.
Overtaken avoids the terminal latch only when the owner recorded cancelling
that exact job. Error-chain membership never determines the outcome. A
cancellation-only teardown may omit the context error without ending the
incarnation. Missing dispositions and unrecorded cancellation fail closed.
Recover on a terminal incarnation refuses `incarnation-terminal` in the local
mount-control grammar, separately from malformed-frame `invalid`. The supervisor
does not renew sessions. These remain typed driver contracts until the real
admission, clock and lifecycle owners exist.

## Controlled suspension transaction

All app-initiated pauses must use this transaction. Power notifications must
register before VM startup; registration failure refuses startup. Missing
service state defaults to discard, and no RAM state survives an app/service
replacement. These rules are independent of the unresolved uncontrolled path.

1. **Close admission and fix membership.** Invalidate prior resume eligibility,
   close attach/restart admission, and capture boot, host and guest service
   incarnations, a new monotonically increasing generation and fresh suspend
   nonce. The guest alone owns membership: the host sends no roster, and the
   guest fixes it atomically with closure and returns it in the acknowledgement.
   Every daemon starts closed and cannot acquire permission before registration.
   A refused start receives exact process/kernel cleanup; failed cleanup retains
   its witness for retry. Any identity-matching Suspend closes every daemon and
   cancels the generation before other checks; refusal leaves admission closed.
   Reject replies for older generations.
2. **Prove SUSPENDED-COLD.** Every daemon atomically denies ordinary serving,
   cache publication and delegation admission while retaining drain/control.
   Interrupt capacity-blocked writers, settle admitted work and physical FUSE
   replies, clear metadata/name/enumeration state and complete kernel data and
   attribute withdrawal. Quiesce renewal, recovery and queued replies so they
   cannot reinstall permission. Attempt the accepted-entry durability cut and
   exact delegation release within the old valid generation. An unprovable tail
   advances the loss ledger and fails affected barriers; never replay it after
   resume. Report cold completion and loss separately. Blocked or failed
   invalidation earns no cold acknowledgement. Serialize Prepare, Recover,
   Suspend and admission publication per mount. A new suspension cancels the
   preceding generation and waits for overtaken driver calls before withdrawal.
   Each reusable proof must retain and recheck the exact generation/close serial.
   A close racing local installation leaves that result inert; it cannot forget
   a known remote renewal sequence. Suspend joins and retires raced work before
   acknowledgement.
   Only exact process exit plus kernel absence makes a terminal mount trivially
   cold. Other terminal mounts still require withdrawal. The Go
   `workspaceguest.Mount` interface defines this boundary; Stage 1c must implement
   it in the daemon.
3. **Confirm pause before acknowledging sleep.** Await VZ's successful pause
   completion on its serial queue. Eligibility requires the complete roster's
   cold acknowledgement and confirmed pause for the same generation. Host
   continuous time measures every budget, including delayed callbacks. The
   control queue must be empty before pause. Retirement acknowledgement is
   permitted only while running or recovering. The model defaults to absolute
   deadlines of 15 seconds for drain, 17.5 seconds
   for confirmed pause and 20 seconds total after native notification arrival,
   reserving stop time within that budget. The timestamp precedes the MainActor
   hop; queue delay consumes the budget. This does not bound the gap between
   system posting and native callback execution. Sleep during VM resume carries
   the same deadlines, and insufficient remaining time attempts stop. Every
   notification receives exactly one acknowledgement, including during startup,
   stop and unknown state. A non-increasing notification ID violates the power
   adapter contract and takes the unknown-transition stop path. Confirmed
   termination unregisters participation. A failed drain
   still attempts pause but marks the VM discard-only. A failed or late pause
   attempts stop. Neither an invocation nor a stop request establishes a fence;
   an unconfirmed stop leaves unsafe/unknown state and acknowledges no fence.
   A real power adapter must release its sleep participation within its budget;
   the product never prevents laptop sleep as its correctness mechanism.
4. **Resume cold or discard.** Consume eligibility once. Only a confirmed cold,
   paused VM may execute old guest RAM, with every mount still closed. Send a
   single-use token bound to boot, both service incarnations, generation,
   guest-acknowledged roster, suspend nonce and a fresh wake nonce. The guest
   accepts any nonzero correctly sized wake nonce; exact suspension equality and
   the consume-once phase transition enforce single use. It permits recovery only:
   validate live authority session and authorization, install initial renewal
   and a fresh cold subscription with new request anchors/incarnation, then
   reopen admission. Terminal mounts require supervised authorization/remount.
   A second sleep invalidates pending authorization; serialize VM completions
   and run a newer suspension before sending any delayed token. A stale
   recovery result cannot reopen the newer generation. A repeated notification
   while already cold and paused acknowledges that fence directly; it needs no
   extra resume/drain/pause cycle. Bound only VM resume completion on wake, not
   authority recovery. The guest consumes the token, returns per-mount recovering
   status and recovers mounts independently. A slow or unavailable authority
   keeps its mount recovering while its driver is pending. Prepare and Recover
   return only when ready is proven, terminal or authorization-required state is
   proven, or their context is cancelled. Drivers retry transient transport
   failures internally under the supplied generation context, holding the
   per-mount lane and using fresh request anchors for each attempt. BeginSuspend
   or ChannelLost cancels that context. A failed Prepare or
   Recover terminalizes that mount; exact cleanup and replacement with a new
   incarnation obtain a fresh Prepare proof. The supervisor does not retry a failed call.
   Other mounts and shells continue. Status polling reconciles an invalid but
   decodable recovery reply; paired-channel loss discards the VM. Initial activation and replacement
   obtain generation-tagged proofs from the driver, never from the caller.
   Stage 1c must dispatch an initial Prepare outside Serve's serial request loop:
   a long retry there would queue a sleep's Suspend behind authority recovery.
   Discard-only/uncertain
   state stops without resuming old RAM; only exact termination permits a new
   coordinator with a new boot identity. A cancelled sleep reconciles the current
   generation by the same cold recovery path. Dark wake stays paused. Startup
   and the paired Hello share one deadline: the model defaults to 20 seconds;
   the development driver sets 150 seconds for first boot and data formatting. Unknown stop state retains
   any outstanding stop and queries the exact VM state before another attempt;
   another wake never duplicates a pending stop.

Voluntary updates require a clean drain and shutdown; defer an undrainable
update. Forced sleep may report loss and discard. Neither policy converts
accepted volatile data into durable data.

## Unfenced host sleep: OPEN release gate

A power notification can be posted without the host service completing its
handler before the system's acknowledgement timeout. Delaying that service
while the VM worker remains live supplies the counterexample: after sleep,
guest work can execute before the service handles wake. This does not require
assuming thermal or low-battery sleep omits notification.

The experiment measured frozen guest BOOTTIME during public VZ pause and
successful stale held-fd, size and name observations after peer completion.
Later REALTIME correction did not repair BOOTTIME. Awake-host SIGSTOP advanced
guest clocks; neither method establishes actual host-sleep ordering. The
controlled fence removes deliberate pause from the continuity requirement by
withdrawing permission beforehand.

Supported release still needs a guest-visible elapsed clock that includes
unfenced host sleep before the first resumed admission, within the authority's
clock-error budget, or platform enforcement that prevents affected execution
until complete withdrawal/replacement. No such mechanism has been established
for the proposed macOS 26/27 configurations. The separate PL031 measurement
remains research, not an implemented clock mechanism.

Wake callbacks, watchdogs, periodic timestamps, a shared heartbeat, NTP/REALTIME
updates and guest timers provide eventual detection. A pre-sleep vsock clock
response can arrive after wake; a second acknowledgement moves that gap.
None supplies the missing ordering proof. Do not add a clock workaround or
claim that later remount repairs earlier stale success. If the platform cannot
supply the required mechanism, it cannot support this release architecture.

The workspace also inherits the stock Linux stalled-daemon resident-page
residual in [portable-coherence.md](./portable-coherence.md): a daemon that
cannot run cannot withdraw kernel pages before a consumer observes them.
Successful stale daemon metadata/name admissions due to a frozen clock are a
separate defect. Stage 1a makes no stronger kernel claim.

## Paired workspace control 8

The new, pending local surface is
[`proto/workspace/v8/control.proto`](../proto/workspace/v8/control.proto), with
package `portablefs.workspace.v8`. Its exact version is **8** on every envelope;
there is no negotiation, compatibility decoder or earlier-version path. This
addition does not renumber the independent frozen pfslocal, daemon control or
lifecycle interfaces in [COMPATIBILITY.md](../COMPATIBILITY.md).

Use one ordered vsock byte stream bound to the owned VM. A four-byte unsigned
big-endian payload length precedes one canonical protobuf Envelope. Payloads
are 1 through 1,048,576 bytes; no bulk trailer, compression or alternate framing.
Ascending field tags, minimal varints and omitted default scalar values are
mandatory. Reject unknown fields/bodies, duplicate singular fields, multiple
oneof members, incorrect wire types and noncanonical encoding before dispatch.
The descriptor-generated scanner bounds repeated fields at 128 and nesting at
16 before protobuf allocation. Semantic validation further limits rosters to
64 mounts, byte/string fields to 65,536 bytes, volume IDs to 128 ASCII bytes,
release versions to 128 bytes, reasons to 256 UTF-8 bytes and endpoints to
4,096 bytes. IDs/nonces
are nonzero 16-byte values; authority, image and route digests are nonzero
32-byte values. Commits are 40 lowercase hexadecimal bytes. Volume IDs use letters, digits, dot, underscore and hyphen; they must be
nonempty single path components other than dot/dot-dot. Release versions use
printable ASCII without spaces. These restrictions make identity comparisons
byte-exact in both languages.

A roster sorts by byte order of the joined lowercase `hex/volume/hex` key;
this is not tuple order when a volume is a prefix of another. One
authority/volume appears once. Repeated per-mount results equal that ordered
roster exactly. Loss sequences increase strictly and remain cumulative for the
mount incarnation. Reports carry at most 32 records per mount with 256-byte
reasons. On overflow the first 31 records remain fixed and the final record
aggregates the remainder, retaining the highest sequence and saturating
accepted-entry/byte counters. The driver retains exact barrier outcomes.
Overflow terminalizes only that mount for exact cleanup/replacement; its cold
withdrawal still counts toward suspension. Later reports cannot reduce a
reported aggregate. Even 64 active and 16 retired maximum-size mount ledgers, statuses and identities
fit a 1 MiB frame by construction. Cold completion never implies loss-free
durability.

| Body | Required meaning |
| --- | --- |
| Hello / HelloAck | First paired exchange: app version, commit, image digest and authority major 8, boot nonce and host-service incarnation. Host leaves guest-service ID empty; guest responds with its fresh incarnation. Exact release/boot/host equality is required before other requests. Restart invalidates the pairing and all old tokens. |
| Suspend / SuspendAck | Request carries transaction identity with an empty roster. The guest fixes membership and returns it with every mount's loss ledger only after whole-roster cold completion. There is no partial cold acknowledgement or redundant cold bit; Status reports progress. |
| Resume / ResumeAck | Full suspension plus new wake nonce. Consume once; reply echoes the exact token with each mount's recovery/cleanup status and retained loss. It grants no authority permission itself. |
| Status / StatusReply | Typed boot/service/generation state and mount statuses. Terminal authorization and retained cleanup remain distinct. |
| RetireAck / Result | Status reports the first 16 unacknowledged retired outcomes. Each outcome has a monotonic retirement sequence. After retaining the outcomes, the observer acknowledges through a sequence in the exposed batch; duplicate/older acknowledgements succeed, future acknowledgements are refused without closing the channel. The host keeps one acknowledgement in flight; the guest frees only acknowledged capacity. No unobserved outcome is evicted. |
| Provision | Mount identity, authority endpoint, CA, client certificate, signed capability, route revision and guest-generated public key only. No private-key or issuer-key field or import path. The guest compares public-key bytes with its locally generated identity before accepting provisioned material; a substring scan does not establish key identity. |
| Mount / Umount / Result | Exact mount identity; typed accepted, unavailable, authorization-required or refused result with a reason. Admission remains subject to the fixed-roster and local-volume reservation rules. |

Every envelope has a nonzero request ID. The host allocates strictly increasing
IDs within a paired channel; each response echoes its request ID and expected
body. Hello is the only request before pairing. One suspend generation and at
most one resume authorization are outstanding. A malformed frame, mismatched
response, unequal version or broken channel closes the channel and invalidates
eligibility; do not transparently reconnect and reuse a token. Stage 1b connects these codecs and models to a correlated vsock stream. The
guest accepts only host CID 2 on reserved port 1023, requires its independently seeded
boot/service identity and exact release, and consumes one paired stream per
boot. Disconnect discards its model; supervisor restart within that boot is
refused. Provision, Mount and Umount return `unavailable`. The dev process is
the sole host caller; the signed-process local service API is Stage 2 work.

Host-side callers must pass the existing same-user signed-process/audit-token
check. The guest channel must bind to the app-owned VM and fresh boot nonce.
Generate mount private keys in the guest and keep them there. The Mac relays
public enrollment and provisioning material; no Mac FSKit key or issuer signing
key enters the guest. Signed capabilities must also stay out of logs. Hosted
renewal scopes must separate guest incarnation and volume from Mac enrollment.
Without an authorized fresh issuer, terminal recovery reports
`authorization-required`.

Generate the Go and Swift bindings with `scripts/generate-workspace-proto.sh`,
using the Go protobuf version in go.mod and the exact SwiftProtobuf package pin.
It also generates the Swift allocation-bound wire table from protoc descriptors
and schema/binding digests checked by the Go suite. Golden frames live beside the
schema and in the Swift test bundle. Both languages decode/re-encode every
valid frame and refuse the shared invalid frames. The native Xcode inventory
includes `PortableFSWorkspaceCoreTests` in its one test process and requires
exact equality with all-passing xcresult identifiers.

## Local coexistence and networking

Refuse a local FSKit and local workspace mount of the same authority/volume in
either order, including read-only FSKit requests. Serialize checks and pending
reservations across both signed services and all CLI entry points. Consult
authenticated live inventories; key by authority identity and volume, never an
endpoint alias or display name. Authority exclusion remains the final global
arbiter. A remote Mac writer can make Linux mutations return EBUSY; expose it.
Other volumes may use FSKit concurrently. The cross-service reservation layer
is pending; these model targets cannot create a real mount.

Use VZ NAT only, with direct guest DATA and CONTROL TLS to the advertised
authority. Guest localhost means the guest; reject copied host-loopback
provisioning endpoints. Qualify split DNS, full/split VPNs, IPv4, dual stack and
IPv6-only authorities. Host ping or TLS success is insufficient. Do not add a
host relay, bridged-network substitution or hidden authority proxy. Local
Network privacy must qualify the installed signed VM owner, including app
replacement and exact old-process termination.

The dev SSH entry `portablefs-workspace` uses an owner-only host Unix socket
and bridges directly to vsock port 22. A systemd `ListenStream=vsock::22` socket
starts OpenSSH in inetd mode; no guest TCP SSH listener exists. Use separate SSH credentials and a pinned, persistent guest host
key. Install an app-owned include only through explicit setup, preserving
unrelated SSH configuration. Qualify VS Code/Cursor, Zed and JetBrains Linux
arm64 backends independently; local UI or AI networking does not establish that
file tools execute in Linux.

## Development artifact and boot path

Run from an Apple-silicon Mac with macOS 26+, Xcode and Docker:

```sh
bash scripts/build-linux-workspace-image.sh /absolute/image
bash scripts/build-linux-workspace-dev.sh
swift/PortableFSKit/.build/out/Products/Debug/portablefs-workspace-dev /absolute/image /absolute/state
```

The builder uses mmdebstrap in its own container with SYS_ADMIN for mmdebstrap mounts from the digest in
`image.lock.json`, with Debian trixie at one snapshot timestamp and
`SOURCE_DATE_EPOCH` and a fixed ext4 creation clock. Security and updates use the
same snapshot timestamp; hostname and hosts are explicit. The native gate builds
twice and compares every manifest hash. It checks the complete installed binary/source version
inventory against that lock. `--update-lock` explicitly refreshes that inventory;
`--reuse` reuses only matching input identity and package inventory. There is no
boot-time package installation, upgrade or fetch. Debian's archive signatures
check the snapshot indexes, including the builder bootstrap over HTTP.

The artifact directory contains `kernel` (an uncompressed Debian arm64 Image),
`initramfs`, `system.ext4`, `kernel.config`, `initramfs.inventory`,
`packages.json`, `packages.tsv`, `source-manifest.json`, `licenses.tar.gz`,
`bin/{portablefs,portablefsd,portablefs-workspaced}`, `image-inputs.json`, `release.json` and
`manifest.json`. The kernel is on Debian's maintained 6.12 line. Required block,
network, console, vsock, entropy, FUSE and ext4 drivers must be built in or
present in the initramfs; source configuration alone is insufficient for modules.
Package copyright/source notices remain in the system image under
`/usr/share/doc`. `packages.json` records binary and corresponding source names
and versions at the pinned snapshot. Release source redistribution and the
attested client archive insertion are not implemented by this development build.

`image-inputs.json` canonically hashes the pinned snapshot/builder recipe,
image overlay and exact static Linux/arm64 client/supervisor binaries. Its SHA-256
is the noncircular image identity embedded in `release.json`; `manifest.json`
additionally binds the actual generated disk, kernel, initramfs and inventories.
The owner verifies exact manifest membership and every output hash before VZ
configuration. The dev build script compiles the host source commit into the
executable before ad-hoc signing with only `com.apple.security.virtualization`.
An unconfigured SwiftPM executable or unequal host/guest commit refuses boot.
Development images do not have release attestation or a signed resource seal.

The VZ owner uses the main serial dispatch queue for configuration, operations
and completion callbacks. Devices are Linux direct boot, read-only virtio system
block disk, writable data block disk, NAT, vsock, two virtio serial consoles and
entropy. No shared directory, RAM save/restore, bridged network or host authority
relay is configured. IOKit power notification registration must succeed before
start. A controlled pause enters the existing coordinator; only confirmed cold
pause creates single-use resume eligibility. The real adapter uses host
sleep-inclusive continuous time for deadlines and releases sleep participation
within its bounded budget. This does not establish the unfenced-sleep invariant.

The state directory has an exclusive owner lock, a 64 GiB sparse `data.ext4`,
a separate persisted host SSH client key, pinned guest host public key,
`known_hosts`, `ssh_config` and `serial.log`. Durable host format authorization
is console-seeded on every boot until the guest reports format 8 complete.
Interrupted formatting can retry within that authorization; after its removal,
unrecognized or corrupt data is never reformatted. Disk, keys and state files
are fsynced under temporary names, renamed, then directory-fsynced. The guest
validates SSH private keys with `ssh-keygen -y` and fscks data before mounting.
The data filesystem retains format 8, home/editor installs, SSH host identity,
home and SSH identity. A persisted host-side machine ID and locally administered
MAC fix the guest network identity. `/var`, `/tmp` and
`/run` are volatile. `/workspaces` is a root-owned mode-0755 tmpfs; Stage 1c
creates each volume mount point root-owned mode 000, so unmounted volume roots
deny access while mounted roots remain traversable.

The second virtio console provisions only fresh boot/service nonces and the host
client public key. The guest generates and persists its private SSH host key on
the data disk and returns the public key over that VM-bound console. The owner
checks the persisted pin before opening its mode-0600 Unix socket in the
validated mode-0700 owner directory, and fails on a changed key. The
guest proves knowledge of its seeded nonce before the host sends Hello, which pairs app version, commit, image digest, protocol 8 and both
service incarnations. No host private key or Mac FSKit identity enters Linux.

The executable prints a JSON `ready` event containing the SSH stanza and its
config path. Use `ssh -F /absolute/state/ssh_config portablefs-workspace`.
The stanza uses `ProxyCommand /usr/bin/nc -U` for standard OpenSSH transports,
including Remote-SSH. This preserves the generated-config workflow and excludes
other local users, so there is no loopback TCP listener. Full editor qualification
remains pending. Relay descriptors use nonblocking dispatch sources, bounded
buffers and dedicated serial queues; the cap includes pending vsock connects.
The control stream uses a dedicated descriptor-I/O queue; its FIFO request
queue runs on MainActor with the VZ owner. Requests carry deadlines
supplied by the coordinator. No global SSH configuration is edited. Standard input accepts one JSON command
per line: `{"command":"pause"}`, `resume`, `status` or `stop`. Pause/resume and stop use
the real coordinator. The native gate resends an already-consumed token over
the paired stream and proves guest refusal followed by discard. A normal running stop asks
the guest to shut down and waits for VZ's guest-stopped delegate callback. Unsafe
or paused instances take the coordinator's confirmed stop path instead.

Run the native gate with explicit artifact and evidence directories:

```sh
bash scripts/test-linux-workspace-native.sh /absolute/image /absolute/evidence
```

It builds or verifies/reuses the pinned image, builds and signs the owner, then
requires exact equality with `scripts/linux-workspace-required-native-tests.txt`.
It boots fresh guests, proves real FUSE INIT >= 7.31 on a throwaway filesystem, and checks
fresh in-VM Hello refusals for mismatched app version, commit and image digest,
UID/GID 1000 and tool execution through pinned SSH (including literal percent
characters in every generated path), read-only root and no TCP
SSH listener, unmounted-path denial, data/key persistence, cold VZ pause completion,
empty-roster recovery, actual token-replay refusal and clean guest shutdown.
`results.json` records boot time, idle guest memory and owner RSS; `events.jsonl`
and serial logs retain the transaction. The no-mount recovery is not authority
validation or real FUSE withdrawal evidence. Unsupported virtualization is a
named **UNAVAILABLE** gate with nonzero exit status, never a passing skip.

Guest wall-clock correction after a host pause is Stage 1c work. No RTC, wall
clock or NTP observation is used to assert sleep safety. The unfenced host-sleep
gate remains OPEN; the separate PL031 experiment is not part of this change.
The coordinator owns each native notification's arrival-relative deadline;
IOKit has no second release timer. An expired notification is explicitly released
unfenced and cannot later earn cold eligibility. Unexpected VZ stops unregister
power participation and revoke resume eligibility.

## Remaining construction and qualification

Stage 1b adds a development image, public VZ and IOKit adapters, VM-bound
bootstrap console, exact vsock control, pinned SSH bridge and native gate. It
creates no PortableFS mount and registers no synthetic participant. Cold proof
and recovery use the empty guest-owned roster. The FUSE probe is invoked only
by the native gate as the ordinary workspace user, never by a boot service.
The real daemon suspension boundary, durable mount inventory and provisioning
remain Stage 1c work. Production service registration, app UI, workspace CLI,
release packaging, update coordination and editor qualification remain pending.

All new workspace surfaces are pending and unreleased: the control grammar,
service identity/entitlements, guest paths, inventory format, image manifest,
SSH entry and proposed workspace command namespace. Define exact CLI flags and
status schemas when their implementation is ready. Do not repurpose any
existing frozen surface. Preserve the two-binary Linux client archive; a future
separate attested workspace asset must bind the exact image, kernel, package
sources/licenses, PortableFS commit and sealed app resources.

| Gate | Status and evidence required |
| --- | --- |
| Controlled fence | Stage 1a model tests and Stage 1b native VZ transaction with an empty roster. Real managed-daemon withdrawal and the full duration/fault matrix remain pending. Typed initial-renewal readiness is covered at the control boundary. Test 5/15/45/150/600-second pauses, lost channels, blocked invalidation, stale replies/tokens, mount races and crashes. |
| Unfenced host sleep | OPEN. Identify the clock/execution mechanism and ordering, then qualify actual lid/menu/idle sleep on exact supported OS/hardware/image digests with independently advancing remote authority and peer. Delay the service past the notification timeout. A finite successful sample cannot replace the mechanism. |
| Short-sleep availability | Root cause identified: authority replay-before-coherence admission ordering. Fix and regression work are in progress in a separate PR. This stage does not change the authority or Linux data plane. |
| Image, lifecycle and persistence | Pin Debian artifact; prove boot/FUSE INIT and kernel notification/durability behavior. Prove exact teardown/remount with cwd, fd, mapping and editor holders, no empty-directory writes, ENOSPC/image-corruption handling, signed updates and same-volume exclusion. |
| Protocol-8 correctness | Full privileged Linux integration and coherence matrix, root barriers, dirty-tail loss, authority restart and power-loss qualification. The experiment's 22 passes, 7 skips and relay topology do not qualify the product. |
| Network, editors and performance | Installed signed-owner NAT/privacy/VPN/IPv6 tests and each claimed editor. Measure direct product-topology RPC RTT, latency tails, Git/search/index/save and resource use without the lab relay. No performance SLO follows from the experiment. |

Default local verification plus the separate native workspace gate covers
Stage 1b's transport and VM owner; it touches no authority or real PortableFS
frontend/coherence execution path. Stage 1c and
real product integration require full verification and native workspace gates.
Neither this document nor model success qualifies the planned feature. Intel,
multiple VMs, custom images, RAM snapshots/migration, Rosetta, root-system
customization and Linux desktops remain deferred. No Finder mirror, native Mac
re-export, synchronization engine or automatic remote-workspace substitution
belongs to this product.

### Later PR obligations from the Stage 1c control review

- macOS enrollment closure (Opus r6 note 1): when portablefsd consumes the
  attach disposition, `registry.go` must retain the Manager enrollment on
  AttachCleanupRequired until exact cleanup proves release. Qualify both
  successful Detach and failed/uncertain release through the daemon path.
- Prepared-publication cancellation (note 3): this control owner now cancels
  its job context when a permit rejects publication. The protected-path Mount
  driver PR must join that cancellation, return Overtaken only without an
  independent failure, and prove a retry cannot remain pending or publish under
  the closed permit.
- Managed renewal observation (note 6): the managed consumer PR must publish
  the retained permit-closed remote install and its Resume republication to
  observers, including RenewalSucceeded semantics. Prove readiness and Observe
  agree on the exact session, sequence, deadline and current permit.
- Bootstrap entry ordering (note 7): the protected-path root driver PR must
  distinguish a never-begun Bootstrap from outstanding work at Finalize and
  prove its callers never interpret occupied as an accepted Begin or as
  evidence of absence. This boundary currently returns occupied in both cases.

### Stage 1c drain dispatch

The current guest transport drains its roster serially. Stage 1b registers no
real mounts, so native suspension exercises an empty roster. Stage 1c must
start mount drains in parallel under the coordinator's remaining drain budget,
cancel unfinished work at expiry, and prove whole-roster completion before
acknowledging cold state. The current suspension grammar carries no drain
budget; the transport's service-lifetime context does not bound each request.
Parallel dispatch alone would not establish this deadline contract. Real mount
integration must supply both deadline propagation and cancellation before it
can qualify the 15-second boundary.

Data formatting relies on mke2fs's device flush before successful exit. The
initializer treats that completion as its format boundary; it does not use
`sync -f /dev/vdb`, which would synchronize devtmpfs rather than the device.
