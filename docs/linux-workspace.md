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
OpenSSH and a development toolchain. The exact image lock, kernel configuration,
packages and digests remain to be built and qualified. Use an immutable system
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
   Each driver must atomically check the latest close generation and cancellation
   before installing any subscription or renewal; failed or overtaken calls install
   nothing, including background renewal.
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
   stop and unknown state. Confirmed termination unregisters participation. A failed drain
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
   and the paired Hello share a 20-second deadline. Unknown stop state retains
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
eligibility; do not transparently reconnect and reuse a token. Stage 1a supplies
the grammar/codecs and typed model interfaces; the real correlated vsock
transport, authentication and dispatch remain pending.

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

The planned SSH entry `portablefs-workspace` binds a host listener to loopback
and bridges vsock to guest-loopback sshd, avoiding unstable guest IPs and LAN
SSH exposure. Use separate SSH credentials and a pinned, persistent guest host
key. Install an app-owned include only through explicit setup, preserving
unrelated SSH configuration. Qualify VS Code/Cursor, Zed and JetBrains Linux
arm64 backends independently; local UI or AI networking does not establish that
file tools execute in Linux.

## Remaining construction and qualification

Stage 1a contains no VM/image, VZ or power adapter, vsock listener, signed service,
real mount suspension, durable guest inventory, provisioning dispatcher, CLI
workspace commands, SSH bridge, editor integration, release asset or installer
change. The guest daemon command remains absent from product registration
until Stage 1b supplies its real transport. No new runtime environment switches,
fallback paths or authority behavior accompany it.

All new workspace surfaces are pending and unreleased: the control grammar,
service identity/entitlements, guest paths, inventory format, image manifest,
SSH entry and proposed workspace command namespace. Define exact CLI flags and
status schemas when their implementation is ready. Do not repurpose any
existing frozen surface. Preserve the two-binary Linux client archive; a future
separate attested workspace asset must bind the exact image, kernel, package
sources/licenses, PortableFS commit and sealed app resources.

| Gate | Status and evidence required |
| --- | --- |
| Controlled fence | Model tests only in Stage 1a. Real daemon withdrawal, initial-renewal readiness and VZ completion ordering remain pending. Test 5/15/45/150/600-second pauses, lost channels, blocked invalidation, stale replies/tokens, mount races and crashes. |
| Unfenced host sleep | OPEN. Identify the clock/execution mechanism and ordering, then qualify actual lid/menu/idle sleep on exact supported OS/hardware/image digests with independently advancing remote authority and peer. Delay the service past the notification timeout. A finite successful sample cannot replace the mechanism. |
| Short-sleep availability | Root cause identified: authority replay-before-coherence admission ordering. Fix and regression work are in progress in a separate PR. This stage does not change the authority or Linux data plane. |
| Image, lifecycle and persistence | Pin Debian artifact; prove boot/FUSE INIT and kernel notification/durability behavior. Prove exact teardown/remount with cwd, fd, mapping and editor holders, no empty-directory writes, ENOSPC/image-corruption handling, signed updates and same-volume exclusion. |
| Protocol-8 correctness | Full privileged Linux integration and coherence matrix, root barriers, dirty-tail loss, authority restart and power-loss qualification. The experiment's 22 passes, 7 skips and relay topology do not qualify the product. |
| Network, editors and performance | Installed signed-owner NAT/privacy/VPN/IPv6 tests and each claimed editor. Measure direct product-topology RPC RTT, latency tails, Git/search/index/save and resource use without the lab relay. No performance SLO follows from the experiment. |

Default local verification is appropriate for Stage 1a's isolated model targets;
it touches no authority, frontend or coherence execution path. Stage 1c and
real product integration require full verification and native workspace gates.
Neither this document nor model success qualifies the planned feature. Intel,
multiple VMs, custom images, RAM snapshots/migration, Rosetta, root-system
customization and Linux desktops remain deferred. No Finder mirror, native Mac
re-export, synchronization engine or automatic remote-workspace substitution
belongs to this product.
