# G3 clock-soak evidence

The qualifier accepts one uninterrupted, host-awake 72-hour run. Its 8,640
half-open 30-second slots are distinct from the closing observation. At least
8,554 slots must contain authenticated, agreeing NTS evidence from two approved
operator groups. Opening and closing observations require direct references;
actual reference-anchor separation cannot exceed 120 seconds. Aliases and
address families do not create additional operators. Every authenticated
response participates in agreement, including during planned guest pauses.

Ordinary source measurements retain the one-second source allocation, strictly
less than one second of quantization, sample/set age at most 250 ms, awake guest
wall/BOOTTIME drift at most 250 ms, and conditional total at most three seconds.
The records retain host wall/monotonic brackets and RTC-to-host intervals.
Guest BOOTTIME projection is never accepted across a planned pause/recovery
window. Missing measurements or inconclusive source intervals remain
inconclusive. Established source, age, drift, conditional-total or admission
violations remain failures even if subsequent observations pass.

The policy implementation supports bracketed interval propagation from both
surrounding reference anchors. It requires an independently supported, pinned
pointwise awake host-monotonic rate envelope with rho at most 500 ppm, retains
both timing brackets, intersects both propagated intervals, and applies the
existing source budget. It does not extrapolate endpoints. This campaign pins
no such envelope. Guest wall/BOOTTIME agreement and authenticated endpoints do
not exclude a common clock excursion. The approved fallback is improved direct
collection; an ordinary source measurement without a direct reference remains
inconclusive. The 99 percent availability policy does not override that result.

The five approved operator groups and exact hostnames are in
[`policy.json`](../scripts/nts-reference/policy.json). Collection is concurrent,
tries available IPv4 and IPv6 paths, preserves TLS hostname verification and
NTS authentication, allows one retry per failed operator, and shares a
nine-second aggregate deadline. A missing or failed path is recorded; no
unauthenticated fallback or favorable-pair selection exists.

The exact pause inventory contains 12 six-hour blocks, three fencing modes and
eight durations (0.1, 0.5, 2, 5, 15, 45, 150 and 600 seconds). Acceptance checks
identities and actual three-hour idle/load placement. A prestarted reader in
the product VM duplicates a managed daemon's inherited read-only RTC description,
which comes from the root service's retained opening
using pidfd_getfd under the image’s existing same-user ptrace policy. It records its first read after the requested pause, the
sealed clock page's exact generation before and after that read, boot/service
identity, host resume-to-receipt bracket and NTS exchanges. If the raw ioctl straddles generation publication, both generations remain
explicit and must belong to this case’s single armed-to-recovered transition.
The raw RTC interval makes no BOOTTIME projection or admission decision; the
ordinary projection guard requires the completed recovery generation. Unexpected
generation changes remain inconclusive. Eight duplicated
readers then perform at least 8,000 reads per case, with maximum age at most
250 ms. Ownership also retains the root service’s published read-only/second-open-busy
inspection; an unprivileged second-open permission denial is recorded separately.
Separate two-second initramfs evidence remains fixture evidence.
These observations qualify the prestarted reader in the product VM; they do
not establish scheduler ordering against every other RTC reader in that VM.

The run pins candidate, image, host owner, harness files, reference binary and
policy before boot. The image commit can differ from the harness commit only
with a recorded path/diff assessment. The run owns its caffeinate assertion,
and uses a private, prestarted SSH master for ordinary probes. Reusing the
connection removes handshake latency from the charged sampling bracket; it
does not narrow a bracket after collection or change any acceptance bound.
The master disables keepalives during scheduled guest pauses, never adopts an
existing socket, and stops through its exact owned process identity. No SSH
control command or shared transport socket is used. The run owns its
guest, authority container and independent peer. Docker events, process/boot
identities, host awake/continuous clock pairs and durable peer progress detect
unplanned disruption. The sampler independently checks its exact parent PID,
fresh owner/authority/peer heartbeat, and host awake/continuous clock pairs;
owner loss cannot leave a qualifying orphan sampler. Any authority pause, host sleep/reboot, guest/owner
restart or lost authority/peer continuity invalidates the run. Evidence is
preserved, the owned resources stop, and the next run starts at zero in a new
directory. No interruption is subtracted and no run is spliced.

UTC, RTC admission and aggregate G0 remain separate verdicts. Qualification is
scoped to the pinned candidate and image. A UTC-source campaign can remain
applicable when later directory-cache or RTC-sampling consolidation changes
alter admission without changing the RTC source. Record that split explicitly;
the final candidate's admission behavior still requires its native G0 inventory.
Qualification is conditional on the trusted host and authenticated reference servers; NTS does
not prove server UTC correctness or future clock behavior. The native
sampling/use-straddle and resident-kernel-state residual remain unproven.

During a coordinator HOLD, no new native work begins. An active qualification
stops, its evidence remains invalid/incomplete, and container cleanup is deferred.
The owner must not unpause, stop, kill, remove or replace a coordinator-paused
container. A later explicit release authorizes cleanup and a new run, never
continuation of the interrupted timer.
