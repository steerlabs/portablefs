# Hosted control plane

Status: **implemented; single-manager and single-AZ by design**

PortableFS can still be self-hosted with credentials minted out of band. The
hosted stack adds a product-neutral manager and a narrow storage-cell control
loop around the same authority data plane. It does not put the manager in the
filesystem I/O path and it does not create a second writable filesystem truth.

The exact mount transport is Linux FUSE. Shipping macOS 26 uses the named
best-effort FSKit data plane against the same hosted authority.

```text
product backend                    Linux mount
      | user authorization               | local private key + CSR
      +--------------------+--------------+
                           |
                    portablefs-manager
             placement, PKI, grants, desired state
                           |
                     mTLS, outbound poll
                           |
                 portablefs-cell-agent (non-root)
                           |
                  signed plan over Unix socket
                           |
                 portablefs-cell-helper (root)
                           |
                  XFS + systemd reconciliation
                           |
            one non-root authority for one volume
```

Human file inspection may use the optional `portablefs-files` read gateway in
parallel with mounts. The product backend remains the user-authorization
boundary and signs a token bound to the exact read request. It issues a
standalone `access: ["read"]`, `automatic_reauthorization: false` Manager grant
for the gateway CSR; no mount enrollment is created. For a live volume the
gateway opens an uncached authority session and performs only object-relative
lookup, directory read, and file read operations. For an ARCHIVED volume it
serves the same bounded operations directly from the sealed manifest and pack
objects without an authority session or wake. Directory pages, preview bytes,
session count, cursor count, and lifetimes are bounded. The Manager remains
outside the file data path. A scaled deployment consistently routes a volume ID
to one gateway instance for the lifetime of its short session and one-use
cursors; it does not create a second metadata store to share that disposable
state.
Volumes with machine-local route declarations are refused by this non-mounting
reader because it cannot honestly project those machine-local paths.
Path resolution is object-relative and never follows symlinks; symlink and
opaque inode kinds may be listed but are not opened by the gateway.
Live content streams retain PortableFS's ordinary live-file semantics when
another client mutates the same inode; the gateway does not create a snapshot
or copy.

## Component boundaries

`portablefs-manager` is the network control plane. It allocates stable volume
IDs and immutable isolation identifiers, signs complete cell plans, signs
short-lived mount grants, issues certificates from CSRs, records exact
idempotency receipts, and reconciles observed state. It runs as a non-root
single writer. Its durable store is checksummed, hash-chained, fsynced before a
result is published, recovers a torn final record, and compacts long record
chains atomically. Expired mount enrollments are removed immediately;
terminated enrollments retain a 15-minute retry tombstone and are then pruned
on control-plane activity. Its
reference host boundary is documented in
[hosted-manager-deployment.md](./hosted-manager-deployment.md).

`portablefs-cell-agent` is the only cell process with a manager connection. It
runs unprivileged and makes outbound mTLS requests. It verifies every manager
plan itself, sends the unchanged signed envelope to the local helper, reports a
durable observation only when observed state changes, and otherwise sends a
non-durable heartbeat. After a manager restart, mount issuance fails closed
until a fresh authenticated heartbeat arrives.

The Manager tracks process liveness and desired-plan convergence separately.
A fresh heartbeat from an applied generation at or behind the current desired
generation keeps placement admission live while the cell reconciles a newer
complete plan; durable pending charges and never-reused allocator identities
make those placements safe to batch. Mount issuance and renewal require a
heartbeat at the exact desired generation. A heartbeat claiming a generation
the Manager never issued is refused.

`portablefs-cell-helper` is the small root boundary. It has no network listener.
Its Unix socket accepts only the configured agent UID using `SO_PEERCRED`. It
verifies the same manager signature again and accepts no network-selected path,
command, executable, systemd unit text, environment, UID, project, or port
outside the typed plan. Durable helper state pins every assignment and refuses
ID changes, plan equivocation, skipped authority generations, or replacement
before a local process-absence proof.

`portablefs-authority-launcher` is an even smaller execution boundary. It reads
one strict root-owned config, constructs a fixed authority argument shape, and
execs a root-owned authority binary. The authority itself runs under a unique
service UID, receives its listener from systemd, sees only one bind-mounted
volume/config/state/staging set, has no network namespace of its own, and
refuses root. Staging is outside the served namespace but inherits the exact
volume XFS project and hard quota; its bind source cannot be replaced by the
authority UID.

`portablefs-files` is the optional read-only product adapter. It accepts only
short-lived, body-bound requests signed by its colocated product backend, then
uses a read-only capability and its own proof-of-possession identity to speak
directly to the volume authority. It has bounded sessions, cursors, operations,
downloads, request bodies, previews, and directory pages. It never mounts a
volume and keeps no namespace or content cache. Protocol 5 has one strict
session model, so the adapter still joins the visibility barrier with an exact
no-kernel-mount observation and acknowledges each visibility phase immediately
after observing it. It never adds a second filesystem truth or a weaker
coherence profile.

The intended deployment is one adapter beside one product backend in a shared
pod network namespace, listening only on loopback. The product backend's exact
public request-signing key is the adapter's sole HTTP trust root; the adapter
does not receive that backend's private key or product-control credentials. Its
private authority identity may persist for the pod lifetime, but active
sessions and cursors are intentionally process-local and reconstructible.

## Authorization is deliberately two-party

PortableFS Cloud must not silently become the product's user database. A mount
therefore carries two signatures:

1. The product signs who may use which volume, with which access, for which
   owner and authorization domain.
2. The PortableFS manager verifies that assertion and signs the infrastructure
   placement: exact volume, cell, authority identity and generation, client
   public key, access, nonce, and deadline.

The authority verifies both signatures and their agreement on the initial
attach. A valid grant for
another customer, volume, cell, authority generation, TLS key, or access set is
useless. The manager's mTLS API also binds every product operation to the exact
product issuer in its control certificate; a product principal cannot inspect,
restart, retire, or mint for another product's volume.

The client private key is generated on the Linux mount host, sandbox, or macOS
host. The signed macOS product exercises the same key-custody boundary. Only a
signed CSR crosses the network.
The manager verifies proof of possession, overwrites CSR identity fields, and
returns a client certificate and capability bound to the CSR's SPKI. It never
receives or generates the client private key.

When the product explicitly requests `automatic_reauthorization: true`, that
initial two-party decision also creates one bounded mount enrollment. Ordinary
and manually reauthorized mounts omit the field and receive no durable Manager
credential. The enrollment records the product-authorized subject and access ceiling together
with the exact volume, mount-key SPKI, cell, authority identity, and authority
generation. Later grants cite that durable enrollment instead of replaying an
expired product assertion. The product remains the source of authorization; it
does not have to stay online in the renewal loop.

Products using Go can create the independent assertion with the public
`github.com/steerlabs/portablefs/vcs/hostedauth` package. Other languages sign
the same compact token: `v1.<base64url-json>.<base64url-ed25519-signature>`.
The signature input is the UTF-8 bytes
`portablefs-product-authorization-v1\0` followed by the exact JSON payload. The
payload fields are `issuer`, `audience` (`portablefs-manager`),
`authorization_domain`, `owner`, `subject`, `volume_id`, `access`,
`peer_spki_sha256`, `nonce`, `not_before`, `expires`, and the optional
`renewal_scope` and `renewal_epoch`. The renewal fields must either both be
absent or both be present. `renewal_scope` is 1 through 200 bytes using only
ASCII alphanumerics plus `.`, `_`, `-`, `:`, and `/`; `renewal_epoch` is an
integer from 1 through 9007199254740991. Base64url is unpadded;
`peer_spki_sha256` is SHA-256 of the CSR public key's DER SubjectPublicKeyInfo.
Unknown fields, an invalid CSR signature, an expired or overlong window, nonce
reuse, or disagreement on any tenant/client/access field is refused.

## Automatic long-lived mounts

Keepalive still proves only liveness. It cannot extend authorization.

An initial grant is single-use and creates a session with authorization
sequence zero. With `automatic_reauthorization: true`, `POST
/v1/mount-authorizations` returns both the short-lived attach credential and a
Manager enrollment certificate for the same local key. Its sole identity is
`spiffe://portablefs/mount-enrollment/{id}`. It authenticates only to the
Manager's enrollment endpoints; a short-lived authority client certificate has
a different identity and cannot authenticate there. The enrollment certificate
is an identity credential signed through the enrollment CA's remaining
validity. Its certificate expiry does not set the enrollment lease deadline.

The production launcher starts `portablefs mount` with the initial credential
plus the Manager origin, Manager trust material, enrollment ID/certificate,
exact authority generation, and initial grant deadline. After Attach, the per-mount
Linux FUSE supervisor is the one renewal owner. There is no global mount daemon
and no second sequencer, and an automatic mount exposes no manual rotation
socket.

The macOS data plane has an equivalent single renewer inside its portablefsd
attach and refuses manual rotation.

The owner immediately asks
`POST /v1/mount-enrollments/{id}/reauthorizations` for sequence one, then
refreshes near the middle of each installed window. It sends a CSR for the same
key, the authority session ID, and the exact sequence. The Manager durably keys
idempotency by `(enrollment, session, sequence, request digest)`, not only the
HTTP header, so a lost response cannot mint a different proof for the same
authority sequence. Only that one current response is retained on the
enrollment; periodic refreshes do not create generic response receipts. The
Manager rate-limits sequence advancement relative to the grant lifetime. Each
fresh successful refresh sets the enrollment lease deadline to `now + lease`.
An exact replay, rate-limited request, or failed request does not move that
deadline. The
durable store admits at most 2,048 active enrollments, including at most 512 per
authorization domain (tenant) and 256 per volume. It retains at most 4,096 enrollment records
in total. A lapsed active lease transitions to `EXPIRED` with termination reason
`lease-expired`; all terminal retry tombstones expire after 15 minutes, and the oldest terminal tombstone is
evicted first if a new active enrollment needs that retained-state slot. The
latest non-derivable response is stored once per enrollment, while Manager-wide
CA and release material is content-addressed and shared rather than copied into
every enrollment. The
authority pins the enrollment as the session's sole reauthorization issuer at
initial attach and handles `Reauthorize` on its reserved
liveness lane and:

- accepts only the exact next sequence;
- makes a byte-identical retry of that sequence harmless;
- fences a changed replay or a sequence gap;
- permits access to stay the same or narrow, never broaden;
- extends the signed authorization deadline without replacing the filesystem
  session, locks, handles, or strict-cache membership.

Activate returns the exact authority-verified initial deadline. The owner checks
it against the Manager response and schedules only from the authority value, so
a copied or malformed CLI timestamp cannot extend the safety window.

Manager deadlines are whole Unix seconds. A launcher passes the returned
`expires_unix` exactly as `expires_unix * 1000` to
`--auth-expires-at-ms`; it must not derive that value from a receipt timestamp
or the launcher's local clock.

The renewed certificate must match the mount-local private key. The session
owner uses it for future TLS reconnects without persisting the capability.
Changing the key is a new mTLS principal and requires a new mount/session.

Temporary Manager failures retry the same sequence with bounded exponential
backoff. A definitive denial fails closed immediately. If renewal cannot finish
before the safety margin, Linux unmounts while the last grant is still valid.
Clean detach closes the enrollment; the product may revoke it earlier.
Revocation cannot erase an installed grant, so its remaining exposure is
bounded by the short grant lifetime. The qualification macOS implementation
instead terminalizes its data plane and exercises its FSKit-detach watchdog;
that historical path does not broaden production platform support.

A live enrollment lease may renew short data grants without an absolute
session-age limit. Explicit revocation, renewal fencing, authority replacement,
volume state, or a missed lease renewal ends future grants. Previously issued
data access may remain usable until its grant expiry plus bounded clock skew and
fail-close effects. Possession of both the enrollment certificate and local
private key authorizes only that enrollment's volume and recorded access
ceiling; it is not an account-wide Manager credential. The lease defaults to 30
minutes and must be at least twice the grant lifetime; deployments can set it
with `--mount-enrollment-lease`.

A renewal scope names one machine incarnation. Scoped issuance permits one live
enrollment per `(scope, volume)`: issuing a replacement for volume A supersedes
the prior active enrollment for volume A but leaves volume B active. Advancing
the scope's epoch still revokes every lower-epoch enrollment in that scope.

Standalone mounts omit all enrollment flags and retain the explicit
`portablefs reauthorize` path. The mode is fixed at mount creation. An
incomplete automatic configuration is refused and never falls back.

Automatic authorization does not weaken strict-session continuity rules. If a
qualification Mac sleeps past the installed grant, `portablefsd` restarts, the
Linux mount owner exits, or the authority changes epoch/generation, that exact
session cannot safely be reconstructed from kernel caches. It fails closed and
requires the existing exact unmount/remount flow. A normal sleep or network
interruption shorter than the installed window simply resumes the same renewal
loop.

The product writes the returned certificates and CA bundle to protected local
files and invokes this production Linux command shape (timestamps are Unix
milliseconds). A qualification Mac can exercise the same credential syntax,
but that does not bypass its pre-Attach platform gate:

```text
PORTABLEFS_MOUNT_TOKEN="$CAPABILITY" portablefs mount "$VOLUME" "$PATH" \
  --addr "$AUTHORITY_ENDPOINT" \
  --data-plane-transport tls-private-ca \
  --data-plane-server-name "$AUTHORITY_SERVER_NAME" \
  --data-plane-ca authority-ca.pem --client-cert client.pem --client-key client.key \
  --auth-expires-at-ms "$GRANT_EXPIRES_MS" \
  --manager-url "$MANAGER_ORIGIN" --manager-server-name "$MANAGER_SERVER_NAME" \
  --manager-ca manager-ca.pem --mount-enrollment-id "$ENROLLMENT_ID" \
  --mount-enrollment-cert enrollment.pem \
  --authority-generation "$AUTHORITY_GENERATION"
```

Authority server certificates rotate without changing the authority epoch. The
cell keeps the authority key local, reports its CSR, receives a renewed
manager-signed certificate in a later plan, writes it atomically, and the
authority reloads it on each new TLS handshake. Existing connections continue;
no second writer or unsafe epoch restart is introduced.

## Volume lifecycle and fencing

Manager state schema v2 has one volume lifecycle:

```text
PROVISIONING -> READY <-> FENCING
READY -> ARCHIVING -> ARCHIVED -> RESTORING -> READY   (READY at a later epoch)
READY | ARCHIVED -> DESTROYING -> DESTROYED            (terminal, durable record)
QUARANTINED
```

Archive first closes strict-attach admission and proves membership empty, then
stops the authority, exports to attempt-addressed immutable objects, and commits
ARCHIVED only after the Manager verifies the manifest and object inventory.
`DESTROY` and `RELEASE` remove the old placement with an exact helper-recorded
proof. Wake allocates a fresh placement, materializes the namespace, and serves
RESTORING as sealed base plus monotone hydration map plus XFS until convergence
returns the volume to READY. The complete cursor, identity, admission, and crash
ordering contract is in
[identity-lifecycle-and-capacity.md](./tiered-storage/identity-lifecycle-and-capacity.md).

A new volume receives a never-reused project ID, service UID/GID, and TCP port
on one cell. The helper creates and verifies a deterministic persistent Linux
service account for that exact UID/GID, creates the XFS project directory,
applies block and inode hard limits, creates an authority key and CSR, and
writes systemd drop-ins. The manager signs the CSR; the helper verifies that
certificate against the local key and configured authority CA before systemd
starts the socket-activated authority.

`quota_bytes` is exact and must be a multiple of 1024 because `xfs_quota`
represents these limits in KiB. The manager rejects unrepresentable values;
the helper reads the resulting project identity and block/inode totals back
from XFS before it reports provisioning success.

Restart is a fencing transaction, not `kill` followed by hope. The helper kills
the complete service cgroup, stops both service and listener, verifies both are
inactive, and verifies the cgroup is empty. The manager will allocate the next
authority generation only after that local absence proof and either an
operator's external proof that every prior strict kernel mount is absent or
fenced, for restart, or the authority's process-bound quiesce proof, for
archive. On restart the helper independently remembers that the previous signed
phase was `FENCE` and refuses a skipped or premature generation.

Retirement stops serving but preserves the XFS directory and all allocation
identities. IDs are not recycled. Destruction is a typed, proof-bearing plan
transaction: archive-cycle `DESTROY`/`RELEASE` is gated on the Manager's own
archive verification; an explicit terminal delete from READY quiesces and uses
the same proof-bearing phases without export. The helper still accepts no
free-form remote command. Plans carry archive identities and digests, never
object keys or credentials; the helper derives keys from root-pinned cell
configuration.

## Manager API

The control listener is TLS 1.3 with required client certificates. One URI SAN
names the role and identity:

```text
spiffe://portablefs/control/operator/<id>
spiffe://portablefs/control/product/<product-issuer>
spiffe://portablefs/control/cell/<cell-uuid>
spiffe://portablefs/mount-enrollment/<enrollment-id>
```

| Caller | Endpoint | Purpose |
| --- | --- | --- |
| operator | `POST /v1/cells` | register cell capacity and allocator ranges |
| operator | `PUT /v1/cells/{id}` | converge an exactly named cell registration without overwriting live state |
| operator | `GET /v1/cells` | list the complete cell inventory in cell-ID order |
| operator | `PATCH /v1/cells/{id}/capacity` | raise registered cell capacity monotonically (v2) |
| operator | `POST /v1/cells/{id}/decommission` | stop admission and drain the cell through archive (v2) |
| operator | `POST /v1/cells/{id}/abandon` | record a permanently lost cell and release only Manager-verified archived placements (v2) |
| operator | `GET /v1/capacity` | inspect per-pool measured use, pending charges, counts, and admission verdicts (v2) |
| cell | `GET /v1/cells/{id}/plan` | fetch complete signed desired state |
| cell | `POST /v1/cells/{id}/observations` | reconcile changed observed state |
| cell | `POST /v1/cells/{id}/heartbeat` | refresh live health without a durable log write |
| product | `POST /v1/volumes` | allocate a volume |
| operator | `GET /v1/volumes` | list the complete volume inventory in volume-ID order |
| product/operator | `GET /v1/volumes/{id}` | inspect an authorized volume |
| product | `POST /v1/volumes/{id}/restart` | enter the fencing state |
| operator | `POST /v1/volumes/{id}/strict-fence` | record external strict-mount fence evidence |
| product | `POST /v1/volumes/{id}/archive` | enter the typed archive cycle (v2 surface) |
| product | `POST /v1/volumes/{id}/wake` | place and restore an ARCHIVED volume (v2 surface) |
| product | `DELETE /v1/volumes/{id}` | destroy the volume and retain the terminal audit record (v2) |
| product | `POST /v1/mount-authorizations` | issue client cert plus initial grant and, when explicitly requested, an automatic enrollment |
| product | `POST /v1/mount-reauthorizations` | renew cert plus exact session grant |
| enrolled mount | `POST /v1/mount-enrollments/{id}/reauthorizations` | obtain the exact next live-session grant |
| enrolled mount | `POST /v1/mount-enrollments/{id}/close` | close enrollment after exact detach |
| product | `PUT /v1/volumes/{volume-id}/mount-enrollments/{enrollment-id}/revocation` | converge future renewal to revoked, closed, expired, or absent within the product-owned volume |
| product | `PUT /v1/renewal-fences` | atomically advance a batch of issuer-scoped renewal epoch fences and revoke superseded enrollments |

`PUT /v1/cells/{id}` accepts no `Idempotency-Key`. The path supplies the cell
identity and the body is normalized exactly as for registration. The first PUT
creates the cell; an exact normalized replay returns the live current cell as a
no-op. It never resets a monotonic capacity raise, allocator progress, health,
or desired-plan state. Any changed registration declaration returns `409` and
leaves state untouched. A schema-v2 cell written before declaration digests
existed accepts one compatible declaration (same identities and pool, with
capacity and allocator starts no greater than their monotonic live values) and
persists only its digest; later replays use the exact rule. The two operator
inventory GETs always return arrays, including when empty, with entries sorted
by stable ID.

Refusal classes on create, archive, wake, and delete routes are kept
distinct because each demands a different client response:

| Status | Meaning | Raised by | Client response |
| --- | --- | --- | --- |
| `503` | the archive store is unreachable right now | `POST /v1/volumes/{id}/archive`, `DELETE /v1/volumes/{id}` | retry the unchanged request later |
| `503` | every eligible cell is at its per-cell archive or restore concurrency cap | `POST /v1/volumes/{id}/archive`, `POST /v1/volumes/{id}/wake` | retry the unchanged request later |
| `503` | a cell can physically hold the placement, but every such cell lacks a fresh heartbeat or full usage observation | `POST /v1/volumes`, `POST /v1/volumes/{id}/wake` | retry the unchanged request after cell reconciliation recovers |
| `409` | no cell in the pool has capacity for the volume at all | `POST /v1/volumes`, `POST /v1/volumes/{id}/wake` | resolve the durable capacity state |
| `501` | this deployment cannot archive at all: the volume's cell advertises no archive configuration, or the Manager runs without the archive component (verifier, purger) the operation needs | `POST /v1/volumes/{id}/archive`, `DELETE /v1/volumes/{id}` | surface to an operator; retrying is useless |

Saturation and missing fresh cell evidence are deliberately not `409`: a
conflict names a durable state the caller must resolve, while those conditions
can resolve without changing the request. Capacity exhaustion keeps `409`
because it does not. Missing archive configuration is
deliberately neither `409` nor `503`: it is a durable deployment fact that no
retry and no volume-state change resolves, and a client that filed it under
"busy" would let a misconfigured deployment fail every archive sweep silently
forever.
The renewal-fence request and response have these exact shapes:

```json
{"reason":"<identity>","fences":[{"scope":"<scope>","epoch":1}]}
```

```json
{"fences":[{"scope":"<scope>","epoch":1}]}
```

A batch contains 1 through 4096 entries. Manager validates the complete batch
before one durable transaction, applies the maximum requested epoch for a
duplicate scope, and returns the resulting high-water mark for every request
entry in request order. Advancing a fence revokes only active enrollments below
the resulting epoch. Issuing a new scoped enrollment rotates every other active
enrollment in that issuer and scope, including an enrollment at the same epoch.

The two convergent PUT operations reject `Idempotency-Key`: convergence in the
durable state is stronger than retaining a transport replay receipt. Other
mutating product/operator requests and changed cell observations require the
header. Reusing a retained key with different bytes or another operation is
refused. Receipts are durable and byte-identical on retry for a 24-hour retry
window; observations are state-based and reapplying them is safe.

## Current limits

- One manager process owns the state file. There is no manager HA or consensus
  protocol yet. Run it on durable storage with process supervision and backups.
- Placement is single-cell and single-AZ. There is no automatic cross-cell
  migration, block-device failover, or second writer.
- A cell plan admits at most 256 placement assignments. An assignment counts
  until `RELEASE` removes it and frees the plan slot.
- Operator EBS snapshots remain an offline storage-provider workflow. The
  archive tier's `portablefs-archiver` and `portablefs-hydrator` are the
  narrow-identity controllers reserved by that boundary: typed archive phases
  carry identities and digests, while root-provisioned cell configuration holds
  object keys and credentials. The helper accepts no free-form remote snapshot
  command. Neither controller adds file-copy semantics to the authority; during
  recall the hydrator returns verified bytes and the authority writes XFS
  itself.
- The manager currently loads CA and Ed25519 signing keys from private local
  files. Production key custody can replace those signers with KMS/HSM-backed
  implementations without changing the cell or mount contracts.
- The hosted API and manager state schema are new internal surfaces, not part of
  the frozen v3 authority protocol. The authority `Reauthorize` RPC is additive
  and advertised as `session-reauthorization-v1`. Automatic mounts additionally
  require `mount-enrollment-reauthorization-v1` and refuse an older authority
  rather than changing renewal modes. A client that supports the sliding lease
  contract advertises `hosted-automatic-mount-reauthorization-v2`.
- Tiered storage uses Manager state schema v2 and signed cell-plan v2. Rollout is
  gated helper, then agent, then Manager using explicit advertised plan and
  helper-state versions; the Manager does not sign v2 or admit archive/restore
  on a cell until both host components report v2 capability.

These are explicit scope boundaries, not silent availability claims. The data
plane remains usable in standalone mode without the hosted components.
