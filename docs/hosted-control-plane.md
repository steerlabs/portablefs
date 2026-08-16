# Hosted control plane

Status: **implemented v1 foundation; single-manager and single-AZ by design**

PortableFS can still be self-hosted with credentials minted out of band. The
hosted stack adds a product-neutral manager and a narrow storage-cell control
loop around the same authority data plane. It does not put the manager in the
filesystem I/O path and it does not create a second filesystem truth.

Current production mount transport is Linux FUSE. The retained macOS data-plane
code is a non-shipping qualification lane and is refused before Attach by an
ordinary release.

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

The client private key is generated on the Linux mount host or sandbox. A
separately signed macOS qualification harness exercises the same key-custody
boundary, but is not a production mount. Only a signed CSR crosses the network.
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
`peer_spki_sha256`, `nonce`, `not_before`, and `expires`. Base64url is unpadded;
`peer_spki_sha256` is SHA-256 of the CSR public key's DER SubjectPublicKeyInfo.
Unknown fields, an invalid CSR signature, an expired or overlong window, nonce
reuse, or disagreement on any tenant/client/access field is refused.

## Automatic long-lived mounts

Keepalive still proves only liveness. It cannot extend authorization.

An initial grant is single-use and creates a session with authorization
sequence zero. With `automatic_reauthorization: true`, `POST
/v1/mount-authorizations` returns both the short-lived attach credential and a
longer-lived enrollment certificate for the same local key. Its sole identity is
`spiffe://portablefs/mount-enrollment/{id}`. It authenticates only to the
Manager's enrollment endpoints; a short-lived authority client certificate has
a different identity and cannot authenticate there.

The production launcher starts `portablefs mount` with the initial credential
plus the Manager origin, Manager trust material, enrollment ID/certificate,
exact authority generation, and both deadlines. After Attach, the per-mount
Linux FUSE supervisor is the one renewal owner. There is no global mount daemon
and no second sequencer, and an automatic mount exposes no manual rotation
socket.

The retained macOS qualification data plane has an equivalent single renewer
inside its portablefsd attach and refuses manual rotation. That code is not a
production owner while current FSKit is refused before Attach.

The owner immediately asks
`POST /v1/mount-enrollments/{id}/reauthorizations` for sequence one, then
refreshes near the middle of each installed window. It sends a CSR for the same
key, the authority session ID, and the exact sequence. The Manager durably keys
idempotency by `(enrollment, session, sequence, request digest)`, not only the
HTTP header, so a lost response cannot mint a different proof for the same
authority sequence. Only that one current response is retained on the
enrollment; periodic refreshes do not create generic response receipts. The
Manager rate-limits sequence advancement relative to the grant lifetime. The
durable store admits at most 2,048 active enrollments, including at most 512 per
authorization domain (tenant) and 256 per volume. It retains at most 4,096 enrollment records
in total; expired enrollments are removed immediately, terminated retry
tombstones expire after 15 minutes, and the oldest terminal tombstone is
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

The security tradeoff is intentionally simple: possession of both the
enrollment certificate and local private key can renew access to that one
volume, at no more than its recorded access ceiling, until enrollment expiry or
revocation. It is not an account-wide Manager credential. The default is 24
hours versus a ten-minute grant; deployments can pin a shorter
`--mount-enrollment-lifetime`.

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
  --mount-enrollment-expires-at-ms "$ENROLLMENT_EXPIRES_MS" \
  --authority-generation "$AUTHORITY_GENERATION"
```

Authority server certificates rotate without changing the authority epoch. The
cell keeps the authority key local, reports its CSR, receives a renewed
manager-signed certificate in a later plan, writes it atomically, and the
authority reloads it on each new TLS handshake. Existing connections continue;
no second writer or unsafe epoch restart is introduced.

## Volume lifecycle and fencing

The v1 state machine is intentionally small:

```text
PROVISIONING -> READY -> FENCING -> PROVISIONING
      |           |          |
      +-----------+----------+-> QUARANTINED
                              \-> RETIRED
```

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
authority generation only after that local absence proof **and** an operator's
external proof that every prior strict kernel mount is absent or fenced. The
helper independently remembers that the previous signed phase was `FENCE` and
refuses a skipped or premature generation.

Retirement stops serving but preserves the XFS directory and all allocation
identities. IDs are not recycled. Destructive data deletion is intentionally
not a network plan operation.

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
| cell | `GET /v1/cells/{id}/plan` | fetch complete signed desired state |
| cell | `POST /v1/cells/{id}/observations` | reconcile changed observed state |
| cell | `POST /v1/cells/{id}/heartbeat` | refresh live health without a durable log write |
| product | `POST /v1/volumes` | allocate a volume |
| product/operator | `GET /v1/volumes/{id}` | inspect an authorized volume |
| product | `POST /v1/volumes/{id}/restart` | enter the fencing state |
| operator | `POST /v1/volumes/{id}/strict-fence` | record external strict-mount fence evidence |
| product | `POST /v1/volumes/{id}/retire` | stop serving while preserving data |
| product | `POST /v1/mount-authorizations` | issue client cert plus initial grant and, when explicitly requested, an automatic enrollment |
| product | `POST /v1/mount-reauthorizations` | renew cert plus exact session grant |
| enrolled mount | `POST /v1/mount-enrollments/{id}/reauthorizations` | obtain the exact next live-session grant |
| enrolled mount | `POST /v1/mount-enrollments/{id}/close` | close enrollment after exact detach |
| product | `POST /v1/mount-enrollments/{id}/revoke` | revoke future renewal for a mount |

Every mutating product/operator request and changed cell observation requires
`Idempotency-Key`. Reusing a retained key with different bytes or another
operation is refused. Receipts are durable and byte-identical on retry for a
24-hour retry window; observations are state-based and reapplying them is safe.

## Deliberate v1 limits

- One manager process owns the state file. There is no manager HA or consensus
  protocol yet. Run it on durable storage with process supervision and backups.
- Placement is single-cell and single-AZ. There is no automatic cross-cell
  migration, block-device failover, or second writer.
- A v1 cell admits at most 256 durable volume assignments. Retired assignments
  still count because their isolation IDs and data are deliberately retained.
- Backup and restore remain offline operator/storage-provider workflows. The
  privileged helper deliberately accepts no remote snapshot command. A future
  backup controller must fence or freeze the exact volume, use provider APIs
  with its own narrow identity, and reconcile immutable backup records; it must
  not add file-copy semantics to the authority.
- The manager currently loads CA and Ed25519 signing keys from private local
  files. Production key custody can replace those signers with KMS/HSM-backed
  implementations without changing the cell or mount contracts.
- The hosted API and manager state schema are new internal surfaces, not part of
  the frozen v3 authority protocol. The authority `Reauthorize` RPC is additive
  and advertised as `session-reauthorization-v1`. Automatic mounts additionally
  require `mount-enrollment-reauthorization-v1` and refuse an older authority
  rather than changing renewal modes.

These are explicit scope boundaries, not silent availability claims. The data
plane remains usable in standalone mode without the hosted components.
