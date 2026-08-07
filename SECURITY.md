# Security Policy

## Supported Versions

Security fixes land on the latest minor release line.

| Version         | Supported |
| --------------- | --------- |
| Latest minor    | Yes       |
| Older releases  | No        |

If you run an older release, upgrade to the latest minor before reporting behavior
you believe is a vulnerability, unless the issue is clearly exploitable data loss or
credential exposure.

## Reporting A Vulnerability

Report privately to **security@portablefs.com**. Do not open a public issue for
suspected vulnerabilities.

Include what you can: the affected component — the authority
(`portablefs-authority`), the Linux FUSE mount client (`portablefs-mount-v3`),
the macOS `portablefsd` daemon or the FSKit extension, or the `portablefs` CLI
and its installer (`scripts/install.sh`) — a reproduction or proof of concept,
the deployment shape (authority flags, TLS material, capability issuance), and
impact.

You will get an acknowledgement within 3 business days. We follow **90-day
coordinated disclosure**: we aim to ship a fix and publish an advisory well within
90 days of the report, and we ask that you hold public disclosure until a fix is
released or the 90-day window lapses, whichever comes first. We will credit
reporters in the advisory unless you ask otherwise.

## Scope

PortableFS serves one authoritative XFS directory tree to several machines over
the network. The boundaries below are the ones the implementation enforces;
flaws in them are in scope.

### Session authentication and authorization

- **Mutual TLS 1.3 on every authority session.** The authority refuses to serve
  a TLS configuration below TLS 1.3, without `RequireAndVerifyClientCert`, or
  without a client CA; the mount client pins TLS 1.3 as its minimum. There is no
  plaintext mode and no negotiated fallback.
- **Ed25519 mount capabilities.** A capability is a domain-separated,
  Ed25519-signed claim set bound to one volume ID and to the client's mutually
  authenticated TLS public key. The authority enforces its own maximum lifetime
  rather than trusting the token's expiry, and accepts each capability exactly
  once — if the single-use record cannot be retained, the authority refuses the
  capability instead of silently dropping replay protection
  (`vcs/internal/volumecap`).
- **An absolute, non-renewable deadline.** The verified expiry becomes the
  session's deadline. Lease renewal can keep an otherwise idle session alive but
  can never extend the authority the capability granted.
- **Write is not admin.** An ordinary write claim covers file content and the
  namespace. Changing a volume's machine-local routing is a separate `admin`
  claim: mount mutation under `.portablefs/` is refused outright, the routing
  declaration is reachable only through the admin `ApplyRoutes` call, and an
  admin-requiring request presented on a non-admin session is answered `EPERM`.
  A capability that lets an agent write files must not also let it hide a
  subtree from every other machine.

### Filesystem confinement

- **Descriptor-relative access only.** The authority reaches XFS with `openat2`
  under `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV` and
  descriptor-relative `*at` syscalls. Requests carry object capabilities backed
  by held descriptors, never a client-supplied path and never a client-supplied
  inode number. The stored XFS export-handle identity the authority publishes is
  coordination identity only, never authorization.
- **No crossing out of the volume.** An object that crosses the volume's device
  boundary is rejected as `EXDEV`, so cross-volume link and rename are refused by
  construction rather than by a check that could be bypassed.
- **Object types the volume will not create.** Device nodes are refused
  (`EPERM`); FIFOs and unix-domain sockets are refused (`EOPNOTSUPP`) because the
  authority models a tree of regular files, directories, and symlinks only.
  Set-user-ID and set-group-ID bits are refused outright rather than silently
  dropped, so no caller can create an inode whose mode is not what it asked for.
  Portable `user.*` extended-attribute writes are disabled, because XFS excludes
  extended attributes from project-quota accounting and they would otherwise
  consume uncharged space in a shared cell.
- **Storage mount options.** `scripts/provision-xfs-volume.sh` refuses to
  proceed unless the backing XFS mount carries `nodev`, `nosuid`, `noexec`, and
  `noatime` along with project quotas.
- **Not root.** `portablefs-authority` refuses to start as root. Provisioning is
  privileged; serving requests is not.

### Machine-local route backing

Machine-local graft paths are tenant-controlled input, so their host backing
directory is a capability boundary. `vcs/internal/confinedfs` resolves them with
`openat2` under `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS` and fails closed when
`openat2` is unavailable or blocked; runtime code never joins a graft path onto a
host path and hands the result to a path-based syscall. The threat model and the
required verification, including the concurrent destination-parent symlink-swap
attack under the race detector, are in
[docs/graft-security.md](./docs/graft-security.md).

### Tenancy

- **One XFS project directory per volume**, carrying `PROJINHERIT` so children
  cannot escape the project, with block and inode hard limits set at
  provisioning time.
- **One authority worker per volume**, with runtime admission bounds that a
  deployment sizes explicitly: live sessions, descriptor-backed item
  capabilities, open file descriptions, accepted TLS connections, retained reply
  bytes, and inbound frame bytes in flight. The worker refuses to start without
  positive bounds.

### Local boundaries

Per-account mount state, the daemon control socket, and the app-group socket
reject foreign ownership, unsafe permissions, and symlinked paths before they
are used: state directories are validated by a component-by-component
`openat(O_NOFOLLOW)` walk that demands an exact uid-owned `0700` inode, and
socket and helper paths are checked for the expected owner. On macOS the CLI,
the daemon, and the FSKit extension must agree on one release-stamped identity
tuple — filesystem type, resource scheme, and app group.

The operating-system account is the local security boundary. PortableFS assumes
processes running as the same effective user are mutually trusted: such processes
can ordinarily inspect or signal one another and can modify that user's private
state. A user who can run code as the account can reach that account's mounts.
Run mutually untrusted workloads under distinct OS accounts or stronger OS
isolation.

### Supply chain

- **Linux.** The installer downloads `checksums.txt`, verifies the archive's
  SHA-256, and verifies the published GitHub artifact attestation with a pinned,
  digest-checked `gh` — bound to the exact repository, the exact release
  workflow, the exact tag, and non-self-hosted runners, and requiring exactly one
  attestation with exactly one subject. All of that happens **before** any byte is
  extracted, and the archive's member list must then be exactly the two expected
  regular files.
- **macOS.** There is no standalone CLI. PortableFS ships only as the
  Developer ID-signed, notarized `PortableFS.app`. The installer audits the zip
  before extraction, rejects any symlink inside the bundle, and then checks the
  code signature, the hardened runtime, Gatekeeper assessment, the team ID, the
  app and FSKit extension bundle identifiers and executables, the FSKit
  filesystem type and personality, the single advertised resource scheme, and the
  app-group identity — with the CLI, daemon, and extension all agreeing on that
  tuple.

## Out Of Scope

- Reports that require an attacker to already control the operating-system
  account running a mount.
- Reports against configurations the software refuses to enter.
- Vulnerabilities in third-party dependencies with no PortableFS-specific
  exploit path. Report those upstream, though a heads-up is welcome.
