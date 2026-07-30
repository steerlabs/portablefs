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

Include what you can: affected component (VCS data plane, volume-api,
authority-manager, mount client, CLI), a reproduction or proof of concept, the
deployment shape (production mode flags, TLS, token configuration), and impact.

You will get an acknowledgement within 3 business days. We follow **90-day
coordinated disclosure**: we aim to ship a fix and publish an advisory well within
90 days of the report, and we ask that you hold public disclosure until a fix is
released or the 90-day window lapses, whichever comes first. We will credit
reporters in the advisory unless you ask otherwise.

## Scope

PortableFS moves agent workspace data across the network and stores it durably.
These are security surfaces; flaws in them are in scope:

- **Data-plane authentication**: `VCS_AUTH_TOKEN` handshakes on the custom mount
  protocol and WAL replication channel, managed-mode router session tokens and their
  scoping to one authority instance, and the fail-closed startup checks for
  network-reachable listeners.
- **Control-plane authentication**: volume-api admin vs tenant token separation and
  tenant data isolation; the authority-manager API token and the rule that mount
  credentials are only returned by session-minting routes.
- **TLS**: the custom protocol, replication channel, and managed-mode router
  (TLS 1.3, optional mTLS), including the production fail-closed requirements and
  the plaintext override paths.
- **Encryption at rest**: `VCS_ENCRYPTION_KEY` sealing of the WAL and disk cache
  (AES-256-GCM), and bucket server-side encryption configuration.
- **Read-path integrity**: content-address verification of blobs and chunks on every
  read.
- **Local mount state**: per-account mount state, write-back journals, and daemon
  control sockets reject foreign ownership, unsafe permissions, and unexpected
  symlink or hard-link shapes before an offline transaction mutates them.

The operating-system account is the local security boundary. PortableFS assumes
processes running as the same effective user are mutually trusted: such processes
can ordinarily inspect or signal one another and can modify that user's private
state. Run mutually untrusted workloads under distinct OS accounts or stronger OS
isolation.

Out of scope: deployments that deliberately disable the production guards
(`VCS_ALLOW_PLAINTEXT_PRODUCTION=1`,
`PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE=plaintext`,
`PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION=1`,
`PORTABLEFS_AUTHORITY_MANAGER_ALLOW_UNAUTHENTICATED=1`) outside an authenticated
private network, missing rate limiting or denial-of-service resilience on
self-hosted endpoints you expose publicly, and vulnerabilities in third-party
dependencies with no PortableFS-specific exploit path (report those upstream, though
a heads-up is welcome).
