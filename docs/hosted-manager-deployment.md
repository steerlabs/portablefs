# Deploying the hosted manager

Status: **single-manager reference deployment for hosted v1**

Read [hosted-control-plane.md](./hosted-control-plane.md) first. The manager is
not in the filesystem data path, but compromise of its signing keys can admit
clients or replace authority generations across every registered cell. Run it
on a dedicated host; do not co-locate it with an authority or product backend.

## Host and network boundary

- Use one small, dedicated Linux VM in the same private network and availability
  zone as the v1 cells. It requires no public IP.
- Admit TCP 8443 only from registered cell hosts and explicitly configured
  product or operator egress identities. Administrative SSH should use the
  cloud provider's identity-aware tunnel rather than a public SSH address.
- Put `/var/lib/portablefs-manager` on a dedicated encrypted persistent disk
  with deletion protection, scheduled snapshots, and a tested restore runbook.
- The manager TLS listener requires TLS 1.3 and client certificates. A network
  allowlist is defense in depth, never a replacement for its SPIFFE role check.

The state file uses an adjacent, process-lifetime exclusive lock. The lock inode
is deliberately separate from the compacted state inode, so atomic state-log
replacement cannot admit a second writer.

## Identities and keys

Create separate roots and signers for these purposes:

| Material | Manager needs | Other holders |
| --- | --- | --- |
| control-channel CA | certificate only | offline issuer for operator, product, and cell mTLS identities |
| manager TLS identity | certificate and private key | none |
| cell-plan signer | Ed25519 private key | cells receive only the public key |
| capability signer | Ed25519 private key | authorities receive only the public key |
| authority CA | certificate and private key | cells receive only the certificate |
| mount-client CA | certificate and private key | authorities receive only the certificate |
| product authorization key | public key only | product backend retains the private key |

Do not reuse a key across rows. Private files are root-provisioned, owned by the
`portablefs-manager` account, mode `0600`, in root-owned non-manager-writable
directories. The control CA private key and product private key do not belong
on the manager host.

The manager server certificate must name the exact private DNS name configured
in every cell's `PORTABLEFS_MANAGER_SERVER_NAME`. Manager client certificates
have exactly one URI SAN. Control clients are issued from the control-client
CA:

```text
spiffe://portablefs/control/operator/<id>
spiffe://portablefs/control/product/<product-issuer>
spiffe://portablefs/control/cell/<cell-uuid>
```

Mount enrollment clients are issued from a separate mount-enrollment CA:

```text
spiffe://portablefs/mount-enrollment/<enrollment-id>
```

The listener trusts both the control-client CA and the mount-enrollment CA.
The authority does not trust the mount-enrollment CA, and the Manager does not
trust the authority-facing mount-client CA. Exact URI role parsing further
limits a mount-enrollment certificate to its own refresh and close endpoints.

## Install and configure

Install a root-owned, non-group-writable, release-stamped Linux binary at:

```text
/usr/local/bin/portablefs-manager
```

Install `deploy/systemd/portablefs-manager.service`. Create the stable service
account and root-owned configuration hierarchy:

```text
/etc/portablefs/manager/manager.env
/etc/portablefs/manager/tls/manager.cert
/etc/portablefs/manager/tls/manager.key
/etc/portablefs/manager/trust/control-client-ca.pem
/etc/portablefs/manager/trust/authority-ca.pem
/etc/portablefs/manager/trust/mount-client-ca.pem
/etc/portablefs/manager/trust/mount-enrollment-ca.pem
/etc/portablefs/manager/trust/product-public.pem
/etc/portablefs/manager/keys/plan-signing.key
/etc/portablefs/manager/keys/capability-signing.key
/etc/portablefs/manager/keys/authority-ca.key
/etc/portablefs/manager/keys/mount-client-ca.key
/etc/portablefs/manager/keys/mount-enrollment-ca.key
```

`manager.env` is root-owned mode `0600` and contains no private key bytes:

```text
PORTABLEFS_MANAGER_LISTEN=0.0.0.0:8443
PORTABLEFS_PRODUCT_ISSUER_KEY=portablefs-test=/etc/portablefs/manager/trust/product-public.pem
```

Start the unit only after checking every file owner, mode, certificate purpose,
SAN, validity window, and public/private key match. Record the binary SHA-256,
embedded release identity, manager state disk identity, and active certificate
fingerprints in the deployment manifest.

## Acceptance and recovery

Before admitting a real product:

1. Prove unauthenticated TLS, wrong-role clients, wrong cell IDs, and unknown
   product issuers are rejected.
2. Register a disposable cell and provision a disposable quota-limited volume.
3. Prove an exact idempotent retry is byte-identical and changed reuse fails.
4. Restart the manager and prove mount issuance remains closed until a fresh
   cell heartbeat.
5. Attempt a concurrent second manager and prove the state lock rejects it.
6. Restore the state disk snapshot onto a replacement VM while the original is
   fenced, then reconcile without advancing an authority generation.
7. Exercise block and inode quota exhaustion, authority crash, helper/agent
   restart, certificate renewal, strict-fence refusal, and cross-tenant denial.

Never attach a restored state disk to a replacement manager until the original
VM is stopped and externally fenced. Snapshots are backups, not distributed
locking or manager HA.
