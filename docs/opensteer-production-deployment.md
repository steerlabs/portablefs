# Deploying PortableFS for OpenSteer

Status: **one forward-only production promotion path**

OpenSteer deploys from this repository. A second repository, copied source
tree, or separately selected client artifact would create another version
boundary without adding isolation. The `opensteer-production` branch contains
only reviewed promotion merges whose source tree exactly matches a commit on
`main`; the deployment workflow verifies that invariant again before building.

## Normal release

1. Merge a PortableFS change to `main` and let `ci` pass.
2. Open a pull request that advances `opensteer-production` to that `main`
   commit.
3. Merge the promotion pull request.

The push runs the same complete `ci` workflow. Only its successful
`workflow_run` can enter the protected `opensteer-production` GitHub
environment. `.github/workflows/deploy-opensteer-production.yml` then performs
one serialized deployment:

1. Check out the exact successful branch-head commit.
2. Build and verify one immutable hosted bundle. It contains the Manager, cell
   services, Authority, and the exact Linux client used by E2B.
3. Build a commit-tagged E2B candidate from a digest-pinned OpenSteer Runner
   image, then start a disposable candidate sandbox and run the template smoke.
   See [What the smoke proves](#what-the-smoke-proves) — it is a narrow gate,
   not a qualification.
4. Stream one gzip-compressed release archive through each private IAP tunnel,
   then activate it on the Manager and cell control processes. This does not
   restart a live Authority.
5. Preflight every configured volume, drain OpenSteer E2B sandboxes once, and
   request each required Manager restart transaction. A co-located Manager and
   cell are activated as two explicit roles; sharing a VM does not skip either
   unit set.
6. Drain once more, prove each old Authority service, listener, and cgroup is
   absent, and submit that evidence SHA-256 to every fencing volume. The
   Manager advances each Authority generation; the cell starts every new
   Authority from the same immutable release.
7. Verify every new generation and executable release, atomically move E2B's
   `default` tag to the tested candidate, and drain once more. That final pass
   removes a sandbox that might have been created with the old default tag
   during the maintenance window.

GitHub retains the volume, Authority, and sandbox-fence evidence for 90 days.
The Manager also durably records the evidence hash.

There is no downgrade job or rollback branch. Once the new Authority generation
is live, a problem is fixed by promoting another commit. The host activator does
restore the prior symlink if an individual atomic activation fails before it
finishes; that is transaction failure handling, not an operator rollback of a
completed deployment.

## What the smoke proves

The candidate smoke (`deploy/opensteer/e2b-release.mjs smoke`) runs inside one
disposable sandbox with no manager and no authority. There is nothing there for
a mount to attach to, and faking one would make the gate worse than useless, so
its scope is deliberately narrow.

It proves:

- the template contains this exact release's client, and the client agrees
  about its own version;
- the sandbox kernel exposes a usable `/dev/fuse` to that client;
- the client can complete a real kernel FUSE INIT handshake. `portablefs
  mount-check --strategy fuse --probe-mount` installs one throwaway FUSE mount
  on a private temporary directory using the client's own mount options, checks
  the capabilities the coherence contract requires — atomic `O_TRUNC`, explicit
  data-cache control, forwarded POSIX and BSD locks, entry and inode
  invalidation, a 1 MiB request bound — and unmounts. This is the one check
  that a client which can never complete FUSE INIT cannot pass. The device node
  existing, the device opening, `CAP_SYS_ADMIN` being held, and a helper being
  installed are all equally true of such a client, which is how that failure
  class previously reached a tenant's first mount instead of the gate.

It does not prove anything about the authority, the wire protocol, visibility,
durability, locking across mounts, leases, recalls, or any workload. A client
that completes INIT can still be wrong about every one of those.

Full qualification is the real-workload corpus in
`deploy/opensteer/staging-qualification.sh`, run against a live staging cell:
serial and `tee -a` appends, a git repository created and `fsck`-verified on the
mount, two concurrent `O_APPEND` writers on one file, a hot file read by several
processes while another rewrites it, and a durability check across unmount and
remount. That script also names the two things to watch on the authority while
it runs — RecallBudget-exhaustion fences and uncertain-outcome revocations — a
pass with either of those firing is a result the authority paid for, not a clean
one.

## Data

Ordinary software releases do not migrate volume data. Authority generations
continue to serve the same XFS project directory, so E2B sandbox replacement
loses only ephemeral processes and cache. PortableFS volume contents remain in
place.

Manager state and on-disk formats must remain readable by the promoted code.
An intentionally incompatible persisted-format change is not an ordinary
promotion: it needs its own reviewed migration runbook and must not be merged
to `opensteer-production` until that runbook has completed. The workflow does
not guess at or automatically manufacture data conversions.

## One-time setup

Create a GitHub environment named `opensteer-production`. Allow deployments
from `main` and add one secret, `E2B_API_KEY`. A `workflow_run` deployment uses
the workflow file from GitHub's default branch, so GitHub evaluates the
environment against `main`; the job itself separately requires an exact
successful `opensteer-production` push from this repository. Do not store a
Google service-account JSON key. The workflow exchanges GitHub's OIDC token
through the existing Google Workload Identity provider and impersonates:

```text
portablefs-deployer@opensteer-admin.iam.gserviceaccount.com
```

Grant that service account only these project roles on the PortableFS GCP
project:

```bash
gcloud projects add-iam-policy-binding smooth-comfort-488701-t3 \
  --member=serviceAccount:portablefs-deployer@opensteer-admin.iam.gserviceaccount.com \
  --role=roles/compute.viewer
gcloud projects add-iam-policy-binding smooth-comfort-488701-t3 \
  --member=serviceAccount:portablefs-deployer@opensteer-admin.iam.gserviceaccount.com \
  --role=roles/compute.osAdminLogin
gcloud projects add-iam-policy-binding smooth-comfort-488701-t3 \
  --member=serviceAccount:portablefs-deployer@opensteer-admin.iam.gserviceaccount.com \
  --role=roles/iap.tunnelResourceAccessor
```

Grant the same service account `roles/artifactregistry.reader` on only the
`opensteer-admin/us-west1/staging` Artifact Registry repository. Its Workload
Identity User binding names the exact GitHub OIDC subject
`repo:steerlabs@252926615/portablefs@1313214092:environment:opensteer-production`.
PortableFS was created after GitHub introduced immutable OIDC subjects, so the
organization and repository IDs are part of the subject. Use the repository
OIDC API's `sub_claim_prefix` rather than assuming the legacy name-only format.
OpenSteer's separate image-publishing identity keeps Artifact Registry write
access; this deployment identity does not.

Enable OS Login in both the VM project and the project that owns the deployer
service account. Google creates the service account's POSIX profile through the
latter project even though the VMs live in the former:

```bash
gcloud services enable oslogin.googleapis.com --project=opensteer-admin
gcloud services enable oslogin.googleapis.com --project=smooth-comfort-488701-t3
```

The VMs have no public SSH address. Deployment uses OS Login through IAP. The
service account needs administrative login because the existing host activator
must replace root-owned releases and systemd units. A single compressed tar
stream avoids recursive SFTP's per-file behavior on the private tunnel.

Prepare an absolute root-private credential directory containing
`client-ca.pem`, `client-ca.key`, `manager-ca.pem`, `product.cert`, and
`product.key`. The client CA must already be in the Manager's configured trust
bundle and the product certificate must name the configured product issuer.
Then install the Manager's narrow product identity and a freshly issued
operator identity:

```bash
deploy/opensteer/bootstrap-manager-deployer.sh \
  smooth-comfort-488701-t3 us-east4-a \
  pfs-v3-manager-01 manager.pfs-v3.internal \
  opensteer-production \
  57483c00-a90d-42f1-bc80-945c0b477227 \
  /absolute/path/to/deployment-credentials
```

The bootstrap validates the CA, certificate, private-key, issuer, and server
trust relationships before upload. It issues a 30-day operator certificate,
atomically activates a versioned root-owned credential bundle, and verifies
both roles against the live API without changing Manager trust or restarting
the Manager. Re-run it before deployment to renew the operator identity. Keep
the client CA key in the environment's protected secret store; no Manager
credential or private key is stored in GitHub.

Protect `opensteer-production` against deletion and force pushes, allow only
merge commits through pull requests, and require every `ci` job before merge.
Do not create the branch until the environment secret, Google roles, and
Manager identities above are ready: the first successful push is a real
deployment.

## Fixed inputs

The workflow pins the OpenSteer Runner by image digest. That image contains all
OpenSteer-owned activation and Runner code; this repository adds only the exact
PortableFS client built by the promoted commit. When OpenSteer publishes a new
production Runner, update the one digest in a reviewed PortableFS pull request.
A mutable `latest` tag and a cross-repository GitHub credential are never
deployment inputs. PortableFS's promotion commit, hosted release identity, E2B
client digest, Runner image digest, and Authority generation remain visible as
one audit chain.
