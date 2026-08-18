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
   image, then start a disposable candidate sandbox and verify the client
   release plus Linux FUSE prerequisites.
4. Stream one gzip-compressed release archive through each private IAP tunnel,
   then activate it on the Manager and cell control processes. This does not
   restart a live Authority.
5. Drain OpenSteer E2B sandboxes, request the Manager's restart transaction,
   drain once more, and prove the old Authority service, listener, and cgroup
   are absent.
6. Submit the SHA-256 of that drain evidence to the Manager's strict-fence API.
   The Manager advances the Authority generation; the cell starts the new
   Authority from the same immutable release.
7. Verify the new generation and executable release, atomically move E2B's
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

Bootstrap the Manager's narrow product and operator mTLS identities once:

```bash
deploy/opensteer/bootstrap-manager-deployer.sh \
  smooth-comfort-488701-t3 us-east4-a \
  pfs-v3-manager-01 pfs-v3-authority-01 \
  manager.pfs-v3.internal \
  57483c00-a90d-42f1-bc80-945c0b477227
```

The bootstrap generates a one-purpose CA locally, installs only its CA
certificate plus the product/operator client identities on the root-owned
Manager host, verifies both roles against the live API, and discards the CA
private key with its temporary directory. Re-run it before the one-year client
certificates expire. No Manager credential or private key is stored in GitHub.

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
