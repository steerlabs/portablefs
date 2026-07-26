# Public source release

Publish from a fresh Git root. Do not make a previously private development
repository public, mirror its refs, or copy its `.git` directory.

The release gate has two independent checks:

1. The exported product tree contains no protected upstream-product markers.
2. The new public repository's complete object database and ref namespace are
   clean after its initial commit.

From a clean, reviewed release commit:

```bash
scripts/audit-public-source.sh --revision HEAD
scripts/export-public-source.sh --dry-run /absolute/path/to/portablefs-public HEAD
scripts/export-public-source.sh /absolute/path/to/portablefs-public HEAD
```

The export command writes only files tracked by the selected commit. It does not
initialize a repository, rewrite history, add a remote, push, or modify the
source repository.

In the separate export directory, after the owner has selected the permanent
public Go module namespace:

```bash
git init
git add --all
git commit -m "Initial public release"
scripts/audit-public-source.sh --all-objects
```

Copy the audit script into the new root before running the final command, or run
it by absolute path from this source tree. Add the all-object audit as a required
release check. `--all-objects` decodes every object known to the repository,
including unreachable objects, and scans ref names; it therefore catches
contamination that a checkout-only search cannot see.

Additional organization-specific markers can be supplied without weakening the
default:

```bash
PORTABLEFS_PUBLIC_FORBIDDEN_REGEX='marker-one|marker-two' \
  scripts/audit-public-source.sh --all-objects
```

The Go module path is a public compatibility contract. Resolve the owner and
repository namespace before creating the fresh root; changing it later forces
downstream import churn.
