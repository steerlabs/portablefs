# Linux workspace image distribution

The guest is Debian 13 arm64 at the snapshot in
`deploy/linux-workspace/image.lock.json`, with exact binary/source inventories,
the 6.12.113 kernel and Go 1.26.10. The 3 GiB ext4 system disk is read-only.
The owner creates the 64 GiB sparse persistent data disk locally; it is never
part of an image or source download. Node.js, npm, Python pip/venv, Git and the
C/C++ toolchain are installed before sealing the system disk.

## Build and check

Build from a clean commit with Go and Docker on a native arm64 machine:

```sh
bash scripts/build-linux-workspace-image.sh /absolute/image
python3 scripts/check-linux-workspace-image.py /absolute/image
python3 scripts/test-linux-workspace-coverage.py /absolute/image
bash scripts/test-linux-workspace-reproducible.sh /absolute/reproduction
```

Each build uses a fresh container and rootfs. The builder fixes filesystem UUID,
directory hash seed, file times, ext4 creation time, tar ownership and gzip time.
Go uses its pinned toolchain, trimpath, no VCS auto-stamping and no build ID.
The binaries carry VERSION; the guest handshake binds the exact source commit
and image-input digest. No older authority protocol or image decoder is used.
The reproduction gate hashes every output, including both compressed archives.

The base snapshot and build epoch remain fixed. A separately pinned security
snapshot supplies Debian's 6.12.113-1 kernel and matching userspace headers;
APT preferences retain every other locked package version before bootstrap.
The pinned `wireless-regdb` package supplies the regulatory firmware requested
by Debian's kernel, avoiding missing-firmware errors during boot.
This kernel includes the 6.12.112 anon-vma publication ordering fix, upstream
`b6ac0b3f6013c168f22cad97e79967accacb08e1`, listed in
[Debian's changelog](https://tracker.debian.org/news/1811640/accepted-linux-612113-1-source-into-stable-security/).

To change package inputs, edit the include list or exact package versions and run the builder with
`--update-lock` from a clean commit. Commit its generated lock, then build
normally twice. The refresh is input maintenance, not release evidence.

For kernel stability, build the paired native development executable and run
50 serial boot/workload/orderly-stop cycles on Apple silicon:

```sh
bash scripts/build-linux-workspace-dev.sh
python3 scripts/test-linux-workspace-kernel-stability.py \
  swift/PortableFSKit/.build/arm64-apple-macosx/debug/portablefs-workspace-dev \
  /absolute/image /absolute/stability-evidence --cycles 50
```

Each cycle runs offline Git operations, npm and pip installs, a parallel C
build and 512 fork/exec churn iterations before requesting ordinary shutdown.
The loop retains every serial transcript, rejects kernel diagnostics and
requires `shutdown-completed`; it never retries a failed cycle. Its result
file binds the kernel, image release and workload hash. Coordinate native VZ
runs with other sessions on the same Mac. This soak supplements the exact
native workspace inventory; it does not replace it.

## Retained source and notices

The output contains `guest-image.tar.gz`, `corresponding-source.tar.gz` and
`distribution.json`. The guest archive contains the exact files verified by
`WorkspaceArtifact`, plus `manifest.json`. It includes `licenses.tar.gz` and
`source-manifest.json`; the latter binds the separate corresponding-source
archive by SHA-256 and byte length. `distribution.json` binds both archives
and both manifests. Source bytes need not be installed inside the app.

The corresponding-source archive contains:

- Each installed Debian package's exact source: its `.dsc` and every original
  and Debian source component named by that control file. These retain Debian's
  recipe, configuration and patches. The exact Built-Using and Static-Built-Using
  versions are included even when they differ from the snapshot's current source.
- The repository at the embedded commit, including the guest recipe, overlay,
  image lock and maintained go-fuse fork; the actual kernel configuration; each
  external linked Go module's original module zip; and the pinned Go source archive.

The checker requires complete package and incorporated-source coverage, exact
source-control SHA-256s, retained archive membership, recipe/commit equality,
linked Go module versions, and nonempty notices for every binary package,
linked module and runtime. Missing source or notice mappings fail even when
the caller recomputes the outer manifest hash. Debian copyright symlinks are
materialized into `licenses.tar.gz`, alongside common license texts.
The retention rule follows Debian's
[source package policy](https://www.debian.org/doc/debian-policy/ch-source.html)
and [incorporated-source relationships](https://www.debian.org/doc/debian-policy/ch-relationships.html#additional-source-packages-used-to-build-the-binary-built-using).

The `workspace-image` workflow builds twice on `ubuntu-24.04-arm`, checks coverage,
runs the omission controls and uploads the guest/source archives, manifests,
space measurements and reproduction proof together for 90 days. A release
packaging job must retain and publish the matching corresponding-source archive
beside the release assets for the entire distribution period. CI's temporary
artifact retention does not satisfy that release retention obligation. This
workflow does not publish a release or change `release.yml`.

## Space accounting

`distribution.json` records byte counts for the compressed image, expanded guest
and a same-size update that retains the old guest. Expanded counts include all
logical system-disk bytes, without assuming APFS clones or sparse extraction.
Peak extraction is compressed plus expanded bytes. Peak guest-only update is
compressed plus twice the expanded bytes; the already installed guest consumes
the first expanded copy. Add the non-guest app/installer bytes when integrating
the release. Existing data is retained and excluded from these incremental counts.

The expected compressed installer increase is the measured guest archive size.
It is an estimate until the final signed app installer is packaged; ZIP framing,
compression settings and app contents can change the exact increase. Source
archive bytes are a separate release asset, not an installer cost.

`WorkspaceDiskSpace(artifact:)` counts verified logical artifact bytes.
`extractionRequiredBytes` adds a 2 GiB reserve for initial sparse-data filesystem
writes and working headroom. PR 2's owner can call
`WorkspaceDiskSpace.preflight(at:requiredBytes:)` on the destination filesystem
before extraction/update, adding any compressed installer or app bytes it still
needs. Before first boot it can preflight `initialDataReserveBytes`. This checks
present capacity; subsequent project data growth still needs available disk.
