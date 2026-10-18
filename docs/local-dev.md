# Local Development

This is a two-language tree — the Go data plane under `vcs/` and the Swift
FSKit/app package under `swift/PortableFSKit` — with no build system above them
and no package manager to install.

## The merge gate

```bash
bash scripts/verify-local.sh          # default: no Docker, no real mount
bash scripts/verify-local.sh --full   # + both privileged real-mount suites
```

That script is the local gate, and it is plain bash so a developer Mac and a
Linux CI runner execute the same steps. The default mode below stops short of
the two real-mount suites and names them as not run; `--full` appends them.

1. cross-platform compile and vet, both built before anything runs, because
   the daemon, mount clients, and frontend adapters all carry per-GOOS files:
   on macOS the real Foundation/cgo Darwin boundary plus static Linux, and on
   Linux the native product plus Darwin's deliberate `!cgo` refusal stub;
2. the pinned `govulncheck` reachable-call scan, which also enforces the exact
   Go security patch level required by `vcs/go.mod`;
3. the native Go suite, then the native race suite — these tests exercise real
   syscalls, sockets, and mounts, so they are only meaningful on the host;
4. `bash scripts/test-swift-xcode.sh` on macOS. The gate asks Xcode to
   enumerate the complete package inventory, executes that already-built
   inventory once through Xcode's native serial test runner, and rejects the
   result unless the `.xcresult` contains the same unique all-passing set. This
   avoids SwiftPM's separate Darwin helper process while preserving exact
   coverage. Non-macOS hosts skip this macOS-only package loudly; the macOS CI
   job always runs it;
5. workflow semantics and release-trust policy: the pinned `actionlint`,
   `sh -n scripts/install.sh`, `scripts/check-workflow-pins.mjs`, and
   `scripts/check-install-release-trust.mjs` (the project checkers are
   dependency-free single-file node programs that read the installer, the
   workflows, and `.goreleaser.yaml` as text);
6. the current-architecture check, `scripts/check-current-architecture.py`,
   which asserts the current state positively rather than scanning for retired
   names: the exact authority major and ALPN, the frontend profile set, the
   authority and `pfslocal` schema shape and pairing, the daemon control and
   lifecycle versions, production readiness and flag wiring, the required-test
   inventories, version statements in maintained text, and documentation
   links. `--only <check>` runs one check; `--list` names them.

The raw commands, when you want one piece:

```bash
CGO_ENABLED=1 GOOS=darwin go -C vcs build ./...   # on macOS; Foundation resolver
CGO_ENABLED=0 GOOS=linux  go -C vcs build ./...   # static Linux release
go -C vcs vet ./...
go -C vcs test ./...
go -C vcs test -race ./...
python3 scripts/check-current-architecture.py
bash scripts/test-swift-xcode.sh
```


## The privileged Linux gate

```bash
bash scripts/xfs-fuse-integration.sh          # host side; needs docker
bash scripts/xfs-fuse-integration.sh --in-container   # container side; needs root
```

Runs a throwaway privileged container against a real XFS loopback filesystem
with project quotas and real kernel FUSE mounts. Its host or VM must expose
`/dev/fuse`, loop devices, and stock FUSE protocol 7.31 or newer. The same script
is the CI entry point and local reproduction. It enforces exact required-test
inventories, one per owning package: `scripts/xfs-required-authority-tests.txt`,
`scripts/xfs-required-fuse-tests.txt`, and `scripts/xfs-required-tiered-tests.txt`.
A separate root invocation runs the cell helper's root-only boundary tests
against its own exact list in the script. A test that is renamed, deleted, or
skipped fails the job (exit 70) rather than quietly shrinking privileged
coverage, and a focused `PORTABLEFS_GO_TEST_FLAGS='-run ...'` selection is
reported as missing tests, never as a full pass. Rename or delete a required
test and its list entry in the same change.

## The cross-mount coherence matrix

```bash
bash scripts/coherence-matrix-linux.sh        # host side; needs docker
```

On a stock Linux host or VM, this provisions a real XFS cell, starts a real
authority and two real mount processes, then drives both mountpoints with
ordinary syscalls from a separate black-box program: 29 named cases, nothing
in-process and nothing faked. The matrix proves only observed syscall behavior;
dedicated protocol tests must prove subscription withdrawal, delegation grant,
recall, and break. The harness has no profile selector.

On macOS the shared cases run between one FSKit mount on the Mac and one Linux
kernel-FUSE mount on a remote peer. There is no Mac-to-Mac form, because writer
exclusion refuses a second Mac mount of a volume. The script never mounts,
unmounts, or drives `portablefsd`, and a run is not native FSKit qualification:

```bash
scripts/coherence-matrix-macos.sh --mount-a /path/on/mac \
  --remote user@linux-host --remote-mount /path/on/linux \
  [--remote-binary /path/to/linux/pfs-coherence-matrix]
```

Both scripts fail closed. A case that cannot be honestly asserted skips loudly
with a stated reason and a nonzero exit; a quiet pass is never an option. See
[cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md).

## Running a real authority

Standing up an authoritative-XFS volume by hand — host and disk preparation, the
isolated volume worker, credentials, and connecting a Linux mount — is
[xfs-authority-deployment.md](./xfs-authority-deployment.md).

Production mounts pass `--mount-token` and an explicit transport: `tls-system-pki`
plus `--data-plane-server-name`, or `tls-private-ca` plus that exact server name
and `--data-plane-ca <ca.pem>`. There is no TLS environment fallback, an empty CA
never selects plaintext, and plaintext is refused outright: an authority
session is mutually authenticated TLS 1.3.
