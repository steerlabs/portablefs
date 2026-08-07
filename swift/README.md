# PortableFS on macOS (FSKit)

This directory contains the macOS FSKit frontend for PortableFS: one Swift
package and two Xcode projects.

## Layout

- **`PortableFSKit`** — the SwiftPM package (`swift-tools-version: 6.2`,
  `.macOS(.v26)`). It holds everything that is not an app: the pfslocal client
  and its transport, `VolumeCore`, the FSKit Operations adapter, the macOS 26
  strict coherence composition, the generated protobuf bindings, a mock daemon
  used by the tests, and `PortableFSAppCore`, a small support target for the
  menu-bar app.
- **`PortableFSApp`** — the shipping product: `PortableFS.app` (a SwiftUI
  `MenuBarExtra` agent app, `LSUIElement`) with the embedded CLI and daemon in
  `Contents/Helpers` and `PortableFSExt.appex` in `Contents/Extensions`. The app
  is a presentation layer over the bundled CLI, which is the sole
  mount-lifecycle owner.
- **`PortableFSKitDev`** — a minimal Xcode host app plus `PortableFSDev.appex`,
  used to register an FSKit extension manually for the package's
  test/verification loop. Its extension bundle id
  (`dev.portablefs.oss.KitDev.PortableFSDev`) is deliberately distinct from the
  shipping app's, so a developer harness and a shipping install are never
  confused for one another on the same machine.

## PortableFSKit package

### What is in the target

The `PortableFSKit` target is one library with three cooperating layers.

**The pfslocal client** is the local frontend transport: `PfsLocalClient` plus
`PfsFrameCodec`, `PfsUnixSocket`, `PfsAsyncSocket`, `PfsErrors`,
`PfsSocketPathResolver`, and the checked-in `Generated/pfslocal/pfslocal.pb.swift`.
It speaks to `portablefsd` over a unix socket. It never sees authority TLS
credentials.

**`VolumeCore`** is the volume-level state the adapter operates on: item
identity, resolution, lookup/create/enumerate results, attribute shapes. It also
holds the v3 gate — when a resolve reply declares a v3 coherence contract,
`VolumeCore` parses it and admits only the declared macOS 26 policy;
`fskit-native-revocation-v1` is refused with `ENOTSUP` rather than silently
downgraded.

**The FSKit Operations adapter** is `OperationsAdapter.swift`
(`PortableFSFileSystem`, `PortableFSVolume`) plus `FSKitMapping.swift` and
`PortableFSIdentity.swift`. These, with `VolumeCore`, are the only files that
import FSKit.

**The macOS 26 strict coherence composition** now lives in this target
alongside the above, in five files:

| File | Role |
| --- | --- |
| `MacOSV3Namespace.swift` | `PfsMacOSNamespaceIndex` (name coordinates, with a reverse index so every hard-link alias survives independently) and `PfsMacOSLiveObjectIndex` (live objects, which unlink must not retire), plus `PfsMacOSRepairPlanner` |
| `MacOSV3Coherence.swift` | the coherence runner, backends, transport protocol, `PfsMacOS26RepairAuthenticator`, and the `PfsMacOS26POSIXActuator` |
| `MacOSV3RepairGate.swift` | `PfsMacOS26RepairArmRegistry`, the repair arm/gate |
| `MacOSV3FSKitComposition.swift` | `PfsMacOSFSKitPublicationBarrier`, the deferred mount actuator, mount-root location, and `PfsMacOSV3VolumeCoherence` — the composition root the adapter installs |
| `MacOSV3PfsLocalTransport.swift` | `PfsLocalMacOSV3CoherenceTransport`, which carries the contract and visibility events over pfslocal |

The contract these implement, and what is still ungated, is
[../docs/macos-26-coherence-contract.md](../docs/macos-26-coherence-contract.md).

`PortableFSAppCore` is a small target holding only what the menu-bar app needs
that is worth testing on its own: account-home resolution, mount-inventory row
decoding, and kernel mount-table parsing. It owns no daemon, mount, lease, or
recovery behavior; all of that belongs to the CLI.

### Regenerating pfslocal Swift bindings

The generated protobuf file is checked in so normal builds do not require
`protoc`.

```sh
cd swift/PortableFSKit
make generate
```

`generate` expects `protoc` and `protoc-gen-swift` on `PATH`. The generated code
must be regenerated whenever `pfslocal/pfslocal.proto` changes.

### Build and test

The canonical command, from the repository root:

```sh
swift build --package-path swift/PortableFSKit
swift test --package-path swift/PortableFSKit --no-parallel
```

**`--no-parallel` is required, not a tuning choice.** Swift Testing can run
cases concurrently inside one SwiftPM worker. Several tests share process
resources — sockets, mount points, the app-group container — or exercise hard
protocol deadlines, so the corpus must run serially. The same command appears in `AGENTS.md`,
`scripts/verify-local.sh`, the root `README.md`, and the `swift` job in
`.github/workflows/ci.yml`.

The suite is swift-testing, not XCTest, so a passing run ends with a line of the
form `Test run with N tests in 0 suites passed`. It currently reports **186
tests**, covering the pfslocal transport and wire goldens, the Operations
adapter and its open-handle lifecycle, attribute and error mapping, enumeration
paging, write acknowledgement, and the macOS 26 coherence stack (namespace and
live-object indexes, the publication barrier, the repair gate and authenticator,
enforcement, and production wiring).

### Nothing in the suite mounts a real FSKit volume

Every test runs in process. They build `PortableFSVolume` directly over a
`VolumeCore` wired to the mock daemon across a plain unix socket; the six test
files that import FSKit do so only to use its types, never to register or mount
anything. The one test that reaches outside the process,
`PfsLiveRootTests`, talks to a live `portablefsd` socket when
`PFS_LIVE_SOCKET` and `PFS_LIVE_ATTACH_REF` are set, and returns immediately
otherwise — it still never involves the kernel.

The consequence is load-bearing: **this suite alone does not prove live-kernel
behaviour.** Installed-extension testing separately verifies callback dispatch,
cross-mount namespace visibility, callback-serialized mutation storms, daemon
death, forced unmount, and held-descriptor revocation. The final full matrix
still exercises negative/positive lookup, attributes, data/EOF, concurrent
mutators, direct source removal, hard links, rename-over-open descriptors,
authority restart, hostile exact-callback races, and bounded metadata-storm
latency. The current evidence and remaining matrix are in
[../docs/macos-26-coherence-contract.md](../docs/macos-26-coherence-contract.md);
see [Manual FSKit verification](#manual-fskit-verification) below for the loop.

### Building the dev harness

```sh
xcodebuild -project swift/PortableFSKitDev/PortableFSKitDev.xcodeproj \
  -scheme PortableFSKitDev build CODE_SIGNING_ALLOWED=NO
```

For signed local extension testing of the dev harness, set `DEVELOPMENT_TEAM` in
`swift/PortableFSKitDev/Config/Development.xcconfig`.

## PortableFS.app (menu-bar app)

- **Mount flow** invokes `Contents/Helpers/portablefs mount|umount|mounts --json`.
  The Go CLI alone owns daemon state, lifecycle locks, readiness, errors, and the
  canonical `~/.local/state/portablefs` root. The app never reconstructs that
  state.
- **The app does not mount.** A v3 session is admitted by direct credentials —
  an authority address, a single-use volume capability, and a mutual-TLS client
  identity — and the app neither mints nor stores any of them, so mounting
  happens from Terminal with `portablefs mount`. The menu presents the mount
  inventory and offers Reveal in Finder, Unmount (or Unmount / Reconcile),
  Refresh, Settings, extension setup, and stopping the background daemon.
- **App lifecycle** holds the CLI's shared lifecycle lease while the UI is open,
  preventing a concurrent bundle replacement. If the holder cannot start or exits
  unexpectedly, the app closes visibly instead of running without the guard.
- **Errors** surface as menu items with a Copy Details action; nothing fails
  silently.
- **Quit** exits only the presentation process. CLI-owned mounts continue until
  explicitly unmounted.

### Build

```sh
xcodebuild -project swift/PortableFSApp/PortableFSApp.xcodeproj \
  -scheme PortableFSApp build CODE_SIGNING_ALLOWED=NO
```

For a runnable, signed local build set your team in
`swift/PortableFSApp/Config/Development.xcconfig`:

```
DEVELOPMENT_TEAM = <your Apple Development team id>
```

then build without `CODE_SIGNING_ALLOWED=NO` (or run from Xcode). FSKit
extensions must be signed to be registered by macOS; unsigned builds validate
compilation and packaging but cannot exercise extension registration.

The local packager embeds universal `portablefs` and `portablefsd` helpers,
verifies the complete code hierarchy, and emits a clearly marked development
zip:

```sh
scripts/package-macos-app.sh 0.2.3
```

Distribution builds set `PORTABLEFS_RELEASE=1`, a monotonic
`PORTABLEFS_BUILD_NUMBER`, `PORTABLEFS_DEVELOPER_ID_EXPORT=1`, and a
`PORTABLEFS_NOTARY_PROFILE`. Release mode refuses unsigned, unexported, or
unnotarized output; it submits, staples, validates, and Gatekeeper-assesses the
final app before using the release filename. What the installer then re-proves
about that bundle is documented in
[../docs/release-identity.md](../docs/release-identity.md).

### Embedded runtime

The app always invokes `Contents/Helpers/portablefs`; that CLI locates its
matching `portablefsd` sibling. There is no app-specific runtime override or
second daemon discovery path.

### One-time FSKit extension approval

macOS requires an interactive approval before a file system extension can serve
mounts. After the first launch of PortableFS.app:

1. Open System Settings -> General -> Login Items & Extensions -> File System
   Extensions.
2. Enable the PortableFS extension (from PortableFS.app).
3. Continue to a real mount. The assistant never claims the toggle is enabled;
   only a successful mount verifies it.

Only one OSS PortableFS file system extension should be enabled at a time:
`PortableFSExt.appex` (the app) and `PortableFSDev.appex` (the dev harness) both
claim the same signed identity tuple: filesystem type `pfs`, generic resource
scheme `dev.portablefs.oss`, and the OSS app group. Disable one before enabling
the other. Other products embedding the shared Swift adapter provide their own
tuple through their extension metadata, so FSKit can route them side-by-side
without an ambiguous URL scheme. Do not automate this toggle; it is a
user-controlled macOS setting.

### End-to-end dogfood checklist

1. Set/override `DEVELOPMENT_TEAM` if building under a fork, then run the app
   from Xcode (or `xcodebuild ... build` signed, then launch the app).
2. Approve the file system extension (one-time, see above).
3. Mount from Terminal with `portablefs mount <volume> <directory>` and the
   direct v3 credential flags; `portablefs help mount` prints the full shape,
   and [../docs/xfs-authority-deployment.md](../docs/xfs-authority-deployment.md)
   covers where those credentials come from.
4. Confirm the mount appears in the menu bar inventory, and use Reveal in Finder.
5. Unmount from the menu when you want to detach a volume. Quit closes only the
   presentation app; CLI-owned mounts keep running. Stop the idle daemon
   explicitly with `portablefs daemon stop` when needed.

### Known limitations

- macOS 26 only (the FSKit Operations adapter targets the macOS 26 API surface,
  and the package declares `.macOS(.v26)`).
- Developer ID export/notarization requires the corresponding Apple signing
  profiles and a local `notarytool` credential; the packager fails visibly if
  either is unavailable.
- The FSKit extension approval is manual (macOS requirement).
- Daemon sockets live in the signing-team-specific app-group container stamped
  into the extension, CLI, and daemon at build time. This is a sandbox
  requirement, not a preference: a sandboxed FSKit extension may only
  `connect(2)` to unix sockets on app-group paths.
- The macOS coherence policy that ships is an explicitly declared compatibility
  policy with open live-kernel gates. Do not treat a macOS mount as equivalent to
  a Linux one without reading
  [../docs/macos-26-coherence-contract.md](../docs/macos-26-coherence-contract.md)
  and the macOS platform gaps in
  [../docs/liveness-followups.md](../docs/liveness-followups.md).

## Manual FSKit verification

The live mount boundary is intentionally manual because macOS requires an
interactive File System Extensions approval. This is also the only way to
exercise the behaviours the offline suite cannot reach.

1. Build and run the `PortableFSKitDev` host app once so macOS registers
   `PortableFSDev.appex` (or use PortableFS.app and its extension instead).
2. Open System Settings -> General -> Login Items & Extensions and open the
   **File System Extensions** category (its ⓘ). Use the category view: on
   macOS 26 the per-app view's toggle can silently do nothing.
3. Enable the "PortableFS OSS Dev" file system extension there.
4. Start `portablefsd` with its pfslocal UDS inside the app-group container the
   appex resolves via `PFSAppGroupIdentifier`:
   `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock`.
   The sandbox only allows the extension to connect to unix sockets inside that
   container, so no other socket location can work.
5. Mount:

```sh
mkdir -p /tmp/pfs
/sbin/mount -t pfs "dev.portablefs.oss://<ref>" /tmp/pfs
```

6. Smoke-test the mounted tree with normal filesystem tools (`ls`, `stat`,
   `cat`, create/write/rename/remove files). Xattrs are intentionally partial:
   pre-existing portable attributes can be read/listed/removed. Production
   resolve declares set unsupported, so FSKit validates and refuses it locally
   with Darwin `EOPNOTSUPP` (102), emits no daemon mutation, and never permits
   an AppleDouble `._*` file to appear.
7. Unmount:

```sh
umount /tmp/pfs
```

Do not automate the System Settings approval step; it is a one-time
user-controlled macOS toggle.

The heavier live harnesses live in `scripts/`: `fskit-solo-battery.sh`,
`live-mount-battery.sh`, `coherence-matrix-macos.sh`, and `two-mac-stress.sh`.
They run against already-mounted paths and are the only things in this
repository that observe real kernel behaviour on macOS.
