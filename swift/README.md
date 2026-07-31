# PortableFS on macOS (FSKit)

This directory contains the macOS FSKit frontend for PortableFS.

## Layout

- `PortableFSKit`: Swift package with the pfslocal client, `VolumeCore`, macOS 26 FSKit Operations adapter, generated protobuf bindings, mock daemon tests, and `PortableFSAppCore` (config file handling, control-plane API client, portablefsd control-socket client, mount state machine — the testable core of the menu-bar app).
- `PortableFSApp`: the PortableFS menu-bar app (`PortableFS.app` + embedded CLI, daemon, and `PortableFSExt.appex`). It is a presentation layer over the bundled CLI, which is the sole mount-lifecycle owner.
- `PortableFSKitDev`: minimal Xcode host app plus `PortableFSDev.appex` for manual FSKit registration and mount testing. Kept for the package's test/verification loop.

## PortableFS.app (menu-bar app)

`PortableFSApp` is a SwiftUI `MenuBarExtra` agent app (`LSUIElement`) for macOS 26:

- **Sign in** mirrors `portablefs login`: device flow (`POST /v1/auth/device/code`, browser approval, token polling) or a pasted pre-issued token. Credentials are stored in the same config file as the CLI (`~/.config/portablefs/config.json`, `currentProfile` + `profiles` with `apiUrl`/`apiToken`/`managerUrl`/`managerToken`, written atomically with mode 0600), so the app and CLI share sessions and profiles.
- **Volumes** come from `GET {apiUrl}/v1/volumes`. Each volume shows a mounted indicator plus Mount / Unmount / Open in Finder actions.
- **Mount flow** invokes `Contents/Helpers/portablefs mount|umount|mounts --json`. The Go CLI alone owns daemon state, access leases, lifecycle locks, readiness, errors, and the canonical `~/.local/state/portablefs` root. The app never reconstructs that state.
- **App lifecycle** holds the CLI's shared lifecycle lease while the UI is open, preventing a concurrent bundle replacement. If the holder cannot start or exits unexpectedly, the app closes visibly instead of running without the guard.
- **Account changes** acquire the CLI's account-exclusive lease, require its
  exact empty mount/attach readiness frame, reload the config while protected,
  atomically save and reload it, then release. Mount lifetimes hold the paired
  shared lease, so sign-in, sign-out, and profile switching cannot race a
  mount session.
- **Errors** surface as menu items with a Copy Details action; nothing fails silently.
- **Quit** exits only the presentation process. CLI-owned mounts continue until explicitly unmounted.

### Build

```sh
xcodebuild -project swift/PortableFSApp/PortableFSApp.xcodeproj -scheme PortableFSApp build CODE_SIGNING_ALLOWED=NO
```

For a runnable, signed local build set your team in `swift/PortableFSApp/Config/Development.xcconfig`:

```
DEVELOPMENT_TEAM = <your Apple Development team id>
```

then build without `CODE_SIGNING_ALLOWED=NO` (or run from Xcode). FSKit extensions must be signed to be registered by macOS; unsigned builds validate compilation and packaging but cannot exercise extension registration.

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
final app before using the release filename.

### Embedded runtime

The app always invokes `Contents/Helpers/portablefs`; that CLI locates its
matching `portablefsd` sibling. There is no app-specific runtime override or
second daemon discovery path.

### One-time FSKit extension approval

macOS requires an interactive approval before a file system extension can serve mounts. After the first launch of PortableFS.app:

1. Open System Settings -> General -> Login Items & Extensions -> File System Extensions.
2. Enable the PortableFS extension (from PortableFS.app).
3. Continue to a real mount. The assistant never claims the toggle is enabled;
   only a successful mount verifies it.

Only one OSS PortableFS file system extension should be enabled at a time:
`PortableFSExt.appex` (the app) and `PortableFSDev.appex` (the dev harness)
both claim the same signed identity tuple: filesystem type `pfs`, generic
resource scheme `dev.portablefs.oss`, and the OSS app group. Disable one before
enabling the other. Other products embedding the shared Swift adapter provide
their own tuple through their extension metadata, so FSKit can route them
side-by-side without an ambiguous URL scheme. Do not automate this toggle; it
is a user-controlled macOS setting.

### End-to-end dogfood checklist

1. Set/override `DEVELOPMENT_TEAM` if building under a fork, then run the app from Xcode (or `xcodebuild ... build` signed, then launch the app).
2. Approve the file system extension (one-time, see above).
3. Menu bar -> Sign In: enter the server URL and either complete device sign-in in the browser or paste a token.
4. Menu bar -> volume -> Mount. The volume appears at `~/PortableFS/<volume>`; Open in Finder from the menu.
5. Unmount from the menu when you want to detach a volume. Quit closes only
   the presentation app; CLI-owned mounts keep running. Stop the idle daemon
   explicitly with `portablefs daemon stop` when needed.

### Known limitations (v1 dogfood)

- macOS 26 only (FSKit Operations adapter targets the macOS 26 API surface).
- Developer ID export/notarization requires the corresponding Apple signing
  profiles and a local `notarytool` credential; the packager fails visibly if
  either is unavailable.
- The FSKit extension approval is manual (macOS requirement).
- Daemon sockets live in the signing-team-specific app-group container stamped
  into the extension, CLI, and daemon at build time. This is a sandbox
  requirement, not a preference: a sandboxed FSKit extension may only
  `connect(2)` to unix sockets on app-group paths.
- The menu mounts the server-declared `defaultBranch`. A volume response with
  an invalid, missing, or ambiguous default branch is rejected rather than
  guessed.

## PortableFSKit package

### Regenerating pfslocal Swift bindings

The generated protobuf file is checked in so normal builds do not require `protoc`.

```sh
cd swift/PortableFSKit
make generate
```

`generate` expects `protoc` and `protoc-gen-swift` on `PATH`. The generated code must be regenerated whenever `pfslocal/pfslocal.proto` changes.

### Build and Test

```sh
cd swift/PortableFSKit
swift build
swift test
```

The suite covers the pfslocal transport/adapter (mock daemon) and the `PortableFSAppCore` app logic: CLI-compatible config round-trips, control-plane API decoding (volumes, device flow, access leases), the portablefsd control client against an in-process UDS HTTP server, and the mount state machine.

```sh
xcodebuild -project swift/PortableFSKitDev/PortableFSKitDev.xcodeproj -scheme PortableFSKitDev build CODE_SIGNING_ALLOWED=NO
```

For signed local extension testing of the dev harness, set `DEVELOPMENT_TEAM` in `swift/PortableFSKitDev/Config/Development.xcconfig`.

## Manual FSKit Verification

The live mount boundary is intentionally manual because macOS requires an interactive File System Extensions approval.

1. Build and run the `PortableFSKitDev` host app once so macOS registers `PortableFSDev.appex` (or use PortableFS.app and its extension instead).
2. Open System Settings -> General -> Login Items & Extensions and open the **File System Extensions** category (its ⓘ). Use the category view: on macOS 26 the per-app view's toggle can silently do nothing.
3. Enable the "PortableFS OSS Dev" file system extension there.
4. Start `portablefsd` with its pfslocal UDS inside the app-group container the appex resolves via `PFSAppGroupIdentifier`: `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock`.
   The sandbox only allows the extension to connect to unix sockets inside that container, so no other socket location can work.
5. Mount:

```sh
mkdir -p /tmp/pfs
/sbin/mount -t pfs "dev.portablefs.oss://<ref>" /tmp/pfs
```

6. Smoke-test the mounted tree with normal filesystem tools (`ls`, `stat`, `cat`, create/write/rename/remove files, xattrs if available from the daemon).
7. Unmount:

```sh
umount /tmp/pfs
```

Do not automate the System Settings approval step; it is a one-time user-controlled macOS toggle.
