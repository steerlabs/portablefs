# PortableFS on macOS (FSKit)

This directory contains the macOS FSKit frontend for PortableFS.

## Layout

- `PortableFSKit`: Swift package with the pfslocal client, `VolumeCore`, macOS 26 FSKit Operations adapter, generated protobuf bindings, mock daemon tests, and `PortableFSAppCore` (config file handling, control-plane API client, portablefsd control-socket client, mount state machine — the testable core of the menu-bar app).
- `PortableFSApp`: the PortableFS menu-bar app (`PortableFSApp.app` + embedded `PortableFSExt.appex`). Signs in to a PortableFS control plane, lists volumes, manages a child `portablefsd`, and mounts volumes via FSKit. This is the dogfood target.
- `PortableFSKitDev`: minimal Xcode host app plus `PortableFSDev.appex` for manual FSKit registration and mount testing. Kept for the package's test/verification loop.

## PortableFS.app (menu-bar app)

`PortableFSApp` is a SwiftUI `MenuBarExtra` agent app (`LSUIElement`) for macOS 26:

- **Sign in** mirrors `portablefs login`: device flow (`POST /v1/auth/device/code`, browser approval, token polling) or a pasted pre-issued token. Credentials are stored in the same config file as the CLI (`~/.config/portablefs/config.json`, `currentProfile` + `profiles` with `apiUrl`/`apiToken`/`managerUrl`/`managerToken`, written atomically with mode 0600), so the app and CLI share sessions and profiles.
- **Volumes** come from `GET {apiUrl}/v1/volumes`. Each volume shows a mounted indicator plus Mount / Unmount / Open in Finder actions.
- **Mount flow** per volume: mint an access session against the configured authority manager -> `POST /v1/attaches` on the portablefsd control socket (authority URL + token + volume/branch) -> `/sbin/mount -t pfs pfs://<attachRef> <base>/<volume>` (default base `~/PortableFS`, configurable in Settings). A normal unmount synchronizes the attach before removing the kernel mount, then deletes the attach.
- **Daemon management**: release builds bundle the exact universal `portablefsd` binary in the app. The app adopts only that exact running build or spawns it as a child with sockets inside the app-group container and state under `~/Library/Application Support/PortableFS/portablefsd`. A crash is surfaced as a terminal failure and is never restarted automatically. Quit leaves the per-user daemon running after every mount is cleanly detached; stop an idle daemon explicitly with the matching CLI's `portablefs daemon stop`.
- **Errors** surface as menu items with a Copy Details action; nothing fails silently.
- **Quit** synchronizes, unmounts, and detaches every PortableFS mount. It refuses to quit if any durability step fails.

### Build

```sh
xcodebuild -project swift/PortableFSApp/PortableFSApp.xcodeproj -scheme PortableFSApp build CODE_SIGNING_ALLOWED=NO
```

For a runnable, signed local build set your team in `swift/PortableFSApp/Config/Development.xcconfig`:

```
DEVELOPMENT_TEAM = <your Apple Development team id>
```

then build without `CODE_SIGNING_ALLOWED=NO` (or run from Xcode). FSKit extensions must be signed to be registered by macOS; unsigned builds validate compilation and packaging but cannot exercise extension registration.

The local release packager builds the app, embeds a universal daemon, verifies
the complete signature, and emits a checksummed zip without GitHub CI:

```sh
scripts/package-macos-app.sh 0.2.1
```

Set `PORTABLEFS_DEVELOPER_ID_EXPORT=1` for Developer ID export. If a
`notarytool` keychain profile is available, set `PORTABLEFS_NOTARY_PROFILE`;
the script submits, waits, staples, and Gatekeeper-assesses the final app.

### Daemon binary resolution

The app build embeds a matching `portablefsd`. For development overrides it
still resolves in this order:

1. explicit path set in PortableFS Settings (Daemon section)
2. `PFSPortableFSDBinaryPath` in the app Info.plist
3. `PORTABLEFSD_BIN` environment variable
4. `portablefsd` bundled in the app's `Contents/Resources/`
5. `~/bin/portablefsd`
6. `/usr/local/bin/portablefsd`
7. `/opt/homebrew/bin/portablefsd`

An override build can still use:

```sh
cd <go repo>/vcs
go build -o ~/bin/portablefsd ./cmd/portablefsd
```

### One-time FSKit extension approval

macOS requires an interactive approval before a file system extension can serve mounts. After the first launch of PortableFS.app:

1. Open System Settings -> General -> Login Items & Extensions -> File System Extensions.
2. Enable the PortableFS extension (from PortableFSApp.app).
3. If the toggle does not appear, launch the app once more so LaunchServices registers the appex, then reopen System Settings.

Only one PortableFS file system extension should be enabled at a time: `PortableFSExt.appex` (the app) and `PortableFSDev.appex` (the dev harness) both claim the `pfs` FSKit short name, so disable one before enabling the other. This `pfs` type is deliberately distinct from any other PortableFS embedder on the machine (other PortableFS embedders register their own filesystem types), so the two never collide. Do not automate this toggle; it is a user-controlled macOS setting.

### End-to-end dogfood checklist

1. Set/override `DEVELOPMENT_TEAM` if building under a fork, then run the app from Xcode (or `xcodebuild ... build` signed, then launch the app).
2. Approve the file system extension (one-time, see above).
3. Menu bar -> Sign In: enter the server URL and either complete device sign-in in the browser or paste a token.
4. Menu bar -> volume -> Mount. The volume appears at `~/PortableFS/<volume>`; Open in Finder from the menu.
5. Unmount from the menu, or Quit to cleanly unmount everything. Stop the idle daemon explicitly with `portablefs daemon stop` when needed.

### Known limitations (v1 dogfood)

- macOS 26 only (FSKit Operations adapter targets the macOS 26 API surface).
- Developer ID export/notarization requires the corresponding Apple signing
  profiles and a local `notarytool` credential; the packager fails visibly if
  either is unavailable.
- The FSKit extension approval is manual (macOS requirement).
- Daemon sockets live in the `B47U2LLKHW.pfsoss` app-group container (`PFSAppGroupIdentifier`). This is a sandbox requirement, not a preference: a sandboxed FSKit extension may only `connect(2)` to unix sockets on app-group paths. Forks building under another team id change the group id in `AppPaths.swift`, both extension Info.plists/entitlements, and the CLI.
- The menu mounts each volume's `main` branch (or the first branch when there is no `main`).

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
/sbin/mount -t pfs "pfs://<ref>" /tmp/pfs
```

6. Smoke-test the mounted tree with normal filesystem tools (`ls`, `stat`, `cat`, create/write/rename/remove files, xattrs if available from the daemon).
7. Unmount:

```sh
umount /tmp/pfs
```

Do not automate the System Settings approval step; it is a one-time user-controlled macOS toggle.
