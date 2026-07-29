# PortableFSApp — deferred work

This file tracks remaining distribution and product-polish work.

## Signing & distribution

- [ ] Developer ID application signing for the app and the appex
      (`CODE_SIGN_IDENTITY = Developer ID Application`, real provisioning for
      `com.apple.developer.fskit.fsmodule`). Today: `CODE_SIGN_STYLE = Automatic`
      with `DEVELOPMENT_TEAM` from `Config/Development.xcconfig`; unsigned CI
      builds use `CODE_SIGNING_ALLOWED=NO`.
- [x] Local release archive/export pipeline, optional Developer ID export,
      notarization, stapling, verification, zip, and checksum
      (`scripts/package-macos-app.sh`).
- [ ] Decide distribution channel (direct download zip/dmg vs TestFlight-less
      Mac App Store is a non-starter due to the daemon child process; likely
      Sparkle or plain download).

## Sandbox & sockets

- [x] App-group container sockets: `PFSAppGroupIdentifier`
      (`B47U2LLKHW.pfsoss`) in the extension Info.plist + entitlements, with
      the daemon serving `<app-group-container>/portablefsd/`. Not optional —
      the app sandbox only allows unix-socket `connect(2)` on app-group
      paths, so a `/tmp` socket with a file exception can never work.
- [ ] Consider sandboxing the host app (today the app is unsandboxed so it
      can spawn portablefsd and run `/sbin/mount`; the group container is
      reachable either way).

## Daemon lifecycle

- [ ] `SMAppService` login item (auto-start at login) and/or a
      `SMAppService.daemon` plist for portablefsd instead of an app-spawned
      child process, so mounts survive app restarts.
- [x] Bundle a signed universal `portablefsd` into `Contents/Resources/` as
      part of the build.

## App polish

- [ ] Branch picker per volume (currently mounts `main` or the first branch).
- [x] Renew the exact mounted access lease at half-TTL. Ambiguous responses
      replay the same operation ID; terminal refusals fail closed and never
      create a replacement lease.
- [ ] Login Items / launch-at-login toggle in Settings.
- [ ] Keychain storage option for tokens (today: CLI-shared config.json, 0600).
- [ ] Localizations and an app icon.
