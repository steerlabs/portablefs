# PortableFSApp — deferred work

v1 is dogfood-grade on purpose: personal/dev signing, manual FSKit approval.
This file tracks what production packaging still needs.

## Signing & distribution

- [ ] Developer ID application signing for the app and the appex
      (`CODE_SIGN_IDENTITY = Developer ID Application`, real provisioning for
      `com.apple.developer.fskit.fsmodule`). Today: `CODE_SIGN_STYLE = Automatic`
      with `DEVELOPMENT_TEAM` from `Config/Development.xcconfig`; unsigned CI
      builds use `CODE_SIGNING_ALLOWED=NO`.
- [ ] Notarization + stapling (`xcrun notarytool submit`, `xcrun stapler staple`)
      and a release archive/export pipeline (`xcodebuild archive` +
      `-exportOptionsPlist`).
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
- [ ] Bundle a `portablefsd` universal binary into `Contents/Resources/` as
      part of the build (script phase building from the Go repo), so step 4 of
      the binary search order always hits.

## App polish

- [ ] Branch picker per volume (currently mounts `main` or the first branch).
- [ ] Mount session token refresh before `expiresAtMs` (the CLI refreshes ~30s
      early; portablefsd holds the token after attach, so this needs the
      credential endpoint).
- [ ] Login Items / launch-at-login toggle in Settings.
- [ ] Keychain storage option for tokens (today: CLI-shared config.json, 0600).
- [ ] Localizations and an app icon.
