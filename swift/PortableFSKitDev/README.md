# PortableFSKitDev

Minimal manual-registration development host for the `PortableFSKit` Swift
package. It builds the same FSKit extension, daemon, and CLI pairing as the
shipping app (`FRONTEND_PROFILE_FSKIT_EXCLUSIVE`, `pfslocal` 2.0, daemon
control 2) on macOS 26 and 27. It has a distinct compiled bundle and signing
contract; the filesystem implementation and paired protocols are common.

## Build

```sh
xcodebuild \
  -project swift/PortableFSKitDev/PortableFSKitDev.xcodeproj \
  -scheme PortableFSKitDev \
  PORTABLEFS_APP_GROUP=B47U2LLKHW.pfsoss \
  PORTABLEFS_GO="$(realpath "$(go -C vcs env GOROOT)/bin/go")" \
  CODE_SIGNING_ALLOWED=NO \
  build
```

The shared embed script maps the `PortableFSKitDev` build target explicitly to
Go tag `portablefs_devhost` for `portablefs` on every architecture and
configuration. The daemon receives no tag. `PortableFSApp` embeds an ordinary
production CLI. Changing a bundle name or selecting a signing certificate
cannot switch a CLI's compiled contract.

The development contract fixes `PortableFSKitDev.app`, staging name
`PortableFSKitDev.next`, host executable `PortableFSKitDev`, extension
`PortableFSDev.appex` / `PortableFSDev`, and app identifier
`dev.portablefs.oss.KitDev`. The service minimum OS is `26.0`; the CLI remains
`Contents/Helpers/portablefs` and the daemon remains
`Contents/Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd`.
Their version and app group use the host's build inputs.

For signed local extension testing, set `DEVELOPMENT_TEAM` in
`Config/Development.xcconfig`. Apple Development signs the host, extension and
unentitled CLI. The service and daemon require the separate explicit Developer
ID Application identity in `PORTABLEFS_SERVICE_SIGN_IDENTITY`. The CLI validates
the entire sealed bundle and every included architecture before authenticating
a live owner. It requires the same team and hardened runtime throughout, exact
signed identifiers and app-group values, only the daemon's app-group
entitlement, no daemon provisioning profile, and no CLI entitlements. Unsigned
builds prove compilation only. They cannot authenticate a daemon or exercise
service replacement.

`bash scripts/test-macos-cli-layouts.sh` builds and race-tests production and
development CLIs independently; `verify-local.sh` and native macOS CI include
it. A development CLI can authenticate an intact older development release
using its complete path/version/SHA-256/CDHash tuple. The incoming host always
uses its own helper for the outgoing lifecycle guard, including a staged owner;
never replace a frozen outgoing helper or sign that artifact in place.

Development has no notarization requirement. Production requires Developer ID
Application signatures throughout, universal packaging, Gatekeeper and stapled
notarization. A development pass does not qualify shipping installation or
native shipping behavior; see [release identity](../../docs/release-identity.md).
Both artifacts share canonical account state and the app group, so only one
may own the daemon at a time. Distinct extension identifiers do not isolate
that state.

## Manual FSKit Loop

1. Build and run the host app once so macOS registers `PortableFSDev.appex` (bundle id `dev.portablefs.oss.KitDev.PortableFSDev` — deliberately distinct from any other PortableFS embedder's dev harness on the machine).
2. Open System Settings -> General -> Login Items & Extensions and open the **File System Extensions** category (its ⓘ). Use the category view: on macOS 26 the per-app view's toggle can silently do nothing.
3. Enable the "PortableFS OSS Dev" file system extension there.
4. The host registers its exact embedded daemon service through
   ServiceManagement. Wait for the host to report the service enabled; do not
   start a second daemon from the shell.
5. Mount an attach reference:

```sh
mkdir -p /tmp/pfs
/sbin/mount -t pfs "dev.portablefs.oss://<ref>" /tmp/pfs
```

6. Unmount when done. An unforced unmount returns the real `EBUSY` while
   anything holds the mount:

```sh
umount /tmp/pfs
```

Extension enablement is an interactive macOS Settings toggle and is intentionally not automated here.
