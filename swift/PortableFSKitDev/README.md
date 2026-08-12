# PortableFSKitDev

Minimal local development wrapper for the `PortableFSKit` Swift package.

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

The host build embeds the matching CLI and nested `PortableFSDService.app`;
their app group and version are the same build inputs as the host and
extension. For signed local extension testing, set `DEVELOPMENT_TEAM` in
`Config/Development.xcconfig`. The nested service uses the separate explicit
Developer ID identity in `PORTABLEFS_SERVICE_SIGN_IDENTITY`; never replace it
with the host's Apple Development identity.

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

6. Unmount when done:

```sh
umount /tmp/pfs
```

Extension enablement is an interactive macOS Settings toggle and is intentionally not automated here.
