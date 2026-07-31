# PortableFSKitDev

Minimal local development wrapper for the `PortableFSKit` Swift package.

## Build

```sh
xcodebuild -project swift/PortableFSKitDev/PortableFSKitDev.xcodeproj -scheme PortableFSKitDev build CODE_SIGNING_ALLOWED=NO
```

For signed local extension testing, set `DEVELOPMENT_TEAM` in `Config/Development.xcconfig`.

## Manual FSKit Loop

1. Build and run the host app once so macOS registers `PortableFSDev.appex` (bundle id `dev.portablefs.oss.KitDev.PortableFSDev` — deliberately distinct from any other PortableFS embedder's dev harness on the machine).
2. Open System Settings -> General -> Login Items & Extensions and open the **File System Extensions** category (its ⓘ). Use the category view: on macOS 26 the per-app view's toggle can silently do nothing.
3. Enable the "PortableFS OSS Dev" file system extension there.
4. Start `portablefsd` with its pfslocal socket inside the app-group container the appex resolves via `PFSAppGroupIdentifier`: `~/Library/Group Containers/B47U2LLKHW.pfsoss/portablefsd/pfs.sock`.
   The app sandbox only allows the extension to connect(2) to unix sockets on app-group paths, so no other socket location can work. (`portablefs mount` does all of this automatically; this loop is for driving the extension by hand.)
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
