# PortableFSKitMacOS27Dev

This is the signed development host for the SDK 27 adapter. It deliberately
uses a separate Xcode project from PortableFSKitDev: Xcode 26 must never parse
or compile the Swift 6.4/macOS 27 package, while Xcode 27 must compile the real
FSVolume.DataCacheHandler implementation.

Both development hosts use the same OSS bundle IDs, file-system identity, URL
scheme, and app group. Install only the host matching the Mac's OS generation.
Replacing one with the other is therefore an update to the same registered
FSKit provider, not a second PortableFS filesystem.

Build on macOS 27 with Xcode 27 by setting DEVELOPER_DIR to the Xcode 27
Developer directory and running xcodebuild for the PortableFSKitMacOS27Dev
scheme. Pass `PORTABLEFS_GO` as the canonical absolute path to a trusted Go
executable. The target embeds the matching CLI and nested daemon service; the
service is signed with the separate explicit Developer ID identity in
`PORTABLEFS_SERVICE_SIGN_IDENTITY`, never the host's Apple Development
identity. The scheme's product is canonically named `PortableFSKitDev.app`
with host executable `PortableFSKitDev`; the project and scheme name remain
SDK-generation-specific only to keep Xcode 26 from parsing this project.

Only this macOS 27 development target stamps its embedded CLI with the exact
`sdk27-live-qualification-only` admission value. Production and macOS 26
builds remain unstamped and refuse native mounting. The stamp admits only
macOS 27; it does not admit macOS 28 or make the incomplete policy a supported
product surface. Namespace or attribute repair still terminates the
qualification mount before acknowledgement.

That exact stamp also compiles the internal
`install-macos27-qualification-app` command into this target's embedded CLI.
The command invokes the same transactional installer as the shipping
`install-macos-app`, carrying one immutable development layout and exact
Apple-Development/Developer-ID signing policy. It is absent from production
and macOS 26 binaries and from public help. Run only the CLI nested in the
exact staged `PortableFSKitDev.app`; it refuses a different bundle name,
executable, extension, signing policy, or a provisioning profile that does
not contain the current Mac's provisioning UDID.

Current qualification releases use the same exact Apple-Development policy
on both the installed and incoming sides, so a successfully installed build
can be the source of the next ordinary update. One historical recovery build
is admitted only as an installed source by its frozen host CodeDirectory hash;
the remaining sealed bundle tuple is still validated exactly, and that legacy
identity is never accepted as an incoming target. Production continues to use
only its Developer-ID policy and has no recovery exception.

Set DEVELOPMENT_TEAM in Config/Development.xcconfig locally when signing.
Do not commit a personal team value.

## Qualification-only GUI

`PortableFSKitMacOS27IOQualification` is a separate, non-archivable AppKit
target for the bounded macOS Network Volumes privacy qualification. It is not
embedded in either development host and is excluded from the installer,
packager, release workflow, and shipping application. It has no app-group or
helper entitlement. Build and sign this target directly, then launch the app
with exactly `--config /absolute/path/to/config.json`; do not copy it into a
PortableFS application bundle.

The config file must live in a canonical directory owned by the current user
with mode `0700`. The file must be a single-link regular file owned by that user
with mode `0600`, no symlink traversal, and no more than 4096 bytes. Schema 1
accepts only these exact modes:

- `basic`: `schemaVersion`, `mode`, `runID`, `mountPath`, and `attachRef`. The
  app performs bounded create/write/fsync/stat/pread/list/rename/reopen/
  open-unlink-read/remove operations in a new run-specific directory.
- `data-refresh`: the base fields plus `relativePath`, `initialSHA256`, and
  `finalSHA256`. The relative path must be
  `portablefs-data-refresh-<runID>.bin`. The app reads and keeps one descriptor
  open, publishes `<runID>.ready`, waits at most 120 seconds for an exact
  `<runID>.continue` file, and then rereads that same descriptor. Initial and
  final data must have the same length so this matrix does not depend on
  attribute invalidation.

The app attests the exact `pfs` kernel type, mount point, filesystem identity,
and `dev.portablefs.oss://<attachRef>` source before and after the matrix. It
publishes `<runID>.result.json` in the same private directory. Namespace and
attribute cross-client modes are refused: SDK 27 exposes no matching native
repair primitive, so the harness does not simulate them.
