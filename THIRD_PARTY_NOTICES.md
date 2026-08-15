# Third-Party Notices

PortableFS is distributed under the Apache License 2.0 (see `LICENSE`). Its
compiled artifacts — the `vcs`, `portablefs` and `portablefsd` Go binaries and
the Swift `PortableFSKit` package — statically or at runtime include third-party
open-source components listed below. Each remains under its own license. The
go-fuse license ships with the source-pinned fork at
`vcs/third_party/go-fuse/LICENSE`; other dependency license texts are available
from their resolved source and upstream repositories.

No component below is under a copyleft license that would extend to
PortableFS's own source (no GPL/AGPL). `golang-lru` is MPL-2.0 (file-level weak
copyleft, used unmodified as a library).

## Go modules (`vcs/go.mod`)

| Module | Version | License |
| --- | --- | --- |
| github.com/go-git/go-billy/v5 | v5.9.0 | Apache-2.0 |
| github.com/hanwen/go-fuse/v2 | v2.10.1, source-pinned fork | BSD-3-Clause (New BSD) |
| github.com/minio/highwayhash | v1.0.4 | BSD-3-Clause |
| github.com/jackc/pgx/v5 | v5.9.2 | MIT |
| github.com/willscott/go-nfs | v0.0.4 | Apache-2.0 |
| github.com/willscott/go-nfs-client | (pinned pseudo-version) | BSD-2-Clause (derived from VMware go-nfs-client; see its `NOTICE.txt`) |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| github.com/hashicorp/golang-lru/v2 | v2.0.7 | MPL-2.0 |
| github.com/jackc/pgpassfile | v1.0.0 | MIT |
| github.com/jackc/pgservicefile | (pinned pseudo-version) | MIT |
| github.com/jackc/puddle/v2 | v2.2.2 | MIT |
| github.com/rasky/go-xdr | (pinned pseudo-version) | ISC |
| golang.org/x/sys | v0.46.0 | BSD-3-Clause |
| golang.org/x/sync | v0.21.0 | BSD-3-Clause |
| golang.org/x/text | v0.39.0 | BSD-3-Clause |

`github.com/willscott/go-nfs-client` carries a `NOTICE.txt` from its VMware
origin; that notice is reproduced by the module source and applies to the NFS
compatibility client.

The maintained go-fuse fork is pinned to upstream v2.10.1 and carries only the
PortableFS reply-publication lifecycle patch. Its upstream identity, source
hash, and local modification surface are documented in
`vcs/third_party/go-fuse/PORTABLEFS_FORK.md`.

## Swift package (`swift/PortableFSKit`)

Beyond Apple's platform frameworks (FSKit, Foundation, AppKit), the Swift
package resolves one exact-pinned dependency:

| Package | Version | License |
| --- | --- | --- |
| github.com/apple/swift-protobuf | 1.29.0 | Apache-2.0 |

## Regenerating this file

Licenses are read from the resolved dependency sources. When `vcs/go.mod` or
`swift/PortableFSKit/Package.swift` changes, refresh the tables above — the
license of a new Go module is in its `LICENSE`/`COPYING` file in
`$(go env GOMODCACHE)`, and a Swift package's is in its checkout under
`swift/PortableFSKit/.build/checkouts`.
