# Third-Party Notices

PortableFS is distributed under the Apache License 2.0 (see `LICENSE`). Its
compiled artifacts — the `vcs` / mount / `portablefsd` / history-worker Go
binaries and the Node.js control-plane services — statically or at runtime
include third-party open-source components listed below. Each remains under its
own license; the full license text ships with each dependency's source (in the
Go module cache and in `node_modules`) and in each project's upstream
repository.

No component below is under a copyleft license that would extend to
PortableFS's own source (no GPL/AGPL). `golang-lru` is MPL-2.0 (file-level weak
copyleft, used unmodified as a library).

## Go modules (`vcs/go.mod`)

| Module | Version | License |
| --- | --- | --- |
| github.com/go-git/go-billy/v5 | v5.9.0 | Apache-2.0 |
| github.com/hanwen/go-fuse/v2 | v2.10.1 | BSD-3-Clause (New BSD) |
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

## Node.js runtime dependencies

The volume-api, authority-manager, and metadata-db services depend at runtime
on:

| Package | License |
| --- | --- |
| pg | MIT |
| zod | MIT |

Development-only dependencies (TypeScript, Vitest, tooling) are not distributed
in released artifacts and are omitted here.

## Regenerating this file

Licenses are read from the resolved dependency sources. When `vcs/go.mod` or the
service `package.json` runtime dependencies change, refresh the tables above
(the license of a new module is in its `LICENSE`/`COPYING` file in
`$(go env GOMODCACHE)`; npm package licenses are in each package's
`package.json` `license` field).
