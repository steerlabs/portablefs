# PortableFS go-fuse fork

This directory is a source-pinned copy of
`github.com/hanwen/go-fuse/v2@v2.10.1` (tag commit
`1d16325e0693e4aeb40b3c899938e028cc8e538e`; upstream module zip SHA-256
`6945a37ef334da27a747ddd6aacda04423d462d662e5035e367adec7ca8f4642`).
The upstream BSD license is preserved in `LICENSE`.

PortableFS changes one architectural boundary and carries the private strict
coherence wire ABI used at that boundary:

- `fuse.ReplyWriteLifecycle` lets a raw filesystem select replies whose real
  `/dev/fuse` writes must be serialized with reverse-notification writes and
  observes the result only after that write attempt returns.
- `fuse.Server` applies that lifecycle only to selected replies. Unselected
  replies retain upstream's parallel write path. `ProtocolServer` deliberately
  does not emulate physical kernel publication.
- `FUSE_PFS_WRITE` stages every SHARED write (positioned or effective append)
  and applies it once at COMMIT; `FUSE_PFS_PUBLISH` is the kernel's mandatory
  post-VFS receipt. Explicit SHARED/LOCAL inode and open markers prevent an
  omitted marker from silently selecting stock FUSE behavior.
- `FUSE_NOTIFY_PFS_SIZE` carries exact size plus the visibility sequence, so a
  peer installs grow and shrink results from the same ordered change identity.

The hook exists because returning from a `RawFileSystem` method precedes the
kernel response write, and even a successful response write wakes the requester
before its VFS postprocessing is complete. Releasing a distributed gate at
either earlier point permits a peer repair to race stale requester state. The
generic publication receipt is the one release boundary; no timing delay or
cache fallback can close that race.
