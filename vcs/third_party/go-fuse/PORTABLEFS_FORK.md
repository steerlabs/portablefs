# PortableFS go-fuse fork

This directory is a source-pinned copy of
`github.com/hanwen/go-fuse/v2@v2.10.1` (tag commit
`1d16325e0693e4aeb40b3c899938e028cc8e538e`; upstream module zip SHA-256
`6945a37ef334da27a747ddd6aacda04423d462d662e5035e367adec7ca8f4642`).
The upstream BSD license is preserved in `LICENSE`.

PortableFS carries one generic userspace ordering hook:

- `fuse.ReplyWriteLifecycle` lets a raw filesystem select replies whose real
  `/dev/fuse` writes must be serialized with reverse-notification writes and
  observes the result only after that write attempt returns.
- `fuse.Server` applies that lifecycle only to selected replies. Unselected
  replies retain upstream's parallel write path. `ProtocolServer` deliberately
  does not emulate physical kernel publication.
The hook exists because returning from a `RawFileSystem` method precedes the
kernel response write. It lets the protocol-6 lease client order an admitted
cache-bearing reply against a recall and observe failed device writes. It is
not a kernel publication receipt: a successful write wakes the requester before
VFS postprocessing necessarily finishes, so no correctness proof treats the
callback as one.

The retired private opcodes, capability bits, trailers, inode markers, and
notification payloads are absent. Kernel communication is the stock FUSE 7.31+
ABI; the fork does not implement a patched-kernel or compatibility profile.
