# Open after unlink

Status: **v3 mechanism note**

POSIX requires that an unlinked-but-still-open file leave the name tree and
remain readable and writable through every open descriptor until the last one
closes. PortableFS v3 does not implement that rule. It inherits it.

## The mechanism

An open handle is a real open file description on the authority. `open`
resolves the object once with descriptor-relative syscalls, and the authority
retains that server file descriptor for the life of the open-handle capability.
`unlink` is `unlinkat(2)` against the parent directory descriptor: it removes
one name and nothing else. The kernel does the parking. XFS destroys the inode
when its link count and its open-descriptor count both reach zero, exactly as
it would for two local processes.

There is therefore no orphan table, no orphan/reap operation pair, no
registration round trip before `open` may return, no reaper, and no lease
garbage collection. `vcs/internal/xfsstore` owns the descriptor lifetime and
that is the whole design.

Two consequences follow without further machinery:

- A peer that unlinks the name, and then recreates the same name, cannot steer
  an existing handle. The handle is bound to a descriptor, not to a path, and
  the recreated name is a different inode the handle never observes.
- Rename-over behaves the same way. `renameat2` replaces the binding, the
  displaced inode keeps its server descriptors, and a reader holding one keeps
  reading the displaced bytes while path resolution returns the replacement.

Cross-mount behaviour is asserted black box, against the bytes a descriptor
actually returns rather than against `stat`, by the coherence cases
`remote_unlink_open_fd_posix`, `open_after_unlink_cross_mount_contents` and
`rename_over_open_fd` in
[the cross-mount coherence matrix](./cross-mount-coherence-matrix.md).

## The boundary

Authority epoch state is disposable, and a server file descriptor is epoch
state. When an authority dies, the kernel closes every descriptor it held, and
an inode with no remaining link is then destroyed. Applications holding that
file observe `ESTALE` or `EIO` once the mount re-establishes, and the content
is gone: it had no name under which anything could recover it.

This is stated rather than worked around. Surviving an epoch change would
require a durable PortableFS-side namespace parallel to XFS, which v3
deliberately does not have. See [failure-modes.md](./failure-modes.md).
