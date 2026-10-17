// Package portablefsd hosts clientcore volumes behind local Unix-socket APIs.
//
// Both sockets are protected by filesystem permissions: the daemon creates the
// parent directory 0700 and the socket nodes 0600, so same-user access is the
// control-plane authentication boundary. The control API therefore has no bearer
// token of its own; authority credentials are stored per attach and renewed via
// the credential endpoint for future fsproto reconnect handshakes.
//
// pfslocal exposes xattr and hard-link operations. Capabilities.Xattrs means
// that the xattr operation family is available, not that every backing accepts
// every mutation. The production v3 XFS authority serves get, list, and removal
// of pre-existing portable user attributes but advertises
// Capabilities.XattrSetSupported=false: XFS attribute-fork blocks are not
// charged to project quotas, so writable xattrs would violate the volume's
// aggregate storage boundary. FSKit validates set input and refuses it locally
// before emitting a daemon or ordered-mutation frame; get, list, and removal
// still forward normally. The FSKit boundary exposes Darwin EOPNOTSUPP rather
// than ENOTSUP, so XNU does not create an AppleDouble sidecar. There is no local
// WAL, delegated xattr map, or alternate metadata truth.
//
// A pfslocal Item is a daemon-local ownership handle for one retained
// authority capability, allocated monotonically and never reused within an
// attach; ItemGeneration is the attach's persisted identity epoch. File
// identity is separate: Attr.FileID is 1 for the volume root and the authority
// inode for every other object, so it survives reclaim and re-lookup under a
// new handle, and hard-link aliases share it. A v3 session dies with the
// daemon process, so a revived attach serves no Item at all and exists only
// for its exact unmount.
package portablefsd
