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
// The pfslocal Item identity returned to filesystem frontends is stable across
// daemon restarts for a revived attach. portablefsd uses the authority inode as
// ItemID when available and a persisted per-attach identity epoch as
// ItemGeneration. The attach registry also stores the item-to-path table so a
// kernel-held Item minted before a daemon crash can still address the same
// authority object after credentials revive the attach. fsproto coherence
// versions are cache invalidation state and are not part of Item identity.
package portablefsd
