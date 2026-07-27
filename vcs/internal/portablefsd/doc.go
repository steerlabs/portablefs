// Package portablefsd hosts clientcore volumes behind local Unix-socket APIs.
//
// Both sockets are protected by filesystem permissions: the daemon creates the
// parent directory 0700 and the socket nodes 0600, so same-user access is the
// control-plane authentication boundary. The control API therefore has no bearer
// token of its own; authority credentials are stored per attach and renewed via
// the credential endpoint for future fsproto reconnect handshakes.
//
// pfslocal exposes xattr and hard-link operations. Extended attributes are
// served NATIVELY when the attached authority advertises FeatXattrs (the
// ResolveReply capability is per-attach): reads forward to the authority's
// live xattr state, mutations journal write-through, and macOS stops minting
// AppleDouble ._ sidecars. Against an older authority the ops return Darwin
// ENOTSUP and macOS keeps its AppleDouble fallback. Hard links remain
// ENOTSUP (no native authority support yet).
//
// The pfslocal Item identity returned to filesystem frontends is stable across
// daemon restarts for a revived attach. portablefsd uses the authority inode as
// ItemID when available and a persisted per-attach identity epoch as
// ItemGeneration. The attach registry also stores the item-to-path table so a
// kernel-held Item minted before a daemon crash can still address the same
// authority object after credentials revive the attach. fsproto coherence
// versions are cache invalidation state and are not part of Item identity.
package portablefsd
