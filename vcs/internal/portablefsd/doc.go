// Package portablefsd hosts clientcore volumes behind local Unix-socket APIs.
//
// Both sockets are protected by filesystem permissions: the daemon creates the
// parent directory 0700 and the socket nodes 0600, so same-user access is the
// control-plane authentication boundary. The control API therefore has no bearer
// token of its own; authority credentials are stored per attach and renewed via
// the credential endpoint for future fsproto reconnect handshakes.
//
// pfslocal exposes xattr and hard-link operations. Extended attributes are
// served NATIVELY by the attached authority (xattrs are baseline; the
// ResolveReply capability is per-attach): existing objects read from the
// authority, while objects born inside a delegation keep their complete
// xattr map in the same local WAL lane as file data. macOS therefore avoids
// both AppleDouble ._ sidecars and a WAN drain/release cycle for each new
// file. A v8 authority that does not advertise delegated xattrs still serves
// the same operations through the exact authority lane selected during
// protocol negotiation.
//
// The pfslocal Item identity returned to filesystem frontends is stable across
// daemon restarts for a revived attach. portablefsd uses the authority inode as
// ItemID when available and a persisted per-attach identity epoch as
// ItemGeneration. The attach registry also stores the item-to-path table so a
// kernel-held Item minted before a daemon crash can still address the same
// authority object after credentials revive the attach. fsproto coherence
// versions are cache invalidation state and are not part of Item identity.
package portablefsd
