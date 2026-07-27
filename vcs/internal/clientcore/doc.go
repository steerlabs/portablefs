// Package clientcore contains the frontend-neutral PortableFS client brain:
// protocol connection management, versioned metadata/listing caches, invalidation
// subscription handling, write-back session integration, open-after-unlink state,
// advisory lock forwarding, prefetch, disk content caching, fsync policy, and
// credential renewal.
//
// The disk content cache is populated from authority reads and is keyed by
// (volume, authority generation, inode, block, content version). Local write-back
// overlay writes do not update disk-cache blocks; they are served from the overlay
// until flushed, and a later authority read fills the cache under the new content
// version. This avoids mixing speculative local bytes with authority-versioned cache
// entries. The generation component fences the persistent cache across authority
// incarnations (which restart versioning from zero), and every stored block carries a
// content digest so a block corrupted or truncated on disk is discarded as a miss —
// never spliced or silently truncating a file (the repo's Cache Rule).
package clientcore
