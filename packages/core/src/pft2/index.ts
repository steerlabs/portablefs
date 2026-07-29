/**
 * PFT2 immutable filesystem format (docs/history.md): strict canonical
 * codec, lazy digest-verifying BaseTree, legacy manifest adapter, and stable
 * inode namespace helpers — the READ side only. The Go history worker is the
 * sole production producer of PFT2 objects; the deterministic builder mirror
 * (builder.ts) is test-only fixture support and deliberately unexported.
 * Byte-identical with the Go implementation in vcs/internal/pft2 (shared
 * golden vectors under testdata/pft2/).
 */
export * from "./wire.js";
export * from "./types.js";
export * from "./codec.js";
export * from "./basetree.js";
export * from "./ino.js";
