/**
 * PFT2 immutable filesystem format (docs/history.md): strict canonical
 * codec, deterministic builders, lazy digest-verifying BaseTree, legacy
 * manifest adapter, and stable inode namespace helpers. Byte-identical with
 * the Go implementation in vcs/internal/pft2 (shared golden vectors under
 * testdata/pft2/).
 */
export * from "./wire.js";
export * from "./types.js";
export * from "./codec.js";
export * from "./builder.js";
export * from "./basetree.js";
export * from "./ino.js";
