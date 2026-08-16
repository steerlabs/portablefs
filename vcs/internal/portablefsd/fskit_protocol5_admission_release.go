//go:build !portablefs_macos27_qualification

package portablefsd

// Shipping builds cannot admit an FSKit-backed protocol-5 authority session.
// The current public FSKit contract has no exact peer namespace/attribute
// invalidation primitive. This compile-time false reaches EnsureAttach before
// any authority transport is constructed; there is no runtime opt-in.
const fsKitProtocol5QualificationBuild = false
