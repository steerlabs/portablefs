//go:build portablefs_macos27_qualification

package portablefsd

// This tag exists only on the separately signed live-qualification artifact.
// It does not claim production support: any unrepresentable repair still
// terminally fails that qualification mount.
const fsKitProtocol5QualificationBuild = true
