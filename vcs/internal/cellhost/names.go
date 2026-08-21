package cellhost

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

// accountNameLimit is the portable Linux account-name bound. A name that the
// account tooling silently truncated would break the four-way name/UID/group/
// GID binding verifyServiceIdentity depends on, so an over-long derivation is
// a hard error rather than something to shorten here.
const accountNameLimit = 31

// PlacementServiceAccountName derives the per-volume service account name for
// one placement of a volume.
//
// Placements are the unit of cell residence: a volume that lives on a cell N
// times gets N identity tuples, and identity tuples are never reused. The
// account name must therefore be per-placement, not per-volume, or a wake
// would land on the UID an earlier placement owned. Accounts themselves are
// never deleted (destroy removes the sysusers configuration and keeps the
// account), so every name this returns must be unique for all time.
//
//   - placementSequence 1 is the v1 placement and keeps the v1 name,
//     base32 of the volume UUID's 16 raw bytes, so migrated volumes keep the
//     account, UID, and drop-ins they already have.
//   - every later placement uses the first 16 bytes of
//     SHA-256(rawUUID || be64(placementSequence)), which cannot collide with a
//     v1 name except by a 128-bit preimage.
//
// Both forms are 30 characters. This is the derivation named in
// docs/tiered-storage/identity-lifecycle-and-capacity.md section 1; wiring it
// into provisioning belongs to the plan/helper lane, so serviceIdentityConfig
// still derives the v1 name itself and this function is the single place the
// per-placement rule is stated.
func PlacementServiceAccountName(volumeID string, placementSequence uint64) (string, error) {
	if !cellplan.ValidID(volumeID) || placementSequence == 0 {
		return "", ErrInvalid
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(volumeID, "-", ""))
	if err != nil || len(raw) != 16 {
		return "", ErrInvalid
	}
	material := raw
	if placementSequence != 1 {
		var sequence [8]byte
		binary.BigEndian.PutUint64(sequence[:], placementSequence)
		preimage := make([]byte, 0, len(raw)+len(sequence))
		preimage = append(preimage, raw...)
		preimage = append(preimage, sequence[:]...)
		digest := sha256.Sum256(preimage)
		material = digest[:16]
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(material)
	name := "pfs-" + strings.ToLower(encoded)
	if len(name) > accountNameLimit {
		return "", ErrInvalid
	}
	return name, nil
}
