package cellhost

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
)

// authorityNamePattern is the shape an authority identity may have inside the
// proof preimage: a DNS name, nothing else. It exists so the canonical JSON
// can never contain a character the encoder would escape, and so a proof over
// an identity the helper cannot even name is impossible.
var authorityNamePattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// DestroyInput is the complete description of the placement whose host
// resources are being removed - the whole immutable assignment identity, which
// is what the proof binds to. Every field is an identity the manager already
// signed into the plan and the helper already holds durably: no path, no
// command, and no unit name is taken from it, only integers, two DNS names,
// and one validated volume UUID from which the pinned roots derive their
// entries.
type DestroyInput struct {
	VolumeID            string
	AuthorityID         string
	AuthorityServerName string
	AuthorityEpoch      uint64
	PlacementSequence   uint64
	ProjectID           uint32
	ServiceUID          uint32
	ServiceGID          uint32
	ListenPort          uint16
	// QuotaWasApplied is the helper's durable record that this placement ever
	// had an XFS hard limit installed. It only ever widens the work: the
	// zeroing runs when a project tree still exists or when a limit was
	// recorded, so a placement whose tree is already gone still has its stale
	// limit cleared on the retry that observes the flag.
	QuotaWasApplied bool
}

// DestroyPostconditions is the verified end state of one destroy. It records
// what is true after the fact, never which actions this particular run
// happened to perform, so a retry after a partial crash re-verifies the same
// facts and produces the identical proof.
//
// Field order is not cosmetic: encoding/json emits struct fields in
// declaration order, so declaring them in canonical (alphabetical) JSON key
// order is what makes the proof preimage canonical. Do not reorder.
type DestroyPostconditions struct {
	ConfigRootAbsent   bool `json:"config_root_absent"`
	DropInsAbsent      bool `json:"dropins_absent"`
	QuotaCleared       bool `json:"quota_cleared"`
	StateRootAbsent    bool `json:"state_root_absent"`
	SysusersConfAbsent bool `json:"sysusers_conf_absent"`
	TreeAbsent         bool `json:"tree_absent"`
}

// Unsatisfied names the first postcondition that is not proven, in canonical
// key order, or "" when the placement is fully destroyed. Deterministic order
// means a repeated partial failure is reported identically every time.
func (postconditions DestroyPostconditions) Unsatisfied() string {
	switch {
	case !postconditions.ConfigRootAbsent:
		return "config_root_absent"
	case !postconditions.DropInsAbsent:
		return "dropins_absent"
	case !postconditions.QuotaCleared:
		return "quota_cleared"
	case !postconditions.StateRootAbsent:
		return "state_root_absent"
	case !postconditions.SysusersConfAbsent:
		return "sysusers_conf_absent"
	case !postconditions.TreeAbsent:
		return "tree_absent"
	default:
		return ""
	}
}

// DestroyRecord is the typed proof preimage of archive-sequence step 4. It
// carries the complete immutable assignment identity, so the proof binds to
// one exact placement: a proof from an earlier residence of the same volume,
// from a different cell, or from a different authority endpoint cannot be
// replayed against this one.
//
// The signed plan's digest is deliberately not part of the preimage. A benign
// plan refresh - a new generation that changes nothing about this placement -
// must not change the proof, or a retry after a partial crash would produce a
// hash the manager cannot match against what it stored.
//
// Field order is canonical JSON key order. Do not reorder.
type DestroyRecord struct {
	AuthorityEpoch      uint64                `json:"authority_epoch"`
	AuthorityID         string                `json:"authority_id"`
	AuthorityServerName string                `json:"authority_server_name"`
	CellID              string                `json:"cell_id"`
	ListenPort          uint16                `json:"listen_port"`
	PlacementSequence   uint64                `json:"placement_sequence"`
	Postconditions      DestroyPostconditions `json:"postconditions"`
	ProjectID           uint32                `json:"project_id"`
	ServiceGID          uint32                `json:"service_gid"`
	ServiceUID          uint32                `json:"service_uid"`
	VolumeID            string                `json:"volume_id"`
}

// DestroyResult carries the verified record and its canonical proof. The proof
// is set only for a complete destroy: an incomplete record is returned for
// diagnosis but never carries a hash a manager could mistake for evidence.
type DestroyResult struct {
	Record      DestroyRecord
	ProofSHA256 string
}

// CanonicalJSON renders the proof preimage: exactly the contract's keys, in
// sorted order, with no insignificant whitespace. Every string field is a
// validated UUID or a validated DNS name, so the encoder's HTML escaping can
// never alter the bytes; anything else is refused rather than encoded, because
// a proof over an unvalidated identity proves nothing about which placement
// was destroyed.
func (record DestroyRecord) CanonicalJSON() ([]byte, error) {
	if !cellplan.ValidID(record.VolumeID) || !cellplan.ValidID(record.CellID) ||
		!authorityNamePattern.MatchString(record.AuthorityID) ||
		!authorityNamePattern.MatchString(record.AuthorityServerName) ||
		record.AuthorityEpoch == 0 || record.PlacementSequence == 0 ||
		record.ProjectID == 0 || record.ServiceUID == 0 || record.ServiceGID == 0 ||
		record.ListenPort == 0 {
		return nil, ErrInvalid
	}
	return json.Marshal(record)
}

// ProofSHA256 is the destroy proof: SHA-256 over CanonicalJSON, lowercase hex.
func (record DestroyRecord) ProofSHA256() (string, error) {
	payload, err := record.CanonicalJSON()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
