package cellhelper

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"golang.org/x/sys/unix"
)

const (
	helperStateVersionV1 uint32 = 1
	helperStateVersion   uint32 = 2
	maxHelperStateBytes         = 8 << 20
)

// The v1 shapes are kept separate from the live structs. The rollout gate is
// an encoding promise, not merely omission of zero-valued v2 fields: until a
// v2 plan is accepted, an old helper must be able to read the exact state
// shape a new helper writes.
type stateV1 struct {
	Version        uint32                  `json:"version"`
	CellID         string                  `json:"cell_id"`
	PlanGeneration uint64                  `json:"plan_generation"`
	PlanHash       string                  `json:"plan_sha256"`
	Assignments    map[string]assignmentV1 `json:"assignments"`
}

type assignmentV1 struct {
	VolumeID            string               `json:"volume_id"`
	AuthorizationDomain string               `json:"authorization_domain"`
	Owner               string               `json:"owner"`
	ProductIssuer       string               `json:"product_issuer"`
	ProductPublicKeyPEM string               `json:"product_public_key_pem"`
	CellID              string               `json:"cell_id"`
	ProjectID           uint32               `json:"project_id"`
	ServiceUID          uint32               `json:"service_uid"`
	ServiceGID          uint32               `json:"service_gid"`
	ListenPort          uint16               `json:"listen_port"`
	QuotaBytes          uint64               `json:"quota_bytes"`
	QuotaInodes         uint64               `json:"quota_inodes"`
	AuthorityID         string               `json:"authority_id"`
	AuthorityServerName string               `json:"authority_server_name"`
	AuthorityGeneration uint64               `json:"authority_generation"`
	LastPhase           cellplan.VolumePhase `json:"last_phase"`
	AuthorityAbsent     bool                 `json:"authority_absent"`
	QuotaApplied        bool                 `json:"quota_applied"`
	Applied             bool                 `json:"applied"`
	AppliedPlanHash     string               `json:"applied_plan_sha256,omitempty"`
}

func loadState(path, cellID string) (State, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return State{}, errors.New("cellhelper: state path must be clean and absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return State{Version: helperStateVersionV1, CellID: cellID, PlanVersionApplied: cellplan.VersionV1,
			Assignments: map[string]Assignment{}, Tombstones: map[string]Tombstone{}}, nil
	}
	if err != nil {
		return State{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return State{}, errors.New("cellhelper: open state returned no file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return State{}, err
	}
	stat, ownerOK := info.Sys().(*syscall.Stat_t)
	if !ownerOK || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxHelperStateBytes {
		return State{}, errors.New("cellhelper: state must be a private regular file")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxHelperStateBytes+1))
	if err != nil || len(payload) > maxHelperStateBytes {
		return State{}, errors.New("cellhelper: state exceeds its size bound")
	}
	var header struct {
		Version uint32 `json:"version"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		return State{}, err
	}
	var state State
	switch header.Version {
	case helperStateVersionV1:
		var old stateV1
		if err := decodeStateStrict(payload, &old); err != nil {
			return State{}, err
		}
		state = migrateStateV1(old)
	case helperStateVersion:
		if err := decodeStateStrict(payload, &state); err != nil {
			return State{}, err
		}
	default:
		return State{}, errors.New("cellhelper: unsupported state version")
	}
	if err := validateState(state, cellID); err != nil {
		return State{}, err
	}
	return state, nil
}

func decodeStateStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("cellhelper: state has trailing data")
	}
	return nil
}

func migrateStateV1(old stateV1) State {
	state := State{Version: helperStateVersionV1, CellID: old.CellID, PlanGeneration: old.PlanGeneration,
		PlanHash: old.PlanHash, PlanVersionApplied: cellplan.VersionV1,
		Assignments: make(map[string]Assignment, len(old.Assignments)), Tombstones: map[string]Tombstone{}}
	for id, item := range old.Assignments {
		assignment := Assignment{
			VolumeID: item.VolumeID, AuthorizationDomain: item.AuthorizationDomain, Owner: item.Owner,
			ProductIssuer: item.ProductIssuer, ProductPublicKeyPEM: item.ProductPublicKeyPEM,
			CellID: item.CellID, PlacementSequence: 1, ProjectID: item.ProjectID,
			ServiceUID: item.ServiceUID, ServiceGID: item.ServiceGID, ListenPort: item.ListenPort,
			QuotaBytes: item.QuotaBytes, QuotaInodes: item.QuotaInodes,
			AuthorityID: item.AuthorityID, AuthorityServerName: item.AuthorityServerName,
			AuthorityGeneration: item.AuthorityGeneration, LastPhase: item.LastPhase,
			AuthorityAbsent: item.AuthorityAbsent, Applied: item.Applied, AppliedPlanHash: item.AppliedPlanHash,
		}
		if item.QuotaApplied {
			assignment.AppliedQuotaBytes = item.QuotaBytes
			assignment.AppliedQuotaInodes = item.QuotaInodes
		}
		state.Assignments[id] = assignment
	}
	return state
}

func validateState(state State, cellID string) error {
	if state.Version != helperStateVersionV1 && state.Version != helperStateVersion || state.CellID != cellID ||
		state.Assignments == nil || state.Tombstones == nil ||
		state.PlanVersionApplied != cellplan.VersionV1 && state.PlanVersionApplied != cellplan.Version ||
		state.Version == helperStateVersionV1 && state.PlanVersionApplied != cellplan.VersionV1 ||
		state.Version == helperStateVersion && state.PlanVersionApplied != cellplan.Version {
		return errors.New("cellhelper: state identity mismatch")
	}
	if state.PlanGeneration == 0 {
		if state.PlanHash != "" || len(state.Assignments) != 0 || len(state.Tombstones) != 0 {
			return errors.New("cellhelper: initial state contains an applied plan")
		}
	} else if !validDigest(state.PlanHash) {
		return errors.New("cellhelper: state plan digest is invalid")
	}
	for id, assignment := range state.Assignments {
		if id != assignment.VolumeID || !cellplan.ValidID(id) || assignment.CellID != cellID || assignment.PlacementSequence == 0 ||
			assignment.ProjectID == 0 || assignment.AuthorizationDomain == "" || assignment.Owner == "" || assignment.ProductIssuer == "" ||
			assignment.ProductPublicKeyPEM == "" || assignment.AuthorityID == "" || assignment.AuthorityServerName == "" ||
			assignment.ServiceUID < 1000 || assignment.ServiceGID < 1000 || assignment.ListenPort < 1024 ||
			assignment.QuotaBytes == 0 || assignment.QuotaInodes == 0 || assignment.AuthorityGeneration == 0 ||
			assignment.AppliedQuotaBytes > assignment.QuotaBytes || assignment.AppliedQuotaInodes > assignment.QuotaInodes ||
			!validStoredPhase(assignment.LastPhase) || state.Version == helperStateVersionV1 && !validStoredPhaseV1(assignment.LastPhase) {
			return errors.New("cellhelper: state contains an invalid assignment")
		}
		if assignment.Applied {
			if !validDigest(assignment.AppliedPlanHash) {
				return errors.New("cellhelper: applied assignment has an invalid plan digest")
			}
		} else if assignment.AppliedPlanHash != "" {
			return errors.New("cellhelper: failed assignment retained an applied plan digest")
		}
		if assignment.ArchiveSealed != nil && !validStoredArchiveSealed(*assignment.ArchiveSealed) ||
			assignment.DestroyProof != nil && !validDestroyProof(assignment, *assignment.DestroyProof) ||
			assignment.LastQuiesceNonce != "" && !validLowerHex(assignment.LastQuiesceNonce, 32) {
			return errors.New("cellhelper: state contains an invalid durable phase record")
		}
	}
	for id, tombstone := range state.Tombstones {
		if id != tombstone.VolumeID || !cellplan.ValidID(id) || tombstone.PlacementSequence == 0 ||
			tombstone.AuthorityEpoch == 0 || !validLowerHex(tombstone.DestroyProofSHA256, 32) {
			return errors.New("cellhelper: state contains an invalid tombstone")
		}
	}
	return nil
}

func validDestroyProof(assignment Assignment, proof DestroyProof) bool {
	if !validLowerHex(proof.SHA256, 32) || proof.Record.VolumeID != assignment.VolumeID || proof.Record.CellID != assignment.CellID ||
		proof.Record.AuthorityEpoch != assignment.AuthorityGeneration || proof.Record.AuthorityID != assignment.AuthorityID ||
		proof.Record.AuthorityServerName != assignment.AuthorityServerName || proof.Record.PlacementSequence != assignment.PlacementSequence ||
		proof.Record.ProjectID != assignment.ProjectID || proof.Record.ServiceUID != assignment.ServiceUID ||
		proof.Record.ServiceGID != assignment.ServiceGID || proof.Record.ListenPort != assignment.ListenPort {
		return false
	}
	post := proof.Record.Postconditions
	if !post.ConfigRootAbsent || !post.DropInsAbsent || !post.QuotaCleared || !post.StateRootAbsent || !post.SysusersConfAbsent || !post.TreeAbsent {
		return false
	}
	payload, err := json.Marshal(proof.Record)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(payload)
	return proof.SHA256 == hex.EncodeToString(digest[:])
}

func validStoredArchiveSealed(sealed controlplane.ArchiveSealedObservation) bool {
	if !cellplan.ValidID(sealed.Attempt) || sealed.FormatVersion == 0 || sealed.ChunkSizeBytes == 0 || sealed.KeyVersion == "" ||
		!validStoredObjectRef(sealed.Manifest) || len(sealed.Packs) == 0 || len(sealed.Packs) > controlplane.MaxArchivePacks ||
		!validLowerHex(sealed.RootDigest, 32) || sealed.SealedAllocatedBytes == 0 || sealed.SealedInodes == 0 {
		return false
	}
	for _, pack := range sealed.Packs {
		if !validStoredObjectRef(pack) {
			return false
		}
	}
	return true
}

func validStoredObjectRef(ref controlplane.ObjectRef) bool {
	return ref.Key != "" && len(ref.Key) <= controlplane.MaxArchiveObjectKeyBytes && ref.SizeBytes > 0 && validLowerHex(ref.SHA256, 32)
}

func validLowerHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && value == hex.EncodeToString(decoded)
}

func validDigest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == 32
}

func validStoredPhase(phase cellplan.VolumePhase) bool {
	switch phase {
	case cellplan.PhaseProvision, cellplan.PhaseServe, cellplan.PhaseFence, cellplan.PhaseRetire,
		cellplan.PhaseArchive, cellplan.PhaseRestore, cellplan.PhaseDestroy:
		return true
	default:
		return false
	}
}

func validStoredPhaseV1(phase cellplan.VolumePhase) bool {
	switch phase {
	case cellplan.PhaseProvision, cellplan.PhaseServe, cellplan.PhaseFence, cellplan.PhaseRetire:
		return true
	default:
		return false
	}
}

func saveState(path string, state State) error {
	if err := validateState(state, state.CellID); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := marshalState(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cellhelper-state-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync helper state directory: %w", err)
	}
	return nil
}

func marshalState(state State) ([]byte, error) {
	if state.PlanVersionApplied >= cellplan.Version {
		state.Version = helperStateVersion
		return json.Marshal(state)
	}
	old := stateV1{Version: helperStateVersionV1, CellID: state.CellID, PlanGeneration: state.PlanGeneration,
		PlanHash: state.PlanHash, Assignments: make(map[string]assignmentV1, len(state.Assignments))}
	for id, item := range state.Assignments {
		old.Assignments[id] = assignmentV1{
			VolumeID: item.VolumeID, AuthorizationDomain: item.AuthorizationDomain, Owner: item.Owner,
			ProductIssuer: item.ProductIssuer, ProductPublicKeyPEM: item.ProductPublicKeyPEM, CellID: item.CellID,
			ProjectID: item.ProjectID, ServiceUID: item.ServiceUID, ServiceGID: item.ServiceGID, ListenPort: item.ListenPort,
			QuotaBytes: item.QuotaBytes, QuotaInodes: item.QuotaInodes, AuthorityID: item.AuthorityID,
			AuthorityServerName: item.AuthorityServerName, AuthorityGeneration: item.AuthorityGeneration,
			LastPhase: item.LastPhase, AuthorityAbsent: item.AuthorityAbsent,
			QuotaApplied: item.AppliedQuotaBytes == item.QuotaBytes && item.AppliedQuotaInodes == item.QuotaInodes,
			Applied:      item.Applied, AppliedPlanHash: item.AppliedPlanHash,
		}
	}
	return json.Marshal(old)
}
