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
	helperStateVersion  uint32 = 2
	maxHelperStateBytes        = 8 << 20
)

func loadState(path, cellID string) (State, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return State{}, errors.New("cellhelper: state path must be clean and absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return State{Version: helperStateVersion, CellID: cellID, PlanVersionApplied: cellplan.Version,
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
	if header.Version != helperStateVersion {
		return State{}, errors.New("cellhelper: unsupported state version")
	}
	var state State
	if err := decodeStateStrict(payload, &state); err != nil {
		return State{}, err
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

func validateState(state State, cellID string) error {
	if state.Version != helperStateVersion || state.CellID != cellID || state.Assignments == nil || state.Tombstones == nil ||
		state.PlanVersionApplied != cellplan.Version {
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
			!validStoredPhase(assignment.LastPhase) {
			return errors.New("cellhelper: state contains an invalid assignment")
		}
		if assignment.Applied {
			if !validDigest(assignment.AppliedPlanHash) {
				return errors.New("cellhelper: applied assignment has an invalid plan digest")
			}
		} else if assignment.AppliedPlanHash != "" || assignment.AppliedHelperRelease != "" {
			return errors.New("cellhelper: failed assignment retained applied identity")
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
	case cellplan.PhaseProvision, cellplan.PhaseServe, cellplan.PhaseFence,
		cellplan.PhaseArchive, cellplan.PhaseRestore, cellplan.PhaseDestroy:
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
	state.Version = helperStateVersion
	return json.Marshal(state)
}
