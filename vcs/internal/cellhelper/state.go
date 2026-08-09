package cellhelper

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"golang.org/x/sys/unix"
)

const helperStateVersion = 1

func loadState(path, cellID string) (State, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return State{}, errors.New("cellhelper: state path must be clean and absolute")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return State{Version: helperStateVersion, CellID: cellID, Assignments: map[string]Assignment{}}, nil
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
	if !ownerOK || stat.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 8<<20 {
		return State{}, errors.New("cellhelper: state must be a private regular file")
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return State{}, errors.New("cellhelper: state has trailing data")
	}
	if state.Version != helperStateVersion || state.CellID != cellID || state.Assignments == nil {
		return State{}, errors.New("cellhelper: state identity mismatch")
	}
	if state.PlanGeneration == 0 {
		if state.PlanHash != "" || len(state.Assignments) != 0 {
			return State{}, errors.New("cellhelper: initial state contains an applied plan")
		}
	} else if digest, err := hex.DecodeString(state.PlanHash); err != nil || len(digest) != 32 {
		return State{}, errors.New("cellhelper: state plan digest is invalid")
	}
	for id, assignment := range state.Assignments {
		if id != assignment.VolumeID || !cellplan.ValidID(id) || assignment.CellID != cellID || assignment.ProjectID == 0 ||
			assignment.AuthorizationDomain == "" || assignment.Owner == "" || assignment.ProductIssuer == "" || assignment.ProductPublicKeyPEM == "" ||
			assignment.AuthorityID == "" || assignment.AuthorityServerName == "" || assignment.ServiceUID < 1000 || assignment.ServiceGID < 1000 ||
			assignment.ListenPort < 1024 || assignment.QuotaBytes == 0 || assignment.QuotaInodes == 0 || assignment.AuthorityGeneration == 0 ||
			!validStoredPhase(assignment.LastPhase) {
			return State{}, errors.New("cellhelper: state contains an invalid assignment")
		}
		if assignment.Applied {
			if digest, err := hex.DecodeString(assignment.AppliedPlanHash); err != nil || len(digest) != 32 {
				return State{}, errors.New("cellhelper: applied assignment has an invalid plan digest")
			}
		} else if assignment.AppliedPlanHash != "" {
			return State{}, errors.New("cellhelper: failed assignment retained an applied plan digest")
		}
	}
	return state, nil
}

func validStoredPhase(phase cellplan.VolumePhase) bool {
	switch phase {
	case cellplan.PhaseProvision, cellplan.PhaseServe, cellplan.PhaseFence, cellplan.PhaseRetire:
		return true
	default:
		return false
	}
}

func saveState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".cellhelper-state-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func() { _ = os.Remove(temporaryPath) }
	defer cleanup()
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
