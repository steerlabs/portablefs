package restoremode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxStateJSON = 4096

type readyRecord struct {
	Version     uint32 `json:"version"`
	VolumeID    string `json:"volume_id"`
	SealedEpoch uint64 `json:"sealed_epoch"`
	Attempt     string `json:"attempt"`
	Entries     uint64 `json:"entries"`
	WrittenUnix int64  `json:"written_unix"`
}

type progressRecord struct {
	Version          uint32 `json:"version"`
	ProgressPermille uint32 `json:"progress_permille"`
	State            State  `json:"state"`
	RecalledBytes    uint64 `json:"recalled_bytes"`
	DrainedBytes     uint64 `json:"drained_bytes"`
	UpdatedUnix      int64  `json:"updated_unix"`
}

type convergedRecord struct {
	Version        uint32 `json:"version"`
	VolumeID       string `json:"volume_id"`
	AuthorityEpoch uint64 `json:"authority_epoch"`
	Attempt        string `json:"attempt"`
	DrainedBytes   uint64 `json:"drained_bytes"`
	DrainedChunks  uint64 `json:"drained_chunks"`
	WrittenUnix    int64  `json:"written_unix"`
}

func Active(stateRoot string) (bool, error) {
	ready, err := regularExists(filepath.Join(stateRoot, ReadyFilename))
	if err != nil || !ready {
		return false, err
	}
	converged, err := regularExists(filepath.Join(stateRoot, ConvergedFilename))
	if err != nil {
		return false, err
	}
	return !converged, nil
}

func regularExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("restoremode: %s is not a regular file", path)
	}
	return true, nil
}

func readStrictJSON(path string, target any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxStateJSON+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("restoremode: JSON record has trailing content")
	}
	return nil
}

func writeAtomicJSON(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > maxStateJSON {
		return errors.New("restoremode: JSON record exceeds 4 KiB")
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".portablefs-restore-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	cleanup := func() { _ = temp.Close(); _ = os.Remove(tempPath) }
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := io.Copy(temp, bytes.NewReader(raw)); err != nil {
		cleanup()
		return err
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
