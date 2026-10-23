package workspaceguest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// OutcomeInventory is the workspace's retained run evidence, not a write journal.
// A serving interval must be committed as unobserved before exposing its proof.
// Reopening the inventory never upgrades a vanished process's unknown outcome.
type OutcomeInventory struct {
	mu   sync.Mutex
	path string
	runs map[string]*pb.MountStatus
	// Test seam at the actual persistence boundary, before the acknowledgment.
	syncFile func(*os.File) error
}
type outcomeInventoryFile struct {
	Format uint32            `json:"format"`
	Runs   []*pb.MountStatus `json:"runs"`
}

func OpenOutcomeInventory(path string) (*OutcomeInventory, error) {
	i := &OutcomeInventory{path: path, runs: make(map[string]*pb.MountStatus), syncFile: func(f *os.File) error { return f.Sync() }}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return i, nil
	}
	if err != nil {
		return nil, err
	}
	var f outcomeInventoryFile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err = d.Decode(&f); err != nil {
		return nil, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("workspace inventory has trailing data")
	}
	if f.Format != 1 || len(f.Runs) > control.MaxMounts+MaxReservations {
		return nil, errors.New("workspace outcome inventory format/capacity refused")
	}
	for _, r := range f.Runs {
		if r == nil || control.Mount(r.Mount) != nil || control.Outcome(r.Outcome) != nil {
			return nil, errors.New("invalid retained workspace outcome")
		}
		k := control.MountKey(r.Mount)
		if i.runs[k] != nil {
			return nil, errors.New("duplicate retained workspace incarnation")
		}
		i.runs[k] = clone(r)
	}
	return i, nil
}
func (i *OutcomeInventory) Snapshot() []*pb.MountStatus {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.snapshot()
}
func (i *OutcomeInventory) snapshot() []*pb.MountStatus {
	out := make([]*pb.MountStatus, 0, len(i.runs))
	for _, r := range i.runs {
		out = append(out, clone(r))
	}
	sort.Slice(out, func(a, b int) bool { return control.MountKey(out[a].Mount) < control.MountKey(out[b].Mount) })
	return out
}

// Commit keeps prior incarnations during replacement. Only explicit retirement
// acknowledgment may remove them; an empty replacement ledger proves nothing
// about a crashed predecessor.
func (i *OutcomeInventory) Commit(r *pb.MountStatus) error {
	if r == nil || control.Mount(r.Mount) != nil || control.Outcome(r.Outcome) != nil {
		return errors.New("invalid workspace inventory evidence")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	k := control.MountKey(r.Mount)
	old := i.runs[k]
	if old != nil && !control.RetainsLoss(r.Loss, old.Loss) {
		return errors.New("workspace inventory would erase known loss")
	}
	if old == nil && len(i.runs) >= control.MaxMounts+MaxReservations {
		return errors.New("workspace outcome inventory full")
	}
	i.runs[k] = clone(r)
	if err := i.persist(); err != nil {
		if old == nil {
			delete(i.runs, k)
		} else {
			i.runs[k] = old
		}
		return err
	}
	return nil
}
func (i *OutcomeInventory) persist() error {
	raw, err := json.Marshal(outcomeInventoryFile{Format: 1, Runs: i.snapshot()})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(i.path), ".workspace-outcomes-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = i.syncFile(f)
	}
	if err == nil {
		err = f.Close()
	}
	if err == nil {
		err = os.Rename(name, i.path)
	}
	if err != nil {
		return fmt.Errorf("persist workspace outcomes: %w", err)
	}
	dir, err := os.Open(filepath.Dir(i.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return i.syncFile(dir)
}
