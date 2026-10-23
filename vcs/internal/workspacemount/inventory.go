package workspacemount

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
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// Desired is ownership and retained evidence, not another write journal. The
// CLI inventory remains authoritative for the session and its kernel mount.
type Desired struct {
	Mount                     *pb.MountID `json:"mount"`
	Boot                      []byte      `json:"boot"`
	Witness                   Witness     `json:"witness"`
	TargetDevice, TargetInode uint64
	Removed                   bool             `json:"removed"`
	Loss                      []*pb.Loss       `json:"loss,omitempty"`
	Outcome                   *pb.MountOutcome `json:"outcome"`
}
type inventoryFile struct {
	Format int        `json:"format"`
	Runs   []*Desired `json:"runs"`
}
type Inventory struct {
	mu        sync.Mutex
	directory string
	lock      *os.File
	runs      map[string]*Desired
	failed    error
	syncFile  func(*os.File) error
}

const maxInventoryRuns = 3 * control.MaxMounts

func OpenInventory(directory string) (*Inventory, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(directory)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return nil, errors.New("workspace inventory directory must be private")
	}
	fd, err := unix.Open(filepath.Join(directory, "owner.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	i := &Inventory{directory: directory, lock: os.NewFile(uintptr(fd), "workspace inventory owner"), runs: map[string]*Desired{}, syncFile: func(f *os.File) error { return f.Sync() }}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		i.lock.Close()
		return nil, fmt.Errorf("workspace inventory already owned: %w", err)
	}
	if err = i.load(); err != nil {
		i.lock.Close()
		return nil, err
	}
	return i, nil
}
func cloneDesired(d *Desired) *Desired {
	c := *d
	c.Mount = proto.Clone(d.Mount).(*pb.MountID)
	c.Boot = bytes.Clone(d.Boot)
	c.Outcome = proto.Clone(d.Outcome).(*pb.MountOutcome)
	c.Loss = nil
	for _, l := range d.Loss {
		c.Loss = append(c.Loss, proto.Clone(l).(*pb.Loss))
	}
	return &c
}
func validDesired(d *Desired) error {
	if d == nil || control.Mount(d.Mount) != nil || !control.ID(d.Boot) || d.Witness.Intent == "" || d.Witness.Source == "" || !filepath.IsAbs(d.Witness.Target) || d.TargetDevice == 0 || d.TargetInode == 0 || control.Outcome(d.Outcome) != nil {
		return errors.New("invalid desired mount ownership")
	}
	loss, _, err := control.BoundLoss(d.Loss)
	if err != nil || !control.RetainsLoss(loss, d.Loss) {
		return errors.New("invalid desired mount loss")
	}
	return nil
}
func (i *Inventory) load() error {
	fd, err := unix.Open(filepath.Join(i.directory, "inventory.json"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "workspace inventory")
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 16<<20 {
		return errors.New("invalid workspace inventory mode or size")
	}
	var v inventoryFile
	d := json.NewDecoder(io.LimitReader(f, 16<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF || v.Format != format || len(v.Runs) > maxInventoryRuns {
		return errors.New("invalid exact workspace inventory")
	}
	for _, r := range v.Runs {
		if err = validDesired(r); err != nil {
			return err
		}
		key := control.MountKey(r.Mount)
		if i.runs[key] != nil {
			return errors.New("duplicate workspace inventory incarnation")
		}
		for _, old := range i.runs {
			if !old.Removed && !r.Removed && (old.Witness.Target == r.Witness.Target || volumeKey(old.Mount.AuthorityId, old.Mount.VolumeId) == volumeKey(r.Mount.AuthorityId, r.Mount.VolumeId)) {
				return errors.New("conflicting workspace inventory reservations")
			}
		}
		i.runs[key] = r
	}
	return nil
}
func (i *Inventory) snapshot() []*Desired {
	out := make([]*Desired, 0, len(i.runs))
	for _, d := range i.runs {
		out = append(out, cloneDesired(d))
	}
	sort.Slice(out, func(a, b int) bool { return control.MountKey(out[a].Mount) < control.MountKey(out[b].Mount) })
	return out
}
func (i *Inventory) Snapshot() []*Desired { i.mu.Lock(); defer i.mu.Unlock(); return i.snapshot() }
func (i *Inventory) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.failed = errors.New("workspace inventory closed")
	return i.lock.Close()
}
func (i *Inventory) persist() (err error) {
	defer func() {
		if err != nil {
			i.failed = fmt.Errorf("workspace inventory persistence: %w", err)
		}
	}()
	raw, err := json.Marshal(inventoryFile{format, i.snapshot()})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(i.directory, ".workspace-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
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
		err = os.Rename(f.Name(), filepath.Join(i.directory, "inventory.json"))
	}
	if err != nil {
		return err
	}
	d, err := os.Open(i.directory)
	if err != nil {
		return err
	}
	defer d.Close()
	return i.syncFile(d)
}

// CommitDesired must succeed before spawn. Both the volume key and stable path
// are reserved: equal volume strings from different authorities cannot stack.
func (i *Inventory) CommitDesired(d *Desired) error {
	if err := validDesired(d); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.failed != nil {
		return i.failed
	}
	key := control.MountKey(d.Mount)
	if i.runs[key] != nil {
		return errors.New("workspace incarnation already retained")
	}
	if len(i.runs) >= maxInventoryRuns {
		return errors.New("workspace retained inventory full")
	}
	for _, old := range i.runs {
		if !old.Removed && (old.Witness.Target == d.Witness.Target || volumeKey(old.Mount.AuthorityId, old.Mount.VolumeId) == volumeKey(d.Mount.AuthorityId, d.Mount.VolumeId)) {
			return errors.New("workspace volume or target reserved")
		}
	}
	i.runs[key] = cloneDesired(d)
	return i.persist()
}
func (i *Inventory) BindWitness(id *pb.MountID, w Witness) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	d := i.runs[control.MountKey(id)]
	if d == nil || d.Removed {
		return errors.New("bind unknown or removed workspace intent")
	}
	merged, err := MergeWitness(d.Witness, w)
	d.Witness = merged
	// Keep late acquisitions in memory even after a failed commit. The owner
	// cannot acknowledge readiness, but still needs those resources for cleanup.
	if i.failed != nil {
		return errors.Join(err, i.failed)
	}
	return errors.Join(err, i.persist())
}
func (i *Inventory) RetainOutcome(id *pb.MountID, loss []*pb.Loss, outcome *pb.MountOutcome) error {
	if control.Outcome(outcome) != nil {
		return errors.New("invalid retained workspace outcome")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	d := i.runs[control.MountKey(id)]
	if d == nil {
		return errors.New("retain unknown workspace intent")
	}
	if !control.RetainsLoss(loss, d.Loss) {
		return errors.New("workspace outcome would erase loss")
	}
	d.Loss = nil
	for _, l := range loss {
		d.Loss = append(d.Loss, proto.Clone(l).(*pb.Loss))
	}
	d.Outcome = proto.Clone(outcome).(*pb.MountOutcome)
	if i.failed != nil {
		return i.failed
	}
	return i.persist()
}

// Reconcile never signals or resumes an old process. The caller independently
// checks both inventories and actual absence; only that exact join releases a
// path. Unknown crash outcomes remain unknown in the retained record.
func (i *Inventory) Reconcile(id *pb.MountID, observe func(*Desired) error) error {
	if observe == nil {
		return errors.New("workspace reconciliation requires absence observer")
	}
	i.mu.Lock()
	d := i.runs[control.MountKey(id)]
	if d == nil {
		i.mu.Unlock()
		return errors.New("reconcile unknown workspace intent")
	}
	snapshot := cloneDesired(d)
	i.mu.Unlock()
	if err := observe(snapshot); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	current := i.runs[control.MountKey(id)]
	if current.Witness != snapshot.Witness {
		return errors.New("workspace reconciliation overtaken by acquisition")
	}
	if i.failed != nil {
		return i.failed
	}
	current.Removed = true
	return i.persist()
}
