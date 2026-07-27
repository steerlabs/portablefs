package cli

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
)

// mountState is one active mount's record under
// ~/.local/state/portablefs/mounts/<hash>.json; umount and mounts read it.
type mountState struct {
	MountPath    string `json:"mountPath"`
	VolumeID     string `json:"volumeId"`
	Branch       string `json:"branch"`
	PID          int    `json:"pid"`
	Strategy     string `json:"strategy"`
	AuthorityURL string `json:"authorityUrl,omitempty"`
	// AttachRef is the portablefsd attach this fskit mount serves (the
	// pfs:// device the kernel holds); umount diagnostics correlate on it.
	AttachRef   string `json:"attachRef,omitempty"`
	StartedAtMs int64  `json:"startedAtMs"`
	// LocalDirs are the machine-local graft roots this mount serves
	// (--local-dir plus the volume's .portablefs/local-dirs file).
	LocalDirs []string `json:"localDirs,omitempty"`
	// AccessLease is the manager access lease backing this mount's data-plane
	// credential (nil when the manager predates access leases or --addr was
	// used). Persisted so the daemon can renew/release it and an operator can
	// correlate a mount with its lease.
	AccessLease *leaseState `json:"accessLease,omitempty"`
	// Status is the mount's health beyond pid-liveness. Empty means healthy
	// ("live"); mountStatusCredentialExpired means the daemon is running but
	// the control plane definitively rejected its credentials (revoked or
	// expired), so filesystem access is degraded until the user runs
	// `portablefs login` and remounts. Additive: older records have no field.
	Status string `json:"status,omitempty"`
	// StatusChangedAtMs is when Status last transitioned (unix ms).
	StatusChangedAtMs int64 `json:"statusChangedAtMs,omitempty"`
}

// mountStatusCredentialExpired marks a running mount whose credentials the
// control plane has definitively rejected: the kernel mount is still attached
// but operations degrade until re-login and remount.
const mountStatusCredentialExpired = "credential-expired"

// mountHealth folds pid-liveness and the persisted status into the one word
// `portablefs mounts` and `portablefs status` print.
func mountHealth(st *mountState) string {
	if !pidAlive(st.PID) {
		return "stale"
	}
	if st.Status == mountStatusCredentialExpired {
		return mountStatusCredentialExpired
	}
	return "live"
}

// setMountStatus persists a status transition into the mount's state record
// (read-modify-write, tolerating a not-yet-written record). It reports
// whether a record was updated.
func setMountStatus(dir, mountPath, status string, atMs int64) bool {
	st, err := readMountState(dir, mountPath)
	if err != nil || st == nil {
		return false
	}
	st.Status = status
	st.StatusChangedAtMs = atMs
	if status == "" {
		st.StatusChangedAtMs = 0
	}
	return writeMountState(dir, *st) == nil
}

// leaseState is the persisted slice of an access lease: enough to renew
// (controlSeq is the CAS precondition) and to release on unmount.
type leaseState struct {
	AccessLeaseID string `json:"accessLeaseId"`
	AccessToken   string `json:"accessToken"`
	ExpiresAtMs   int64  `json:"expiresAt"`
	ControlSeq    string `json:"controlSeq,omitempty"`
}

func (e *cmdEnv) mountStateDir() (string, error) {
	if base := e.getenv("XDG_STATE_HOME"); base != "" {
		return filepath.Join(base, "portablefs", "mounts"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for mount state: %w", err)
	}
	return filepath.Join(home, ".local", "state", "portablefs", "mounts"), nil
}

// mountStateKey names a mount's state file from its absolute path: stable,
// filesystem-safe, and collision-free enough for a per-user mount table.
func mountStateKey(mountPath string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(mountPath))
	return fmt.Sprintf("%016x", h.Sum64())
}

func mountStatePath(dir, mountPath string) string {
	return filepath.Join(dir, mountStateKey(mountPath)+".json")
}

func mountLogPath(dir, mountPath string) string {
	return filepath.Join(dir, mountStateKey(mountPath)+".log")
}

func writeMountState(dir string, st mountState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create mount state directory: %w", err)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	path := mountStatePath(dir, st.MountPath)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write mount state %s: %w", path, err)
	}
	return nil
}

// readMountState loads the record for mountPath; a missing record returns
// (nil, nil) so callers can degrade gracefully.
func readMountState(dir, mountPath string) (*mountState, error) {
	data, err := os.ReadFile(mountStatePath(dir, mountPath))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st mountState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse mount state for %s: %w", mountPath, err)
	}
	return &st, nil
}

func removeMountState(dir, mountPath string) error {
	err := os.Remove(mountStatePath(dir, mountPath))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func listMountStates(dir string) ([]mountState, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []mountState
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, ent.Name()))
		if err != nil {
			continue
		}
		var st mountState
		if err := json.Unmarshal(data, &st); err != nil || st.MountPath == "" {
			continue
		}
		out = append(out, st)
	}
	return out, nil
}

// ---- machine-local dirs (grafts) persistence ----
//
// Grafted content lives under <stateBase>/local/<storageID>/ (stateBase is
// the parent of the mounts dir), the same convention portablefsd uses for its
// attaches. The configured graft roots are remembered in a sidecar file next
// to that backing so a remount of the same volume+branch+mountPath reuses
// them; the per-mount state file is removed on clean unmount, but the backing
// (and this record) must survive it — persistent local dependency trees are
// the whole point.

// localDirsBackingRoot is the machine-local backing directory for one mount.
func localDirsBackingRoot(mountsDir, volumeID, branch, mountPath string) string {
	return localdirs.BackingRoot(filepath.Dir(mountsDir), volumeID, branch, mountPath)
}

func localDirsRecordPath(mountsDir, volumeID, branch, mountPath string) string {
	return localDirsBackingRoot(mountsDir, volumeID, branch, mountPath) + ".dirs.json"
}

type localDirsRecord struct {
	LocalDirs []string `json:"localDirs"`
}

// readPersistedLocalDirs loads the graft roots remembered for a mount key;
// missing or unreadable records mean "none" (the record is a convenience, not
// a source of truth the mount should fail on).
func readPersistedLocalDirs(mountsDir, volumeID, branch, mountPath string) []string {
	data, err := os.ReadFile(localDirsRecordPath(mountsDir, volumeID, branch, mountPath))
	if err != nil {
		return nil
	}
	var rec localDirsRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil
	}
	return rec.LocalDirs
}

// writePersistedLocalDirs remembers the EXPLICITLY configured graft roots
// (flag-level config; the volume's .portablefs/local-dirs file re-unions on
// every mount and is deliberately not baked in). An empty list removes the
// record: explicit flags win and update state.
func writePersistedLocalDirs(mountsDir, volumeID, branch, mountPath string, dirs []string) error {
	p := localDirsRecordPath(mountsDir, volumeID, branch, mountPath)
	if len(dirs) == 0 {
		err := os.Remove(p)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("create local-dirs state directory: %w", err)
	}
	data, err := json.MarshalIndent(localDirsRecord{LocalDirs: dirs}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(p, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write local-dirs state %s: %w", p, err)
	}
	return nil
}

// pidAlive reports whether pid exists (signal 0 probe).
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	return err == nil || err == syscall.EPERM
}
