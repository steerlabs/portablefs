package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

// mountState is one active mount's record under
// ~/.local/state/portablefs/mounts/<hash>.json; umount and mounts read it.
type mountState struct {
	MountPath string `json:"mountPath"`
	VolumeID  string `json:"volumeId"`
	Branch    string `json:"branch"`
	PID       int    `json:"pid"`
	// ProcessStartIdentity binds PID to one kernel process incarnation. PID
	// alone is never sufficient authority to signal a process because it may
	// have been recycled.
	ProcessStartIdentity string `json:"processStartIdentity,omitempty"`
	Strategy             string `json:"strategy"`
	FSType               string `json:"fsType,omitempty"`
	MountInstanceID      string `json:"mountInstanceId,omitempty"`
	KernelMountID        string `json:"kernelMountId,omitempty"`
	MountTargetDevice    uint64 `json:"mountTargetDevice,omitempty"`
	MountTargetInode     uint64 `json:"mountTargetInode,omitempty"`
	MountMechanism       string `json:"mountMechanism,omitempty"`
	FUSEHelperPath       string `json:"fuseHelperPath,omitempty"`
	DataPlaneCAPath      string `json:"dataPlaneCaPath,omitempty"`
	DataPlaneCASHA256    string `json:"dataPlaneCaSha256,omitempty"`
	DataPlaneTransport   string `json:"dataPlaneTransport,omitempty"`
	DataPlaneServerName  string `json:"dataPlaneServerName,omitempty"`
	AuthorityURL         string `json:"authorityUrl,omitempty"`
	// AttachRef is the portablefsd attach this fskit mount serves (the
	// release-scoped generic URL resource the kernel holds); umount
	// diagnostics correlate on it.
	AttachRef   string `json:"attachRef,omitempty"`
	StartedAtMs int64  `json:"startedAtMs"`
	// LocalDirs are the machine-local graft roots this mount serves
	// (--local-dir plus the volume's .portablefs/local-dirs file).
	LocalDirs []string `json:"localDirs,omitempty"`
	// AccessLease is the manager access lease backing this mount's data-plane
	// credential (nil only when --addr was used). Persisted so the daemon can
	// renew/release it and an operator can correlate a mount with its lease.
	AccessLease *leaseState `json:"accessLease,omitempty"`
	// ManagerURL and AccessLeaseReleaseOperationID make lease teardown an
	// exact retryable operation. They are published before mount readiness
	// and retained until the manager confirms a terminal release.
	ManagerURL                    string `json:"managerUrl,omitempty"`
	AccessLeaseReleaseOperationID string `json:"accessLeaseReleaseOperationId,omitempty"`
	// Status is the mount's health beyond pid-liveness. Empty means healthy
	// ("live"); mountStatusCredentialExpired means the daemon is running but
	// the control plane definitively rejected its credentials (revoked or
	// expired), so filesystem access is degraded until the user runs
	// `portablefs login` and remounts. Additive: older records have no field.
	Status string `json:"status,omitempty"`
	// StatusChangedAtMs is when Status last transitioned (unix ms).
	StatusChangedAtMs int64 `json:"statusChangedAtMs,omitempty"`
	// ForceParkAcknowledged is the durable response frame for the exact
	// identity-bound SIGUSR1 force protocol used by Linux FUSE. The owner
	// publishes it only after CloseJournalDurable has fsynced the recovery
	// job, and before it detaches the kernel mount.
	ForceParkAcknowledged bool   `json:"forceParkAcknowledged,omitempty"`
	ForceRecoveryJobID    string `json:"forceRecoveryJobId,omitempty"`
}

// These mirror the daemon's disjoint credential-plane faults (portablefsd
// attachStatus.credential) on the DATA-PLANE path. They are deliberately
// separate from mountStatusCredentialExpired, which is the CLI-side
// lease-keeper's own persisted verdict: the two paths observe different things
// (a control-plane renewal refusal vs a data-plane handshake outcome) and
// collapsing them would make a mount claim a verdict nothing on that path ever
// reached.
//
// attachCredentialRouterRefused is the third: the router answered, and its
// answer was not about the credential at all (capacity, a lease transition, an
// authority outage behind it). It is retryable, and `portablefs login` is not
// its remedy — which is exactly what the mount used to say.
const (
	attachCredentialRejected            = "rejected"
	attachCredentialPendingVerification = "pending-verification"
	attachCredentialRouterRefused       = "router-refused"
)

// mountStatusCredentialExpired marks a running mount whose credentials the
// control plane has definitively rejected: the kernel mount is still attached
// but operations degrade until re-login and remount.
const mountStatusCredentialExpired = "credential-expired"

var errRecordedMountAbsent = errors.New("recorded kernel mount is absent")

func recordedKernelMountPresent(st *mountState) (bool, error) {
	err := verifyRecordedMountIdentity(st)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, errRecordedMountAbsent):
		return false, nil
	default:
		return false, err
	}
}

// mountHealth folds pid-liveness and the persisted status into the one word
// `portablefs mounts` and `portablefs status` print.
func mountHealth(st *mountState) string {
	if !recordedMountVerified(st) {
		return "stale"
	}
	if st.Status == mountStatusCredentialExpired {
		return mountStatusCredentialExpired
	}
	return "live"
}

func recordedMountVerified(st *mountState) bool {
	if !mountProcessMatches(st) {
		return false
	}
	present, err := recordedKernelMountPresent(st)
	if err != nil || !present {
		return false
	}
	// Inventory and menu/status polling must never enter a potentially wedged
	// userspace filesystem. Root usability is proven on the bounded mount
	// readiness path; ongoing health uses exact process + kernel identity.
	return true
}

// setMountStatus persists a status transition into the mount's state record
// (read-modify-write, tolerating a not-yet-written record). It reports
// whether a record was updated.
func setMountStatus(dir, mountPath, status string, atMs int64) bool {
	updated, err := updateMountState(dir, mountPath, func(st *mountState) {
		st.Status = status
		st.StatusChangedAtMs = atMs
		if status == "" {
			st.StatusChangedAtMs = 0
		}
	})
	return err == nil && updated
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
	if e.stateDir != "" {
		return filepath.Join(e.stateDir, "mounts"), nil
	}
	home, err := accountpath.Home()
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
	path := mountStatePath(dir, st.MountPath)
	if err := validateMountStateRecord(path, &st); err != nil {
		return err
	}
	return withMountStateWriteLock(dir, st.MountPath, func() error {
		return writeMountStateUnlocked(dir, st)
	})
}

func writeMountStateUnlocked(dir string, st mountState) error {
	path := mountStatePath(dir, st.MountPath)
	if err := validateMountStateRecord(path, &st); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := privatepath.WriteFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("write mount state %s: %w", path, err)
	}
	return nil
}

func updateMountState(dir, mountPath string, update func(*mountState)) (bool, error) {
	if !validCanonicalMountPath(mountPath) {
		return false, fmt.Errorf("mount state update has non-canonical mount path %q", mountPath)
	}
	if update == nil {
		return false, fmt.Errorf("mount state update callback is nil")
	}
	updated := false
	err := withMountStateWriteLock(dir, mountPath, func() error {
		st, err := readMountState(dir, mountPath)
		if err != nil || st == nil {
			return err
		}
		update(st)
		if st.MountPath != mountPath {
			return fmt.Errorf("mount state update changed path identity from %q to %q", mountPath, st.MountPath)
		}
		if err := writeMountStateUnlocked(dir, *st); err != nil {
			return err
		}
		updated = true
		return nil
	})
	return updated, err
}

func withMountStateWriteLock(dir, mountPath string, fn func() error) error {
	parent, err := privatepath.OpenDir(dir)
	if err != nil {
		return fmt.Errorf("pin mount state directory: %w", err)
	}
	defer parent.Close()
	path := mountStatePath(dir, mountPath) + ".lock"
	file, err := privatepath.OpenLockFile(parent, dir, filepath.Base(path))
	if err != nil {
		return fmt.Errorf("open mount state lock %s: %w", path, err)
	}
	defer file.Close()
	fd := int(file.Fd())
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect mount state lock %s: %w", path, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return fmt.Errorf("mount state lock %s is not a private uid-owned 0600 regular file", path)
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock mount state %s: %w", path, err)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if err := privatepath.ValidateOpenFile(parent, dir, filepath.Base(path), file); err != nil {
		return err
	}
	return fn()
}

// readMountState loads the record for mountPath; a missing record returns
// (nil, nil) so callers can degrade gracefully.
func readMountState(dir, mountPath string) (*mountState, error) {
	if !validCanonicalMountPath(mountPath) {
		return nil, fmt.Errorf("mount state lookup has non-canonical mount path %q", mountPath)
	}
	path := mountStatePath(dir, mountPath)
	data, err := privatepath.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	st, err := decodeMountState(data)
	if err != nil {
		return nil, fmt.Errorf("parse mount state for %s: %w", mountPath, err)
	}
	if st.MountPath != mountPath {
		return nil, fmt.Errorf("mount state %s records path %q, want %q", path, st.MountPath, mountPath)
	}
	if err := validateMountStateRecord(path, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func decodeMountState(data []byte) (mountState, error) {
	var st mountState
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&st); err != nil {
		return mountState{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return mountState{}, fmt.Errorf("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return mountState{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return st, nil
}

func validateMountStateRecord(path string, st *mountState) error {
	if st == nil {
		return fmt.Errorf("mount state %s is empty", path)
	}
	if !validCanonicalMountPath(st.MountPath) {
		return fmt.Errorf("mount state %s has non-canonical mount path %q", path, st.MountPath)
	}
	if !validVolumeName(st.VolumeID) || !validStateString(st.Branch, 1024) {
		return fmt.Errorf("mount state %s has invalid volume or branch identity", path)
	}
	if st.PID <= 0 || !validStateString(st.ProcessStartIdentity, 128) {
		return fmt.Errorf("mount state %s has incomplete process identity", path)
	}
	if !mountid.ValidMountInstance(st.MountInstanceID) {
		return fmt.Errorf("mount state %s has incomplete mount instance identity", path)
	}
	if st.MountTargetDevice == 0 || st.MountTargetInode == 0 {
		return fmt.Errorf("mount state %s has incomplete mount target identity", path)
	}
	if st.StartedAtMs <= 0 || !validStateString(st.AuthorityURL, 2048) {
		return fmt.Errorf("mount state %s has incomplete data-plane identity", path)
	}

	switch st.Strategy {
	case "fuse":
		if st.FSType != "" || st.AttachRef != "" || !validKernelMountID(st.KernelMountID) {
			return fmt.Errorf("mount state %s has invalid FUSE kernel identity", path)
		}
		switch st.MountMechanism {
		case "direct":
			if st.FUSEHelperPath != "" {
				return fmt.Errorf("mount state %s has a helper path for a direct FUSE mount", path)
			}
		case "helper":
			if !validAbsoluteCleanPath(st.FUSEHelperPath) {
				return fmt.Errorf("mount state %s has invalid FUSE helper path %q", path, st.FUSEHelperPath)
			}
		default:
			return fmt.Errorf("mount state %s has invalid FUSE mount mechanism %q", path, st.MountMechanism)
		}
	case "fskit":
		if !validFSKitType(st.FSType) || !mountid.ValidAttachRef(st.AttachRef) || st.KernelMountID != "" {
			return fmt.Errorf("mount state %s has invalid FSKit attach identity", path)
		}
		if st.MountMechanism != "fskit-system" || st.FUSEHelperPath != "" {
			return fmt.Errorf("mount state %s has invalid FSKit mount mechanism %q", path, st.MountMechanism)
		}
	default:
		return fmt.Errorf("mount state %s has invalid strategy %q", path, st.Strategy)
	}

	if err := validatePersistedDataPlaneTransport(st); err != nil {
		return fmt.Errorf("mount state %s has invalid data-plane transport: %w", path, err)
	}
	if err := validatePersistedLocalDirs(st.LocalDirs); err != nil {
		return fmt.Errorf("mount state %s has invalid local dirs: %w", path, err)
	}

	leaseTransaction := st.ManagerURL != "" || st.AccessLeaseReleaseOperationID != "" || st.AccessLease != nil
	if leaseTransaction {
		if !validStateString(st.ManagerURL, 2048) || !validStateString(st.AccessLeaseReleaseOperationID, 256) ||
			st.AccessLease == nil || !validLeaseState(st.AccessLease) {
			return fmt.Errorf("mount state %s has incomplete access-lease transaction identity", path)
		}
		if _, err := canonicalOrigin(st.ManagerURL); err != nil {
			return fmt.Errorf("mount state %s has invalid access-lease manager URL: %w", path, err)
		}
	}

	switch st.Status {
	case "":
		if st.StatusChangedAtMs != 0 {
			return fmt.Errorf("mount state %s has a status timestamp without a status", path)
		}
	case mountStatusCredentialExpired:
		if st.StatusChangedAtMs <= 0 {
			return fmt.Errorf("mount state %s has credential-expired status without a transition timestamp", path)
		}
	default:
		return fmt.Errorf("mount state %s has invalid status %q", path, st.Status)
	}
	if st.ForceRecoveryJobID != "" && !st.ForceParkAcknowledged {
		return fmt.Errorf("mount state %s has a force-recovery job without a force-park acknowledgement", path)
	}
	if (st.ForceParkAcknowledged || st.ForceRecoveryJobID != "") && st.Strategy != "fuse" {
		return fmt.Errorf("mount state %s has FUSE force state for strategy %q", path, st.Strategy)
	}
	if st.ForceRecoveryJobID != "" && !validRecoveryJobID(st.ForceRecoveryJobID) {
		return fmt.Errorf("mount state %s has invalid force-recovery job identity", path)
	}
	return nil
}

func validCanonicalMountPath(path string) bool {
	return path != "" && path != string(filepath.Separator) &&
		filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validAbsoluteCleanPath(path string) bool {
	return path != "" && path != string(filepath.Separator) &&
		filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validStateString(value string, max int) bool {
	return value != "" && len(value) <= max && value == strings.TrimSpace(value) &&
		!strings.ContainsRune(value, '\x00')
}

func validFSKitType(value string) bool {
	return value == fskitidentity.FSType
}

func validatePersistedDataPlaneTransport(st *mountState) error {
	switch st.DataPlaneTransport {
	case dataPlaneTransportPlaintext:
		if st.DataPlaneServerName != "" || st.DataPlaneCAPath != "" || st.DataPlaneCASHA256 != "" {
			return fmt.Errorf("plaintext must not include TLS fields")
		}
	case dataPlaneTransportTLSSystemPKI:
		if err := validateDataPlaneServerName(st.DataPlaneServerName); err != nil {
			return err
		}
		if st.DataPlaneCAPath != "" || st.DataPlaneCASHA256 != "" {
			return fmt.Errorf("tls-system-pki must not include private CA fields")
		}
	case dataPlaneTransportTLSPrivateCA:
		if err := validateDataPlaneServerName(st.DataPlaneServerName); err != nil {
			return err
		}
		if !validAbsoluteCleanPath(st.DataPlaneCAPath) {
			return fmt.Errorf("tls-private-ca has invalid CA path %q", st.DataPlaneCAPath)
		}
		if st.DataPlaneCASHA256 != strings.ToLower(st.DataPlaneCASHA256) ||
			len(st.DataPlaneCASHA256) != 64 {
			return fmt.Errorf("tls-private-ca CA fingerprint must be 64 lowercase hexadecimal characters")
		}
		if _, err := hex.DecodeString(st.DataPlaneCASHA256); err != nil {
			return fmt.Errorf("tls-private-ca CA fingerprint: %w", err)
		}
	default:
		return fmt.Errorf("unsupported mode %q", st.DataPlaneTransport)
	}
	return nil
}

func validatePersistedLocalDirs(dirs []string) error {
	if err := localdirs.ValidateStrict(dirs); err != nil {
		return err
	}
	normalized, err := localdirs.Normalize(dirs)
	if err != nil {
		return err
	}
	if len(normalized) != len(dirs) {
		return fmt.Errorf("local dirs are not canonical")
	}
	for i := range dirs {
		if normalized[i] != dirs[i] {
			return fmt.Errorf("local dirs are not canonically ordered")
		}
	}
	return nil
}

func validLeaseState(lease *leaseState) bool {
	if lease == nil || !validStateString(lease.AccessLeaseID, 256) ||
		lease.AccessToken == "" || len(lease.AccessToken) > 4096 ||
		lease.ExpiresAtMs <= 0 || !validStateString(lease.ControlSeq, 20) {
		return false
	}
	controlSeq, err := strconv.ParseUint(lease.ControlSeq, 10, 64)
	return err == nil && controlSeq > 0 && strconv.FormatUint(controlSeq, 10) == lease.ControlSeq
}

func validRecoveryJobID(value string) bool {
	if len(value) != 35 || !strings.HasPrefix(value, "job") {
		return false
	}
	_, err := hex.DecodeString(value[3:])
	return err == nil && value == strings.ToLower(value)
}

func removeMountState(dir, mountPath string) error {
	return withMountStateWriteLock(dir, mountPath, func() error {
		return privatepath.RemoveFileDurable(mountStatePath(dir, mountPath))
	})
}

func listMountStates(dir string) ([]mountState, error) {
	entries, err := privatepath.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []mountState
	seen := make(map[string]string)
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".intent.json") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := privatepath.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read mount state record %s: %w", path, err)
		}
		st, err := decodeMountState(data)
		if err != nil {
			return nil, fmt.Errorf("parse mount state record %s: %w", path, err)
		}
		if !validCanonicalMountPath(st.MountPath) {
			return nil, fmt.Errorf("mount state record %s has non-canonical mount path %q", path, st.MountPath)
		}
		expected := filepath.Base(mountStatePath(dir, st.MountPath))
		if name != expected {
			return nil, fmt.Errorf("mount state record %s does not match canonical path key %s", path, expected)
		}
		if err := validateMountStateRecord(path, &st); err != nil {
			return nil, err
		}
		if prior, ok := seen[st.MountPath]; ok {
			return nil, fmt.Errorf("duplicate mount path %s in %s and %s", st.MountPath, prior, path)
		}
		seen[st.MountPath] = path
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
func readPersistedLocalDirs(mountsDir, volumeID, branch, mountPath string) ([]string, error) {
	path := localDirsRecordPath(mountsDir, volumeID, branch, mountPath)
	data, err := privatepath.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read persisted local-dirs record %s: %w", path, err)
	}
	var rec localDirsRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse persisted local-dirs record %s: %w", path, err)
	}
	if err := localdirs.ValidateStrict(rec.LocalDirs); err != nil {
		return nil, fmt.Errorf("validate persisted local-dirs record %s: %w", path, err)
	}
	return rec.LocalDirs, nil
}

// writePersistedLocalDirs remembers the EXPLICITLY configured graft roots
// (flag-level config; the volume's .portablefs/local-dirs file re-unions on
// every mount and is deliberately not baked in). An empty list removes the
// record: explicit flags win and update state.
func writePersistedLocalDirs(mountsDir, volumeID, branch, mountPath string, dirs []string) error {
	p := localDirsRecordPath(mountsDir, volumeID, branch, mountPath)
	if len(dirs) == 0 {
		return privatepath.RemoveFileDurable(p)
	}
	data, err := json.MarshalIndent(localDirsRecord{LocalDirs: dirs}, "", "  ")
	if err != nil {
		return err
	}
	if err := privatepath.WriteFileAtomic(p, append(data, '\n')); err != nil {
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

func mountProcessMatches(st *mountState) bool {
	if st == nil || st.PID <= 0 || st.ProcessStartIdentity == "" {
		return false
	}
	identity, err := processStartIdentity(st.PID)
	return err == nil && identity == st.ProcessStartIdentity
}
