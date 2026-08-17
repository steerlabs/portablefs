package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
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
	// Engine names the data plane behind the strategy's platform transport:
	// mountEngineFuseV3 (the Linux fusev3 stack) or mountEngineDaemonV3 (the
	// portablefsd-owned macOS v3 attach). Empty marks a record written by the
	// retired clientcore engine. Unmount picks its teardown from the
	// (strategy, engine) pair — a v3 FUSE mount has no write-back tail to
	// drain or park, and a v3 FSKit mount's evidence-bearing detach is owned
	// entirely by the daemon.
	Engine              string `json:"engine,omitempty"`
	FSType              string `json:"fsType,omitempty"`
	MountInstanceID     string `json:"mountInstanceId,omitempty"`
	KernelMountID       string `json:"kernelMountId,omitempty"`
	MountTargetDevice   uint64 `json:"mountTargetDevice,omitempty"`
	MountTargetInode    uint64 `json:"mountTargetInode,omitempty"`
	MountMechanism      string `json:"mountMechanism,omitempty"`
	FUSEHelperPath      string `json:"fuseHelperPath,omitempty"`
	DataPlaneCAPath     string `json:"dataPlaneCaPath,omitempty"`
	DataPlaneCASHA256   string `json:"dataPlaneCaSha256,omitempty"`
	DataPlaneTransport  string `json:"dataPlaneTransport,omitempty"`
	DataPlaneServerName string `json:"dataPlaneServerName,omitempty"`
	AuthorityURL        string `json:"authorityUrl,omitempty"`
	// AttachRef is the portablefsd attach this fskit mount serves (the
	// release-scoped generic URL resource the kernel holds); umount
	// diagnostics correlate on it.
	AttachRef string `json:"attachRef,omitempty"`
	// AuthorizationSessionID is the non-secret authority session identity a
	// hosted product binds its exact next reauthorization grant to. The Linux
	// supervisor additionally publishes a private local control socket; macOS
	// routes the same operation through portablefsd's existing control socket.
	AuthorizationSessionID       string `json:"authorizationSessionId,omitempty"`
	ReauthorizationControlSocket string `json:"reauthorizationControlSocket,omitempty"`
	MountEnrollmentID            string `json:"mountEnrollmentId,omitempty"`
	EnrollmentExpiresAtMs        int64  `json:"enrollmentExpiresAtMs,omitempty"`
	AuthorizationDeadlineAtMs    int64  `json:"authorizationDeadlineAtMs,omitempty"`
	LastReauthorizationAtMs      int64  `json:"lastReauthorizationAtMs,omitempty"`
	NextReauthorizationAtMs      int64  `json:"nextReauthorizationAtMs,omitempty"`
	ReauthorizationFailures      uint64 `json:"reauthorizationFailures,omitempty"`
	ReauthorizationError         string `json:"reauthorizationError,omitempty"`
	StartedAtMs                  int64  `json:"startedAtMs"`
	// LocalDirs are the machine-local graft roots an FSKit mount serves, as
	// literal paths (the macOS daemon's shape).
	LocalDirs         []string `json:"localDirs,omitempty"`
	LocalDirsDeclared bool     `json:"localDirsDeclared,omitempty"`
	// LocalRoutes is the canonical rule set a FUSE mount serves and
	// LocalBackingRoot the volume's machine-local backing tree.
	//
	// LocalRouteRevision is the VOLUME DECLARATION's revision — the SHA-256 of
	// the canonical form of .portablefs/local-dirs and of nothing else. It is
	// the value the authority pins the attach to, so it describes what the
	// volume declares, identically on every machine. It is deliberately NOT a
	// hash of LocalRoutes: on the legacy --local-dir path (allowed only when
	// the volume publishes no declaration) the two differ, and
	// LocalRoutesPerMachine records exactly that case.
	//
	// Together they let `portablefs route`, `portablefs mounts` and
	// `portablefs prune-local` answer without re-reading the volume.
	LocalRoutes           []string `json:"localRoutes,omitempty"`
	LocalRouteRevision    string   `json:"localRouteRevision,omitempty"`
	LocalRoutesPerMachine bool     `json:"localRoutesPerMachine,omitempty"`
	LocalBackingRoot      string   `json:"localBackingRoot,omitempty"`
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
	// this mount's credential ended, so filesystem access is degraded until
	// the mount is made again with a fresh volume mount capability;
	// mountStatusRevoked means the mount self-revoked and refuses to serve.
	// Additive: older records have no field.
	Status string `json:"status,omitempty"`
	// StatusChangedAtMs is when Status last transitioned (unix ms).
	StatusChangedAtMs int64 `json:"statusChangedAtMs,omitempty"`
	// StatusReason is the machine-readable class behind a revoked status: one
	// token from the shared revocation vocabulary, the same on both platforms.
	// A program branches on this; StatusDetail is the sentence a human reads.
	// Both are recorded only for mountStatusRevoked — no other status has a
	// classification to carry, and a record that carried one anyway would be
	// two different verdicts wearing one file.
	StatusReason string `json:"statusReason,omitempty"`
	StatusDetail string `json:"statusDetail,omitempty"`
	// ForceParkAcknowledged is the durable response frame for the exact
	// identity-bound SIGUSR1 force protocol used by Linux FUSE. The owner
	// publishes it only after CloseJournalDurable has fsynced the recovery
	// job, and before it detaches the kernel mount.
	ForceParkAcknowledged bool   `json:"forceParkAcknowledged,omitempty"`
	ForceRecoveryJobID    string `json:"forceRecoveryJobId,omitempty"`
}

// The recorded mount engines. Empty is deliberately NOT a constant: it is the
// absence of a claim, the shape every record written by the retired
// clientcore engine has.
const (
	mountEngineFuseV3   = "fusev3"
	mountEngineDaemonV3 = "daemon-v3"
)

// mountStatusCredentialExpired marks a running mount whose credentials the
// control plane has definitively rejected: the kernel mount is still attached
// but operations degrade until re-login and remount.
const mountStatusCredentialExpired = "credential-expired"

// mountStatusRevoked marks a mount that has self-revoked: it refuses to serve
// and can never serve again. It is deliberately independent of whether the
// kernel mount is still installed, because those are different facts and
// conflating them is how a dead mount kept reporting itself live. A revoked
// mount whose MNT_DETACH failed is still installed, still listed by findmnt,
// and still answers nothing.
const mountStatusRevoked = "revoked"

// The shared revocation vocabulary. These are the exact tokens both engines
// produce — the Linux fusev3 frontend classifies its own fatal cause into the
// first four (see fusev3's RevocationSessionTerminal and friends), the macOS
// supervisor's watchdog produces the last three — so `portablefs mounts --json`
// answers with one vocabulary regardless of which platform recorded it.
const (
	mountRevokedSessionTerminal      = "session-terminal"
	mountRevokedRepairBudgetExceeded = "repair-budget-exceeded"
	mountRevokedRoutesChanged        = "routes-changed"
	mountRevokedCoherenceViolation   = "coherence-violation"
	mountRevokedDaemonUnreachable    = "daemon-unreachable"
	mountRevokedAttachNotOwned       = "attach-not-owned"
	// mountRevokedUnclassified is what an unrecognized token becomes. An
	// engine that grows a new reason must not be able to make a revocation
	// unrecordable, and mislabelling it as one of the known classes would be
	// worse than admitting the record cannot name it.
	mountRevokedUnclassified = "unclassified"
)

// mountRevocation is one platform's revocation verdict in the shape the
// supervisor persists. It is deliberately platform-neutral: the Linux engine
// reports a fusev3.RevocationReport and the macOS watchdog reports its own
// probe decision, but both reduce to the same three facts, and `portablefs
// mounts` must not have to know which one produced a row.
type mountRevocation struct {
	reason string
	detail string
	// kernelStateWithdrawn is false when the mount is revoked but its kernel
	// mount could not be removed. It is the residual an operator has to know
	// about: nothing this process can do will discharge it.
	kernelStateWithdrawn bool
}

func validMountRevocationReason(reason string) bool {
	switch reason {
	case mountRevokedSessionTerminal, mountRevokedRepairBudgetExceeded,
		mountRevokedRoutesChanged, mountRevokedCoherenceViolation,
		mountRevokedDaemonUnreachable, mountRevokedAttachNotOwned,
		mountRevokedUnclassified:
		return true
	}
	return false
}

func normalizeMountRevocationReason(reason string) string {
	if validMountRevocationReason(reason) {
		return reason
	}
	return mountRevokedUnclassified
}

// maxStatusDetail bounds the prose a revoking engine may put in the record.
// The sentence is diagnostic, and a state file is not a log.
const maxStatusDetail = 2048

func boundedStatusDetail(detail string) string {
	detail = strings.TrimSpace(strings.ReplaceAll(detail, "\x00", ""))
	if len(detail) > maxStatusDetail {
		detail = strings.TrimSpace(detail[:maxStatusDetail])
	}
	return detail
}

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
// `portablefs mounts` and `portablefs doctor` print.
//
// Revocation is tested FIRST, before any liveness check. A self-revoked mount
// whose withdrawal failed still has its owner process running and its kernel
// mount installed, so every liveness check it is subjected to passes — which is
// precisely how a dead mount used to report itself live. Revocation is a
// recorded terminal verdict about whether this mount can serve, and it outranks
// every observation about whether it is still there.
func mountHealth(st *mountState) string {
	if st.Status == mountStatusRevoked {
		return mountStatusRevoked
	}
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
//
// A revoked record is never overwritten. Revocation is terminal — the mount
// refuses to serve and cannot be repaired — so a later credential verdict
// arriving from a renewal owner that has not noticed yet must not downgrade it
// into something that reads as recoverable.
func setMountStatus(dir, mountPath, status string, atMs int64) bool {
	updated, err := updateMountState(dir, mountPath, func(st *mountState) {
		if st.Status == mountStatusRevoked {
			return
		}
		st.Status = status
		st.StatusChangedAtMs = atMs
		st.StatusReason, st.StatusDetail = "", ""
		if status == "" {
			st.StatusChangedAtMs = 0
		}
	})
	return err == nil && updated
}

// setMountRevoked records the terminal self-revocation verdict: the status, the
// machine-readable class, the engine's own sentence, and when it happened. It
// is called by the mount supervisor on both platforms — the Linux one from the
// fusev3 revocation observer, the macOS one from the FSKit revocation watchdog
// — which is what makes `revoked` a first-class recorded status rather than a
// message that only ever reached a log.
//
// The first revocation wins: escalation can observe the same terminal condition
// more than once, and the earliest timestamp is the honest one.
func setMountRevoked(dir, mountPath, reason, detail string, atMs int64) bool {
	updated, err := updateMountState(dir, mountPath, func(st *mountState) {
		if st.Status == mountStatusRevoked {
			return
		}
		st.Status = mountStatusRevoked
		st.StatusReason = normalizeMountRevocationReason(reason)
		st.StatusDetail = boundedStatusDetail(detail)
		st.StatusChangedAtMs = atMs
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
	if !validVolumeName(st.VolumeID) {
		return fmt.Errorf("mount state %s has invalid volume identity", path)
	}
	// A v3 engine is branchless and a legacy clientcore record is
	// branch-bound. Both claims are checked rather than defaulted: a
	// branchless record carrying a branch (or the reverse) is two different
	// mounts wearing one file.
	switch st.Engine {
	case "":
		if !validStateString(st.Branch, 1024) {
			return fmt.Errorf("mount state %s has invalid branch identity", path)
		}
	case mountEngineFuseV3, mountEngineDaemonV3:
		if st.Branch != "" {
			return fmt.Errorf("mount state %s carries a branch on a branchless v3 engine record", path)
		}
	default:
		return fmt.Errorf("mount state %s has invalid engine %q", path, st.Engine)
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
		if st.Engine != "" && st.Engine != mountEngineFuseV3 {
			return fmt.Errorf("mount state %s has engine %q for a FUSE mount", path, st.Engine)
		}
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
		if st.ReauthorizationControlSocket != "" && !validReauthorizationControlAddress(st.ReauthorizationControlSocket) {
			return fmt.Errorf("mount state %s has invalid reauthorization control socket", path)
		}
	case "fskit":
		if st.Engine != "" && st.Engine != mountEngineDaemonV3 {
			return fmt.Errorf("mount state %s has engine %q for an FSKit mount", path, st.Engine)
		}
		if !validFSKitType(st.FSType) || !mountid.ValidAttachRef(st.AttachRef) || st.KernelMountID != "" {
			return fmt.Errorf("mount state %s has invalid FSKit attach identity", path)
		}
		if st.MountMechanism != "fskit-system" || st.FUSEHelperPath != "" {
			return fmt.Errorf("mount state %s has invalid FSKit mount mechanism %q", path, st.MountMechanism)
		}
		if st.ReauthorizationControlSocket != "" {
			return fmt.Errorf("mount state %s has a FUSE reauthorization socket for FSKit", path)
		}
	default:
		return fmt.Errorf("mount state %s has invalid strategy %q", path, st.Strategy)
	}
	if st.AuthorizationSessionID != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(st.AuthorizationSessionID)
		if err != nil || len(decoded) != 16 {
			return fmt.Errorf("mount state %s has invalid authorization session identity", path)
		}
	}
	if st.ReauthorizationControlSocket != "" && st.AuthorizationSessionID == "" {
		return fmt.Errorf("mount state %s has reauthorization control without a session identity", path)
	}
	if st.MountEnrollmentID != "" {
		if !validStateString(st.MountEnrollmentID, 256) || st.AuthorizationSessionID == "" ||
			st.EnrollmentExpiresAtMs <= 0 || st.AuthorizationDeadlineAtMs <= 0 ||
			st.LastReauthorizationAtMs < 0 || st.NextReauthorizationAtMs < 0 ||
			st.ReauthorizationError != "" && !validStateString(st.ReauthorizationError, 2048) || st.ReauthorizationControlSocket != "" {
			return fmt.Errorf("mount state %s has invalid automatic mount enrollment state", path)
		}
	} else if st.EnrollmentExpiresAtMs != 0 || st.AuthorizationDeadlineAtMs != 0 ||
		st.LastReauthorizationAtMs != 0 || st.NextReauthorizationAtMs != 0 || st.ReauthorizationFailures != 0 || st.ReauthorizationError != "" {
		return fmt.Errorf("mount state %s has renewal health without a mount enrollment", path)
	}

	if err := validatePersistedDataPlaneTransport(st); err != nil {
		return fmt.Errorf("mount state %s has invalid data-plane transport: %w", path, err)
	}
	if err := validatePersistedLocalDirs(st.LocalDirs); err != nil {
		return fmt.Errorf("mount state %s has invalid local dirs: %w", path, err)
	}
	if err := validatePersistedLocalRoutes(st); err != nil {
		return fmt.Errorf("mount state %s has invalid machine-local routes: %w", path, err)
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
	case mountStatusRevoked:
		if st.StatusChangedAtMs <= 0 {
			return fmt.Errorf("mount state %s has revoked status without a transition timestamp", path)
		}
		if !validMountRevocationReason(st.StatusReason) {
			return fmt.Errorf("mount state %s has invalid revocation reason %q", path, st.StatusReason)
		}
		if st.StatusDetail != "" && !validStateString(st.StatusDetail, maxStatusDetail) {
			return fmt.Errorf("mount state %s has invalid revocation detail", path)
		}
	default:
		return fmt.Errorf("mount state %s has invalid status %q", path, st.Status)
	}
	// A classification belongs to exactly one status. Carrying one without the
	// revoked verdict would let a record answer for a revocation it does not
	// record.
	if st.Status != mountStatusRevoked && (st.StatusReason != "" || st.StatusDetail != "") {
		return fmt.Errorf("mount state %s carries a revocation classification under status %q", path, st.Status)
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

// emptyRoutesRevision is the revision of a volume that declares nothing —
// the hash of the empty canonical rule set. A mount serving per-machine
// --local-dir routes reports exactly this, because such routes are allowed
// only when the volume publishes no declaration.
func emptyRoutesRevision() string { return localroutes.RuleSet{}.RevisionHex() }

// validatePersistedLocalRoutes proves a record's routing and the revision it
// answers for are each exactly what they claim. Declared routing must be the
// canonical form of its revision; per-machine routing must answer for the
// empty-declaration revision, since that is the only case it is permitted in.
// A record that failed either check would let `portablefs route` answer for
// one rule set while the authority pinned the attach to another.
func validatePersistedLocalRoutes(st *mountState) error {
	if len(st.LocalRoutes) == 0 && st.LocalRouteRevision == "" && st.LocalBackingRoot == "" && !st.LocalRoutesPerMachine {
		return nil
	}
	if st.LocalBackingRoot != "" && !validAbsoluteCleanPath(st.LocalBackingRoot) {
		return fmt.Errorf("invalid backing root %q", st.LocalBackingRoot)
	}
	rules, err := localroutes.Parse([]byte(strings.Join(st.LocalRoutes, "\n")))
	if err != nil {
		return err
	}
	if strings.Join(rules.Patterns(), "\n") != strings.Join(st.LocalRoutes, "\n") {
		return fmt.Errorf("route patterns are not canonical")
	}
	if st.LocalRoutesPerMachine {
		if st.LocalRouteRevision != emptyRoutesRevision() {
			return fmt.Errorf("per-machine routes must answer for the empty-declaration revision, not %q", st.LocalRouteRevision)
		}
		return nil
	}
	if rules.RevisionHex() != st.LocalRouteRevision {
		return fmt.Errorf("route revision %q does not match the recorded patterns", st.LocalRouteRevision)
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
// FUSE-grafted content lives under <stateBase>/local/<volume storage id>/
// (stateBase is the parent of the mounts dir), with each route root at its own
// volume-relative path inside that tree. portablefsd deliberately has a
// separate <stateBase>/portablefsd/local/<volume+branch storage id>/ tree;
// operator tooling derives that path through portablefsd.LocalBackingRoot.
// The FUSE identity is (volume, route root) and nothing else, so
// a dependency tree survives unmount, remount, and remount at a different
// path, while a different volume at the same mountpoint can never inherit it.
//
// Two sidecars sit BESIDE the tree (never inside it, where a name could
// collide with a route root): the per-mount --local-dir record, which
// preserves the flag precedence across remounts, and the per-volume active
// route record, which tells `portablefs prune-local` what is still routed
// when no mount of the volume is running. Both must survive a clean unmount —
// persistent local dependency trees are the whole point.

// localDirsBackingRoot is the machine-local backing tree for one volume.
func localDirsBackingRoot(mountsDir, volumeID string) string {
	return localdirs.BackingRoot(filepath.Dir(mountsDir), volumeID)
}

// localMountRecordKey distinguishes the per-mount sidecars of one volume.
func localMountRecordKey(branch, mountPath string) string {
	sum := sha256.Sum256([]byte(branch + "\x00" + mountPath))
	return hex.EncodeToString(sum[:8])
}

func localDirsRecordPath(mountsDir, volumeID, branch, mountPath string) string {
	return localDirsBackingRoot(mountsDir, volumeID) + ".dirs-" + localMountRecordKey(branch, mountPath) + ".json"
}

// localRoutesRecordPath names the volume's active route record.
func localRoutesRecordPath(mountsDir, volumeID string) string {
	return localDirsBackingRoot(mountsDir, volumeID) + ".routes.json"
}

type localDirsRecord struct {
	LocalDirs []string `json:"localDirs"`
}

// localRoutesRecord is the volume's last activated routing on this machine.
// prune-local reads it to decide which backing subtrees are still reachable
// when nothing is mounted; it is written on every successful activation.
// Revision is the volume declaration's, exactly as in mountState.
type localRoutesRecord struct {
	VolumeID    string   `json:"volumeId"`
	Patterns    []string `json:"patterns"`
	Revision    string   `json:"revision"`
	PerMachine  bool     `json:"perMachine,omitempty"`
	UpdatedAtMs int64    `json:"updatedAtMs"`
}

// readLocalRoutesRecord loads a volume's active route set. A missing record
// means "no route set is known", which prune-local treats as "every backing
// subtree of this volume is orphaned" — the honest reading, since nothing on
// this machine can reach it.
func readLocalRoutesRecord(mountsDir, volumeID string) (*localRoutesRecord, error) {
	p := localRoutesRecordPath(mountsDir, volumeID)
	data, err := privatepath.ReadFile(p)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read local-routes record %s: %w", p, err)
	}
	return decodeLocalRoutesRecord(data, p)
}

// decodeLocalRoutesRecord parses and self-checks one record: the patterns
// must be a valid canonical rule set and must hash to the revision recorded
// beside them, so nothing downstream can act on a half-written file.
func decodeLocalRoutesRecord(data []byte, p string) (*localRoutesRecord, error) {
	var rec localRoutesRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("parse local-routes record %s: %w", p, err)
	}
	rules, err := localroutes.Parse([]byte(strings.Join(rec.Patterns, "\n")))
	if err != nil {
		return nil, fmt.Errorf("validate local-routes record %s: %w", p, err)
	}
	want := rules.RevisionHex()
	if rec.PerMachine {
		want = emptyRoutesRevision()
	}
	if want != rec.Revision {
		return nil, fmt.Errorf("local-routes record %s does not match its revision", p)
	}
	return &rec, nil
}

func writeLocalRoutesRecord(mountsDir, volumeID string, routes mountRoutes, nowMs int64) error {
	p := localRoutesRecordPath(mountsDir, volumeID)
	data, err := json.MarshalIndent(localRoutesRecord{
		VolumeID:    volumeID,
		Patterns:    routes.rules.Patterns(),
		Revision:    routes.revision,
		PerMachine:  routes.perMachine,
		UpdatedAtMs: nowMs,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := privatepath.WriteFileAtomic(p, append(data, '\n')); err != nil {
		return fmt.Errorf("write local-routes record %s: %w", p, err)
	}
	return nil
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
// (flag-level config; the volume's declaration is re-read on every mount and
// is deliberately not baked in). An empty list removes the record: explicit
// flags win and update state.
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
