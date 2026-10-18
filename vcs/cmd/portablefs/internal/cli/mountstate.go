package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/mountrecord"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

// mountState is one active mount's record under
// ~/.local/state/portablefs/mounts/<hash>.json; umount and mounts read it.
const mountStateSchemaVersion = 1

type mountState struct {
	SchemaVersion int    `json:"schemaVersion"`
	MountPath     string `json:"mountPath"`
	VolumeID      string `json:"volumeId"`
	PID           int    `json:"pid"`
	// ProcessStartIdentity binds PID to one kernel process incarnation. PID
	// alone is never sufficient authority to signal a process because it may
	// have been recycled.
	ProcessStartIdentity string `json:"processStartIdentity,omitempty"`
	Strategy             string `json:"strategy"`
	Engine               string `json:"engine,omitempty"`
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
	AttachRef string `json:"attachRef,omitempty"`
	// AuthorizationSessionID is the non-secret authority session identity a
	// hosted product binds its exact next reauthorization grant to. The Linux
	// supervisor publishes a same-user local control socket for live loss
	// snapshots and, without automatic enrollment, reauthorization; macOS
	// routes the same operation through portablefsd's existing control socket.
	AuthorizationSessionID       string   `json:"authorizationSessionId,omitempty"`
	ReauthorizationControlSocket string   `json:"reauthorizationControlSocket,omitempty"`
	MountEnrollmentID            string   `json:"mountEnrollmentId,omitempty"`
	AuthorizationDeadlineAtMs    int64    `json:"authorizationDeadlineAtMs,omitempty"`
	LastReauthorizationAtMs      int64    `json:"lastReauthorizationAtMs,omitempty"`
	NextReauthorizationAtMs      int64    `json:"nextReauthorizationAtMs,omitempty"`
	ReauthorizationFailures      uint64   `json:"reauthorizationFailures,omitempty"`
	ReauthorizationError         string   `json:"reauthorizationError,omitempty"`
	StartedAtMs                  int64    `json:"startedAtMs"`
	LocalRoutes                  []string `json:"localRoutes,omitempty"`
	LocalRouteRevision           string   `json:"localRouteRevision,omitempty"`
	LocalBackingRoot             string   `json:"localBackingRoot,omitempty"`
	Status                       string   `json:"status,omitempty"`
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
}

// Exact data-plane identities for the two supported mount strategies.
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

// Linux records terminal frontend verdicts; unavailable FSKit control never
// produces a permanent revocation record.
const (
	mountRevokedSessionTerminal      = "session-terminal"
	mountRevokedRepairBudgetExceeded = "repair-budget-exceeded"
	mountRevokedRoutesChanged        = "routes-changed"
	mountRevokedCoherenceViolation   = "coherence-violation"
	// mountRevokedUnclassified is what an unrecognized token becomes. An
	// engine that grows a new reason must not be able to make a revocation
	// unrecordable, and mislabelling it as one of the known classes would be
	// worse than admitting the record cannot name it.
	mountRevokedUnclassified = "unclassified"
)

// mountRevocation is one platform's revocation verdict in the shape the
// supervisor persists. It is deliberately platform-neutral: the Linux engine
// reports a fusev3.RevocationReport
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

// setMountRevoked persists the Linux frontend's terminal revocation verdict.
// The first verdict wins so repeated observations retain the original cause.
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
	return mountrecord.Key(mountPath)
}

func mountStatePath(dir, mountPath string) string {
	return filepath.Join(dir, mountStateKey(mountPath)+".json")
}

func mountLogPath(dir, mountPath string) string {
	return mountrecord.LogPath(dir, mountPath)
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
	if st.SchemaVersion != mountStateSchemaVersion {
		return fmt.Errorf("mount state %s has unequal format", path)
	}
	if !validCanonicalMountPath(st.MountPath) {
		return fmt.Errorf("mount state %s has non-canonical mount path %q", path, st.MountPath)
	}
	if !validVolumeName(st.VolumeID) {
		return fmt.Errorf("mount state %s has invalid volume identity", path)
	}
	if st.Engine != mountEngineFuseV3 && st.Engine != mountEngineDaemonV3 {
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
		if st.Engine != mountEngineFuseV3 {
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
		if st.Engine != mountEngineDaemonV3 {
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
			st.AuthorizationDeadlineAtMs <= 0 ||
			st.LastReauthorizationAtMs < 0 || st.NextReauthorizationAtMs < 0 ||
			st.ReauthorizationError != "" && !validStateString(st.ReauthorizationError, 2048) {
			return fmt.Errorf("mount state %s has invalid automatic mount enrollment state", path)
		}
	} else if st.AuthorizationDeadlineAtMs != 0 ||
		st.LastReauthorizationAtMs != 0 || st.NextReauthorizationAtMs != 0 || st.ReauthorizationFailures != 0 || st.ReauthorizationError != "" {
		return fmt.Errorf("mount state %s has renewal health without a mount enrollment", path)
	}

	if err := validatePersistedDataPlaneTransport(st); err != nil {
		return fmt.Errorf("mount state %s has invalid data-plane transport: %w", path, err)
	}
	if err := validatePersistedLocalRoutes(st); err != nil {
		return fmt.Errorf("mount state %s has invalid machine-local routes: %w", path, err)
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

// emptyRoutesRevision is the revision of a volume with no local routes.
func emptyRoutesRevision() string { return localroutes.RuleSet{}.RevisionHex() }

// The recorded canonical rules must hash to the exact authority-pinned revision.
func validatePersistedLocalRoutes(st *mountState) error {
	if len(st.LocalRoutes) == 0 && st.LocalRouteRevision == "" && st.LocalBackingRoot == "" {
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
	if rules.RevisionHex() != st.LocalRouteRevision {
		return fmt.Errorf("route revision %q does not match the recorded patterns", st.LocalRouteRevision)
	}
	return nil
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

// The backing tree belongs to a volume, independent of its mount path. The
// adjacent active-route record keeps prune decisions tied to the declaration
// most recently activated by this machine.
func localDirsBackingRoot(mountsDir, volumeID string) string {
	return localdirs.BackingRoot(filepath.Dir(mountsDir), volumeID)
}

// Active-route state sits beside the backing tree, outside routed names.
func localRoutesRecordPath(mountsDir, volumeID string) string {
	return localDirsBackingRoot(mountsDir, volumeID) + ".routes.json"
}

// localRoutesRecord is the volume's last activated routing on this machine.
// prune-local reads it to decide which backing subtrees are still reachable
// when nothing is mounted; it is written on every successful activation.
// Revision is the volume declaration's, exactly as in mountState.
const localRoutesSchemaVersion = 1

type localRoutesRecord struct {
	SchemaVersion int      `json:"schemaVersion"`
	VolumeID      string   `json:"volumeId"`
	Patterns      []string `json:"patterns"`
	Revision      string   `json:"revision"`
	UpdatedAtMs   int64    `json:"updatedAtMs"`
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
	rec, err := decodeLocalRoutesRecord(data, p)
	if err != nil {
		return nil, err
	}
	if rec.VolumeID != volumeID {
		return nil, fmt.Errorf("local-routes record %s names another volume", p)
	}
	return rec, nil
}

// decodeLocalRoutesRecord parses and self-checks one record: the patterns
// must be a valid canonical rule set and must hash to the revision recorded
// beside them, so nothing downstream can act on a half-written file.
func decodeLocalRoutesRecord(data []byte, p string) (*localRoutesRecord, error) {
	var rec localRoutesRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rec); err != nil {
		return nil, fmt.Errorf("parse local-routes record %s: %w", p, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("local-routes record %s has trailing data", p)
	}
	rules, err := localroutes.Parse([]byte(strings.Join(rec.Patterns, "\n")))
	if err != nil {
		return nil, fmt.Errorf("validate local-routes record %s: %w", p, err)
	}
	if rec.SchemaVersion != localRoutesSchemaVersion || !validVolumeName(rec.VolumeID) || rec.UpdatedAtMs <= 0 || strings.Join(rec.Patterns, "\n") != strings.Join(rules.Patterns(), "\n") {
		return nil, fmt.Errorf("local-routes record has unequal format")
	}
	want := rules.RevisionHex()
	if want != rec.Revision {
		return nil, fmt.Errorf("local-routes record %s does not match its revision", p)
	}
	return &rec, nil
}

func writeLocalRoutesRecord(mountsDir, volumeID string, routes mountRoutes, nowMs int64) error {
	p := localRoutesRecordPath(mountsDir, volumeID)
	data, err := json.MarshalIndent(localRoutesRecord{
		SchemaVersion: localRoutesSchemaVersion,
		VolumeID:      volumeID,
		Patterns:      routes.rules.Patterns(),
		Revision:      routes.revision,
		UpdatedAtMs:   nowMs,
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := privatepath.WriteFileAtomic(p, append(data, '\n')); err != nil {
		return fmt.Errorf("write local-routes record %s: %w", p, err)
	}
	return nil
}

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
