package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

type mountIntent struct {
	SchemaVersion               int         `json:"schemaVersion"`
	Phase                       string      `json:"phase"`
	MountPath                   string      `json:"mountPath"`
	VolumeID                    string      `json:"volumeId,omitempty"`
	Branch                      string      `json:"branch,omitempty"`
	Strategy                    string      `json:"strategy,omitempty"`
	AttachRef                   string      `json:"attachRef,omitempty"`
	FSType                      string      `json:"fsType,omitempty"`
	MountInstanceID             string      `json:"mountInstanceId"`
	KernelMountID               string      `json:"kernelMountId,omitempty"`
	MountTargetDevice           uint64      `json:"mountTargetDevice,omitempty"`
	MountTargetInode            uint64      `json:"mountTargetInode,omitempty"`
	ManagerURL                  string      `json:"managerUrl,omitempty"`
	LeaseCreateOperationID      string      `json:"leaseCreateOperationId,omitempty"`
	LeaseReleaseOperationID     string      `json:"leaseReleaseOperationId,omitempty"`
	LeaseConsumerID             string      `json:"leaseConsumerId,omitempty"`
	LeaseTeamID                 string      `json:"leaseTeamId,omitempty"`
	AccessLease                 *leaseState `json:"accessLease,omitempty"`
	MountMechanism              string      `json:"mountMechanism,omitempty"`
	FUSEHelperPath              string      `json:"fuseHelperPath,omitempty"`
	StartedAtMs                 int64       `json:"startedAtMs,omitempty"`
	AuthorityURL                string      `json:"authorityUrl,omitempty"`
	DataPlaneTransport          string      `json:"dataPlaneTransport,omitempty"`
	DataPlaneServerName         string      `json:"dataPlaneServerName,omitempty"`
	DataPlaneCAPath             string      `json:"dataPlaneCaPath,omitempty"`
	DataPlaneCASHA256           string      `json:"dataPlaneCaSha256,omitempty"`
	MountOwnerPID               int         `json:"mountOwnerPid,omitempty"`
	MountOwnerStartIdentity     string      `json:"mountOwnerStartIdentity,omitempty"`
	OperationOwnerPID           int         `json:"operationOwnerPid"`
	OperationOwnerStartIdentity string      `json:"operationOwnerStartIdentity"`
	UpdatedAtMs                 int64       `json:"updatedAtMs"`
}

type mountOperation struct {
	file            *os.File
	dir             *os.File
	lockPath        string
	intentPath      string
	mountPath       string
	volumeID        string
	branch          string
	strategy        string
	attachRef       string
	mountInstanceID string
	kernelMountID   string
	mountTarget     mountTargetIdentity
	managerURL      string
	leaseCreateOp   string
	leaseReleaseOp  string
	leaseConsumerID string
	leaseTeamID     string
	accessLease     *leaseState
	mountMechanism  string
	fuseHelperPath  string
	fsType          string
	startedAtMs     int64
	authorityURL    string
	transportMode   string
	transportServer string
	dataPlaneCAPath string
	dataPlaneCAHash string
	prior           *mountIntent
}

func mountOperationPaths(stateDir, mountPath string) (string, string) {
	base := filepath.Join(stateDir, mountStateKey(mountPath))
	return base + ".op.lock", base + ".intent.json"
}

func acquireMountOperation(stateDir, mountPath, volumeID, branch, strategy string) (*mountOperation, error) {
	lockPath, intentPath := mountOperationPaths(stateDir, mountPath)
	dir, err := privatepath.OpenDir(stateDir)
	if err != nil {
		return nil, fmt.Errorf("pin mount operation directory: %w", err)
	}
	file, err := privatepath.OpenLockFile(dir, stateDir, filepath.Base(lockPath))
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	fd := int(file.Fd())
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("mount operation lock %s is not a regular 0600 file", lockPath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		_ = file.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("mount operation lock %s is not a sole uid-owned inode", lockPath)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		_ = dir.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another mount or unmount operation already owns %s", mountPath)
		}
		return nil, fmt.Errorf("lock mount operation for %s: %w", mountPath, err)
	}
	if err := privatepath.ValidateOpenFile(dir, stateDir, filepath.Base(lockPath), file); err != nil {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = file.Close()
		_ = dir.Close()
		return nil, err
	}
	op := &mountOperation{
		file: file, dir: dir, lockPath: lockPath, intentPath: intentPath, mountPath: mountPath,
		volumeID: volumeID, branch: branch, strategy: strategy,
	}
	prior, err := readMountIntent(intentPath, mountPath)
	if err != nil {
		return nil, errors.Join(err, op.close(false))
	}
	if prior != nil && volumeID != "" {
		conflictErr := fmt.Errorf(
			"an incomplete prior mount operation (%s) remains for %s; run `portablefs umount %s` to reconcile it before mounting"+
				" (if that operation's owner is gone and nothing is mounted there, `portablefs umount --discard-record %s` ends it)",
			prior.Phase, mountPath, mountPath, mountPath,
		)
		return nil, errors.Join(conflictErr, op.close(false))
	}
	op.prior = prior
	if prior == nil {
		err = op.writeIntent("starting", 0, "")
	}
	if err != nil {
		return nil, errors.Join(err, op.close(false))
	}
	return op, nil
}

func readMountIntent(path, mountPath string) (*mountIntent, error) {
	data, err := privatepath.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read mount operation intent %s: %w", path, err)
	}
	intent, err := decodeMountIntent(data)
	if err != nil {
		return nil, fmt.Errorf("parse mount operation intent %s: %w", path, err)
	}
	if intent.SchemaVersion != 2 || intent.MountPath != mountPath {
		return nil, fmt.Errorf("mount operation intent %s has incompatible identity", path)
	}
	if err := validateMountIntent(path, &intent); err != nil {
		return nil, err
	}
	return &intent, nil
}

func decodeMountIntent(data []byte) (mountIntent, error) {
	var intent mountIntent
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return mountIntent{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return mountIntent{}, fmt.Errorf("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return mountIntent{}, fmt.Errorf("trailing JSON: %w", err)
	}
	return intent, nil
}

func validateMountIntent(path string, intent *mountIntent) error {
	switch intent.Phase {
	case "starting", "mounting", "attaching", "attached", "kernel-mounted", "live", "unmounting", "drain-prepared", "force-requested", "force-prepared", "resources-cleaned", "lease-released", "cleanup-unverified":
	default:
		return fmt.Errorf("mount operation intent %s has unknown phase %q", path, intent.Phase)
	}
	if intent.MountOwnerPID < 0 || (intent.MountOwnerPID > 0 && intent.MountOwnerStartIdentity == "") ||
		intent.OperationOwnerPID <= 0 || intent.OperationOwnerStartIdentity == "" {
		return fmt.Errorf("mount operation intent %s has incomplete owner identity", path)
	}
	if intent.Phase != "starting" && intent.Phase != "cleanup-unverified" &&
		!mountid.ValidMountInstance(intent.MountInstanceID) {
		return fmt.Errorf("mount operation intent %s has incomplete mount instance identity", path)
	}
	if intent.Strategy == "fskit" &&
		(intent.Phase == "attaching" || intent.Phase == "attached" || intent.Phase == "kernel-mounted" || intent.Phase == "live" || intent.Phase == "unmounting" || intent.Phase == "force-requested" || intent.Phase == "force-prepared") &&
		!mountid.ValidAttachRef(intent.AttachRef) {
		return fmt.Errorf("mount operation intent %s has incomplete FSKit attach identity", path)
	}
	if intent.Strategy == "fuse" &&
		(intent.Phase == "kernel-mounted" || intent.Phase == "live" || intent.Phase == "unmounting" || intent.Phase == "drain-prepared" || intent.Phase == "force-requested" || intent.Phase == "force-prepared") &&
		!validKernelMountID(intent.KernelMountID) {
		return fmt.Errorf("mount operation intent %s has incomplete kernel mount identity", path)
	}
	if intent.KernelMountID != "" && !validKernelMountID(intent.KernelMountID) {
		return fmt.Errorf("mount operation intent %s has invalid kernel mount identity %q", path, intent.KernelMountID)
	}
	if (intent.MountTargetDevice == 0) != (intent.MountTargetInode == 0) {
		return fmt.Errorf("mount operation intent %s has incomplete mount target identity", path)
	}
	leaseTransaction := intent.ManagerURL != "" || intent.LeaseCreateOperationID != "" ||
		intent.LeaseReleaseOperationID != "" || intent.LeaseConsumerID != "" ||
		intent.LeaseTeamID != "" || intent.AccessLease != nil
	if leaseTransaction && (intent.ManagerURL == "" || intent.LeaseReleaseOperationID == "" ||
		intent.VolumeID == "" || intent.Branch == "") {
		return fmt.Errorf("mount operation intent %s has incomplete access-lease transaction identity", path)
	}
	if intent.AccessLease != nil && (intent.AccessLease.AccessLeaseID == "" || intent.AccessLease.AccessToken == "") {
		return fmt.Errorf("mount operation intent %s has incomplete access lease", path)
	}
	if intent.AccessLease == nil && leaseTransaction &&
		(intent.LeaseCreateOperationID == "" || intent.LeaseConsumerID == "") {
		return fmt.Errorf("mount operation intent %s cannot recover a create response", path)
	}
	if intent.Strategy == "fuse" && intent.Phase != "starting" &&
		intent.MountMechanism != "direct" && intent.MountMechanism != "helper" {
		return fmt.Errorf("mount operation intent %s has invalid FUSE mount mechanism %q", path, intent.MountMechanism)
	}
	if intent.Strategy == "fuse" && intent.MountMechanism == "helper" &&
		(!filepath.IsAbs(intent.FUSEHelperPath) || filepath.Clean(intent.FUSEHelperPath) != intent.FUSEHelperPath) {
		return fmt.Errorf("mount operation intent %s has invalid FUSE helper path %q", path, intent.FUSEHelperPath)
	}
	if intent.Phase != "starting" && intent.Phase != "mounting" && intent.Phase != "cleanup-unverified" {
		if intent.StartedAtMs <= 0 || intent.AuthorityURL == "" || intent.DataPlaneTransport == "" {
			return fmt.Errorf("mount operation intent %s has incomplete eventual mount-state identity", path)
		}
		if intent.Strategy == "fskit" && !validFSKitType(intent.FSType) {
			return fmt.Errorf(
				"mount operation intent %s has invalid FSKit type identity %q",
				path,
				intent.FSType,
			)
		}
	}
	return nil
}

func validKernelMountID(id string) bool {
	value, err := strconv.ParseUint(id, 10, 64)
	return err == nil && value > 0
}

func mountIntentOperationOwnerMatches(intent *mountIntent) bool {
	if intent == nil || intent.OperationOwnerPID <= 0 || intent.OperationOwnerStartIdentity == "" {
		return false
	}
	identity, err := processStartIdentity(intent.OperationOwnerPID)
	return err == nil && identity == intent.OperationOwnerStartIdentity
}

func listMountIntents(dir string) ([]mountIntent, error) {
	entries, err := privatepath.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []mountIntent
	seen := make(map[string]string)
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".intent.json") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := privatepath.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read mount operation intent %s: %w", path, err)
		}
		intent, err := decodeMountIntent(data)
		if err != nil {
			return nil, fmt.Errorf("parse mount operation intent %s: %w", path, err)
		}
		if intent.SchemaVersion != 2 || intent.MountPath == "" ||
			!filepath.IsAbs(intent.MountPath) || filepath.Clean(intent.MountPath) != intent.MountPath {
			return nil, fmt.Errorf("mount operation intent %s has incompatible identity", path)
		}
		expected := mountStateKey(intent.MountPath) + ".intent.json"
		if name != expected {
			return nil, fmt.Errorf("mount operation intent %s does not match canonical path key %s", path, expected)
		}
		if err := validateMountIntent(path, &intent); err != nil {
			return nil, err
		}
		if prior, ok := seen[intent.MountPath]; ok {
			return nil, fmt.Errorf("duplicate mount operation intent for %s in %s and %s", intent.MountPath, prior, path)
		}
		seen[intent.MountPath] = path
		out = append(out, intent)
	}
	return out, nil
}

func adoptMountOperation(fd int, stateDir, mountPath string) (*mountOperation, error) {
	if fd <= 0 {
		return nil, fmt.Errorf("invalid inherited mount operation fd %d", fd)
	}
	lockPath, intentPath := mountOperationPaths(stateDir, mountPath)
	dir, err := privatepath.OpenDir(stateDir)
	if err != nil {
		return nil, fmt.Errorf("pin inherited mount operation directory: %w", err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = dir.Close()
		return nil, fmt.Errorf("adopt inherited mount operation fd %d", fd)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("inherited mount operation fd %d is not a regular 0600 file", fd)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		_ = file.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("inherited mount operation fd %d is not a sole uid-owned inode", fd)
	}
	if err := privatepath.ValidateOpenFile(dir, stateDir, filepath.Base(lockPath), file); err != nil {
		_ = file.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("inherited mount operation fd %d does not match %s: %w", fd, lockPath, err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		_ = dir.Close()
		return nil, fmt.Errorf("revalidate inherited mount operation lock: %w", err)
	}
	return &mountOperation{file: file, dir: dir, lockPath: lockPath, intentPath: intentPath, mountPath: mountPath}, nil
}

func (op *mountOperation) writeIntent(phase string, pid int, identity string) error {
	operationIdentity, err := processStartIdentity(os.Getpid())
	if err != nil {
		return fmt.Errorf("record mount operation process identity: %w", err)
	}
	intent := mountIntent{
		SchemaVersion:               2,
		Phase:                       phase,
		MountPath:                   op.mountPath,
		VolumeID:                    op.volumeID,
		Branch:                      op.branch,
		Strategy:                    op.strategy,
		AttachRef:                   op.attachRef,
		FSType:                      op.fsType,
		MountInstanceID:             op.mountInstanceID,
		KernelMountID:               op.kernelMountID,
		MountTargetDevice:           op.mountTarget.device,
		MountTargetInode:            op.mountTarget.inode,
		ManagerURL:                  op.managerURL,
		LeaseCreateOperationID:      op.leaseCreateOp,
		LeaseReleaseOperationID:     op.leaseReleaseOp,
		LeaseConsumerID:             op.leaseConsumerID,
		LeaseTeamID:                 op.leaseTeamID,
		AccessLease:                 op.accessLease,
		MountMechanism:              op.mountMechanism,
		FUSEHelperPath:              op.fuseHelperPath,
		StartedAtMs:                 op.startedAtMs,
		AuthorityURL:                op.authorityURL,
		DataPlaneTransport:          op.transportMode,
		DataPlaneServerName:         op.transportServer,
		DataPlaneCAPath:             op.dataPlaneCAPath,
		DataPlaneCASHA256:           op.dataPlaneCAHash,
		MountOwnerPID:               pid,
		MountOwnerStartIdentity:     identity,
		OperationOwnerPID:           os.Getpid(),
		OperationOwnerStartIdentity: operationIdentity,
		UpdatedAtMs:                 time.Now().UnixMilli(),
	}
	return writeMountIntentRecord(op.intentPath, &intent)
}

func writeMountIntentRecord(path string, intent *mountIntent) error {
	if intent == nil {
		return fmt.Errorf("publish mount intent: missing record")
	}
	if err := validateMountIntent(path, intent); err != nil {
		return err
	}
	data, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	if err := privatepath.WriteFileAtomic(path, append(data, '\n')); err != nil {
		return fmt.Errorf("publish mount intent: %w", err)
	}
	return nil
}

func (op *mountOperation) preserveCleanupIntent(pid int, identity string) error {
	if _, err := os.Lstat(op.intentPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect cleanup intent: %w", err)
	}
	return op.writeIntent("cleanup-unverified", pid, identity)
}

func (op *mountOperation) close(removeIntent bool) error {
	if op == nil {
		return nil
	}
	var removeErr error
	if removeIntent {
		removeErr = privatepath.RemoveFileDurable(op.intentPath)
	}
	if op.file == nil {
		if op.dir == nil {
			return removeErr
		}
		dirErr := op.dir.Close()
		op.dir = nil
		return errors.Join(removeErr, dirErr)
	}
	file := op.file
	op.file = nil
	unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	closeErr := file.Close()
	var dirErr error
	if op.dir != nil {
		dirErr = op.dir.Close()
		op.dir = nil
	}
	return errors.Join(removeErr, unlockErr, closeErr, dirErr)
}
