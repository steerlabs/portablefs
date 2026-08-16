//go:build linux

// Package cellhost implements the closed Linux/XFS/systemd operations used by
// the privileged helper. Every path is derived from a validated volume ID
// under operator-pinned roots; every executable and argument shape is fixed.
package cellhost

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/steerlabs/portablefs/vcs/internal/cellhelper"
	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"golang.org/x/sys/unix"
)

const (
	xfsMagic           = 0x58465342
	fsIOCFSGetXattr    = 0x801c581f
	fsXFlagProjInherit = 0x00000200
)

type fsXAttr struct {
	XFlags     uint32
	ExtSize    uint32
	Nextents   uint32
	ProjectID  uint32
	CowExtSize uint32
	Pad        [8]byte
}

var safeRootPattern = regexp.MustCompile(`^/[A-Za-z0-9_@./-]+$`)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, arguments ...string) ([]byte, error) {
	return exec.CommandContext(ctx, executable, arguments...).CombinedOutput()
}

type Config struct {
	CellID           string
	CellRoot         string
	ConfigRoot       string
	StateRoot        string
	SystemdUnitRoot  string
	SysusersRoot     string
	XFSQuotaBinary   string
	SystemctlBinary  string
	SystemdRunBinary string
	SysusersBinary   string
	Runner           CommandRunner
	Now              func() time.Time
}

type Host struct{ cfg Config }

func New(config Config) (*Host, error) {
	if !cellplan.ValidID(config.CellID) || !safeRoot(config.CellRoot) || !safeRoot(config.ConfigRoot) ||
		!safeRoot(config.StateRoot) || !safeRoot(config.SystemdUnitRoot) || !safeRoot(config.SysusersRoot) ||
		!filepath.IsAbs(config.XFSQuotaBinary) || !filepath.IsAbs(config.SystemctlBinary) ||
		!filepath.IsAbs(config.SystemdRunBinary) || !filepath.IsAbs(config.SysusersBinary) {
		return nil, errors.New("cellhost: complete pinned absolute configuration is required")
	}
	if config.Runner == nil {
		config.Runner = ExecRunner{}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Host{cfg: config}, nil
}

func (host *Host) Apply(ctx context.Context, plan cellplan.VolumePlan, previous cellhelper.Assignment) controlplane.VolumeObservation {
	observed := controlplane.VolumeObservation{}
	var err error
	switch plan.Phase {
	case cellplan.PhaseProvision:
		observed.Provisioned, observed.AuthorityCSRPEM, err = host.provision(ctx, plan, !previous.QuotaApplied)
		observed.AuthorityAbsent = true
	case cellplan.PhaseServe:
		observed.Provisioned, observed.AuthorityCSRPEM, err = host.provision(ctx, plan, !previous.QuotaApplied)
		if err == nil {
			err = host.start(ctx, plan)
			observed.AuthorityRunning = err == nil
		}
	case cellplan.PhaseFence, cellplan.PhaseRetire:
		observed.AuthorityAbsent, err = host.fence(ctx, plan.VolumeID)
		observed.Provisioned = host.volumeExists(plan.VolumeID)
	default:
		err = errors.New("unknown volume phase")
	}
	if err != nil {
		observed.Error = err.Error()
	}
	return observed
}

// Observe checks the already-applied plan without re-running quota changes,
// rewriting systemd drop-ins, or starting a stopped authority. A stopped
// serving authority is reported as failure so the manager fences the epoch;
// the helper never hides a crash by automatically restarting the same writer.
func (host *Host) Observe(ctx context.Context, plan cellplan.VolumePlan, _ cellhelper.Assignment) controlplane.VolumeObservation {
	observed := controlplane.VolumeObservation{}
	switch plan.Phase {
	case cellplan.PhaseProvision:
		var err error
		observed.Provisioned, observed.AuthorityCSRPEM, err = host.observeProvisioned(plan)
		observed.AuthorityAbsent = true
		if err != nil {
			observed.Error = err.Error()
		}
	case cellplan.PhaseServe:
		var err error
		observed.Provisioned, observed.AuthorityCSRPEM, err = host.observeProvisioned(plan)
		if err == nil {
			service := "portablefs-authority@" + plan.VolumeID + ".service"
			if output, activeErr := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "is-active", "--quiet", service); activeErr != nil {
				err = commandError("observe authority active", output, activeErr)
			} else {
				observed.AuthorityRunning = true
			}
		}
		if err != nil {
			observed.Error = err.Error()
		}
	case cellplan.PhaseFence, cellplan.PhaseRetire:
		absent, err := host.authorityAbsent(ctx, plan.VolumeID)
		observed.AuthorityAbsent = absent
		observed.Provisioned = host.volumeExists(plan.VolumeID)
		if err != nil {
			observed.Error = err.Error()
		}
	default:
		observed.Error = "cellhost: unknown volume phase"
	}
	return observed
}

func (host *Host) observeProvisioned(plan cellplan.VolumePlan) (bool, string, error) {
	volumeFD, err := host.openVolumeDirectory(plan.VolumeID, false)
	if err != nil {
		return false, "", fmt.Errorf("cellhost: provisioned volume directory is absent or unsafe: %w", err)
	}
	defer unix.Close(volumeFD)
	if err := verifyProvisionedVolume(volumeFD, plan); err != nil {
		return false, "", err
	}
	stagingFD, err := host.openWriteStaging(plan.VolumeID)
	if err != nil {
		return false, "", fmt.Errorf("cellhost: write staging is absent or unsafe: %w", err)
	}
	defer unix.Close(stagingFD)
	if err := verifyProjectDirectory(stagingFD, plan, plan.ServiceUID, plan.ServiceGID, 0o700, "write staging"); err != nil {
		return false, "", err
	}
	csrPath := filepath.Join(host.cfg.ConfigRoot, plan.VolumeID, fmt.Sprintf("authority-%d.csr", plan.AuthorityGeneration))
	info, err := os.Lstat(csrPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, "", errors.New("cellhost: authority CSR is absent or unsafe")
	}
	csr, err := os.ReadFile(csrPath)
	if err != nil {
		return false, "", err
	}
	if plan.Phase == cellplan.PhaseServe {
		certificatePath := filepath.Join(host.cfg.ConfigRoot, plan.VolumeID, fmt.Sprintf("authority-%d.cert", plan.AuthorityGeneration))
		certificate, err := os.Lstat(certificatePath)
		if err != nil || !certificate.Mode().IsRegular() || certificate.Mode()&os.ModeSymlink != 0 {
			return false, "", errors.New("cellhost: authority certificate is absent or unsafe")
		}
	}
	return true, string(csr), nil
}

func (host *Host) provision(ctx context.Context, plan cellplan.VolumePlan, applyQuota bool) (bool, string, error) {
	volumePath := filepath.Join(host.cfg.CellRoot, plan.VolumeID)
	if err := host.ensureServiceIdentity(ctx, plan); err != nil {
		return false, "", err
	}
	volumeFD, err := host.ensureVolumeDirectory(plan)
	if err != nil {
		return false, "", err
	}
	defer unix.Close(volumeFD)
	if applyQuota {
		projectCommand := fmt.Sprintf("project -s -p %s %d", volumePath, plan.ProjectID)
		projectArguments := transientArguments(
			"portablefs-xfs-project-"+plan.VolumeID, host.cfg.XFSQuotaBinary,
			[]string{"-x", "-c", projectCommand, host.cfg.CellRoot},
			"CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN", false,
		)
		if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemdRunBinary, projectArguments...); err != nil {
			return false, "", commandError("assign XFS project", output, err)
		}
		limitCommand, err := xfsHardLimitCommand(plan)
		if err != nil {
			return false, "", err
		}
		limitArguments := transientArguments(
			"portablefs-xfs-limit-"+plan.VolumeID, host.cfg.XFSQuotaBinary,
			[]string{"-x", "-c", limitCommand, host.cfg.CellRoot},
			"CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN", false,
		)
		if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemdRunBinary, limitArguments...); err != nil {
			return false, "", commandError("apply XFS hard quotas", output, err)
		}
	}
	if err := verifyProvisionedVolume(volumeFD, plan); err != nil {
		return false, "", err
	}
	stagingPath, err := host.ensureWriteStaging(ctx, plan)
	if err != nil {
		return false, "", err
	}
	configDirectory := filepath.Join(host.cfg.ConfigRoot, plan.VolumeID)
	stateDirectory := filepath.Join(host.cfg.StateRoot, plan.VolumeID)
	if err := ensureManagedDirectory(configDirectory, 0, int(plan.ServiceGID), 0o750); err != nil {
		return false, "", err
	}
	if err := ensureManagedDirectory(stateDirectory, int(plan.ServiceUID), int(plan.ServiceGID), 0o700); err != nil {
		return false, "", err
	}
	keyPath := filepath.Join(configDirectory, fmt.Sprintf("authority-%d.key", plan.AuthorityGeneration))
	privateKey, err := ensureAuthorityKey(keyPath, int(plan.ServiceUID), int(plan.ServiceGID))
	if err != nil {
		return false, "", err
	}
	csr, err := authorityCSR(privateKey, plan.AuthorityID)
	if err != nil {
		return false, "", err
	}
	csrPath := filepath.Join(configDirectory, fmt.Sprintf("authority-%d.csr", plan.AuthorityGeneration))
	if err := writeAtomic(csrPath, []byte(csr), 0, int(plan.ServiceGID), 0o440); err != nil {
		return false, "", err
	}
	if err := writeAtomic(filepath.Join(configDirectory, "authority-ca.pem"), []byte(plan.AuthorityCAPEM), 0, int(plan.ServiceGID), 0o440); err != nil {
		return false, "", err
	}
	if err := writeAtomic(filepath.Join(configDirectory, "client-ca.pem"), []byte(plan.ClientCAPEM), 0, int(plan.ServiceGID), 0o440); err != nil {
		return false, "", err
	}
	if err := writeAtomic(filepath.Join(configDirectory, "capability-public.pem"), []byte(plan.CapabilityPublicKey), 0, int(plan.ServiceGID), 0o440); err != nil {
		return false, "", err
	}
	if err := writeAtomic(filepath.Join(configDirectory, "product-public.pem"), []byte(plan.ProductPublicKeyPEM), 0, int(plan.ServiceGID), 0o440); err != nil {
		return false, "", err
	}
	if plan.AuthorityCertificate == "" {
		return true, csr, nil
	}
	if err := verifyAuthorityCertificate(plan, privateKey, host.cfg.Now()); err != nil {
		return false, csr, err
	}
	certificatePath := filepath.Join(configDirectory, fmt.Sprintf("authority-%d.cert", plan.AuthorityGeneration))
	if err := writeAtomic(certificatePath, []byte(plan.AuthorityCertificate), 0, int(plan.ServiceGID), 0o440); err != nil {
		return false, csr, err
	}
	launcherConfig := AuthorityConfig{
		Version: 1, VolumeID: plan.VolumeID, CellID: host.cfg.CellID,
		AuthorizationDomain: plan.AuthorizationDomain, Owner: plan.Owner, ProductIssuer: plan.ProductIssuer,
		AuthorityID: plan.AuthorityID, AuthorityGeneration: plan.AuthorityGeneration,
		ProjectID: plan.ProjectID, PriorStrictMountsFenced: plan.PriorStrictFenced,
	}
	configBytes, err := json.Marshal(launcherConfig)
	if err != nil {
		return false, csr, err
	}
	if err := writeAtomic(filepath.Join(configDirectory, "authority.json"), configBytes, 0, int(plan.ServiceGID), 0o440); err != nil {
		return false, csr, err
	}
	if err := host.writeSystemdDropIns(plan, volumePath, configDirectory, stateDirectory, stagingPath); err != nil {
		return false, csr, err
	}
	return true, csr, nil
}

func xfsHardLimitCommand(plan cellplan.VolumePlan) (string, error) {
	if plan.ProjectID == 0 || plan.QuotaBytes == 0 || plan.QuotaBytes%1024 != 0 || plan.QuotaInodes == 0 {
		return "", ErrInvalid
	}
	return fmt.Sprintf("limit -p bhard=%dk ihard=%d %d", plan.QuotaBytes/1024, plan.QuotaInodes, plan.ProjectID), nil
}

func (host *Host) ensureServiceIdentity(ctx context.Context, plan cellplan.VolumePlan) error {
	name, payload, err := serviceIdentityConfig(plan)
	if err != nil {
		return err
	}
	if err := ensureManagedDirectory(host.cfg.SysusersRoot, 0, 0, 0o755); err != nil {
		return err
	}
	configPath := filepath.Join(host.cfg.SysusersRoot, "portablefs-volume-"+plan.VolumeID+".conf")
	if err := writeAtomic(configPath, payload, 0, 0, 0o644); err != nil {
		return err
	}
	arguments := transientArguments(
		"portablefs-sysusers-"+plan.VolumeID, host.cfg.SysusersBinary, []string{configPath},
		"CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER", true,
	)
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemdRunBinary, arguments...); err != nil {
		return commandError("create volume service identity", output, err)
	}
	return verifyServiceIdentity(name, plan.ServiceUID, plan.ServiceGID)
}

func transientArguments(unit, executable string, commandArguments []string, capabilities string, isolateMounts bool) []string {
	arguments := []string{
		"--quiet", "--wait", "--collect", "--unit=" + unit,
		"--property=NoNewPrivileges=yes",
		"--property=PrivateNetwork=yes",
		"--property=ProtectClock=yes",
		"--property=ProtectControlGroups=yes",
		"--property=ProtectHome=yes",
		"--property=ProtectHostname=yes",
		"--property=ProtectKernelLogs=yes",
		"--property=ProtectKernelModules=yes",
		"--property=ProtectKernelTunables=yes",
		"--property=RestrictAddressFamilies=AF_UNIX",
		"--property=RestrictNamespaces=yes",
		"--property=RestrictRealtime=yes",
		"--property=CapabilityBoundingSet=" + capabilities,
		"--property=SystemCallArchitectures=native",
		"--property=UMask=0077",
	}
	if isolateMounts {
		arguments = append(arguments, "--property=PrivateDevices=yes", "--property=PrivateTmp=yes")
	}
	arguments = append(arguments, executable)
	return append(arguments, commandArguments...)
}

func serviceIdentityConfig(plan cellplan.VolumePlan) (string, []byte, error) {
	if !cellplan.ValidID(plan.VolumeID) || plan.ServiceUID < 1000 || plan.ServiceGID < 1000 {
		return "", nil, ErrInvalid
	}
	identifier, err := hex.DecodeString(strings.ReplaceAll(plan.VolumeID, "-", ""))
	if err != nil || len(identifier) != 16 {
		return "", nil, ErrInvalid
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(identifier)
	name := "pfs-" + strings.ToLower(encoded)
	payload := fmt.Sprintf(
		"# Generated by portablefs-cell-helper; do not edit.\n"+
			"g %s %d\n"+
			"u %s %d:%s \"PortableFS volume %s\" /nonexistent /usr/sbin/nologin\n",
		name, plan.ServiceGID, name, plan.ServiceUID, name, plan.VolumeID,
	)
	return name, []byte(payload), nil
}

func verifyServiceIdentity(name string, expectedUID, expectedGID uint32) error {
	account, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("cellhost: volume service user is absent: %w", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid != uint64(expectedUID) || gid != uint64(expectedGID) {
		return errors.New("cellhost: volume service user does not match its signed UID/GID")
	}
	byID, err := user.LookupId(strconv.FormatUint(uint64(expectedUID), 10))
	if err != nil || byID.Username != name {
		return errors.New("cellhost: signed service UID is owned by another user")
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return fmt.Errorf("cellhost: volume service group is absent: %w", err)
	}
	groupID, groupIDErr := strconv.ParseUint(group.Gid, 10, 32)
	if groupIDErr != nil || groupID != uint64(expectedGID) {
		return errors.New("cellhost: volume service group does not match its signed GID")
	}
	groupByID, err := user.LookupGroupId(strconv.FormatUint(uint64(expectedGID), 10))
	if err != nil || groupByID.Name != name {
		return errors.New("cellhost: signed service GID is owned by another group")
	}
	return nil
}

func (host *Host) ensureVolumeDirectory(plan cellplan.VolumePlan) (int, error) {
	fd, err := host.openVolumeDirectory(plan.VolumeID, true)
	if err != nil {
		return -1, err
	}
	if err := unix.Fchown(fd, int(plan.ServiceUID), int(plan.ServiceGID)); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (host *Host) openVolumeDirectory(volumeID string, create bool) (int, error) {
	if !cellplan.ValidID(volumeID) {
		return -1, ErrInvalid
	}
	rootFD, err := host.openCellRoot()
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	if create {
		if err := unix.Mkdirat(rootFD, volumeID, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
	}
	return unix.Openat2(rootFD, volumeID, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func (host *Host) openCellRoot() (int, error) {
	rootFD, err := unix.Open(host.cfg.CellRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(rootFD, &filesystem); err != nil || uint64(filesystem.Type) != xfsMagic {
		_ = unix.Close(rootFD)
		return -1, errors.New("cellhost: cell root is not XFS")
	}
	var rootStat, parentStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		_ = unix.Close(rootFD)
		return -1, err
	}
	if err := unix.Stat(filepath.Dir(host.cfg.CellRoot), &parentStat); err != nil {
		_ = unix.Close(rootFD)
		return -1, err
	}
	if rootStat.Dev == parentStat.Dev {
		_ = unix.Close(rootFD)
		return -1, errors.New("cellhost: cell root is not a dedicated XFS mountpoint")
	}
	return rootFD, nil
}

func (host *Host) openWriteStaging(volumeID string) (int, error) {
	if !cellplan.ValidID(volumeID) {
		return -1, ErrInvalid
	}
	rootFD, err := host.openCellRoot()
	if err != nil {
		return -1, err
	}
	defer unix.Close(rootFD)
	controlFD, err := openDirectoryAt(rootFD, ".portablefs-control")
	if err != nil {
		return -1, err
	}
	defer unix.Close(controlFD)
	if err := verifyRootControlDirectory(controlFD); err != nil {
		return -1, err
	}
	volumeControlFD, err := openDirectoryAt(controlFD, volumeID)
	if err != nil {
		return -1, err
	}
	defer unix.Close(volumeControlFD)
	if err := verifyRootControlDirectory(volumeControlFD); err != nil {
		return -1, err
	}
	return openDirectoryAt(volumeControlFD, "write-staging")
}

func (host *Host) ensureWriteStaging(ctx context.Context, plan cellplan.VolumePlan) (string, error) {
	if !cellplan.ValidID(plan.VolumeID) {
		return "", ErrInvalid
	}
	rootFD, err := host.openCellRoot()
	if err != nil {
		return "", err
	}
	defer unix.Close(rootFD)
	controlFD, err := ensureRootDirectoryAt(rootFD, ".portablefs-control", 0o711)
	if err != nil {
		return "", fmt.Errorf("cellhost: prepare control root: %w", err)
	}
	defer unix.Close(controlFD)
	volumeControlFD, err := ensureRootDirectoryAt(controlFD, plan.VolumeID, 0o711)
	if err != nil {
		return "", fmt.Errorf("cellhost: prepare volume control root: %w", err)
	}
	defer unix.Close(volumeControlFD)

	const stagingName = "write-staging"
	stagingFD, err := openDirectoryAt(volumeControlFD, stagingName)
	if errors.Is(err, unix.ENOENT) {
		const prepareName = ".write-staging.prepare"
		prepareFD, prepareErr := ensureRootDirectoryAt(volumeControlFD, prepareName, 0o700)
		if prepareErr != nil {
			return "", fmt.Errorf("cellhost: prepare write staging transaction: %w", prepareErr)
		}
		if emptyErr := requireEmptyDirectory(prepareFD); emptyErr != nil {
			_ = unix.Close(prepareFD)
			return "", emptyErr
		}
		preparePath := filepath.Join(host.cfg.CellRoot, ".portablefs-control", plan.VolumeID, prepareName)
		projectCommand := fmt.Sprintf("project -s -p %s %d", preparePath, plan.ProjectID)
		projectArguments := transientArguments(
			"portablefs-xfs-staging-"+plan.VolumeID, host.cfg.XFSQuotaBinary,
			[]string{"-x", "-c", projectCommand, host.cfg.CellRoot},
			"CAP_DAC_OVERRIDE CAP_FOWNER CAP_SYS_ADMIN", false,
		)
		if output, runErr := host.cfg.Runner.Run(ctx, host.cfg.SystemdRunBinary, projectArguments...); runErr != nil {
			_ = unix.Close(prepareFD)
			return "", commandError("assign write staging XFS project", output, runErr)
		}
		if verifyErr := verifyProjectDirectory(prepareFD, plan, 0, 0, 0o700, "prepared write staging"); verifyErr != nil {
			_ = unix.Close(prepareFD)
			return "", verifyErr
		}
		if syncErr := unix.Fsync(prepareFD); syncErr != nil {
			_ = unix.Close(prepareFD)
			return "", syncErr
		}
		_ = unix.Close(prepareFD)
		if renameErr := unix.Renameat2(volumeControlFD, prepareName, volumeControlFD, stagingName, unix.RENAME_NOREPLACE); renameErr != nil && !errors.Is(renameErr, unix.EEXIST) {
			return "", renameErr
		}
		if syncErr := unix.Fsync(volumeControlFD); syncErr != nil {
			return "", syncErr
		}
		stagingFD, err = openDirectoryAt(volumeControlFD, stagingName)
	}
	if err != nil {
		return "", fmt.Errorf("cellhost: open write staging: %w", err)
	}
	defer unix.Close(stagingFD)
	var stat unix.Stat_t
	if err := unix.Fstat(stagingFD, &stat); err != nil {
		return "", err
	}
	if !((stat.Uid == 0 && stat.Gid == 0) || (stat.Uid == plan.ServiceUID && stat.Gid == plan.ServiceGID)) {
		return "", errors.New("cellhost: write staging has an unexpected owner")
	}
	if err := verifyProjectIdentityAndQuota(stagingFD, plan, "write staging"); err != nil {
		return "", err
	}
	if err := unix.Fchown(stagingFD, int(plan.ServiceUID), int(plan.ServiceGID)); err != nil {
		return "", err
	}
	if err := unix.Fchmod(stagingFD, 0o700); err != nil {
		return "", err
	}
	if err := verifyProjectDirectory(stagingFD, plan, plan.ServiceUID, plan.ServiceGID, 0o700, "write staging"); err != nil {
		return "", err
	}
	if err := unix.Fsync(stagingFD); err != nil {
		return "", err
	}
	if err := unix.Syncfs(rootFD); err != nil {
		return "", err
	}
	return filepath.Join(host.cfg.CellRoot, ".portablefs-control", plan.VolumeID, stagingName), nil
}

func openDirectoryAt(parentFD int, name string) (int, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return -1, ErrInvalid
	}
	return unix.Openat2(parentFD, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
	})
}

func ensureRootDirectoryAt(parentFD int, name string, mode uint32) (int, error) {
	if err := unix.Mkdirat(parentFD, name, mode); err != nil && !errors.Is(err, unix.EEXIST) {
		return -1, err
	}
	fd, err := openDirectoryAt(parentFD, name)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if stat.Uid != 0 || stat.Gid != 0 {
		_ = unix.Close(fd)
		return -1, errors.New("cellhost: privileged control directory is not root-owned")
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func verifyRootControlDirectory(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != 0 || stat.Gid != 0 || stat.Mode&0o777 != 0o711 {
		return errors.New("cellhost: privileged control directory ownership or mode changed")
	}
	return nil
}

func requireEmptyDirectory(fd int) error {
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(dupFD), "write-staging-prepare")
	if directory == nil {
		_ = unix.Close(dupFD)
		return errors.New("cellhost: duplicate staging directory returned no file")
	}
	defer directory.Close()
	names, err := directory.Readdirnames(1)
	if err == nil || len(names) != 0 {
		return errors.New("cellhost: prepared write staging directory is not empty")
	}
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func verifyProvisionedVolume(fd int, plan cellplan.VolumePlan) error {
	return verifyProjectDirectory(fd, plan, plan.ServiceUID, plan.ServiceGID, 0o700, "volume")
}

func verifyProjectDirectory(fd int, plan cellplan.VolumePlan, uid, gid, mode uint32, label string) error {
	if err := verifyProjectIdentityAndQuota(fd, plan, label); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != mode {
		return fmt.Errorf("cellhost: %s ownership/mode mismatch: got %d:%d %#o, want %d:%d %#o",
			label, stat.Uid, stat.Gid, stat.Mode&0o777, uid, gid, mode)
	}
	return nil
}

func verifyProjectIdentityAndQuota(fd int, plan cellplan.VolumePlan, label string) error {
	var attributes fsXAttr
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), fsIOCFSGetXattr, uintptr(unsafe.Pointer(&attributes))); errno != 0 {
		return fmt.Errorf("cellhost: query %s XFS project identity: %w", label, errno)
	}
	if attributes.ProjectID != plan.ProjectID || attributes.XFlags&fsXFlagProjInherit == 0 {
		return fmt.Errorf("cellhost: %s XFS project isolation mismatch: got project=%d inherit=%t, want project=%d inherit=true",
			label, attributes.ProjectID, attributes.XFlags&fsXFlagProjInherit != 0, plan.ProjectID)
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return err
	}
	if filesystem.Bsize <= 0 || filesystem.Blocks > ^uint64(0)/uint64(filesystem.Bsize) {
		return errors.New("cellhost: invalid XFS project statfs block result")
	}
	reportedBytes := filesystem.Blocks * uint64(filesystem.Bsize)
	if reportedBytes != plan.QuotaBytes || filesystem.Files != plan.QuotaInodes {
		return fmt.Errorf("cellhost: %s XFS hard quota mismatch: got bytes=%d inodes=%d, want bytes=%d inodes=%d",
			label, reportedBytes, filesystem.Files, plan.QuotaBytes, plan.QuotaInodes)
	}
	return nil
}

func (host *Host) writeSystemdDropIns(plan cellplan.VolumePlan, volumePath, configPath, statePath, stagingPath string) error {
	serviceDirectory := filepath.Join(host.cfg.SystemdUnitRoot, "portablefs-authority@"+plan.VolumeID+".service.d")
	socketDirectory := filepath.Join(host.cfg.SystemdUnitRoot, "portablefs-authority@"+plan.VolumeID+".socket.d")
	if err := ensureManagedDirectory(serviceDirectory, 0, 0, 0o755); err != nil {
		return err
	}
	if err := ensureManagedDirectory(socketDirectory, 0, 0, 0o755); err != nil {
		return err
	}
	service := authorityServiceDropIn(plan, volumePath, configPath, statePath, stagingPath)
	socket := fmt.Sprintf("[Socket]\nListenStream=\nListenStream=0.0.0.0:%d\n", plan.ListenPort)
	if err := writeAtomic(filepath.Join(serviceDirectory, "10-portablefs.conf"), []byte(service), 0, 0, 0o644); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(socketDirectory, "10-portablefs.conf"), []byte(socket), 0, 0, 0o644)
}

func authorityServiceDropIn(plan cellplan.VolumePlan, volumePath, configPath, statePath, stagingPath string) string {
	return fmt.Sprintf("[Service]\nUser=%d\nGroup=%d\nBindPaths=%s:/srv/portablefs-volume\nBindReadOnlyPaths=%s:/run/portablefs-volume\nBindPaths=%s:/var/lib/portablefs-volume\nBindPaths=%s:/var/lib/portablefs-write-staging\n", plan.ServiceUID, plan.ServiceGID, volumePath, configPath, statePath, stagingPath)
}

func (host *Host) start(ctx context.Context, plan cellplan.VolumePlan) error {
	service := "portablefs-authority@" + plan.VolumeID + ".service"
	socket := "portablefs-authority@" + plan.VolumeID + ".socket"
	for _, arguments := range [][]string{{"daemon-reload"}, {"enable", "--now", socket}, {"start", service}} {
		if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, arguments...); err != nil {
			return commandError("start authority", output, err)
		}
	}
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "is-active", "--quiet", service); err != nil {
		return commandError("verify authority active", output, err)
	}
	return nil
}

func (host *Host) fence(ctx context.Context, volumeID string) (bool, error) {
	if !cellplan.ValidID(volumeID) {
		return false, ErrInvalid
	}
	service := "portablefs-authority@" + volumeID + ".service"
	socket := "portablefs-authority@" + volumeID + ".socket"
	_, _ = host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "kill", "--kill-whom=all", "--signal=SIGKILL", service)
	if output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "stop", service, socket); err != nil {
		return false, commandError("stop authority and listener", output, err)
	}
	return host.authorityAbsent(ctx, volumeID)
}

func (host *Host) authorityAbsent(ctx context.Context, volumeID string) (bool, error) {
	if !cellplan.ValidID(volumeID) {
		return false, ErrInvalid
	}
	service := "portablefs-authority@" + volumeID + ".service"
	socket := "portablefs-authority@" + volumeID + ".socket"
	for _, unit := range []string{service, socket} {
		if _, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "is-active", "--quiet", unit); err == nil {
			return false, errors.New("cellhost: authority unit remained active after fencing")
		}
	}
	output, err := host.cfg.Runner.Run(ctx, host.cfg.SystemctlBinary, "show", "--property=ControlGroup", "--value", service)
	if err != nil {
		return false, commandError("inspect authority cgroup", output, err)
	}
	controlGroup := strings.TrimSpace(string(output))
	if controlGroup != "" && controlGroup != "/" {
		eventsPath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(controlGroup, "/"), "cgroup.events")
		events, readErr := os.ReadFile(eventsPath)
		if readErr == nil && !strings.Contains(string(events), "populated 0") {
			return false, errors.New("cellhost: authority cgroup is still populated")
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return false, readErr
		}
	}
	return true, nil
}

func (host *Host) volumeExists(volumeID string) bool {
	info, err := os.Lstat(filepath.Join(host.cfg.CellRoot, volumeID))
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func ensureAuthorityKey(path string, uid, gid int) (ed25519.PrivateKey, error) {
	if raw, err := readPrivate(path); err == nil {
		block, rest := pem.Decode(raw)
		if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
			return nil, errors.New("cellhost: authority key has invalid PEM")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		key, ok := parsed.(ed25519.PrivateKey)
		if err != nil || !ok {
			return nil, errors.New("cellhost: authority key is not Ed25519")
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ENOENT) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), uid, gid, 0o400); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func authorityCSR(privateKey ed25519.PrivateKey, commonName string) (string, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, privateKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func verifyAuthorityCertificate(plan cellplan.VolumePlan, privateKey ed25519.PrivateKey, now time.Time) error {
	block, rest := pem.Decode([]byte(plan.AuthorityCertificate))
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE" {
		return errors.New("cellhost: authority certificate has invalid PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return err
	}
	keyPublic, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil || !equalBytes(certificatePublic, keyPublic) {
		return errors.New("cellhost: authority certificate does not match the local private key")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(plan.AuthorityCAPEM)) {
		return errors.New("cellhost: authority CA is invalid")
	}
	_, err = certificate.Verify(x509.VerifyOptions{
		DNSName: plan.AuthorityServerName, Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func ensureManagedDirectory(path string, uid, gid int, mode os.FileMode) error {
	if !safeRoot(path) {
		return errors.New("cellhost: derived path failed validation")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("cellhost: managed path is not a real directory")
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func writeAtomic(path string, payload []byte, uid, gid int, mode os.FileMode) error {
	if !safeRoot(path) {
		return errors.New("cellhost: derived file path failed validation")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".portablefs-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chown(uid, gid); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
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
	return directory.Sync()
}

func readPrivate(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, syscall.EBADF
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("cellhost: private key permissions are unsafe")
	}
	return io.ReadAll(file)
}

func safeRoot(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && safeRootPattern.MatchString(path) && !strings.Contains(path, "..")
}

func commandError(operation string, output []byte, err error) error {
	detail := strings.TrimSpace(string(output))
	if len(detail) > 512 {
		detail = detail[:512]
	}
	if detail == "" {
		return fmt.Errorf("cellhost: %s: %w", operation, err)
	}
	return fmt.Errorf("cellhost: %s: %w: %s", operation, err, detail)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}
