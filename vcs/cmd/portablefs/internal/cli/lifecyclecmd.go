package cli

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountlifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
)

func (e *cmdEnv) mountLifecycleStateDir() (string, error) {
	if e.lifecycleStateDir != "" {
		return e.lifecycleStateDir, nil
	}
	return mountlifecycle.DefaultStateDir()
}

func cmdLifecycle(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.usageError("lifecycle", fmt.Errorf("expected `hold-shared`, `hold-account-exclusive`, `hold-install-exclusive`, or `identity`"))
	}
	if args[0] == "identity" {
		fs := newFlagSet("lifecycle identity")
		var jsonOut bool
		fs.BoolVar(&jsonOut, "json", false, "write the versioned identity")
		positionals, err := parseArgs(fs, args[1:])
		if err != nil {
			return e.handleParseError("lifecycle", err)
		}
		if len(positionals) != 0 {
			return e.usageError("lifecycle", fmt.Errorf("identity expects no arguments"))
		}
		if jsonOut {
			return e.printJSON(fskitidentity.Current())
		}
		fmt.Fprintln(e.stdout, fskitidentity.AppGroup)
		return 0
	}
	if args[0] == "hold-account-exclusive" {
		return cmdHoldAccountExclusive(e, args[1:])
	}
	if args[0] == "hold-install-exclusive" {
		return cmdHoldInstallExclusive(e, args[1:])
	}
	if args[0] != "hold-shared" {
		return e.usageError("lifecycle", fmt.Errorf("expected `hold-shared`, `hold-account-exclusive`, `hold-install-exclusive`, or `identity`"))
	}
	fs := newFlagSet("lifecycle hold-shared")
	var jsonOut bool
	fs.BoolVar(&jsonOut, "json", false, "write the versioned readiness handshake")
	positionals, err := parseArgs(fs, args[1:])
	if err != nil {
		return e.handleParseError("lifecycle", err)
	}
	if len(positionals) != 0 {
		return e.usageError("lifecycle", fmt.Errorf("hold-shared expects no arguments"))
	}
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return e.fail("lifecycle", err)
	}
	guard, err := mountlifecycle.AcquireShared(stateDir)
	if err != nil {
		return e.fail("lifecycle", fmt.Errorf("hold shared guard: %w", err))
	}
	defer guard.Close()

	if jsonOut {
		// This exact one-line frame is the readiness protocol consumed by the
		// macOS app before it presents any interactive UI.
		fmt.Fprintln(e.stdout, `{"schemaVersion":1,"held":true}`)
	} else {
		fmt.Fprintln(e.stdout, "mount lifecycle guard held; close stdin to release")
	}
	return holdUntilInputOrSignal(e)
}

func cmdHoldAccountExclusive(e *cmdEnv, args []string) int {
	fs := newFlagSet("lifecycle hold-account-exclusive")
	var jsonOut bool
	fs.BoolVar(&jsonOut, "json", false, "write the versioned readiness handshake")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("lifecycle", err)
	}
	if len(positionals) != 0 {
		return e.usageError("lifecycle", fmt.Errorf("hold-account-exclusive expects no arguments"))
	}
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return e.fail("lifecycle", err)
	}
	guard, err := accountsession.AcquireExclusive(stateDir)
	if err != nil {
		return e.fail("lifecycle", fmt.Errorf("hold account-exclusive guard: %w", err))
	}
	defer guard.Close()

	inventory, err := e.strictAccountInventory("changing account credentials", nil)
	if err != nil {
		return e.fail("lifecycle", err)
	}
	if jsonOut {
		fmt.Fprintf(
			e.stdout,
			"{\"schemaVersion\":1,\"held\":true,\"mounts\":%d,\"attaches\":%d}\n",
			inventory.mountCount(),
			inventory.attachCount(),
		)
	} else {
		fmt.Fprintln(e.stdout, "account session exclusive guard held with empty inventory; close stdin to release")
	}
	return holdUntilInputOrSignal(e)
}

type lifecycleInventory struct {
	KernelMounts    int `json:"kernelMounts"`
	MountRecords    int `json:"mountRecords"`
	MountIntents    int `json:"mountIntents"`
	DurableAttaches int `json:"durableAttaches"`
	LiveAttaches    int `json:"liveAttaches"`
}

func (i lifecycleInventory) mountCount() int {
	return i.KernelMounts + i.MountRecords + i.MountIntents
}

func (i lifecycleInventory) attachCount() int {
	return i.DurableAttaches + i.LiveAttaches
}

type installExclusiveReadiness struct {
	SchemaVersion int    `json:"schemaVersion"`
	Held          bool   `json:"held"`
	Purpose       string `json:"purpose"`
	lifecycleInventory
}

// cmdHoldInstallExclusive is the host-owned service replacement boundary. It
// first excludes new account mount starts, then takes the mount-lifetime lock
// used by every serving mount and installer. Both acquisitions are
// nonblocking. Only while holding both does it prove every kernel, durable,
// and live daemon inventory empty, publish one readiness frame, and wait for
// the host to close stdin. ServiceManagement unregister/register must happen
// inside that held interval.
func cmdHoldInstallExclusive(e *cmdEnv, args []string) int {
	fs := newFlagSet("lifecycle hold-install-exclusive")
	var jsonOut bool
	var expectedDaemonVersion string
	var expectedDaemonSHA256 string
	var expectedPFSLocalMajor uint
	var expectedPFSLocalMinor uint
	fs.BoolVar(&jsonOut, "json", false, "write the versioned service-update readiness handshake")
	fs.StringVar(&expectedDaemonVersion, "expected-daemon-version", "", "previously registered daemon version")
	fs.StringVar(&expectedDaemonSHA256, "expected-daemon-sha256", "", "previously registered daemon executable SHA-256")
	fs.UintVar(&expectedPFSLocalMajor, "expected-pfslocal-major", 0, "previously registered daemon pfslocal major")
	fs.UintVar(&expectedPFSLocalMinor, "expected-pfslocal-minor", 0, "previously registered daemon pfslocal minor")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("lifecycle", err)
	}
	if len(positionals) != 0 {
		return e.usageError("lifecycle", fmt.Errorf("hold-install-exclusive expects no arguments"))
	}
	present := map[string]bool{}
	fs.Visit(func(value *flag.Flag) {
		present[value.Name] = true
	})
	expectedIdentity, err := parseExpectedDaemonIdentity(
		expectedDaemonVersion,
		expectedDaemonSHA256,
		expectedPFSLocalMajor,
		expectedPFSLocalMinor,
		present["expected-daemon-version"],
		present["expected-daemon-sha256"],
		present["expected-pfslocal-major"],
		present["expected-pfslocal-minor"],
	)
	if err != nil {
		return e.usageError("lifecycle", err)
	}
	stateDir, err := e.mountLifecycleStateDir()
	if err != nil {
		return e.fail("lifecycle", err)
	}
	accountGuard, err := accountsession.AcquireExclusive(stateDir)
	if err != nil {
		return e.fail("lifecycle", fmt.Errorf("hold install account-session guard: %w", err))
	}
	defer accountGuard.Close()
	mountGuard, err := mountlifecycle.AcquireExclusive(stateDir)
	if err != nil {
		return e.fail("lifecycle", fmt.Errorf("hold install mount-lifecycle guard: %w", err))
	}
	defer mountGuard.Close()

	inventory, err := e.strictAccountInventory(
		"updating the PortableFS service",
		expectedIdentity,
	)
	if err != nil {
		return e.fail("lifecycle", err)
	}
	if jsonOut {
		payload, err := json.Marshal(installExclusiveReadiness{
			SchemaVersion:      1,
			Held:               true,
			Purpose:            "service-update",
			lifecycleInventory: inventory,
		})
		if err != nil {
			return e.fail("lifecycle", fmt.Errorf("encode install-exclusive readiness: %w", err))
		}
		if _, err := fmt.Fprintln(e.stdout, string(payload)); err != nil {
			return e.fail("lifecycle", fmt.Errorf("write install-exclusive readiness: %w", err))
		}
	} else {
		fmt.Fprintln(e.stdout, "install lifecycle guards held with empty inventory; close stdin to release")
	}
	return holdUntilInputOrSignal(e)
}

func parseExpectedDaemonIdentity(
	version string,
	sha256 string,
	pfslocalMajor uint,
	pfslocalMinor uint,
	versionPresent bool,
	sha256Present bool,
	majorPresent bool,
	minorPresent bool,
) (*daemonctl.Identity, error) {
	provided := versionPresent || sha256Present || majorPresent || minorPresent
	if !provided {
		return nil, nil
	}
	if !versionPresent || !sha256Present || !majorPresent || !minorPresent ||
		version == "" || sha256 == "" || pfslocalMajor == 0 {
		return nil, fmt.Errorf("the expected old daemon identity requires version, SHA-256, pfslocal major, and pfslocal minor together")
	}
	if len(version) > 128 || strings.IndexFunc(version, func(r rune) bool {
		return r < 0x21 || r > 0x7e
	}) >= 0 {
		return nil, fmt.Errorf("expected daemon version must be 1-128 visible ASCII characters")
	}
	digest, err := hex.DecodeString(sha256)
	if err != nil || len(digest) != 32 || strings.ToLower(sha256) != sha256 {
		return nil, fmt.Errorf("expected daemon SHA-256 must be exactly 64 lowercase hexadecimal characters")
	}
	if pfslocalMajor > math.MaxUint32 || pfslocalMinor > math.MaxUint32 {
		return nil, fmt.Errorf("expected pfslocal version is outside uint32")
	}
	return &daemonctl.Identity{
		SchemaVersion:    daemonctl.IdentitySchemaVersion,
		ControlProtocol:  daemonctl.ControlProtocolVersion,
		DaemonVersion:    version,
		ExecutableSHA256: sha256,
		PFSLocalMajor:    uint32(pfslocalMajor),
		PFSLocalMinor:    uint32(pfslocalMinor),
	}, nil
}

func (e *cmdEnv) strictAccountInventory(
	action string,
	expectedIdentity *daemonctl.Identity,
) (lifecycleInventory, error) {
	var inventory lifecycleInventory
	kernelMounts, err := e.kernelMountInventory()
	if err != nil {
		return inventory, fmt.Errorf("strict kernel mount inventory: %w", err)
	}
	inventory.KernelMounts = len(kernelMounts)
	if len(kernelMounts) != 0 {
		return inventory, fmt.Errorf("%d PortableFS kernel mount(s) remain (for example %s); cleanly unmount them before %s", len(kernelMounts), kernelMounts[0], action)
	}
	mountStateDir, err := e.mountStateDir()
	if err != nil {
		return inventory, err
	}
	states, err := listMountStates(mountStateDir)
	if err != nil {
		return inventory, fmt.Errorf("strict mount inventory: %w", err)
	}
	inventory.MountRecords = len(states)
	intents, err := listMountIntents(mountStateDir)
	if err != nil {
		return inventory, fmt.Errorf("strict mount operation inventory: %w", err)
	}
	inventory.MountIntents = len(intents)
	if len(states) != 0 {
		return inventory, fmt.Errorf("%d mount record(s) remain; cleanly reconcile them before %s", len(states), action)
	}
	if len(intents) != 0 {
		intent := intents[0]
		return inventory, fmt.Errorf(
			"%d incomplete mount operation(s) remain (for example %s, phase %s); run `portablefs umount %s` before %s",
			len(intents), intent.MountPath, intent.Phase, intent.MountPath, action,
		)
	}
	persisted, err := portablefsd.ReadPersistedAttachInventory(filepath.Join(filepath.Dir(mountStateDir), "portablefsd"))
	if err != nil {
		return inventory, fmt.Errorf("strict durable daemon attach inventory: %w", err)
	}
	inventory.DurableAttaches = len(persisted)
	if len(persisted) != 0 {
		return inventory, fmt.Errorf(
			"%d durable daemon attach(es) remain (for example %s at %s); run `portablefs umount %s` before %s",
			len(persisted), persisted[0].AttachRef, persisted[0].MountPath, persisted[0].MountPath, action,
		)
	}
	cfg, err := fskitConfigFromEnv(e.getenv)
	if err != nil {
		return inventory, err
	}
	if _, err := os.Lstat(cfg.controlSock); err == nil {
		statuses, listErr := e.daemonAttachStatuses(expectedIdentity)
		if listErr != nil {
			return inventory, fmt.Errorf("strict daemon attach inventory: %w", listErr)
		}
		inventory.LiveAttaches = len(statuses)
	} else if !os.IsNotExist(err) {
		return inventory, fmt.Errorf("inspect daemon control socket: %w", err)
	}
	if inventory.LiveAttaches != 0 {
		return inventory, fmt.Errorf("%d daemon attach(es) remain; cleanly unmount them before %s", inventory.LiveAttaches, action)
	}
	return inventory, nil
}

// rejectDurableMountAnchors is the common installer transaction gate. A
// replacement may proceed only when every durable source used by explicit
// reconciliation is empty. Stale records are refused just like live records:
// only `portablefs umount` owns the proof and deletion protocol.
func rejectDurableMountAnchors(stateDir string) error {
	mountStateDir := filepath.Join(stateDir, "mounts")
	states, err := listMountStates(mountStateDir)
	if err != nil {
		return fmt.Errorf("strict installer mount-state inventory: %w", err)
	}
	if len(states) != 0 {
		state := states[0]
		return fmt.Errorf(
			"%d mount record(s) remain (for example %s@%s at %s); run `portablefs umount %s` to reconcile them before installing",
			len(states), state.VolumeID, state.Branch, state.MountPath, state.MountPath,
		)
	}
	intents, err := listMountIntents(mountStateDir)
	if err != nil {
		return fmt.Errorf("strict installer mount-intent inventory: %w", err)
	}
	if len(intents) != 0 {
		intent := intents[0]
		return fmt.Errorf(
			"%d incomplete mount operation(s) remain (for example %s, phase %s); run `portablefs umount %s` to reconcile them before installing",
			len(intents), intent.MountPath, intent.Phase, intent.MountPath,
		)
	}
	attaches, err := portablefsd.ReadPersistedAttachInventory(filepath.Join(stateDir, "portablefsd"))
	if err != nil {
		return fmt.Errorf("strict installer durable attach inventory: %w", err)
	}
	if len(attaches) != 0 {
		attach := attaches[0]
		return fmt.Errorf(
			"%d durable daemon attach(es) remain (for example %s at %s); run `portablefs umount %s` to reconcile them before installing",
			len(attaches), attach.AttachRef, attach.MountPath, attach.MountPath,
		)
	}
	return nil
}

func holdUntilInputOrSignal(e *cmdEnv) int {
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, e.stdinReader())
		close(stdinDone)
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-stdinDone:
	case <-signals:
	}
	return 0
}
