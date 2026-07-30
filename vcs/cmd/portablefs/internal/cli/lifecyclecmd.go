package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/accountsession"
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
		return e.usageError("lifecycle", fmt.Errorf("expected `hold-shared`, `hold-account-exclusive`, or `identity`"))
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
			return e.printJSON(struct {
				SchemaVersion int    `json:"schemaVersion"`
				AppGroup      string `json:"appGroup"`
			}{SchemaVersion: 1, AppGroup: fskitidentity.AppGroup})
		}
		fmt.Fprintln(e.stdout, fskitidentity.AppGroup)
		return 0
	}
	if args[0] == "hold-account-exclusive" {
		return cmdHoldAccountExclusive(e, args[1:])
	}
	if args[0] != "hold-shared" {
		return e.usageError("lifecycle", fmt.Errorf("expected `hold-shared`, `hold-account-exclusive`, or `identity`"))
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

	mounts, attaches, err := e.strictAccountInventory()
	if err != nil {
		return e.fail("lifecycle", err)
	}
	if jsonOut {
		fmt.Fprintf(e.stdout, "{\"schemaVersion\":1,\"held\":true,\"mounts\":%d,\"attaches\":%d}\n", mounts, attaches)
	} else {
		fmt.Fprintln(e.stdout, "account session exclusive guard held with empty inventory; close stdin to release")
	}
	return holdUntilInputOrSignal(e)
}

func (e *cmdEnv) strictAccountInventory() (int, int, error) {
	kernelMounts, err := e.kernelMountInventory()
	if err != nil {
		return 0, 0, fmt.Errorf("strict kernel mount inventory: %w", err)
	}
	if len(kernelMounts) != 0 {
		return len(kernelMounts), 0, fmt.Errorf("%d PortableFS kernel mount(s) remain (for example %s); cleanly unmount them before changing account credentials", len(kernelMounts), kernelMounts[0])
	}
	mountStateDir, err := e.mountStateDir()
	if err != nil {
		return 0, 0, err
	}
	states, err := listMountStates(mountStateDir)
	if err != nil {
		return 0, 0, fmt.Errorf("strict mount inventory: %w", err)
	}
	intents, err := listMountIntents(mountStateDir)
	if err != nil {
		return 0, 0, fmt.Errorf("strict mount operation inventory: %w", err)
	}
	if len(states) != 0 {
		return len(states), 0, fmt.Errorf("%d mount record(s) remain; cleanly reconcile them before changing account credentials", len(states))
	}
	if len(intents) != 0 {
		intent := intents[0]
		return 0, 0, fmt.Errorf(
			"%d incomplete mount operation(s) remain (for example %s, phase %s); run `portablefs umount %s` before changing account credentials",
			len(intents), intent.MountPath, intent.Phase, intent.MountPath,
		)
	}
	persisted, err := portablefsd.ReadPersistedAttachInventory(filepath.Join(filepath.Dir(mountStateDir), "portablefsd"))
	if err != nil {
		return 0, 0, fmt.Errorf("strict durable daemon attach inventory: %w", err)
	}
	if len(persisted) != 0 {
		return 0, len(persisted), fmt.Errorf(
			"%d durable daemon attach(es) remain (for example %s at %s); run `portablefs umount %s` before changing account credentials",
			len(persisted), persisted[0].AttachRef, persisted[0].MountPath, persisted[0].MountPath,
		)
	}
	attaches := 0
	cfg, err := fskitConfigFromEnv(e.getenv)
	if err != nil {
		return 0, 0, err
	}
	if _, err := os.Lstat(cfg.controlSock); err == nil {
		statuses, listErr := fskitAttachStatuses(e.getenv, e.version)
		if listErr != nil {
			return 0, 0, fmt.Errorf("strict daemon attach inventory: %w", listErr)
		}
		attaches = len(statuses)
	} else if !os.IsNotExist(err) {
		return 0, 0, fmt.Errorf("inspect daemon control socket: %w", err)
	}
	if attaches != 0 {
		return 0, attaches, fmt.Errorf("%d daemon attach(es) remain; cleanly unmount them before changing account credentials", attaches)
	}
	return 0, 0, nil
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
