// Package cli implements the portablefs command-line interface. It is
// cmd-local: the reusable mount/protocol machinery lives in the shared
// internal packages (fusev3, mountv3, authorityrpc, portablefsd); this package
// only adds this machine's mount records, transport selection, and command
// wiring.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// cmdEnv carries the process environment a command runs in; tests substitute
// writers, env lookups, the config path, and the poll sleeper.
type cmdEnv struct {
	stdout     io.Writer
	stderr     io.Writer
	stdin      io.Reader   // nil = os.Stdin (tests script confirmations)
	stdinIsTTY func() bool // nil = real character-device check on os.Stdin
	getenv     func(string) string
	version    string
	sleepFn    func(time.Duration) // nil = time.Sleep (tests poll instantly)
	// Test-only override. Production lifecycle locking deliberately ignores
	// XDG_STATE_HOME so environment variants cannot split the lock inode.
	lifecycleStateDir string
	// Test-only canonical operational state override.
	stateDir string
	// Test-only presentation seam. Production always performs the exact
	// process + kernel mount identity checks in mountHealth.
	mountHealthFn func(*mountState) string
	// Test-only daemon lifecycle seam. Production always adopts or starts the
	// exact portablefsd sibling through ensurePortablefsd.
	ensurePortablefsdFn func(fskitConfig, string, string) (*fsdControl, error)
	// Test-only account-inventory seam. Production always reads the live
	// kernel mount table before changing credentials or profiles.
	kernelInventoryFn func() ([]string, error)
}

func (e *cmdEnv) classifyMount(st *mountState) string {
	if e.mountHealthFn != nil {
		return e.mountHealthFn(st)
	}
	return mountHealth(st)
}

func (e *cmdEnv) kernelMountInventory() ([]string, error) {
	if e.kernelInventoryFn != nil {
		return e.kernelInventoryFn()
	}
	return portableFSKernelInventory()
}

func (e *cmdEnv) ensureFskitDaemon(cfg fskitConfig, stateRoot string) (*fsdControl, error) {
	if e.ensurePortablefsdFn != nil {
		return e.ensurePortablefsdFn(cfg, stateRoot, e.version)
	}
	return ensurePortablefsd(cfg, stateRoot, e.version)
}

func (e *cmdEnv) stdinReader() io.Reader {
	if e.stdin != nil {
		return e.stdin
	}
	return os.Stdin
}

// stdinIsTerminal reports whether stdin is an interactive terminal — the gate
// for confirmation prompts (a pipe or /dev/null must never hang on a prompt).
func (e *cmdEnv) stdinIsTerminal() bool {
	if e.stdinIsTTY != nil {
		return e.stdinIsTTY()
	}
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// commonOpts are the flags every command accepts.
type commonOpts struct {
	jsonOut bool
}

func addCommonFlags(fs *flag.FlagSet, o *commonOpts) {
	fs.BoolVar(&o.jsonOut, "json", false, "print machine-readable JSON")
}

func (e *cmdEnv) printJSON(v any) int {
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(e.stderr, "portablefs: encode output: %v\n", err)
		return 1
	}
	return 0
}

func (e *cmdEnv) fail(cmd string, err error) int {
	fmt.Fprintf(e.stderr, "portablefs %s: %v\n", cmd, err)
	return 1
}

func (e *cmdEnv) usageError(cmd string, err error) int {
	fmt.Fprintf(e.stderr, "portablefs %s: %v\n", cmd, err)
	fmt.Fprintf(e.stderr, "run `portablefs help %s` for usage\n", cmd)
	return 2
}

type command struct {
	name    string
	summary string
	run     func(e *cmdEnv, args []string) int
}

func commands() []command {
	return []command{
		{"mount", "mount a live volume on this machine", cmdMount},
		{"umount", "cleanly unmount a mounted volume", cmdUmount},
		{"mounts", "list active mounts on this machine", cmdMounts},
		{"route", "explain whether a path is served machine-locally or by the volume", cmdRoute},
		{"prune-local", "reclaim machine-local backing that no route can reach", cmdPruneLocal},
		{"daemon", "stop the per-user daemon only when it is atomically proven idle", cmdDaemon},
		{"lifecycle", "hold the internal mount/update lifecycle guard", cmdLifecycle},
		{"install-macos-app", "install the signed macOS app bundle", cmdInstallMacOSApp},
		{"mount-check", "inspect this host's mount transport without changing it", cmdMountCheck},
		{"internal-root-probe", "internal bounded mount-root usability probe", cmdInternalRootProbe},
		{"doctor", "check this machine's PortableFS setup and report problems", cmdDoctor},
		{"install-linux-release", "atomically activate a verified Linux release", cmdInstallLinuxRelease},
		{"version", "print the CLI version", cmdVersion},
	}
}

func findCommand(name string) (command, bool) {
	for _, c := range commands() {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// Main dispatches a portablefs invocation and returns the process exit code.
func Main(args []string, version string) int {
	e := &cmdEnv{stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv, version: version}
	return e.run(args)
}

func (e *cmdEnv) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(e.stdout, rootHelp())
		return 0
	}
	name := args[0]
	switch name {
	case "help", "-h", "--help":
		if len(args) > 1 {
			return e.printCommandHelp(args[1])
		}
		fmt.Fprint(e.stdout, rootHelp())
		return 0
	case "-version", "--version":
		name, args = "version", args[:1]
	case "unmount":
		// `umount` is the POSIX spelling; accept `unmount` (what many macOS
		// users type, cf. `diskutil unmount`) as an alias.
		name = "umount"
	}
	cmd, ok := findCommand(name)
	if !ok {
		fmt.Fprintf(e.stderr, "portablefs: unknown command %q\nrun `portablefs help` for the command list\n", name)
		return 2
	}
	return cmd.run(e, args[1:])
}

func (e *cmdEnv) printCommandHelp(name string) int {
	text, ok := commandHelp(name)
	if !ok {
		fmt.Fprintf(e.stderr, "portablefs: unknown command %q\nrun `portablefs help` for the command list\n", name)
		return 2
	}
	fmt.Fprint(e.stdout, text)
	return 0
}

// handleParseError maps a flag-parse failure to an exit code: -h/--help shows
// the command's help (exit 0), anything else is a usage error (exit 2).
func (e *cmdEnv) handleParseError(cmd string, err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return e.printCommandHelp(cmd)
	}
	return e.usageError(cmd, err)
}

func cmdVersion(e *cmdEnv, args []string) int {
	fs := newFlagSet("version")
	var o commonOpts
	addCommonFlags(fs, &o)
	if _, err := parseArgs(fs, args); err != nil {
		return e.handleParseError("version", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]string{"version": e.version})
	}
	fmt.Fprintf(e.stdout, "portablefs %s\n", e.version)
	return 0
}
