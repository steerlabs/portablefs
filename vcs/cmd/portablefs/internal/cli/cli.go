// Package cli implements the portablefs command-line interface. It is
// cmd-local: the reusable mount/protocol machinery lives in the shared
// internal packages (clientcore, fsproto, portablefsd, secure); this package only
// adds config, HTTP control-plane clients, and command wiring.
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
	configPath string              // empty = default (~/.config/portablefs/config.json)
	sleepFn    func(time.Duration) // nil = time.Sleep (tests poll instantly)
	openURLFn  func(string) error  // nil = platform browser open (tests record instead)
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

func (e *cmdEnv) resolveConfigPath() (string, error) {
	if e.configPath != "" {
		return e.configPath, nil
	}
	return defaultConfigPath()
}

func (e *cmdEnv) loadConfig() (*Config, string, error) {
	path, err := e.resolveConfigPath()
	if err != nil {
		return nil, "", err
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, "", err
	}
	return cfg, path, nil
}

// commonOpts are the flags every command accepts: connection overrides
// (flags > env > config file), profile selection, and machine-readable output.
type commonOpts struct {
	apiURL       string
	apiToken     string
	managerURL   string
	managerToken string
	profile      string
	jsonOut      bool
}

func addCommonFlags(fs *flag.FlagSet, o *commonOpts) {
	fs.StringVar(&o.apiURL, "api-url", "", "volume API base URL (overrides env/config)")
	fs.StringVar(&o.apiToken, "api-token", "", "volume API bearer token (overrides env/config)")
	fs.StringVar(&o.managerURL, "manager-url", "", "authority manager base URL (overrides env/config)")
	fs.StringVar(&o.managerToken, "manager-token", "", "authority manager bearer token (overrides env/config)")
	fs.StringVar(&o.profile, "profile", "", "config profile to use (default: currentProfile)")
	fs.BoolVar(&o.jsonOut, "json", false, "print machine-readable JSON")
}

func (e *cmdEnv) resolveSettings(o *commonOpts) (settings, error) {
	cfg, _, err := e.loadConfig()
	if err != nil {
		return settings{}, err
	}
	return resolveSettings(cfg, o.profile, e.getenv, settings{
		apiURL:       o.apiURL,
		apiToken:     o.apiToken,
		managerURL:   o.managerURL,
		managerToken: o.managerToken,
	}), nil
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
		{"login", "authenticate to a PortableFS server and save credentials", cmdLogin},
		{"logout", "remove saved credentials for a profile", cmdLogout},
		{"create", "create a volume (with branch main)", cmdCreate},
		{"adopt", "import an existing local directory into a new volume", cmdAdopt},
		{"activate", "resume an interrupted adopt (adopt runs this automatically)", cmdActivate},
		{"ls", "list volumes", cmdLs},
		{"rm", "retire (delete) a volume; live mounts detach as their leases expire", cmdRm},
		{"status", "show a branch head summary and activity counts", cmdStatus},
		{"history", "show recent commits on a branch", cmdHistory},
		{"snapshot", "create a named snapshot of a branch head", cmdSnapshot},
		{"snapshots", "list snapshots", cmdSnapshots},
		{"branch", "create a branch within a volume", cmdBranch},
		{"branches", "list branches of a volume", cmdBranches},
		{"fork", "fork a volume into a new volume (give every agent its own fork)", cmdFork},
		{"grep", "search a branch's file bytes server-side", cmdGrep},
		{"mount", "mount a live volume on this machine", cmdMount},
		{"umount", "unmount a mounted volume and stop its daemon", cmdUmount},
		{"mounts", "list active mounts on this machine", cmdMounts},
		{"doctor", "check this machine's PortableFS setup and report problems", cmdDoctor},
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
