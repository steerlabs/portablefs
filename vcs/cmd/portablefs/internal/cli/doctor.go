package cli

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
)

// fskitExtensionBundleIDs are the FSKit file-system extensions that can
// serve the "pfs" mount type, in preference order: PortableFS.app's release
// extension, then the dev harness (swift/PortableFSApp,
// swift/PortableFSKitDev; both claim FSShortName "pfs").
var fskitExtensionBundleIDs = []string{
	"dev.portablefs.PortableFSApp.PortableFSExt",
	"dev.portablefs.oss.KitDev.PortableFSDev",
}

// fskitSettingsHint is the one reliable place to enable a file-system
// extension; mirrors docs/fskit-mount.md and the mount error hint (the
// per-app list's toggle is unreliable on macOS 26, so the category view is
// the path we always give).
const fskitSettingsHint = "System Settings → General → Login Items & Extensions, open the FILE SYSTEM EXTENSIONS category (the per-app list's toggle is unreliable on macOS 26)"

// doctorResult is one check's outcome. Remedy is the one-line fix printed on
// FAIL; Lines carry per-item context (profiles, mounts).
type doctorResult struct {
	Name   string   `json:"name"`
	Status string   `json:"status"` // PASS | FAIL | UNKNOWN | SKIP
	Detail string   `json:"detail"`
	Remedy string   `json:"remedy,omitempty"`
	Lines  []string `json:"lines,omitempty"`
}

func doctorPass(detail string) doctorResult { return doctorResult{Status: "PASS", Detail: detail} }
func doctorSkip(detail string) doctorResult { return doctorResult{Status: "SKIP", Detail: detail} }
func doctorUnknown(detail string) doctorResult {
	return doctorResult{Status: "UNKNOWN", Detail: detail}
}
func doctorFail(detail, remedy string) doctorResult {
	return doctorResult{Status: "FAIL", Detail: detail, Remedy: remedy}
}

// doctorRun carries one doctor invocation plus its fakeable process and
// network boundaries: tests substitute the HTTP transport, the process
// runner, the OS, and the daemon probe (the same seam style as
// strategyProbe).
type doctorRun struct {
	e    *cmdEnv
	opts commonOpts

	httpDo         func(*http.Request) (*http.Response, error)
	runCmd         func(name string, args ...string) (string, error)
	goos           string
	daemonHealthy  func(controlSock string) bool
	daemonAttaches func(controlSock string) ([]cliAttachStatus, error)
	hostCheck      func(mounthost.Transport) mounthost.Facts
	verifiedMount  func(mounthost.Transport) (string, bool, error)
}

func newDoctorRun(e *cmdEnv, opts commonOpts) *doctorRun {
	// Every doctor probe is a one-shot diagnostic: a flat 10s transport
	// timeout keeps the whole command bounded even against a wedged server.
	client := &http.Client{Timeout: 10 * time.Second}
	return &doctorRun{
		e:      e,
		opts:   opts,
		httpDo: client.Do,
		runCmd: func(name string, args ...string) (string, error) {
			out, err := exec.Command(name, args...).CombinedOutput()
			return string(out), err
		},
		goos:          runtime.GOOS,
		hostCheck:     mounthost.Check,
		verifiedMount: e.verifiedMount,
		daemonHealthy: func(controlSock string) bool {
			cfg, err := fskitConfigFromEnv(e.getenv)
			if err != nil {
				return false
			}
			cfg.controlSock = controlSock
			_, err = connectCompatiblePortablefsd(cfg, e.version)
			return err == nil
		},
		daemonAttaches: func(controlSock string) ([]cliAttachStatus, error) {
			cfg, err := fskitConfigFromEnv(e.getenv)
			if err != nil {
				return nil, err
			}
			cfg.controlSock = controlSock
			ctl, err := connectCompatiblePortablefsd(cfg, e.version)
			if err != nil {
				return nil, err
			}
			ctl.httpClient.Timeout = 5 * time.Second
			return ctl.listAttaches()
		},
	}
}

// doctorChecks is the check table, in order. Every check is local: the CLI
// speaks to this machine's mount records, its mount transport, and its
// portablefsd, and to nothing over the network.
func doctorChecks() []struct {
	name string
	run  func(*doctorRun) doctorResult
} {
	return []struct {
		name string
		run  func(*doctorRun) doctorResult
	}{
		{"mount transport", (*doctorRun).checkMountTransport},
		{"fskit inventory", (*doctorRun).checkFskitExtension},
		{"portablefsd", (*doctorRun).checkDaemon},
		{"attaches", (*doctorRun).checkAttaches},
		{"mounts", (*doctorRun).checkMounts},
	}
}

func cmdDoctor(e *cmdEnv, args []string) int {
	fs := newFlagSet("doctor")
	var o commonOpts
	addCommonFlags(fs, &o)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("doctor", err)
	}
	if len(positionals) != 0 {
		return e.usageError("doctor", fmt.Errorf("expected no arguments"))
	}
	return newDoctorRun(e, o).execute()
}

func (r *doctorRun) execute() int {
	checks := doctorChecks()
	results := make([]doctorResult, 0, len(checks))
	failed := 0
	unknown := 0
	for _, c := range checks {
		res := c.run(r)
		res.Name = c.name
		results = append(results, res)
		if res.Status == "FAIL" {
			failed++
		} else if res.Status == "UNKNOWN" {
			unknown++
		}
	}
	if r.opts.jsonOut {
		if rc := r.e.printJSON(map[string]any{"checks": results, "failed": failed, "unknown": unknown}); rc != 0 {
			return rc
		}
		if failed > 0 {
			return 1
		}
		return 0
	}
	for _, res := range results {
		fmt.Fprintf(r.e.stdout, "%-4s  %s: %s\n", res.Status, res.Name, res.Detail)
		for _, line := range res.Lines {
			fmt.Fprintf(r.e.stdout, "      %s\n", line)
		}
		if res.Status == "FAIL" && res.Remedy != "" {
			fmt.Fprintf(r.e.stdout, "      fix: %s\n", res.Remedy)
		}
	}
	if failed > 0 {
		fmt.Fprintf(r.e.stdout, "\n%d problem(s) found\n", failed)
		return 1
	}
	if unknown > 0 {
		fmt.Fprintf(r.e.stdout, "\nno definite problems found; %d check(s) remain unverified\n", unknown)
		return 0
	}
	fmt.Fprintf(r.e.stdout, "\nno problems found\n")
	return 0
}

// checkConfig verifies the config file parses and lists every profile with
// its server, flagging the one this run resolves against.
func (r *doctorRun) checkMountTransport() doctorResult {
	facts, err := observeMountHost(r.goos, "auto", r.hostCheck, r.verifiedMount)
	if err != nil {
		return doctorFail(err.Error(), "use macOS with FSKit or Linux with FUSE")
	}
	switch facts.State {
	case mounthost.Verified:
		return doctorPass(facts.Summary)
	case mounthost.Blocked:
		return doctorFail(facts.Summary, mountHostGuidance(facts.Issue))
	default:
		result := doctorUnknown(facts.Summary)
		for _, evidence := range facts.Details {
			result.Lines = append(result.Lines, evidence.Key+": "+evidence.Value)
		}
		return result
	}
}

// pluginkitState parses one `pluginkit -m -i <id>` inventory line. The
// election annotation occupies column one. PlugInKit election is deliberately
// not interpreted as FSKit enablement: enabled, disabled, and default
// elections have all contradicted actual mountability.
func pluginkitState(out string) (state byte, registered bool) {
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		switch c := line[0]; c {
		case '+', '-', '!', '?':
			return c, true
		default:
			return ' ', true
		}
	}
	return 0, false
}

func (r *doctorRun) checkFskitExtension() doctorResult {
	if r.goos != "darwin" {
		return doctorSkip("FSKit is macOS-only (Linux mounts use FUSE)")
	}
	path, live, err := r.verifiedMount(mounthost.FSKit)
	if err != nil {
		return doctorFail("cannot inventory recorded FSKit mounts: "+err.Error(), "repair or explicitly reconcile the private mount-state inventory")
	}
	if live {
		return doctorSkip(fmt.Sprintf("live FSKit mount at %s is authoritative; PlugInKit inventory was not used", path))
	}
	result := doctorUnknown("PlugInKit election is inventory only and does not establish FSKit mountability")
	for _, id := range fskitExtensionBundleIDs {
		// pluginkit exits non-zero when nothing matches; the empty output
		// already says that, so the error itself is not load-bearing.
		out, _ := r.runCmd("pluginkit", "-m", "-i", id)
		state, registered := pluginkitState(out)
		if !registered {
			continue
		}
		election := map[byte]string{
			'+': "plus",
			'-': "minus",
			'!': "superseded",
			'?': "unknown",
			' ': "default",
		}[state]
		if election == "" {
			election = fmt.Sprintf("byte-%d", state)
		}
		result.Lines = append(result.Lines, fmt.Sprintf("%s  election=%s", id, election))
	}
	if len(result.Lines) == 0 {
		result.Detail = "no matching PlugInKit registration was listed; PlugInKit inventory does not establish FSKit mountability"
	}
	return result
}

func (r *doctorRun) checkDaemon() doctorResult {
	if r.goos != "darwin" {
		return doctorSkip("portablefsd serves FSKit mounts (macOS-only)")
	}
	cfg, err := fskitConfigFromEnv(r.e.getenv)
	if err != nil {
		return doctorFail(err.Error(), "repair canonical account home resolution before using FSKit")
	}
	if r.daemonHealthy(cfg.controlSock) {
		return doctorPass(fmt.Sprintf("answering on %s", cfg.controlSock))
	}
	path, live, err := r.verifiedMount(mounthost.FSKit)
	if err != nil {
		return doctorFail("cannot inventory recorded FSKit mounts: "+err.Error(), "repair or explicitly reconcile the private mount-state inventory")
	}
	if live {
		return doctorFail(
			fmt.Sprintf("not answering on %s while fskit mounts are recorded live (e.g. %s)", cfg.controlSock, path),
			fmt.Sprintf("run `portablefs umount %s` and mount again (a fresh daemon starts automatically)", path))
	}
	return doctorPass("not running (it starts on demand at mount time)")
}

// checkAttaches surfaces the daemon's live attaches and the reason behind any
// degraded one. A v3 attach holds no client-side durability debt, so the only
// thing to report is the attach's own state and the verdict that produced it.
func (r *doctorRun) checkAttaches() doctorResult {
	if r.goos != "darwin" {
		return doctorSkip("attach status is read from portablefsd (macOS-only)")
	}
	cfg, err := fskitConfigFromEnv(r.e.getenv)
	if err != nil {
		return doctorFail(err.Error(), "repair canonical account home resolution before using FSKit")
	}
	if !r.daemonHealthy(cfg.controlSock) {
		return doctorSkip("portablefsd is not running (no attaches to inspect)")
	}
	attaches, err := r.daemonAttaches(cfg.controlSock)
	if err != nil {
		return doctorFail(fmt.Sprintf("cannot read attach status: %v", err), "restart portablefsd (unmount and mount again)")
	}
	if len(attaches) == 0 {
		return doctorPass("no attaches")
	}
	var lines []string
	problems := 0
	for _, a := range attaches {
		line := fmt.Sprintf("%s  %s@%s  %s", a.MountPath, a.VolumeID, a.Branch, a.State)
		if a.State == "degraded" && a.LastError != "" {
			line += "  (" + a.LastError + ")"
		}
		if a.State == "degraded" {
			problems++
		}
		lines = append(lines, line)
	}
	if problems > 0 {
		res := doctorFail(
			fmt.Sprintf("%d degraded attach(es)", problems),
			"read each attach's lastError — it names the exact condition and the "+
				"action that changes it; a terminal authority session is resolved "+
				"only by `portablefs umount` and mounting again")
		res.Lines = lines
		return res
	}
	res := doctorPass(fmt.Sprintf("%d attach(es), none degraded", len(attaches)))
	res.Lines = lines
	return res
}

func (r *doctorRun) checkMounts() doctorResult {
	stateDir, err := r.e.mountStateDir()
	if err != nil {
		return doctorFail(err.Error(), "ensure the current OS account has a real, uid-owned home directory")
	}
	states, err := listMountStates(stateDir)
	if err != nil {
		return doctorFail(fmt.Sprintf("cannot read mount state under %s: %v", stateDir, err), "check the directory's permissions")
	}
	if len(states) == 0 {
		return doctorPass("no mounts recorded on this machine")
	}
	var lines []string
	var stale, expired []string
	for _, st := range states {
		health := r.e.classifyMount(&st)
		lines = append(lines, fmt.Sprintf("%s  %s@%s  %s  %s", st.MountPath, st.VolumeID, st.Branch, st.Strategy, health))
		switch health {
		case "stale":
			stale = append(stale, st.MountPath)
		case mountStatusCredentialExpired:
			expired = append(expired, st.MountPath)
		}
	}
	if len(stale) == 0 && len(expired) == 0 {
		res := doctorPass(fmt.Sprintf("%d mount(s), all live", len(states)))
		res.Lines = lines
		return res
	}
	var problems, remedies []string
	if len(stale) > 0 {
		problems = append(problems, fmt.Sprintf("%d stale", len(stale)))
		remedies = append(remedies, fmt.Sprintf("clean up stale mounts with `portablefs umount %s`", stale[0]))
	}
	if len(expired) > 0 {
		problems = append(problems, fmt.Sprintf("%d credential-expired", len(expired)))
		remedies = append(remedies, "mount credential-expired paths again with a fresh "+
			"volume mount capability (the direct CLI does not acquire hosted reauthorization)")
	}
	res := doctorFail(
		fmt.Sprintf("%d mount(s): %s", len(states), strings.Join(problems, ", ")),
		strings.Join(remedies, "; "))
	res.Lines = lines
	return res
}
