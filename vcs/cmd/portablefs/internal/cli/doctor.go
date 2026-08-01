package cli

import (
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
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

	// resolved once before the checks run
	settings    settings
	settingsErr error

	// captured by the server/token probes for the version check
	serverReached bool
	minCLIVersion string
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

// doctorChecks is the check table, in order. Order is load-bearing: the
// server and token probes capture the min-CLI-version header the version
// check evaluates.
func doctorChecks() []struct {
	name string
	run  func(*doctorRun) doctorResult
} {
	return []struct {
		name string
		run  func(*doctorRun) doctorResult
	}{
		{"config", (*doctorRun).checkConfig},
		{"server", (*doctorRun).checkServer},
		{"token", (*doctorRun).checkToken},
		{"version", (*doctorRun).checkVersion},
		{"mount transport", (*doctorRun).checkMountTransport},
		{"fskit inventory", (*doctorRun).checkFskitExtension},
		{"portablefsd", (*doctorRun).checkDaemon},
		{"write-back", (*doctorRun).checkWriteBack},
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
	r.settings, r.settingsErr = r.e.resolveSettings(&r.opts)
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
func (r *doctorRun) checkConfig() doctorResult {
	path, err := r.e.resolveConfigPath()
	if err != nil {
		return doctorFail(err.Error(), "ensure the current OS account has a real, uid-owned home directory")
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return doctorFail(err.Error(), "fix or remove the file, then run `portablefs login` to recreate it")
	}
	if len(cfg.Profiles) == 0 {
		return doctorPass(fmt.Sprintf("%s parses (no profiles saved yet)", path))
	}
	active := r.opts.profile
	if active == "" {
		active = cfg.CurrentProfile
	}
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	res := doctorPass(fmt.Sprintf("%s parses (%d profile(s))", path, len(cfg.Profiles)))
	for _, name := range names {
		line := fmt.Sprintf("%s -> %s", name, cfg.Profiles[name].APIUrl)
		if name == active {
			line += "  (active)"
		}
		res.Lines = append(res.Lines, line)
	}
	return res
}

// probe issues one read-only GET against the API and reports the status plus
// the min-CLI-version header. Any HTTP response counts as the server
// answering — an unauthenticated 401/404 still proves it is there.
func (r *doctorRun) probe(token string) (int, error) {
	req, err := http.NewRequest("GET", r.settings.apiURL+"/v1/volumes", nil)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := r.httpDo(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if v := strings.TrimSpace(resp.Header.Get(minCLIVersionHeader)); v != "" {
		r.minCLIVersion = v
	}
	return resp.StatusCode, nil
}

func (r *doctorRun) checkServer() doctorResult {
	if r.settingsErr != nil {
		return doctorSkip("connection settings unresolved (see config)")
	}
	if r.settings.apiURL == "" {
		return doctorFail("no server configured", "run `portablefs login` (or set PORTABLEFS_API_URL)")
	}
	status, err := r.probe("")
	if err != nil {
		return doctorFail(fmt.Sprintf("%s is not reachable: %v", r.settings.apiURL, err),
			"check the URL in the config file and your network; self-hosted stacks: confirm the server is running")
	}
	r.serverReached = true
	return doctorPass(fmt.Sprintf("%s answered (HTTP %d)", r.settings.apiURL, status))
}

func (r *doctorRun) checkToken() doctorResult {
	if r.settingsErr != nil || r.settings.apiURL == "" {
		return doctorSkip("no server to verify a token against")
	}
	if r.settings.apiToken == "" {
		return doctorSkip("no saved token for this profile; run `portablefs login` to mint one")
	}
	status, err := r.probe(r.settings.apiToken)
	if err != nil {
		return doctorFail(fmt.Sprintf("could not verify the token: %v", err),
			"check the URL in the config file and your network; self-hosted stacks: confirm the server is running")
	}
	r.serverReached = true
	// Mirrors verifyCredential: the server authenticates before routing, so
	// any response other than 401/403 proves the token was accepted.
	if status == 401 || status == 403 {
		return doctorFail(fmt.Sprintf("the server rejected the saved token (HTTP %d)", status), "run `portablefs login`")
	}
	return doctorPass(fmt.Sprintf("saved token accepted (HTTP %d)", status))
}

func (r *doctorRun) checkVersion() doctorResult {
	if !r.serverReached {
		return doctorSkip("server unreachable; cannot read its minimum CLI version")
	}
	if r.minCLIVersion == "" {
		return doctorSkip("server does not advertise a minimum CLI version")
	}
	minRequired, ok := parseSemver(r.minCLIVersion)
	if !ok {
		return doctorFail(
			fmt.Sprintf("server sent invalid minimum CLI version %q", r.minCLIVersion),
			"fix the server's "+minCLIVersionHeader+" response header before using this client")
	}
	cli, ok := parseSemver(r.e.version)
	if !ok {
		return doctorFail(
			fmt.Sprintf("%q is not a stamped release version, so compatibility with server minimum %s cannot be verified", r.e.version, r.minCLIVersion),
			"install a stamped release with: "+upgradeCommand())
	}
	if cli.less(minRequired) {
		return doctorFail(
			fmt.Sprintf("this CLI is %s but the server requires at least %s", r.e.version, r.minCLIVersion),
			"upgrade with: "+upgradeCommand())
	}
	return doctorPass(fmt.Sprintf("CLI %s meets the server minimum %s", r.e.version, r.minCLIVersion))
}

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

// checkWriteBack surfaces the daemon's durability debt: degraded attaches and
// parked write-back WALs the background recovery job is still retrying. This
// is the operator-visible face of "no acknowledged write is ever silently
// abandoned".
func (r *doctorRun) checkWriteBack() doctorResult {
	if r.goos != "darwin" {
		return doctorSkip("write-back recovery status is read from portablefsd (macOS-only)")
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
		if wb := a.WriteBack; wb != nil {
			for _, p := range wb.ParkedWALs {
				problems++
				detail := fmt.Sprintf("parked WAL: %d record(s), %s old", p.Records, (time.Duration(p.AgeMs) * time.Millisecond).Round(time.Second))
				if p.Root != "" {
					detail += ", subtree " + p.Root
				}
				if p.LastError != "" {
					detail += ", last error: " + p.LastError
				}
				line += "\n        " + detail
			}
			if wb.PendingRecords > 0 && len(wb.ParkedWALs) == 0 {
				line += fmt.Sprintf("  (%d record(s) flushing)", wb.PendingRecords)
			}
			// Data-lane pacing is the credit controller working, not a fault:
			// it is reported so a backlog held back on purpose is never read
			// as a hung flusher, and it does not count as a problem.
			if wb.paced() {
				detail := fmt.Sprintf("data-lane pacing (not a failure): %d writer(s) waiting on credit, debt %d of setpoint %d bytes (ceiling %d), authority applying %.0f B/s",
					wb.CreditWaiters, wb.CreditDebt, wb.CreditSetpoint, wb.CreditCeiling, wb.AppliedRateBps)
				if wb.DataLaneFull {
					detail += "; bulk-data lane at its hard cap, metadata reserve still held"
				}
				if wb.LastProgressMs > 0 {
					detail += fmt.Sprintf("; last drain progress %s ago", (time.Duration(wb.LastProgressMs) * time.Millisecond).Round(time.Second))
				}
				line += "\n        " + detail
			}
		}
		lines = append(lines, line)
	}
	if problems > 0 {
		res := doctorFail(
			fmt.Sprintf("%d attach(es) with degraded state or parked write-back records", problems),
			"the daemon retries recovery automatically; if it persists, check authority reachability and credentials (`portablefs login`)")
		res.Lines = lines
		return res
	}
	res := doctorPass(fmt.Sprintf("%d attach(es), no parked write-back records", len(attaches)))
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
		remedies = append(remedies, "run `portablefs login` and remount credential-expired paths")
	}
	res := doctorFail(
		fmt.Sprintf("%d mount(s): %s", len(states), strings.Join(problems, ", ")),
		strings.Join(remedies, "; "))
	res.Lines = lines
	return res
}
