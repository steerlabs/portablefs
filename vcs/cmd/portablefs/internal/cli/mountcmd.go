package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
)

const mountTokenEnv = "PORTABLEFS_MOUNT_TOKEN"

// applyTLSEnvAliases maps the CLI-branded PORTABLEFS_TLS_CA onto VCS_TLS_CA,
// which the shared secure package reads for data-plane TLS.
func applyTLSEnvAliases() {
	if ca := os.Getenv("PORTABLEFS_TLS_CA"); ca != "" && os.Getenv("VCS_TLS_CA") == "" {
		_ = os.Setenv("VCS_TLS_CA", ca)
	}
}

// applyProfileDataPlaneCA makes the CA bundle captured at login (the
// deployment's router CA, stored in the profile) the process's data-plane
// trust anchor when no explicit VCS_TLS_CA/PORTABLEFS_TLS_CA override is set.
// Without it a hosted mount would dial the TLS router in plaintext and die
// with a misleading rejection. The PEM is materialized under the mount state
// dir because every TLS consumer reads a file path from VCS_TLS_CA.
func applyProfileDataPlaneCA(caPEM, stateDir string) error {
	if caPEM == "" || os.Getenv("VCS_TLS_CA") != "" {
		return nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create mount state dir for data-plane CA: %w", err)
	}
	path := filepath.Join(stateDir, "data-plane-ca.pem")
	if err := os.WriteFile(path, []byte(caPEM), 0o600); err != nil {
		return fmt.Errorf("write data-plane CA from profile: %w", err)
	}
	return os.Setenv("VCS_TLS_CA", path)
}

type mountOpts struct {
	common      commonOpts
	branch      string
	strategy    string
	addr        string
	mountToken  string
	foreground  bool
	readyFD     int
	localDirs   stringListFlag
	noLocalDirs bool
}

// errFastRetired is the typed refusal for the retired --fast flag: write
// mode is no longer a mount property — the authority delegates adaptively on
// every mount, and fsync is always durable at the authority.
var errFastRetired = fmt.Errorf("--fast is retired: every mount is adaptive (the authority delegates write-back per scope automatically); remove the flag")

func addMountFlags(fs *flag.FlagSet, o *mountOpts) {
	addCommonFlags(fs, &o.common)
	fs.StringVar(&o.branch, "branch", "main", "branch to mount")
	fs.StringVar(&o.strategy, "strategy", "auto", "mount strategy: auto (fskit on macOS, fuse on Linux), fskit, or fuse")
	fs.StringVar(&o.addr, "addr", "", "mount a VCS authority address directly, skipping the manager")
	fs.StringVar(&o.mountToken, "mount-token", "", "data-plane token for --addr (or "+mountTokenEnv+")")
	fs.BoolFunc("fast", "retired: every mount is adaptive; passing this flag is an error", func(string) error {
		return errFastRetired
	})
	fs.Var(&o.localDirs, "local-dir", "serve this workspace-relative directory from machine-local disk instead of the volume (repeatable; e.g. --local-dir node_modules)")
	fs.BoolVar(&o.noLocalDirs, "no-local-dirs", false, "disable machine-local dirs entirely for this mount (clears persisted --local-dir state and ignores the volume's .portablefs/local-dirs)")
	fs.BoolVar(&o.foreground, "foreground", false, "stay attached instead of daemonizing")
	fs.IntVar(&o.readyFD, "ready-fd", 0, "internal: fd to write the readiness report to")
}

// perfOptions carries the FUSE mount cache options plus the write-back
// engine's durable state location. There is no write-mode knob: the
// authority delegates adaptively per scope, and fsync always means durable
// at the authority. Un-fsynced writes have a bounded (~flush batching)
// window, the same contract as a local page cache.
type perfOptions struct {
	// negativeCache forces the negative dentry cache on; negativeCacheOff
	// forces it off. Neither (the default) keeps the v6 baseline: on.
	negativeCache    bool
	negativeCacheOff bool
	// writebackDir is the engine's durable state directory, keyed by
	// (volume, branch) so parked streams recover across mount paths.
	writebackDir string
	volumeID     string
	branch       string
}

func perfOptionsFromEnv(getenv func(string) string) perfOptions {
	return perfOptions{
		negativeCache:    getenv("PORTABLEFS_NEGATIVE_CACHE") == "1",
		negativeCacheOff: getenv("PORTABLEFS_NEGATIVE_CACHE") == "0",
	}
}

// storageDirID names the per-(volume, branch) write-back state directory:
// stable across mount paths so a parked stream recovers wherever the volume
// mounts next.
func storageDirID(volumeID, branch string) string {
	sum := sha256.Sum256([]byte(volumeID + "\x00" + branch))
	return hex.EncodeToString(sum[:8])
}

// mountReady is the readiness handshake between the daemonized child and the
// parent `portablefs mount` invocation (one JSON line over a pipe).
type mountReady struct {
	OK        bool     `json:"ok"`
	Error     string   `json:"error,omitempty"`
	PID       int      `json:"pid,omitempty"`
	Strategy  string   `json:"strategy,omitempty"`
	MountPath string   `json:"mountPath,omitempty"`
	VolumeID  string   `json:"volumeId,omitempty"`
	Branch    string   `json:"branch,omitempty"`
	AttachRef string   `json:"attachRef,omitempty"`
	LocalDirs []string `json:"localDirs,omitempty"`
}

// resolveLocalDirs applies the documented precedence for machine-local dirs:
// explicit --local-dir flags win and update the persisted per-mount record;
// no flags reuses the persisted record; --no-local-dirs clears it and
// disables grafts (including the volume's declaration file) for this mount.
// The volume's .portablefs/local-dirs file unions in later, at mount time.
func resolveLocalDirs(o *mountOpts, stateDir, volumeID, mountPath string) (flagDirs []string, volumeFileEnabled bool, err error) {
	if o.noLocalDirs && len(o.localDirs) > 0 {
		return nil, false, fmt.Errorf("--local-dir and --no-local-dirs are mutually exclusive")
	}
	if o.noLocalDirs {
		if err := writePersistedLocalDirs(stateDir, volumeID, o.branch, mountPath, nil); err != nil {
			return nil, false, fmt.Errorf("clear persisted local dirs: %w", err)
		}
		return nil, false, nil
	}
	if len(o.localDirs) > 0 {
		if err := localdirs.ValidateStrict(o.localDirs); err != nil {
			return nil, false, err
		}
		norm, err := localdirs.Normalize(o.localDirs)
		if err != nil {
			return nil, false, err
		}
		if err := writePersistedLocalDirs(stateDir, volumeID, o.branch, mountPath, norm); err != nil {
			return nil, false, fmt.Errorf("persist local dirs: %w", err)
		}
		return norm, true, nil
	}
	return readPersistedLocalDirs(stateDir, volumeID, o.branch, mountPath), true, nil
}

func cmdMount(e *cmdEnv, args []string) int {
	fs := newFlagSet("mount")
	var o mountOpts
	addMountFlags(fs, &o)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("mount", err)
	}
	if len(positionals) != 2 {
		return e.usageError("mount", fmt.Errorf("expected <volumeId> <mountPath>"))
	}
	volumeID := positionals[0]
	mountPath, err := filepath.Abs(positionals[1])
	if err != nil {
		return e.fail("mount", err)
	}
	// Validate graft flags in the parent so errors surface immediately
	// instead of via the daemonized child's readiness report.
	if o.noLocalDirs && len(o.localDirs) > 0 {
		return e.usageError("mount", fmt.Errorf("--local-dir and --no-local-dirs are mutually exclusive"))
	}
	if err := localdirs.ValidateStrict(o.localDirs); err != nil {
		return e.usageError("mount", err)
	}

	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("mount", err)
	}
	if st, err := readMountState(stateDir, mountPath); err == nil && st != nil && pidAlive(st.PID) {
		return e.fail("mount", fmt.Errorf("%s is already mounted (volume %s, pid %d); run `portablefs umount %s` first", mountPath, st.VolumeID, st.PID, mountPath))
	}

	if o.foreground {
		return e.runMountForeground(&o, volumeID, mountPath, stateDir)
	}
	return e.daemonizeMount(&o, volumeID, mountPath, stateDir)
}

// daemonizeMount re-execs this binary with --foreground in a detached session,
// then waits for its readiness report so `portablefs mount` returns only once
// the path is live (or with the child's real error).
func (e *cmdEnv) daemonizeMount(o *mountOpts, volumeID, mountPath, stateDir string) int {
	s, err := e.resolveSettings(&o.common)
	if err != nil {
		return e.fail("mount", err)
	}
	if o.addr == "" {
		if url, _ := s.managerEndpoint(); url == "" {
			return e.fail("mount", fmt.Errorf("no authority manager configured: run `portablefs login`, set PORTABLEFS_API_URL/PORTABLEFS_MANAGER_URL, or mount directly with --addr <host:port>"))
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return e.fail("mount", fmt.Errorf("locate own executable for daemonizing: %w", err))
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return e.fail("mount", err)
	}
	logPath := mountLogPath(stateDir, mountPath)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return e.fail("mount", err)
	}
	defer logFile.Close()

	childArgs := []string{"mount", volumeID, mountPath,
		"--branch", o.branch, "--strategy", o.strategy, "--foreground", "--ready-fd", "3"}
	if o.addr != "" {
		childArgs = append(childArgs, "--addr", o.addr)
	}
	for _, dir := range o.localDirs {
		childArgs = append(childArgs, "--local-dir", dir)
	}
	if o.noLocalDirs {
		childArgs = append(childArgs, "--no-local-dirs")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return e.fail("mount", err)
	}
	defer r.Close()

	cmd := exec.Command(exe, childArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{w} // child fd 3: readiness report
	// Detach into its own session so the mount daemon survives this process's
	// terminal and signals. Credentials travel via environment, never argv.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Env = append(os.Environ(),
		"PORTABLEFS_API_URL="+s.apiURL,
		"PORTABLEFS_API_TOKEN="+s.apiToken,
		"PORTABLEFS_MANAGER_URL="+s.managerURL,
		"PORTABLEFS_MANAGER_TOKEN="+s.managerToken,
	)
	if tok := o.resolveMountToken(e.getenv); tok != "" {
		cmd.Env = append(cmd.Env, mountTokenEnv+"="+tok)
	}
	if err := cmd.Start(); err != nil {
		_ = w.Close()
		return e.fail("mount", fmt.Errorf("start mount daemon: %w", err))
	}
	_ = w.Close()

	readyCh := make(chan mountReady, 1)
	errCh := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(r).ReadString('\n')
		if err != nil && line == "" {
			errCh <- fmt.Errorf("mount daemon exited before reporting readiness")
			return
		}
		var ready mountReady
		if err := json.Unmarshal([]byte(line), &ready); err != nil {
			errCh <- fmt.Errorf("unreadable readiness report from mount daemon: %q", strings.TrimSpace(line))
			return
		}
		readyCh <- ready
	}()

	var ready mountReady
	select {
	case ready = <-readyCh:
	case err := <-errCh:
		_ = cmd.Process.Release()
		return e.fail("mount", fmt.Errorf("%w; see %s", err, logPath))
	case <-time.After(3 * time.Minute):
		_ = cmd.Process.Release()
		return e.fail("mount", fmt.Errorf("mount did not become ready within 3 minutes; the daemon may still be starting — check `portablefs mounts` and %s", logPath))
	}
	_ = cmd.Process.Release()
	if !ready.OK {
		return e.fail("mount", fmt.Errorf("%s (log: %s)", ready.Error, logPath))
	}
	if o.common.jsonOut {
		return e.printJSON(ready)
	}
	fmt.Fprintf(e.stdout, "mounted %s@%s at %s (%s, pid %d)\n", ready.VolumeID, ready.Branch, ready.MountPath, ready.Strategy, ready.PID)
	fmt.Fprintf(e.stdout, "unmount with: portablefs umount %s\n", ready.MountPath)
	return 0
}

func (o *mountOpts) resolveMountToken(getenv func(string) string) string {
	if o.mountToken != "" {
		return o.mountToken
	}
	return getenv(mountTokenEnv)
}

// sessionTokenSource serves the current data-plane credential to reconnect
// handshakes, re-resolving access when the token nears expiry or
// when the router explicitly rejects it (refreshNow).
type sessionTokenSource struct {
	mu          sync.Mutex // guards token/expiresAtMs/refresh — never held across a refresh call
	token       string
	expiresAtMs int64
	refresh     func() (*accessSession, error)

	// refreshMu serializes re-resolutions so the timed near-expiry path and
	// the reactive rejection path never race two manager round-trips. It is
	// a separate lock because the refresh closure itself feeds tokens back
	// through setToken (via the lease keeper's adopt) — holding mu across it
	// would self-deadlock.
	refreshMu sync.Mutex
}

// setToken installs a fresh data-plane credential (the lease keeper pushes
// renewed/rotated tokens here so reconnect handshakes always use the live one).
func (t *sessionTokenSource) setToken(token string, expiresAtMs int64) {
	t.mu.Lock()
	t.token = token
	t.expiresAtMs = expiresAtMs
	t.mu.Unlock()
}

func (t *sessionTokenSource) get() string {
	t.mu.Lock()
	token, expires, refresh := t.token, t.expiresAtMs, t.refresh
	t.mu.Unlock()
	if refresh != nil && expires > 0 && time.Now().UnixMilli() > expires-30_000 {
		if t.refreshNow() {
			t.mu.Lock()
			token = t.token
			t.mu.Unlock()
		}
	}
	if token != "" {
		return token
	}
	// Direct --addr mounts without a token: the VCS_AUTH_TOKEN environment
	// variable authenticates the data plane.
	return os.Getenv("VCS_AUTH_TOKEN")
}

// refreshNow re-resolves access immediately and installs the fresh
// credential, reporting whether it did. This is the reactive recovery path:
// the fsproto client calls it (already coalesced across its pool) the moment
// a dial's token frame is explicitly rejected, so a manager restart is healed
// by the first op that notices instead of waiting out the lease-renewal tick.
func (t *sessionTokenSource) refreshNow() bool {
	t.refreshMu.Lock()
	defer t.refreshMu.Unlock()
	t.mu.Lock()
	refresh := t.refresh
	t.mu.Unlock()
	if refresh == nil {
		return false // static-token mount (--addr): nothing to re-resolve
	}
	ms, err := refresh()
	if err != nil || ms == nil || ms.Token == "" {
		return false
	}
	t.setToken(ms.Token, ms.ExpiresAtMs)
	return true
}

// resolveVolumeTeamID looks up the volume's tenant id through the volume API
// so manager requests can carry it as teamId (journal-native production
// managers key authorities and leases by the tenant namespace and require
// it). Best-effort: without an API endpoint, or on lookup failure, requests
// go out without a teamId exactly as before, which environment-mode managers
// accept.
//
// Tenancy ownership is deployment-shaped. A UNIFIED control plane (the hosted
// broker, where the manager and API share an origin) derives tenancy from the
// credential and rejects a client-asserted teamId, so the client must not send
// one. A SPLIT self-host deployment (a distinct volume-api and authority-
// manager) has no server-side tenancy authority on the manager, so the client
// resolves the volume's tenant and passes it through. The origin comparison is
// exactly that distinction, not a heuristic.
func (e *cmdEnv) resolveVolumeTeamID(s settings, volumeID, branch string) string {
	if s.apiURL == "" || s.apiToken == "" {
		return ""
	}
	if sameOrigin(s.managerURL, s.apiURL) {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Mode-agnostic resolution (volume list first, manifest head as the
	// backstop): a journal-owned (managed_journal) branch refuses the head
	// route with 409 LIVE_AUTHORITY_ROUTE_REQUIRED, and journal-owned
	// branches are exactly the volumes a managed mount needs the teamId for.
	return e.apiClient(s.apiURL, s.apiToken).resolveVolumeTenant(ctx, volumeID, branch)
}

// sameOrigin reports whether two endpoint URLs share a scheme+host+port, i.e.
// one control-plane origin fronts both the API and the manager. An empty
// manager URL means the manager defaulted to the API origin (unified).
func sameOrigin(managerURL, apiURL string) bool {
	if managerURL == "" {
		return true
	}
	m, errM := url.Parse(managerURL)
	a, errA := url.Parse(apiURL)
	if errM != nil || errA != nil {
		return false
	}
	return m.Scheme == a.Scheme && m.Host == a.Host
}

// runMountForeground performs the actual mount in this process: resolve the
// session, pick a strategy, attach, record state, then serve until unmounted.
func (e *cmdEnv) runMountForeground(o *mountOpts, volumeID, mountPath, stateDir string) int {
	var readyPipe *os.File
	if o.readyFD > 0 {
		readyPipe = os.NewFile(uintptr(o.readyFD), "portablefs-ready")
	}
	report := func(ready mountReady) {
		line, _ := json.Marshal(ready)
		if readyPipe != nil {
			_, _ = readyPipe.Write(append(line, '\n'))
			_ = readyPipe.Close()
			return
		}
		if o.common.jsonOut {
			_, _ = e.stdout.Write(append(line, '\n'))
		} else if ready.OK {
			fmt.Fprintf(e.stdout, "mounted %s@%s at %s (%s); Ctrl-C unmounts\n", ready.VolumeID, ready.Branch, ready.MountPath, ready.Strategy)
		}
	}
	failReady := func(err error) int {
		report(mountReady{OK: false, Error: err.Error()})
		if readyPipe != nil {
			fmt.Fprintf(e.stderr, "portablefs mount: %v\n", err)
			return 1
		}
		return e.fail("mount", err)
	}

	applyTLSEnvAliases()
	authorityURL := o.addr
	tokens := &sessionTokenSource{token: o.resolveMountToken(e.getenv)}
	// leaseHook lets the selected strategy observe renewed/rotated lease
	// credentials after the keeper (constructed before strategy selection)
	// exists — the fskit path pushes them into portablefsd, which owns the
	// authority connection for its attaches.
	var leaseHook atomic.Value
	var keeper *leaseKeeper
	if authorityURL == "" {
		s, err := e.resolveSettings(&o.common)
		if err != nil {
			return failReady(err)
		}
		// Trust the deployment's data-plane CA captured at login unless an
		// explicit env override exists. Materialized to a file because both
		// TLS consumers (secure.ClientTLS for FUSE, readTLSCAPEM for the
		// portablefsd attach) read a VCS_TLS_CA file path.
		if err := applyProfileDataPlaneCA(s.dataPlaneCAPEM, stateDir); err != nil {
			return failReady(err)
		}
		managerURL, managerToken := s.managerEndpoint()
		if managerURL == "" {
			return failReady(fmt.Errorf("no authority manager configured: run `portablefs login`, set PORTABLEFS_API_URL/PORTABLEFS_MANAGER_URL, or mount directly with --addr <host:port>"))
		}
		manager := e.managerClient(managerURL, managerToken)
		// Journal-native production managers key every authority and lease by
		// the tenant namespace, so resolve the volume's tenant id up front and
		// send it as teamId on every manager request.
		teamID := e.resolveVolumeTeamID(s, volumeID, o.branch)
		session, err := manager.resolveAccess(context.Background(), volumeID, o.branch, teamID)
		if err != nil {
			return failReady(err)
		}
		authorityURL = session.AuthorityURL
		tokens.token = session.Token
		tokens.expiresAtMs = session.ExpiresAtMs
		// A key revocation must not degrade this mount silently: the watch
		// logs ONE line (into the daemon's mount log), flips the persisted
		// mount status `portablefs mounts` reads, and clears both on
		// recovery. Enforcement itself is unchanged — the lease TTL grace
		// and the eventual refusal both stay exactly as the manager decides.
		credWatch := newCredentialWatch(
			func(format string, args ...any) { log.Printf("portablefs mount: "+format, args...) },
			func(status string, atMs int64) { setMountStatus(stateDir, mountPath, status, atMs) },
		)
		// The mount holds an access lease, renewed at half-TTL in the
		// background and released on unmount. The persisted slice lets
		// `portablefs mounts`/debugging correlate mount → lease.
		keeper = newLeaseKeeper(manager, volumeID, o.branch, teamID, tokens, *session.Lease, func(lease leaseState) {
			if st, err := readMountState(stateDir, mountPath); err == nil && st != nil {
				st.AccessLease = &lease
				_ = writeMountState(stateDir, *st)
			}
			if fn, _ := leaseHook.Load().(func(leaseState)); fn != nil {
				fn(lease)
			}
		})
		keeper.credWatch = credWatch
		tokens.refresh = func() (*accessSession, error) {
			// Bounded: this runs on the reconnect path (a rejected dial is
			// blocked on it), so a hung manager must fail the attempt quickly
			// and let the backoff schedule own the waiting.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ms, err := manager.resolveAccess(ctx, volumeID, o.branch, teamID)
			if err == nil && keeper != nil {
				keeper.adopt(*ms.Lease)
			}
			// The reactive path sees revocation first when the router starts
			// rejecting the data-plane token between renew ticks.
			if err != nil {
				if credentialRejected(err) {
					credWatch.noteRejected(err)
				}
			} else {
				credWatch.noteHealthy()
			}
			return ms, err
		}
	}

	strategy, err := resolveStrategy(o.strategy, hostStrategyProbe())
	if err != nil {
		return failReady(err)
	}
	// Both strategies graft machine-local dirs natively: go-fuse in-process
	// on Linux, portablefsd on macOS.
	flagLocalDirs, volumeFileEnabled, err := resolveLocalDirs(o, stateDir, volumeID, mountPath)
	if err != nil {
		return failReady(err)
	}
	if err := os.MkdirAll(mountPath, 0o755); err != nil {
		return failReady(fmt.Errorf("create mount point: %w", err))
	}

	state := mountState{
		MountPath:    mountPath,
		VolumeID:     volumeID,
		Branch:       o.branch,
		PID:          os.Getpid(),
		Strategy:     strategy,
		AuthorityURL: authorityURL,
		StartedAtMs:  time.Now().UnixMilli(),
	}
	ready := mountReady{
		OK: true, PID: os.Getpid(), Strategy: strategy,
		MountPath: mountPath, VolumeID: volumeID, Branch: o.branch,
	}

	switch strategy {
	case "fuse":
		localCfg := localDirsMountConfig{
			dirs:              flagLocalDirs,
			backingRoot:       localDirsBackingRoot(stateDir, volumeID, o.branch, mountPath),
			disableVolumeFile: !volumeFileEnabled,
			onChange: func(dirs []string) {
				// An ancestor rename carried grafts to new names; persist them
				// so a remount serves the carried backing under those names.
				if err := writePersistedLocalDirs(stateDir, volumeID, o.branch, mountPath, dirs); err != nil {
					fmt.Fprintf(e.stderr, "portablefs mount: persist carried local dirs: %v\n", err)
				}
				if st, err := readMountState(stateDir, mountPath); err == nil && st != nil {
					st.LocalDirs = dirs
					_ = writeMountState(stateDir, *st)
				}
			},
		}
		perf := perfOptionsFromEnv(e.getenv)
		perf.volumeID = volumeID
		perf.branch = o.branch
		perf.writebackDir = filepath.Join(stateDir, "writeback", storageDirID(volumeID, o.branch))
		m, err := mountFUSE(authorityURL, tokens, mountPath, perf, localCfg)
		if err != nil {
			return failReady(err)
		}
		state.LocalDirs = m.localDirs
		ready.LocalDirs = m.localDirs
		if keeper != nil {
			lease := keeper.snapshot()
			state.AccessLease = &lease
		}
		if err := writeMountState(stateDir, state); err != nil {
			_ = m.Unmount()
			m.Wait()
			return failReady(err)
		}
		report(ready)
		keeperCtx, stopKeeper := context.WithCancel(context.Background())
		if keeper != nil {
			go keeper.run(keeperCtx)
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			for range sig {
				// A failed drain keeps the mount up; the next signal (or a
				// recovered authority) retries. Forced detach goes through
				// `portablefs umount --force`, never a silent fallback here.
				if m.Unmount() == nil {
					return
				}
			}
		}()
		m.Wait() // returns when the kernel mount is gone (signal or external umount)
		stopKeeper()
		if keeper != nil {
			keeper.release()
		}
		_ = removeMountState(stateDir, mountPath)
		return 0

	case "fskit":
		fskitCfg := fskitConfigFromEnv(e.getenv)
		caPEM, err := readTLSCAPEM()
		if err != nil {
			return failReady(err)
		}
		ctl, err := ensurePortablefsd(fskitCfg, filepath.Dir(stateDir))
		if err != nil {
			return failReady(err)
		}
		attachReply, err := ctl.ensureAttachDetailed(fskitEnsureAttachRequest{
			VolumeID:     volumeID,
			Branch:       o.branch,
			AuthorityURL: authorityURL,
			AuthToken:    tokens.get(),
			TLSCAPEM:     caPEM,
			MountPath:    mountPath,
			Options:      fskitOptionsFromPerf(perfOptionsFromEnv(e.getenv), flagLocalDirs, volumeFileEnabled),
		})
		if err != nil {
			return failReady(err)
		}
		attachRef := attachReply.AttachRef
		detach := func() {
			if err := ctl.deleteAttach(attachRef); err != nil {
				fmt.Fprintf(e.stderr, "portablefs mount: detach %s: %v\n", attachRef, err)
			}
		}
		if err := fskitPreflight(fskitCfg.frontendSock, attachRef); err != nil {
			detach()
			return failReady(err)
		}
		if err := mountFSKitPath(fskitCfg.fsType, attachRef, mountPath); err != nil {
			detach()
			return failReady(err)
		}
		// Rotated/renewed lease credentials must reach the daemon: it owns
		// the authority connection for this attach.
		leaseHook.Store(func(lease leaseState) {
			if err := ctl.setCredential(attachRef, lease.AccessToken); err != nil {
				fmt.Fprintf(e.stderr, "portablefs mount: push rotated credential to portablefsd: %v\n", err)
			}
		})
		state.AttachRef = attachRef
		ready.AttachRef = attachRef
		state.LocalDirs = attachReply.LocalDirs
		ready.LocalDirs = attachReply.LocalDirs
		if keeper != nil {
			lease := keeper.snapshot()
			state.AccessLease = &lease
		}
		if err := writeMountState(stateDir, state); err != nil {
			_ = platformUnmount("fskit", mountPath)
			detach()
			return failReady(err)
		}
		report(ready)
		keeperCtx, stopKeeper := context.WithCancel(context.Background())
		if keeper != nil {
			go keeper.run(keeperCtx)
		}
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		if err := platformUnmount("fskit", mountPath); err != nil {
			fmt.Fprintf(e.stderr, "portablefs mount: unmount on shutdown: %v\n", err)
		}
		// Detach AFTER the kernel unmount so the daemon flushes everything
		// the extension handed it before the attach drops.
		detach()
		stopKeeper()
		if keeper != nil {
			keeper.release()
		}
		_ = removeMountState(stateDir, mountPath)
		return 0

	default:
		return failReady(fmt.Errorf("unknown strategy %q", strategy))
	}
}

// platformUnmount detaches mountPath using the host's unmount tooling.
func platformUnmount(strategy, mountPath string) error {
	_ = strategy // one transport per platform; the tooling depends only on the OS
	var attempts [][]string
	if runtime.GOOS == "darwin" {
		attempts = [][]string{
			{"/sbin/umount", mountPath},
			{"diskutil", "unmount", mountPath},
		}
	} else {
		attempts = [][]string{
			{"fusermount3", "-u", mountPath},
			{"fusermount", "-u", mountPath},
			{"umount", mountPath},
		}
	}
	var lastErr error
	for _, argv := range attempts {
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		if err == nil {
			return nil
		}
		lastErr = fmt.Errorf("%s: %w (output: %s)", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return lastErr
}

// isMountpoint reports whether path currently has a filesystem mounted on it:
// its device id differs from its parent directory's (the same check
// mountpoint(1) performs, via syscall.Stat_t on darwin and linux — no tool
// output to parse). A path that does not exist or cannot be stat'ed counts as
// not mounted; umount reconciliation treats both the same way.
func isMountpoint(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	parentFi, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return false
	}
	parentSt, ok := parentFi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return st.Dev != parentSt.Dev
}

func cmdUmount(e *cmdEnv, args []string) int {
	fs := newFlagSet("umount")
	var o commonOpts
	var force bool
	addCommonFlags(fs, &o)
	fs.BoolVar(&force, "force", false, "detach even with an unshipped write-back tail: it parks as a durable recovery job (its ID is printed) and drains automatically on the next attach")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("umount", err)
	}
	if len(positionals) != 1 {
		return e.usageError("umount", fmt.Errorf("expected exactly one mount path"))
	}
	mountPath, err := filepath.Abs(positionals[0])
	if err != nil {
		return e.fail("umount", err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("umount", err)
	}
	st, err := readMountState(stateDir, mountPath)
	if err != nil {
		return e.fail("umount", err)
	}
	if st == nil {
		fmt.Fprintf(e.stderr, "portablefs umount: warning: no mount state recorded for %s; attempting a plain unmount\n", mountPath)
		if err := platformUnmount("", mountPath); err != nil {
			if isMountpoint(mountPath) {
				return e.fail("umount", err)
			}
			// Unmount is idempotent: a path with nothing mounted on it is
			// already in the state the user asked for.
			fmt.Fprintf(e.stderr, "portablefs umount: warning: nothing was mounted at %s\n", mountPath)
		}
		if o.jsonOut {
			return e.printJSON(map[string]any{"mountPath": mountPath, "unmounted": true, "tracked": false})
		}
		fmt.Fprintf(e.stdout, "unmounted %s\n", mountPath)
		return 0
	}

	var forcedJobs []string
	switch {
	case !pidAlive(st.PID):
		// The daemon is already gone: this is stale-record reconciliation,
		// not a drain decision. Any parked WAL recovers on the next attach.
	case force:
		// The EXPLICIT force path: the daemon parks the unshipped tail as a
		// durable recovery job OUTSIDE the attach and reports its ID.
		forcedJobs = e.forceDetachForUnmount(st)
	default:
		// A NORMAL unmount requires the full drain barrier. Failure aborts
		// with the mount fully alive — never a silently parked tail behind a
		// healthy-looking unmount.
		if err := e.drainBeforeUnmount(st); err != nil {
			return e.fail("umount", fmt.Errorf("%v\nnothing was unmounted: the write-back tail could not reach the authority. Retry when it is reachable, or run `portablefs umount --force %s` to detach now — the tail then parks as a durable recovery job and drains on the next attach", err, mountPath))
		}
	}

	switch {
	case isMountpoint(mountPath):
		if err := platformUnmount(st.Strategy, mountPath); err != nil && isMountpoint(mountPath) && pidAlive(st.PID) {
			return e.fail("umount", fmt.Errorf("%w\nif the volume is busy, close processes using %s and retry", err, mountPath))
		}
	case pidAlive(st.PID):
		// The platform mount was torn down externally (forced diskutil
		// unmount, extension crash) but the daemon lingers: reconcile —
		// stop it and drop the record — instead of reporting "busy" for
		// a path that has nothing mounted on it.
		fmt.Fprintf(e.stderr, "portablefs umount: warning: %s was not mounted (daemon pid %d still running); stopping it and removing stale mount state\n", mountPath, st.PID)
	default:
		// Daemon already gone and nothing to unmount: a stale record. Clean it
		// up instead of failing, so `mounts` stops flagging it.
		fmt.Fprintf(e.stderr, "portablefs umount: warning: %s was not mounted (daemon pid %d already gone); removing stale mount state\n", mountPath, st.PID)
	}
	if pidAlive(st.PID) {
		stopMountDaemon(st.PID)
	}
	if force {
		// FUSE parks its job inside the daemon during teardown; report every
		// parked stream from the on-disk registry (visible OUTSIDE any
		// attach) so forced unmounts always print their recovery handles.
		forcedJobs = append(forcedJobs, parkedRecoveryJobs(stateDir, st)...)
		forcedJobs = dedupeStrings(forcedJobs)
		for _, id := range forcedJobs {
			fmt.Fprintf(e.stdout, "parked write-back recovery job %s (drains automatically on the next attach of %s@%s)\n", id, st.VolumeID, st.Branch)
		}
	}
	if err := removeMountState(stateDir, mountPath); err != nil {
		fmt.Fprintf(e.stderr, "portablefs umount: warning: remove mount state: %v\n", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": st.VolumeID, "unmounted": true, "tracked": true, "forced": force, "recoveryJobs": forcedJobs})
	}
	fmt.Fprintf(e.stdout, "unmounted %s (volume %s)\n", mountPath, st.VolumeID)
	return 0
}

// drainBeforeUnmount runs the REQUIRED normal-unmount drain barrier while
// the mount is still fully alive. An error means the unmount must not
// proceed.
func (e *cmdEnv) drainBeforeUnmount(st *mountState) error {
	switch {
	case st.Strategy == "fskit" && st.AttachRef != "":
		ctl := newFsdControl(fskitConfigFromEnv(e.getenv).controlSock)
		if _, err := ctl.syncAttach(st.AttachRef); err != nil {
			return fmt.Errorf("pre-unmount drain failed: %w", err)
		}
		return nil
	case st.Strategy == "fuse":
		// The FUSE daemon owns its drain: SIGTERM asks it to drain and
		// detach; a failed drain leaves the mount up, which we detect.
		proc, err := os.FindProcess(st.PID)
		if err != nil {
			return nil
		}
		_ = proc.Signal(syscall.SIGTERM)
		deadline := time.Now().Add(daemonStopTimeout)
		for time.Now().Before(deadline) {
			if !isMountpoint(st.MountPath) {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		if isMountpoint(st.MountPath) {
			return fmt.Errorf("the mount daemon could not drain within %v (the mount stays up)", daemonStopTimeout)
		}
		return nil
	}
	return nil
}

// forceDetachForUnmount runs the explicit force path against a live daemon
// (fskit control) and returns any reported recovery job IDs. Best-effort: a
// wedged daemon still gets torn down by the caller, and the on-disk job
// registry reports the parked streams.
func (e *cmdEnv) forceDetachForUnmount(st *mountState) []string {
	if st.Strategy != "fskit" || st.AttachRef == "" {
		return nil
	}
	ctl := newFsdControl(fskitConfigFromEnv(e.getenv).controlSock)
	jobID, err := ctl.forceDetach(st.AttachRef)
	if err != nil {
		fmt.Fprintf(e.stderr, "portablefs umount: warning: force-detach through the daemon failed (%v); proceeding with the platform unmount — parked streams remain visible in the on-disk recovery registry\n", err)
		return nil
	}
	if jobID == "" {
		return nil
	}
	return []string{jobID}
}

// parkedRecoveryJobs reads the on-disk recovery registry for this mount's
// (volume, branch) write-back store: job.json lives OUTSIDE any attach, so a
// forced unmount can always name the recovery handles it parked.
func parkedRecoveryJobs(stateDir string, st *mountState) []string {
	roots := []string{
		// FUSE mounts key the store under the CLI state dir.
		filepath.Join(stateDir, "writeback", storageDirID(st.VolumeID, st.Branch)),
	}
	// FSKit mounts key it under the daemon's state dir (a sibling of the
	// mount state dir).
	roots = append(roots, filepath.Join(filepath.Dir(stateDir), "portablefsd", "wal", storageDirID(st.VolumeID, st.Branch)))
	var ids []string
	for _, root := range roots {
		matches, _ := filepath.Glob(filepath.Join(root, "stream-*", "job.json"))
		for _, m := range matches {
			var job struct {
				JobID string `json:"jobId"`
			}
			if b, err := os.ReadFile(m); err == nil && json.Unmarshal(b, &job) == nil && job.JobID != "" {
				ids = append(ids, job.JobID)
			}
		}
	}
	return ids
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// daemonStopTimeout is how long stopMountDaemon waits after SIGTERM before
// escalating to SIGKILL. It MUST exceed the daemon's detach drain budget
// (portablefsd detachDrainBudget, 30s) plus the control round-trip — a
// shorter timeout SIGKILLs the daemon mid-drain, exactly the data-parking
// race this constant exists to prevent.
const daemonStopTimeout = 60 * time.Second

// stopMountDaemon terminates the daemonized mount process: SIGTERM first so it
// can drain and clean up, SIGKILL only after the drain budget has fully lapsed.
func stopMountDaemon(pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(daemonStopTimeout)
	for time.Now().Before(deadline) {
		if !pidAlive(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = proc.Signal(syscall.SIGKILL)
}

func cmdMounts(e *cmdEnv, args []string) int {
	fs := newFlagSet("mounts")
	var o commonOpts
	addCommonFlags(fs, &o)
	if _, err := parseArgs(fs, args); err != nil {
		return e.handleParseError("mounts", err)
	}
	stateDir, err := e.mountStateDir()
	if err != nil {
		return e.fail("mounts", err)
	}
	states, err := listMountStates(stateDir)
	if err != nil {
		return e.fail("mounts", err)
	}
	type mountRow struct {
		mountState
		Alive bool `json:"alive"`
		// Health folds pid-liveness and the persisted credential status:
		// live | stale | credential-expired.
		Health string `json:"health"`
		// WriteBack carries the daemon's durability-debt view for fskit
		// mounts: live un-flushed backlog plus parked WALs awaiting the
		// background recovery job.
		WriteBack *cliWriteBackStatus `json:"writeBack,omitempty"`
		// AttachState is the daemon-reported attach state (degraded carries
		// the daemon's last error in the printed line).
		AttachState string `json:"attachState,omitempty"`
	}
	daemonView := fskitAttachStatuses(e.getenv)
	rows := make([]mountRow, 0, len(states))
	for i := range states {
		row := mountRow{mountState: states[i], Alive: pidAlive(states[i].PID), Health: mountHealth(&states[i])}
		if a, ok := daemonView[states[i].AttachRef]; ok {
			row.WriteBack = a.WriteBack
			row.AttachState = a.State
		}
		rows = append(rows, row)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"mounts": rows})
	}
	if len(rows) == 0 {
		fmt.Fprintln(e.stdout, "no active mounts")
		return 0
	}
	for _, row := range rows {
		var status string
		switch row.Health {
		case "stale":
			status = "stale (daemon gone; run `portablefs umount " + row.MountPath + "` to clean up)"
		case mountStatusCredentialExpired:
			since := ""
			if row.StatusChangedAtMs != 0 {
				since = " since " + formatMs(row.StatusChangedAtMs)
			}
			status = "credential-expired" + since + " (credentials revoked or expired; run `portablefs login` and remount)"
		default:
			status = "live"
			if row.AttachState == "degraded" {
				status = "degraded"
			}
		}
		extras := ""
		if len(row.LocalDirs) > 0 {
			extras = "  local-dirs:" + strings.Join(row.LocalDirs, ",")
		}
		if wb := row.WriteBack; wb != nil {
			parkedRecords := 0
			for _, p := range wb.ParkedWALs {
				parkedRecords += p.Records
			}
			if parkedRecords > 0 {
				extras += fmt.Sprintf("  write-back:%d records pending recovery", parkedRecords)
			} else if wb.PendingRecords > 0 {
				extras += fmt.Sprintf("  write-back:%d records flushing", wb.PendingRecords)
			}
		}
		fmt.Fprintf(e.stdout, "%s  %s@%s  %s  pid %d%s  %s\n", row.MountPath, row.VolumeID, row.Branch, row.Strategy, row.PID, extras, status)
	}
	return 0
}

// fskitAttachStatuses reads the daemon's attach table, keyed by attach ref.
// Best-effort with a short budget: `portablefs mounts` must answer instantly
// whether or not a daemon is running.
func fskitAttachStatuses(getenv func(string) string) map[string]cliAttachStatus {
	ctl := newFsdControl(fskitConfigFromEnv(getenv).controlSock)
	ctl.httpClient.Timeout = 3 * time.Second
	attaches, err := ctl.listAttaches()
	if err != nil {
		return nil
	}
	out := make(map[string]cliAttachStatus, len(attaches))
	for _, a := range attaches {
		out[a.AttachRef] = a
	}
	return out
}
