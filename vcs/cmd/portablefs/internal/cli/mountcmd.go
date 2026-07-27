package cli

import (
	"bufio"
	"context"
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
	"strconv"
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
	fast        bool
	foreground  bool
	readyFD     int
	localDirs   stringListFlag
	noLocalDirs bool
}

func addMountFlags(fs *flag.FlagSet, o *mountOpts) {
	addCommonFlags(fs, &o.common)
	fs.StringVar(&o.branch, "branch", "main", "branch to mount")
	fs.StringVar(&o.strategy, "strategy", "auto", "mount strategy: auto (fskit on macOS, fuse on Linux), fskit, or fuse")
	fs.StringVar(&o.addr, "addr", "", "mount a VCS authority address directly, skipping the manager")
	fs.StringVar(&o.mountToken, "mount-token", "", "data-plane token for --addr (or "+mountTokenEnv+")")
	fs.BoolVar(&o.fast, "fast", false, "single-writer speed mode: write-back + negative caching (fsync = durable at the authority)")
	fs.Var(&o.localDirs, "local-dir", "serve this workspace-relative directory from machine-local disk instead of the volume (repeatable; e.g. --local-dir node_modules)")
	fs.BoolVar(&o.noLocalDirs, "no-local-dirs", false, "disable machine-local dirs entirely for this mount (clears persisted --local-dir state and ignores the volume's .portablefs/local-dirs)")
	fs.BoolVar(&o.foreground, "foreground", false, "stay attached instead of daemonizing")
	fs.IntVar(&o.readyFD, "ready-fd", 0, "internal: fd to write the readiness report to")
}

// perfOptions carries the FUSE mount performance knobs. The zero value is the
// correctness-first default: write-through, no negative cache — coherence via
// authority push invalidation only. --fast (or the documented PORTABLEFS_*
// environment knobs, same names cmd/mount reads) turns on write-back
// batching and version-gated negative caching. Under --fast, fsync defaults
// to the "authority" policy so applications that fsync (git, SQLite) get a
// real durability barrier; un-fsynced writes have a bounded (~flush interval)
// window, the same contract as a local page cache.
type perfOptions struct {
	writeBack bool
	// negativeCache forces the negative dentry cache on; negativeCacheOff
	// forces it off. Neither (the default) is capability-auto: clientcore
	// enables it iff the authority advertises ParentVersion stamping in the
	// protocol handshake.
	negativeCache    bool
	negativeCacheOff bool
	flushInterval    time.Duration
	fsyncPolicy      string
	flushMaxRecords  int
	flushMaxBytes    int64
}

func perfOptionsFromEnv(fast bool, getenv func(string) string) perfOptions {
	p := perfOptions{
		writeBack:        fast || getenv("PORTABLEFS_WRITEBACK") == "1",
		negativeCache:    fast || getenv("PORTABLEFS_NEGATIVE_CACHE") == "1",
		negativeCacheOff: !fast && getenv("PORTABLEFS_NEGATIVE_CACHE") == "0",
	}
	if v := getenv("PORTABLEFS_FLUSH_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			p.flushInterval = time.Duration(ms) * time.Millisecond
		}
	}
	if p.writeBack && p.flushInterval == 0 {
		p.flushInterval = 250 * time.Millisecond
	}
	p.fsyncPolicy = getenv("PORTABLEFS_FSYNC_POLICY")
	if p.fsyncPolicy == "" && fast {
		p.fsyncPolicy = "authority"
	}
	if v := getenv("PORTABLEFS_FLUSH_MAX_RECORDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.flushMaxRecords = n
		}
	}
	if v := getenv("PORTABLEFS_FLUSH_MAX_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			p.flushMaxBytes = n
		}
	}
	return p
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
	if o.fast {
		childArgs = append(childArgs, "--fast")
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
// handshakes, re-resolving the mount session when the token nears expiry or
// when the router explicitly rejects it (refreshNow).
type sessionTokenSource struct {
	mu          sync.Mutex // guards token/expiresAtMs/refresh — never held across a refresh call
	token       string
	expiresAtMs int64
	refresh     func() (*mountSession, error)

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
	// Direct --addr mounts without a token keep cmd/mount's contract: the
	// VCS_AUTH_TOKEN environment variable authenticates the data plane.
	return os.Getenv("VCS_AUTH_TOKEN")
}

// refreshNow re-resolves the mount session immediately and installs the fresh
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
		session, err := manager.mountSession(context.Background(), volumeID, o.branch, teamID)
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
		if session.Lease != nil {
			// Canonical transport: the mount holds an access lease, renewed at
			// half-TTL in the background and released on unmount. The persisted
			// slice lets `portablefs mounts`/debugging correlate mount → lease.
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
		}
		tokens.refresh = func() (*mountSession, error) {
			// Bounded: this runs on the reconnect path (a rejected dial is
			// blocked on it), so a hung manager must fail the attempt quickly
			// and let the backoff schedule own the waiting.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			ms, err := manager.mountSession(ctx, volumeID, o.branch, teamID)
			if err == nil && ms.Lease != nil && keeper != nil {
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
		m, err := mountFUSE(authorityURL, tokens, mountPath, perfOptionsFromEnv(o.fast, e.getenv), localCfg)
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
			m.Unmount()
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
			<-sig
			m.Unmount()
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
			Options:      fskitOptionsFromPerf(perfOptionsFromEnv(o.fast, e.getenv), flagLocalDirs, volumeFileEnabled),
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
	addCommonFlags(fs, &o)
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

	if err := platformUnmount(st.Strategy, mountPath); err != nil {
		switch {
		case isMountpoint(mountPath) && pidAlive(st.PID):
			return e.fail("umount", fmt.Errorf("%w\nif the volume is busy, close processes using %s and retry", err, mountPath))
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
	}
	if pidAlive(st.PID) {
		stopMountDaemon(st.PID)
	}
	if err := removeMountState(stateDir, mountPath); err != nil {
		fmt.Fprintf(e.stderr, "portablefs umount: warning: remove mount state: %v\n", err)
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"mountPath": mountPath, "volumeId": st.VolumeID, "unmounted": true, "tracked": true})
	}
	fmt.Fprintf(e.stdout, "unmounted %s (volume %s)\n", mountPath, st.VolumeID)
	return 0
}

// stopMountDaemon terminates the daemonized mount process: SIGTERM first so it
// can flush and clean up, SIGKILL if it lingers.
func stopMountDaemon(pid int) {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return
	}
	_ = proc.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(5 * time.Second)
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
	}
	rows := make([]mountRow, 0, len(states))
	for i := range states {
		rows = append(rows, mountRow{states[i], pidAlive(states[i].PID), mountHealth(&states[i])})
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
		}
		extras := ""
		if len(row.LocalDirs) > 0 {
			extras = "  local-dirs:" + strings.Join(row.LocalDirs, ",")
		}
		fmt.Fprintf(e.stdout, "%s  %s@%s  %s  pid %d%s  %s\n", row.MountPath, row.VolumeID, row.Branch, row.Strategy, row.PID, extras, status)
	}
	return 0
}
