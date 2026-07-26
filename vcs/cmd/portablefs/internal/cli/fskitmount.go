package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/pfslocal"
)

// ---------------------------------------------------------------------------
// FSKit strategy: the ONE macOS mount path.
//
// The CLI drives exactly the portablefsd + FSKit extension pair the menu-bar
// app uses: ensure a per-user portablefsd (adopt a healthy one, else spawn),
// register the attach over its control socket (authority endpoint + data-
// plane credential + tuning), then hand the kernel the attach reference via
// `/sbin/mount -t <fstype> pfs://<attachRef> <mountPath>`. The registered
// FSKit extension dials the daemon's frontend socket inside the PortableFS
// app-group container (PFSAppGroupIdentifier in the extension Info.plist),
// so the frontend socket this CLI serves MUST be that same path. The app
// group is the one location a sandboxed extension may connect(2) to a unix
// socket — the app sandbox only grants network-outbound on app-group paths,
// so a socket under /tmp is unreachable regardless of file exceptions.
//
// There is deliberately no fallback transport: a missing extension fails
// closed with install guidance, never a silently weaker mount.
// ---------------------------------------------------------------------------

const (
	fskitTypeEnv    = "PORTABLEFS_FSKIT_TYPE"
	fskitSocketEnv  = "PORTABLEFS_FSKIT_SOCKET"
	fskitControlEnv = "PORTABLEFS_FSKIT_CONTROL_SOCKET"
	fskitDaemonEnv  = "PORTABLEFS_FSKIT_DAEMON"

	// The portablefs-oss/cloud FSKit identity is deliberately distinct from
	// any other product that embeds PortableFS (another embedder
	// may register its own FSName extension with its own app group): a unique
	// mount type and a private app-group socket directory guarantee the two
	// never collide when installed on the same machine. Overridable via
	// PORTABLEFS_FSKIT_* for bespoke deployments.
	defaultFskitType = "pfs"

	// Must match PFSAppGroupIdentifier in the extension Info.plist and the
	// com.apple.security.application-groups entitlement.
	fskitAppGroup = "B47U2LLKHW.pfsoss"
)

// defaultFskitSocketDir is the daemon socket directory inside the app-group
// container. The unsandboxed daemon and CLI address it by its well-known
// path; the sandboxed extension resolves the identical path via
// containerURL(forSecurityApplicationGroupIdentifier:).
func defaultFskitSocketDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "~"
	}
	return filepath.Join(home, "Library", "Group Containers", fskitAppGroup, "portablefsd")
}

// fskitConfig resolves the extension coordinates for this host. Defaults
// match PortableFS.app's extension (PFSAppGroupIdentifier in its
// Info.plist); the env overrides exist for dev extensions registered under
// another fs type / socket location.
type fskitConfig struct {
	fsType       string
	frontendSock string
	controlSock  string
	daemonPath   string // explicit portablefsd binary, "" = discover
}

func fskitConfigFromEnv(getenv func(string) string) fskitConfig {
	socketDir := defaultFskitSocketDir()
	cfg := fskitConfig{
		fsType:       defaultFskitType,
		frontendSock: filepath.Join(socketDir, "pfs.sock"),
		controlSock:  filepath.Join(socketDir, "control.sock"),
		daemonPath:   getenv(fskitDaemonEnv),
	}
	if v := getenv(fskitTypeEnv); v != "" {
		cfg.fsType = v
	}
	if v := getenv(fskitSocketEnv); v != "" {
		cfg.frontendSock = v
		// A custom frontend implies a paired control socket next to it
		// unless one is given explicitly.
		if getenv(fskitControlEnv) == "" {
			cfg.controlSock = filepath.Join(filepath.Dir(v), "control.sock")
		}
	}
	if v := getenv(fskitControlEnv); v != "" {
		cfg.controlSock = v
	}
	return cfg
}

// fsdControl is a minimal client for portablefsd's control socket (HTTP over
// a Unix domain socket; see vcs/internal/portablefsd/control.go).
type fsdControl struct {
	socketPath string
	httpClient *http.Client
}

func newFsdControl(socketPath string) *fsdControl {
	return &fsdControl{
		socketPath: socketPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *fsdControl) do(method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, "http://portablefsd"+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

func (c *fsdControl) healthy() bool {
	status, _, err := c.do(http.MethodGet, "/healthz", nil)
	return err == nil && status >= 200 && status < 300
}

// controlError extracts the daemon's error envelope for bounded messages.
func controlError(status int, body []byte) error {
	var envelope struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Error != "" {
		return fmt.Errorf("portablefsd: %s (HTTP %d)", envelope.Error, status)
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 300 {
		text = text[:300]
	}
	if text == "" {
		return fmt.Errorf("portablefsd control error (HTTP %d)", status)
	}
	return fmt.Errorf("portablefsd: %s (HTTP %d)", text, status)
}

// fskitAttachOptions mirrors portablefsd's AttachOptions JSON.
type fskitAttachOptions struct {
	WritePolicy     string   `json:"writePolicy"`
	FsyncPolicy     string   `json:"fsyncPolicy,omitempty"`
	FlushIntervalMs int64    `json:"flushIntervalMs,omitempty"`
	Prefetch        bool     `json:"prefetch"`
	DiskCacheDir    string   `json:"diskCacheDir"`
	DiskCacheMB     int64    `json:"diskCacheMb"`
	NegativeCache   bool     `json:"negativeCache"`
	NoNegativeCache bool     `json:"noNegativeCache,omitempty"`
	LocalDirs       []string `json:"localDirs,omitempty"`
	VolumeLocalDirs bool     `json:"volumeLocalDirs,omitempty"`
}

func fskitOptionsFromPerf(perf perfOptions, localDirs []string, volumeLocalDirs bool) fskitAttachOptions {
	opts := fskitAttachOptions{
		WritePolicy:     "writethrough",
		FsyncPolicy:     perf.fsyncPolicy,
		NegativeCache:   perf.negativeCache,
		NoNegativeCache: perf.negativeCacheOff,
		LocalDirs:       localDirs,
		VolumeLocalDirs: volumeLocalDirs,
	}
	if perf.writeBack {
		opts.WritePolicy = "writeback"
		opts.FlushIntervalMs = perf.flushInterval.Milliseconds()
	}
	return opts
}

type fskitEnsureAttachRequest struct {
	VolumeID     string             `json:"volumeId"`
	Branch       string             `json:"branch"`
	AuthorityURL string             `json:"authorityUrl"`
	AuthToken    string             `json:"authToken"`
	TLSCAPEM     string             `json:"tlsCaPem,omitempty"`
	MountPath    string             `json:"mountPath"`
	Options      fskitAttachOptions `json:"options"`
}

type fskitEnsureAttachReply struct {
	AttachRef string   `json:"attachRef"`
	LocalDirs []string `json:"localDirs,omitempty"`
}

func (c *fsdControl) ensureAttachDetailed(req fskitEnsureAttachRequest) (fskitEnsureAttachReply, error) {
	status, body, err := c.do(http.MethodPost, "/v1/attaches", req)
	if err != nil {
		return fskitEnsureAttachReply{}, fmt.Errorf("attach via portablefsd: %w", err)
	}
	if status < 200 || status >= 300 {
		return fskitEnsureAttachReply{}, controlError(status, body)
	}
	var reply fskitEnsureAttachReply
	if err := json.Unmarshal(body, &reply); err != nil || reply.AttachRef == "" {
		return fskitEnsureAttachReply{}, fmt.Errorf("portablefsd attach reply carried no attachRef")
	}
	return reply, nil
}

func (c *fsdControl) ensureAttach(req fskitEnsureAttachRequest) (string, error) {
	reply, err := c.ensureAttachDetailed(req)
	return reply.AttachRef, err
}

func (c *fsdControl) deleteAttach(ref string) error {
	status, body, err := c.do(http.MethodDelete, "/v1/attaches/"+url.PathEscape(ref), nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

func (c *fsdControl) setCredential(ref, token string) error {
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/credential",
		map[string]string{"authToken": token})
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

// findPortablefsd locates the daemon binary: explicit override, then a
// sibling of this executable (the release layout), then PATH.
func findPortablefsd(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("%s=%s: %w", fskitDaemonEnv, explicit, err)
		}
		return explicit, nil
	}
	if exe, err := os.Executable(); err == nil {
		sibling := filepath.Join(filepath.Dir(exe), "portablefsd")
		if _, err := os.Stat(sibling); err == nil {
			return sibling, nil
		}
	}
	if found, err := exec.LookPath("portablefsd"); err == nil {
		return found, nil
	}
	return "", fmt.Errorf("portablefsd not found: install it next to the portablefs binary or on PATH (or set %s)", fskitDaemonEnv)
}

// ensurePortablefsd adopts a healthy daemon on the control socket or spawns
// one detached. The daemon is per-user and multi-attach: one instance serves
// every mount, so an already-running daemon (this CLI's or the app's, when
// they share sockets) is adopted, never duplicated.
func ensurePortablefsd(cfg fskitConfig, stateRoot string) (*fsdControl, error) {
	ctl := newFsdControl(cfg.controlSock)
	if ctl.healthy() {
		return ctl, nil
	}
	daemon, err := findPortablefsd(cfg.daemonPath)
	if err != nil {
		return nil, err
	}
	for _, sock := range []string{cfg.frontendSock, cfg.controlSock} {
		if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
			return nil, fmt.Errorf("create socket directory: %w", err)
		}
	}
	daemonStateDir := filepath.Join(stateRoot, "portablefsd")
	if err := os.MkdirAll(daemonStateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create portablefsd state dir: %w", err)
	}
	logFile, err := os.OpenFile(filepath.Join(stateRoot, "portablefsd.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer logFile.Close()

	cmd := exec.Command(daemon,
		"-frontend-socket", cfg.frontendSock,
		"-control-socket", cfg.controlSock,
		"-state-dir", daemonStateDir,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Its own session: the daemon outlives this mount process and serves
	// later mounts too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start portablefsd: %w", err)
	}
	_ = cmd.Process.Release()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ctl.healthy() {
			return ctl, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("portablefsd did not become healthy on %s within 15s (log: %s)",
		cfg.controlSock, filepath.Join(stateRoot, "portablefsd.log"))
}

// readTLSCAPEM loads the data-plane CA bundle for the daemon's attach
// request. The daemon dials the authority itself, so the trust material the
// CLI resolved (PORTABLEFS_TLS_CA / VCS_TLS_CA) must travel to it as PEM.
func readTLSCAPEM() (string, error) {
	path := os.Getenv("VCS_TLS_CA")
	if path == "" {
		return "", nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read TLS CA %s: %w", path, err)
	}
	return string(pem), nil
}

// fskitPreflight proves the attach is resolvable over the SAME frontend
// socket the registered extension will dial: Hello + Resolve(attachRef). It
// catches the one foreseeable misconfiguration — the CLI attached to daemon
// A while the installed extension's Info.plist points at daemon B — as a
// typed error before the kernel mount, instead of an opaque I/O error after.
func fskitPreflight(frontendSock, attachRef string) error {
	conn, err := net.DialTimeout("unix", frontendSock, 5*time.Second)
	if err != nil {
		return fmt.Errorf("portablefsd frontend socket %s is not answering: %w", frontendSock, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	call := func(id uint64, body any) (any, error) {
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{RequestID: id, Body: body}); err != nil {
			return nil, err
		}
		for {
			env, err := pfslocal.ReadFrame(conn)
			if err != nil {
				return nil, err
			}
			if env.RequestID != id {
				continue
			}
			if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
				return nil, fmt.Errorf("errno %d: %s", er.Errno, er.Message)
			}
			return env.Body, nil
		}
	}
	if _, err := call(1, &pfslocal.Hello{ProtocolMajor: pfslocal.ProtocolMajor, ProtocolMinor: pfslocal.ProtocolMinor, ClientName: "portablefs-cli", ClientVersion: "preflight"}); err != nil {
		return fmt.Errorf("portablefsd frontend handshake on %s: %w", frontendSock, err)
	}
	if _, err := call(2, &pfslocal.ResolveRequest{AttachRef: attachRef}); err != nil {
		return fmt.Errorf("attach %s is not resolvable on frontend %s (is the registered FSKit extension pointed at a different daemon? set %s/%s to your extension's socket pair): %w",
			attachRef, frontendSock, fskitSocketEnv, fskitControlEnv, err)
	}
	return nil
}

// fskitMountHint rewrites the opaque kernel error for a missing/disabled
// FSKit extension into install guidance.
func fskitMountHint(fsType string, err error) error {
	message := err.Error()
	// "mount_<type>: No such file or directory" means the kernel found no
	// enabled FSKit module for the type and fell through to the legacy
	// /Library/Filesystems probe: the extension is missing or not enabled.
	// "Loading resource: ... Input/output error" means the module IS enabled
	// but its loadResource failed — with no daemon socket reachable inside
	// the app-group container being the overwhelmingly common cause.
	switch {
	case strings.Contains(message, "mount_"+fsType) ||
		strings.Contains(message, "unknown") || strings.Contains(message, "not recognized") ||
		strings.Contains(message, "45") || strings.Contains(message, "Operation not supported"):
		return fmt.Errorf("%w\nthe %q FSKit extension is not enabled: install PortableFS.app, then in System Settings → General → Login Items & Extensions open the FILE SYSTEM EXTENSIONS category (the per-app list's toggle is unreliable on macOS 26) and enable it, then retry", err, fsType)
	case strings.Contains(message, "Loading resource"):
		return fmt.Errorf("%w\nthe %q FSKit extension could not reach portablefsd's socket in the app-group container; if this CLI was configured with PORTABLEFS_FSKIT_SOCKET, that path must match the extension's PFSAppGroupIdentifier container", err, fsType)
	}
	return err
}

// mountFSKitPath attaches the kernel to the daemon-served attach reference.
func mountFSKitPath(fsType, attachRef, mountPath string) error {
	out, err := exec.Command("/sbin/mount", "-t", fsType, "pfs://"+attachRef, mountPath).CombinedOutput()
	if err != nil {
		return fskitMountHint(fsType, fmt.Errorf("mount -t %s %s: %w (output: %s)",
			fsType, mountPath, err, strings.TrimSpace(string(out))))
	}
	return nil
}

// errFskitUnsupported is returned on non-darwin builds (the strategy switch
// never selects fskit there; this is defense in depth).
var errFskitUnsupported = errors.New("the fskit strategy requires macOS")
