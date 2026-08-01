package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fskitidentity"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"golang.org/x/sys/unix"
)

// ---------------------------------------------------------------------------
// FSKit strategy: the ONE macOS mount path.
//
// The CLI drives exactly the portablefsd + FSKit extension pair the menu-bar
// app uses: ensure a per-user portablefsd (adopt a healthy one, else spawn),
// register the attach over its control socket (authority endpoint + data-
// plane credential + tuning), then hand the kernel the attach reference via
// `/sbin/mount -t <fstype> <scheme>://<attachRef> <mountPath>`. The registered
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

	// The PortableFS OSS/Cloud FSKit identity is deliberately distinct from
	// any other product that embeds PortableFS (another embedder may register
	// its own FSShortName, generic-resource URL scheme, and app group): a
	// unique mount type, globally scoped URL scheme, and private app-group
	// socket directory guarantee the products never collide when installed on
	// the same machine. Extension coordinates are overridable via
	// PORTABLEFS_FSKIT_* for bespoke deployments; the executable peer is not.
	defaultFskitType = fskitidentity.FSType
)

// defaultFskitSocketDir is the daemon socket directory inside the app-group
// container. The unsandboxed daemon and CLI address it by its well-known
// path; the sandboxed extension resolves the identical path via
// containerURL(forSecurityApplicationGroupIdentifier:).
func defaultFskitSocketDir() (string, error) {
	home, err := accountpath.Home()
	if err != nil {
		return "", fmt.Errorf("resolve canonical account home for FSKit sockets: %w", err)
	}
	return filepath.Join(home, "Library", "Group Containers", fskitidentity.AppGroup, "portablefsd"), nil
}

// fskitConfig resolves the extension coordinates for this host. The
// filesystem type is a signed release identity and cannot be changed at
// runtime. Socket overrides exist for development builds that preserve that
// identity while using a different app-group container.
type fskitConfig struct {
	fsType            string
	frontendSock      string
	controlSock       string
	daemonPathForTest string // tests inject a peer without adding a production override
	legacyStateDir    string // empty only in isolated tests
}

func fskitConfigFromEnv(getenv func(string) string) (fskitConfig, error) {
	socketDir, err := defaultFskitSocketDir()
	if err != nil {
		return fskitConfig{}, err
	}
	cfg := fskitConfig{
		fsType:       defaultFskitType,
		frontendSock: filepath.Join(socketDir, "pfs.sock"),
		controlSock:  filepath.Join(socketDir, "control.sock"),
	}
	if daemonOverride := getenv(fskitDaemonEnv); daemonOverride != "" {
		return fskitConfig{}, fmt.Errorf(
			"%s is unsupported: portablefsd must be the exact sibling embedded with this portablefs executable",
			fskitDaemonEnv,
		)
	}
	home, err := accountpath.Home()
	if err != nil {
		return fskitConfig{}, fmt.Errorf("resolve canonical account home for legacy FSKit inventory: %w", err)
	}
	cfg.legacyStateDir = filepath.Join(home, "Library", "Application Support", "PortableFS", "portablefsd")
	if v := getenv(fskitTypeEnv); v != "" && v != defaultFskitType {
		return fskitConfig{}, fmt.Errorf(
			"%s=%q does not match this release's signed FSKit identity %q",
			fskitTypeEnv,
			v,
			defaultFskitType,
		)
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
	return cfg, nil
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
			// Must exceed the daemon's detach/sync drain budget (30s): the
			// sync and detach endpoints legitimately hold the request open
			// for the whole bounded drain.
			Timeout: 60 * time.Second,
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
	return c.doContext(context.Background(), method, path, body)
}

func (c *fsdControl) doContext(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://portablefsd"+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(daemonctl.ControlProtocolHeader, fmt.Sprint(daemonctl.ControlProtocolVersion))
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
	return c.healthyWithin(time.Second)
}

func (c *fsdControl) healthyWithin(timeout time.Duration) bool {
	if timeout <= 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	status, _, err := c.doContext(ctx, http.MethodGet, "/healthz", nil)
	return err == nil && status >= 200 && status < 300
}

func (c *fsdControl) identity() (daemonctl.Identity, error) {
	return c.identityWithin(5 * time.Second)
}

func (c *fsdControl) identityWithin(timeout time.Duration) (daemonctl.Identity, error) {
	if timeout <= 0 {
		return daemonctl.Identity{}, context.DeadlineExceeded
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	status, body, err := c.doContext(ctx, http.MethodGet, "/v1/identity", nil)
	if err != nil {
		return daemonctl.Identity{}, err
	}
	if status < 200 || status >= 300 {
		return daemonctl.Identity{}, controlError(status, body)
	}
	var identity daemonctl.Identity
	if err := json.Unmarshal(body, &identity); err != nil {
		return daemonctl.Identity{}, fmt.Errorf("unreadable portablefsd identity: %w", err)
	}
	return identity, nil
}

func (c *fsdControl) requireCompatibleIdentity(cliVersion, executableSHA256 string) error {
	return c.requireCompatibleIdentityWithin(cliVersion, executableSHA256, 5*time.Second)
}

func (c *fsdControl) requireCompatibleIdentityWithin(
	cliVersion,
	executableSHA256 string,
	timeout time.Duration,
) error {
	identity, err := c.identityWithin(timeout)
	if err != nil {
		return fmt.Errorf(
			"the running portablefsd on %s has no compatible control identity: %w; cleanly unmount PortableFS volumes, stop that daemon, and retry (PortableFS will not replace a live daemon automatically)",
			c.socketPath, err,
		)
	}
	if identity.SchemaVersion != daemonctl.IdentitySchemaVersion ||
		identity.ControlProtocol != daemonctl.ControlProtocolVersion ||
		identity.PFSLocalMajor != pfslocal.ProtocolMajor ||
		identity.DaemonVersion != cliVersion ||
		identity.ExecutableSHA256 != executableSHA256 {
		return fmt.Errorf(
			"the running portablefsd on %s is incompatible (daemon %q, CLI %q, executable %q, expected %q, control protocol %d, pfslocal %d.%d); cleanly unmount PortableFS volumes, stop that daemon, and retry (PortableFS will not replace a live daemon automatically)",
			c.socketPath,
			identity.DaemonVersion,
			cliVersion,
			identity.ExecutableSHA256,
			executableSHA256,
			identity.ControlProtocol,
			identity.PFSLocalMajor,
			identity.PFSLocalMinor,
		)
	}
	return nil
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

// fskitAttachOptions mirrors portablefsd's AttachOptions JSON. There is no
// write-mode field: every attach is adaptive.
type fskitAttachOptions struct {
	Prefetch        bool     `json:"prefetch"`
	DiskCacheDir    string   `json:"diskCacheDir"`
	DiskCacheMB     int64    `json:"diskCacheMb"`
	NegativeCache   bool     `json:"negativeCache"`
	NoNegativeCache bool     `json:"noNegativeCache,omitempty"`
	LocalDirs       []string `json:"localDirs,omitempty"`
	VolumeLocalDirs bool     `json:"volumeLocalDirs,omitempty"`
}

func fskitOptionsFromPerf(perf perfOptions, localDirs []string, volumeLocalDirs bool) fskitAttachOptions {
	return fskitAttachOptions{
		NegativeCache:   perf.negativeCache,
		NoNegativeCache: perf.negativeCacheOff,
		LocalDirs:       localDirs,
		VolumeLocalDirs: volumeLocalDirs,
	}
}

type fskitEnsureAttachRequest struct {
	AttachRef           string             `json:"attachRef"`
	VolumeID            string             `json:"volumeId"`
	Branch              string             `json:"branch"`
	AuthorityURL        string             `json:"authorityUrl"`
	AuthToken           string             `json:"authToken"`
	DataPlaneTransport  string             `json:"dataPlaneTransport"`
	DataPlaneServerName string             `json:"dataPlaneServerName,omitempty"`
	TLSCAPEM            string             `json:"tlsCaPem,omitempty"`
	TLSCASHA256         string             `json:"tlsCaSha256,omitempty"`
	MountPath           string             `json:"mountPath"`
	Options             fskitAttachOptions `json:"options"`
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

func (c *fsdControl) stopIfIdle() error {
	status, body, err := c.do(http.MethodPost, "/v1/lifecycle/stop-if-idle", map[string]any{})
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

// forceDetach runs the daemon-owned forced FSKit transaction: durable force
// authorization, journal parking, prepared proof, exact kernel detach, and
// durable registry removal. The response names the parked recovery stream
// ("" is an explicit zero-tail proof).
func (c *fsdControl) forceDetach(ref string) (jobID string, err error) {
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/unmount?force=1", nil)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", controlError(status, body)
	}
	var reply struct {
		RecoveryJob string `json:"recoveryJob"`
	}
	_ = json.Unmarshal(body, &reply)
	return reply.RecoveryJob, nil
}

// cliAttachStatus is the slice of portablefsd's attach status the CLI reads
// for `portablefs mounts` and `portablefs doctor`.
type cliAttachStatus struct {
	AttachRef string              `json:"attachRef"`
	MountPath string              `json:"mountPath"`
	VolumeID  string              `json:"volumeId"`
	Branch    string              `json:"branch"`
	State     string              `json:"state"`
	LastError string              `json:"lastError"`
	WriteBack *cliWriteBackStatus `json:"writeBack"`
}

type cliWriteBackStatus struct {
	PendingRecords int   `json:"pendingRecords"`
	PendingBytes   int64 `json:"pendingBytes"`
	WALBytes       int64 `json:"walBytes"`
	WALBudget      int64 `json:"walBudget"`
	LastProgressMs int64 `json:"lastProgressMs"`
	// Drain-time credit control: the pacing state that distinguishes a
	// flusher deliberately holding writers back from one that is not draining
	// at all. PendingRecords alone cannot tell those apart.
	CreditSetpoint int64               `json:"creditSetpoint"`
	CreditDebt     int64               `json:"creditDebt"`
	CreditCeiling  int64               `json:"creditCeiling"`
	AppliedRateBps float64             `json:"appliedRateBps"`
	CreditWaiters  int                 `json:"creditWaiters"`
	DataLaneFull   bool                `json:"dataLaneFull"`
	Delegations    []cliDelegationView `json:"delegations"`
	ParkedWALs     []cliParkedWAL      `json:"parkedWals"`
}

// paced reports the data lane holding writers back: either mutations are
// currently blocked on credit or the bulk lane is sitting at its hard cap.
func (w *cliWriteBackStatus) paced() bool {
	return w != nil && (w.CreditWaiters > 0 || w.DataLaneFull)
}

type cliDelegationView struct {
	Scope    string `json:"scope"`
	Draining bool   `json:"draining"`
}

type cliParkedWAL struct {
	Root         string `json:"root"`
	Records      int    `json:"records"`
	PayloadBytes int64  `json:"payloadBytes"`
	AgeMs        int64  `json:"ageMs"`
	LastError    string `json:"lastError"`
}

// verifyRecordedFskitAttach correlates a persisted mount/intent with the
// exact live daemon inventory before a lifecycle mutation. Absence is a
// proven result; a reused attach ref with different coordinates is an error.
func verifyRecordedFskitAttach(ctl *fsdControl, st *mountState) (bool, error) {
	attach, err := recordedFskitAttachStatus(ctl, st)
	return attach != nil, err
}

func recordedFskitAttachStatus(ctl *fsdControl, st *mountState) (*cliAttachStatus, error) {
	if ctl == nil || st == nil || !mountid.ValidAttachRef(st.AttachRef) {
		return nil, fmt.Errorf("recorded FSKit attach identity is incomplete")
	}
	attaches, err := ctl.listAttaches()
	if err != nil {
		return nil, err
	}
	for i := range attaches {
		attach := &attaches[i]
		if attach.AttachRef != st.AttachRef {
			continue
		}
		if attach.MountPath != st.MountPath ||
			attach.VolumeID != st.VolumeID ||
			attach.Branch != st.Branch {
			return nil, fmt.Errorf(
				"attach %s identity mismatch: daemon has %s@%s at %s, record has %s@%s at %s",
				st.AttachRef,
				attach.VolumeID,
				attach.Branch,
				attach.MountPath,
				st.VolumeID,
				st.Branch,
				st.MountPath,
			)
		}
		return attach, nil
	}
	return nil, nil
}

func (c *fsdControl) listAttaches() ([]cliAttachStatus, error) {
	status, body, err := c.do(http.MethodGet, "/v1/attaches", nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, controlError(status, body)
	}
	var out struct {
		Attaches []cliAttachStatus `json:"attaches"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("unreadable attach list from portablefsd: %w", err)
	}
	return out.Attaches, nil
}

// syncVerdict is the daemon's successful drain verdict (POST
// /v1/attaches/{ref}/sync). A drain that cannot reach authority durability
// is an HTTP error, never a degraded success.
type syncVerdict struct {
	PendingRecords int   `json:"pendingRecords"`
	PendingBytes   int64 `json:"pendingBytes"`
}

func (c *fsdControl) syncAttach(ref string) (syncVerdict, error) {
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/sync", nil)
	if err != nil {
		return syncVerdict{}, err
	}
	if status < 200 || status >= 300 {
		return syncVerdict{}, controlError(status, body)
	}
	var v syncVerdict
	if err := json.Unmarshal(body, &v); err != nil {
		return syncVerdict{}, fmt.Errorf("unreadable drain verdict from portablefsd: %w", err)
	}
	return v, nil
}

// unmountAttach is the normal FSKit teardown transaction. portablefsd owns
// the admission gate, final durability barrier, exact kernel identity check,
// in-process kernel unmount, and durable attach removal in one request.
func (c *fsdControl) unmountAttach(ref string) error {
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/unmount", nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

func (c *fsdControl) setCredential(ref, token string) error {
	return c.setCredentialWithMode(ref, token, false)
}

func (c *fsdControl) setCredentialIfPending(ref, token string) error {
	return c.setCredentialWithMode(ref, token, true)
}

func (c *fsdControl) setCredentialWithMode(ref, token string, onlyIfPending bool) error {
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/credential",
		map[string]any{"authToken": token, "onlyIfPending": onlyIfPending})
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

// unmountRecordedAttach performs the normal, authority-durable detach for a
// persisted FSKit mount. portablefsd deliberately does not persist authority
// credentials, so a restarted daemon revives managed attaches inert. The
// mount transaction does persist the current access-lease credential; push
// that exact credential back before asking the daemon for its final authority
// barrier. Direct-address mounts have no persisted credential and therefore
// proceed directly: an already-active daemon can drain them, while a revived
// daemon fails closed and requires the explicit force/park transaction.
func (c *fsdControl) unmountRecordedAttach(st *mountState) error {
	if st == nil || !mountid.ValidAttachRef(st.AttachRef) {
		return fmt.Errorf("recorded FSKit attach identity is incomplete")
	}
	if st.AccessLease != nil {
		if !validLeaseState(st.AccessLease) {
			return fmt.Errorf("recorded access lease for attach %s is invalid", st.AttachRef)
		}
		if err := c.setCredentialIfPending(st.AttachRef, st.AccessLease.AccessToken); err != nil {
			return fmt.Errorf("reactivate attach %s with its recorded access lease: %w", st.AttachRef, err)
		}
	}
	return c.unmountAttach(st.AttachRef)
}

type portablefsdPeer struct {
	path   string
	name   string
	parent *os.File
	file   *os.File
	sha256 string
}

func (p *portablefsdPeer) close() {
	if p == nil {
		return
	}
	if p.file != nil {
		_ = p.file.Close()
	}
	if p.parent != nil {
		_ = p.parent.Close()
	}
}

func (p *portablefsdPeer) validate() error {
	var opened, named unix.Stat_t
	if err := unix.Fstat(int(p.file.Fd()), &opened); err != nil {
		return fmt.Errorf("inspect pinned portablefsd peer %s: %w", p.path, err)
	}
	if err := unix.Fstatat(int(p.parent.Fd()), p.name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck exact portablefsd peer %s: %w", p.path, err)
	}
	if opened.Dev != named.Dev || opened.Ino != named.Ino {
		return fmt.Errorf("exact portablefsd peer %s changed while pinned", p.path)
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFREG ||
		opened.Uid != uint32(os.Geteuid()) ||
		opened.Nlink != 1 ||
		opened.Mode&0o111 == 0 ||
		opened.Mode&0o022 != 0 {
		return fmt.Errorf(
			"portablefsd peer %s must be one uid-owned, non-writable executable regular file",
			p.path,
		)
	}
	return nil
}

func openPortablefsdPeer(path string) (*portablefsdPeer, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("portablefsd peer path must be absolute and clean: %q", path)
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("resolve portablefsd peer directory %s: %w", filepath.Dir(path), err)
	}
	path = filepath.Join(parentPath, filepath.Base(path))
	parent, err := privatepath.OpenExistingOwnedDir(parentPath)
	if err != nil {
		return nil, fmt.Errorf("pin portablefsd peer directory %s: %w", parentPath, err)
	}
	name := filepath.Base(path)
	fd, err := unix.Openat(
		int(parent.Fd()),
		name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		_ = parent.Close()
		return nil, fmt.Errorf("open exact portablefsd peer %s without following symlinks: %w", path, err)
	}
	peer := &portablefsdPeer{
		path:   path,
		name:   name,
		parent: parent,
		file:   os.NewFile(uintptr(fd), path),
	}
	if peer.file == nil {
		_ = unix.Close(fd)
		peer.close()
		return nil, fmt.Errorf("open exact portablefsd peer %s: invalid file descriptor", path)
	}
	if err := peer.validate(); err != nil {
		peer.close()
		return nil, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, peer.file); err != nil {
		peer.close()
		return nil, fmt.Errorf("hash exact portablefsd peer %s: %w", path, err)
	}
	peer.sha256 = hex.EncodeToString(hash.Sum(nil))
	if err := peer.validate(); err != nil {
		peer.close()
		return nil, err
	}
	return peer, nil
}

// exactPortablefsdPath resolves only the daemon packaged beside this exact CLI.
// There is no PATH search or environment-selected executable in production.
func exactPortablefsdPath(executable string) (string, error) {
	if executable == "" {
		return "", fmt.Errorf("portablefs executable path is empty")
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", fmt.Errorf("resolve portablefs executable %s: %w", executable, err)
	}
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("resolved portablefs executable is not absolute: %q", resolved)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect portablefs executable %s: %w", resolved, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", fmt.Errorf("portablefs executable %s is not a real executable file", resolved)
	}
	return filepath.Join(filepath.Dir(resolved), "portablefsd"), nil
}

func findPortablefsd(testPath string) (string, error) {
	if testPath != "" {
		return testPath, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve portablefs executable: %w", err)
	}
	path, err := exactPortablefsdPath(executable)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(path); err != nil {
		return "", fmt.Errorf(
			"exact embedded portablefsd peer is unavailable at %s: %w; reinstall the complete PortableFS release",
			path,
			err,
		)
	}
	return path, nil
}

// ensurePortablefsd adopts a healthy daemon on the control socket or spawns
// one detached. The daemon is per-user and multi-attach: one instance serves
// every mount, so an already-running daemon (this CLI's or the app's, when
// they share sockets) is adopted, never duplicated.
func ensurePortablefsd(cfg fskitConfig, stateRoot, cliVersion string) (*fsdControl, error) {
	if cfg.legacyStateDir != "" {
		if err := checkPortablefsdStateRoots(filepath.Join(stateRoot, "portablefsd"), cfg.legacyStateDir); err != nil {
			return nil, err
		}
	}
	daemonPath, err := findPortablefsd(cfg.daemonPathForTest)
	if err != nil {
		return nil, err
	}
	daemon, err := openPortablefsdPeer(daemonPath)
	if err != nil {
		return nil, err
	}
	defer daemon.close()
	ctl := newFsdControl(cfg.controlSock)
	if ctl.healthyWithin(time.Second) {
		if err := ctl.requireCompatibleIdentityWithin(cliVersion, daemon.sha256, 2*time.Second); err != nil {
			return nil, err
		}
		return ctl, nil
	}
	for _, sock := range []string{cfg.frontendSock, cfg.controlSock} {
		if err := privatepath.EnsureDir(filepath.Dir(sock)); err != nil {
			return nil, fmt.Errorf("validate socket directory: %w", err)
		}
	}
	daemonStateDir := filepath.Join(stateRoot, "portablefsd")
	if err := privatepath.EnsureDir(daemonStateDir); err != nil {
		return nil, fmt.Errorf("validate portablefsd state dir: %w", err)
	}
	logFile, err := privatepath.OpenFileAppend(filepath.Join(stateRoot, "portablefsd.log"))
	if err != nil {
		return nil, err
	}
	defer logFile.Close()

	if err := daemon.validate(); err != nil {
		return nil, err
	}
	cmd := exec.Command(daemon.path,
		"-frontend-socket", cfg.frontendSock,
		"-control-socket", cfg.controlSock,
		"-state-dir", daemonStateDir,
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Its own session: the daemon outlives this mount process and serves
	// later mounts too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Revalidate at the final userspace boundary immediately before exec.
	if err := daemon.validate(); err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start portablefsd: %w", err)
	}
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()
	stopSpawned := func() error {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waitCh:
			return nil
		case <-time.After(35 * time.Second):
			return fmt.Errorf("spawned portablefsd did not stop within its 30-second drain budget and was left running")
		}
	}
	if err := daemon.validate(); err != nil {
		if stopErr := stopSpawned(); stopErr != nil {
			return nil, fmt.Errorf("%w; cleanup: %v", err, stopErr)
		}
		return nil, err
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case waitErr := <-waitCh:
			if waitErr == nil {
				return nil, fmt.Errorf(
					"portablefsd exited without becoming healthy on %s (log: %s)",
					cfg.controlSock,
					filepath.Join(stateRoot, "portablefsd.log"),
				)
			}
			return nil, fmt.Errorf(
				"portablefsd exited before becoming healthy on %s: %w (log: %s)",
				cfg.controlSock,
				waitErr,
				filepath.Join(stateRoot, "portablefsd.log"),
			)
		default:
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		probeTimeout := min(250*time.Millisecond, remaining)
		if ctl.healthyWithin(probeTimeout) {
			remaining = time.Until(deadline)
			if remaining <= 0 {
				break
			}
			identityCh := make(chan error, 1)
			go func() {
				identityCh <- ctl.requireCompatibleIdentityWithin(cliVersion, daemon.sha256, remaining)
			}()
			select {
			case waitErr := <-waitCh:
				if waitErr == nil {
					return nil, fmt.Errorf(
						"portablefsd exited without becoming healthy on %s (log: %s)",
						cfg.controlSock,
						filepath.Join(stateRoot, "portablefsd.log"),
					)
				}
				return nil, fmt.Errorf(
					"portablefsd exited before identity verification on %s: %w (log: %s)",
					cfg.controlSock,
					waitErr,
					filepath.Join(stateRoot, "portablefsd.log"),
				)
			case err := <-identityCh:
				if err == nil {
					return ctl, nil
				}
				if stopErr := stopSpawned(); stopErr != nil {
					return nil, fmt.Errorf("%w; cleanup: %v", err, stopErr)
				}
				return nil, err
			case <-time.After(remaining):
				if stopErr := stopSpawned(); stopErr != nil {
					return nil, fmt.Errorf(
						"portablefsd identity did not become verifiable on %s within 15s (log: %s); cleanup: %w",
						cfg.controlSock,
						filepath.Join(stateRoot, "portablefsd.log"),
						stopErr,
					)
				}
				return nil, fmt.Errorf(
					"portablefsd identity did not become verifiable on %s within 15s (log: %s)",
					cfg.controlSock,
					filepath.Join(stateRoot, "portablefsd.log"),
				)
			}
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			break
		}
		select {
		case waitErr := <-waitCh:
			if waitErr == nil {
				return nil, fmt.Errorf(
					"portablefsd exited without becoming healthy on %s (log: %s)",
					cfg.controlSock,
					filepath.Join(stateRoot, "portablefsd.log"),
				)
			}
			return nil, fmt.Errorf(
				"portablefsd exited before becoming healthy on %s: %w (log: %s)",
				cfg.controlSock,
				waitErr,
				filepath.Join(stateRoot, "portablefsd.log"),
			)
		case <-time.After(min(150*time.Millisecond, remaining)):
		}
	}
	if err := stopSpawned(); err != nil {
		return nil, fmt.Errorf("portablefsd did not become healthy on %s within 15s (log: %s); cleanup: %w",
			cfg.controlSock, filepath.Join(stateRoot, "portablefsd.log"), err)
	}
	return nil, fmt.Errorf("portablefsd did not become healthy on %s within 15s (log: %s)",
		cfg.controlSock, filepath.Join(stateRoot, "portablefsd.log"))
}

func rejectLegacyPortablefsdStateAt(legacy string) error {
	return checkPortablefsdStateRoots("", legacy)
}

func checkPortablefsdStateRoots(canonical, legacy string) error {
	canonicalNonempty, err := nonemptyStateDirectory(canonical)
	if err != nil {
		return fmt.Errorf("inspect canonical portablefsd state %s: %w", canonical, err)
	}
	legacyNonempty, err := nonemptyStateDirectory(legacy)
	if err != nil {
		return fmt.Errorf("inspect legacy portablefsd state %s: %w", legacy, err)
	}
	if !legacyNonempty {
		return nil
	}
	if canonicalNonempty {
		return fmt.Errorf("portablefsd state conflict: both canonical %s and legacy %s contain state; PortableFS will never guess or merge them", canonical, legacy)
	}
	return fmt.Errorf("legacy portablefsd state exists at %s; run the PortableFS installer state migration before mounting (the runtime will not copy, merge, or delete it)", legacy)
}

func nonemptyStateDirectory(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("state path %s exists with an unexpected type", path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	return len(entries) != 0, nil
}

// connectCompatiblePortablefsd proves that an already-running daemon is the
// exact installed peer for this CLI before any operational control request.
// This gate is used outside mount adoption too: unmount, mounts, and doctor
// must not drive an older daemon merely because it ignores an unknown header.
func connectCompatiblePortablefsd(cfg fskitConfig, cliVersion string) (*fsdControl, error) {
	daemonPath, err := findPortablefsd(cfg.daemonPathForTest)
	if err != nil {
		return nil, err
	}
	daemon, err := openPortablefsdPeer(daemonPath)
	if err != nil {
		return nil, err
	}
	defer daemon.close()
	ctl := newFsdControl(cfg.controlSock)
	if !ctl.healthy() {
		return nil, fmt.Errorf("portablefsd is not healthy on %s", cfg.controlSock)
	}
	if err := ctl.requireCompatibleIdentity(cliVersion, daemon.sha256); err != nil {
		return nil, err
	}
	return ctl, nil
}

// fskitPreflight proves the attach is resolvable over the SAME frontend
// socket the registered extension will dial: Hello + Resolve(attachRef). It
// catches the one foreseeable misconfiguration — the CLI attached to daemon
// A while the installed extension's Info.plist points at daemon B — as a
// typed error before the kernel mount, instead of an opaque I/O error after.
func fskitPreflight(frontendSock, attachRef, expectedDaemonVersion string) error {
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
	helloBody, err := call(1, &pfslocal.Hello{ProtocolMajor: pfslocal.ProtocolMajor, ProtocolMinor: pfslocal.ProtocolMinor, ClientName: "portablefs-cli", ClientVersion: "preflight"})
	if err != nil {
		return fmt.Errorf("portablefsd frontend handshake on %s: %w", frontendSock, err)
	}
	hello, ok := helloBody.(*pfslocal.HelloReply)
	if !ok || hello.ProtocolMajor != pfslocal.ProtocolMajor || hello.DaemonVersion != expectedDaemonVersion {
		gotMajor := uint32(0)
		gotVersion := ""
		if ok {
			gotMajor = hello.ProtocolMajor
			gotVersion = hello.DaemonVersion
		}
		return fmt.Errorf("portablefsd frontend handshake on %s returned incompatible %T (protocol %d, daemon %q; want major %d, daemon %q)",
			frontendSock, helloBody, gotMajor, gotVersion, pfslocal.ProtocolMajor, expectedDaemonVersion)
	}
	if _, err := call(2, &pfslocal.ResolveRequest{AttachRef: attachRef}); err != nil {
		return fmt.Errorf("attach %s is not resolvable on frontend %s (is the registered FSKit extension pointed at a different daemon? set %s/%s to your extension's socket pair): %w",
			attachRef, frontendSock, fskitSocketEnv, fskitControlEnv, err)
	}
	return nil
}

type fskitMountFailure string

const (
	fskitFailureUnknown       fskitMountFailure = ""
	fskitFailureResourceLoad  fskitMountFailure = "resource-load"
	fskitFailureModuleMissing fskitMountFailure = "module-unavailable"
)

// classifyFSKitMountFailure recognizes only evidence that distinguishes a
// reached extension from the legacy mount-helper fallback. Generic errno text
// is intentionally left unknown: the same errno can be produced by unrelated
// mount point, policy, resource, and extension failures.
func classifyFSKitMountFailure(fsType, message string) fskitMountFailure {
	if strings.Contains(message, "Loading resource") {
		return fskitFailureResourceLoad
	}
	helper := "mount_" + fsType
	if strings.Contains(message, helper) &&
		(strings.Contains(message, "No such file or directory") ||
			strings.Contains(message, "not found")) {
		return fskitFailureModuleMissing
	}
	return fskitFailureUnknown
}

// fskitMountHint adds conservative context to otherwise opaque mount output.
func fskitMountHint(fsType string, err error) error {
	message := err.Error()
	switch classifyFSKitMountFailure(fsType, message) {
	case fskitFailureResourceLoad:
		return fmt.Errorf("%w\nthe %q FSKit extension was reached but failed while loading its resource; verify portablefsd is reachable at the extension's exact app-group socket and inspect the underlying mount error", err, fsType)
	case fskitFailureModuleMissing:
		return fmt.Errorf("%w\nmacOS did not resolve an FSKit module for %q and fell through to the missing legacy %s helper; PortableFS.app may be absent or its extension may need to be enabled in System Settings → General → Login Items & Extensions → FILE SYSTEM EXTENSIONS", err, fsType, "mount_"+fsType)
	}
	return err
}

// mountFSKitPath attaches the kernel to the daemon-served attach reference.
func mountFSKitPath(fsType, attachRef, mountPath string) error {
	out, err := exec.Command(
		"/sbin/mount",
		"-t",
		fsType,
		fskitidentity.ResourcePrefix+attachRef,
		mountPath,
	).CombinedOutput()
	if err != nil {
		return fskitMountHint(fsType, fmt.Errorf("mount -t %s %s: %w (output: %s)",
			fsType, mountPath, err, strings.TrimSpace(string(out))))
	}
	return nil
}
