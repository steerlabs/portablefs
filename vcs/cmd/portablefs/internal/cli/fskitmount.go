package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/accountpath"
	"github.com/steerlabs/portablefs/vcs/internal/apphost"
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
// app owns: adopt a healthy per-user launchd agent or wake the exact host,
// register the attach over the external control socket (authority endpoint +
// data-plane credential + tuning), then hand the kernel the attach reference via
// `/sbin/mount -t <fstype> <scheme>://<attachRef> <mountPath>`. The registered
// FSKit extension dials the daemon's frontend socket inside the PortableFS
// app-group container (PFSAppGroupIdentifier in the extension Info.plist),
// while this deliberately unentitled CLI never resolves or dials that path.
// The daemon performs the exact frontend Hello+Resolve preflight through its
// versioned control API before the CLI asks the kernel to mount.
//
// There is deliberately no fallback transport: a missing extension fails
// closed with install guidance, never a silently weaker mount.
// ---------------------------------------------------------------------------

const (
	// The PortableFS OSS/Cloud FSKit identity is deliberately distinct from
	// any other product that embeds PortableFS (another embedder may register
	// its own FSShortName, generic-resource URL scheme, and app group): a
	// unique mount type, globally scoped URL scheme, and private app-group
	// socket directory guarantee the products never collide when installed on
	// the same machine. Neither the signed socket identity nor the executable
	// peer is runtime-configurable.
	defaultFskitType = fskitidentity.FSType
)

var resolveFSKitAccountHome = accountpath.Home
var launchExactPortableFSHost = func() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve PortableFS executable for host launch: %w", err)
	}
	return apphost.LaunchContainingApp(executable)
}

// defaultFskitControlSocket is deliberately outside the Data Vault protected
// app-group. A shell CLI is not the responsible app and must never resolve,
// inspect, create, or dial the group container. Only the host, launch agent,
// and FSKit extension cross that boundary; the CLI addresses the daemon through
// this exact owner-private account state directory.
func defaultFskitControlSocket() (string, error) {
	home, err := resolveFSKitAccountHome()
	if err != nil {
		return "", fmt.Errorf("resolve canonical account home for FSKit control: %w", err)
	}
	return filepath.Join(home, ".local", "state", "portablefs", "portablefsd", "control.sock"), nil
}

// fskitConfig resolves the extension coordinates for this host. The
// filesystem type and socket paths are a signed release identity and cannot
// be changed at runtime. A development product uses its own compiled app-group
// identity and matching signed helpers rather than an environment override.
type fskitConfig struct {
	fsType                  string
	controlSock             string
	daemonPathForTest       string // tests inject a peer without adding a production override
	authenticatePeerForTest func(net.Conn, string) error
}

func fixedFSKitConfig() (fskitConfig, error) {
	controlSocket, err := defaultFskitControlSocket()
	if err != nil {
		return fskitConfig{}, err
	}
	cfg := fskitConfig{
		fsType:      defaultFskitType,
		controlSock: controlSocket,
	}
	return cfg, nil
}

// fsdControl is a minimal client for portablefsd's control socket (HTTP over
// a Unix domain socket; see vcs/internal/portablefsd/control.go).
type fsdControl struct {
	socketPath         string
	httpClient         *http.Client
	expectedPeerSHA256 string
	authenticatePeer   func(net.Conn, string) error
}

func newFsdControl(socketPath string) *fsdControl {
	ctl := &fsdControl{socketPath: socketPath, authenticatePeer: authenticateFSDPeer}
	ctl.httpClient = &http.Client{
		// Must exceed the daemon's detach/sync drain budget (30s): the
		// sync and detach endpoints legitimately hold the request open
		// for the whole bounded drain.
		Timeout:       60 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				conn, err := d.DialContext(ctx, "unix", socketPath)
				if err != nil {
					return nil, err
				}
				if ctl.expectedPeerSHA256 != "" {
					if err := ctl.authenticatePeer(conn, ctl.expectedPeerSHA256); err != nil {
						_ = conn.Close()
						return nil, err
					}
				}
				return conn, nil
			},
		},
	}
	return ctl
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
	if !strings.HasPrefix(path, "/lifecycle/") {
		req.Header.Set(daemonctl.ControlProtocolHeader, fmt.Sprint(daemonctl.ControlProtocolVersion))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	limit := int64(1 << 20)
	if strings.HasPrefix(path, "/lifecycle/") {
		limit = daemonctl.MaxLifecycleBodyBytes
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(data)) > limit {
		return resp.StatusCode, nil, fmt.Errorf("portablefsd response exceeds %d bytes", limit)
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
	status, body, err := c.doContext(ctx, http.MethodGet, daemonctl.LifecycleIdentityPath, nil)
	if err != nil {
		return daemonctl.Identity{}, err
	}
	if status != http.StatusOK {
		return daemonctl.Identity{}, controlError(status, body)
	}
	identity, err := daemonctl.DecodeIdentity(body)
	if err != nil {
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
	return c.requireExactIdentityWithin(daemonctl.Identity{
		SchemaVersion:    daemonctl.IdentitySchemaVersion,
		ControlProtocol:  daemonctl.ControlProtocolVersion,
		DaemonVersion:    cliVersion,
		ExecutableSHA256: executableSHA256,
		PFSLocalMajor:    pfslocal.ProtocolMajor,
		PFSLocalMinor:    pfslocal.ProtocolMinor,
	}, timeout)
}

func (c *fsdControl) requireExactIdentityWithin(
	expected daemonctl.Identity,
	timeout time.Duration,
) error {
	c.expectedPeerSHA256 = expected.ExecutableSHA256
	identity, err := c.identityWithin(timeout)
	if err != nil {
		return fmt.Errorf(
			"the running portablefsd on %s has no compatible control identity: %w; cleanly unmount PortableFS volumes, stop that daemon, and retry (PortableFS will not replace a live daemon automatically)",
			c.socketPath, err,
		)
	}
	if identity != expected {
		return fmt.Errorf(
			"the running portablefsd on %s is incompatible (daemon %q, expected %q, executable %q, expected %q, schema %d/%d, control protocol %d/%d, pfslocal %d.%d/%d.%d); cleanly unmount PortableFS volumes and retry (PortableFS will not replace an unproven live daemon)",
			c.socketPath,
			identity.DaemonVersion,
			expected.DaemonVersion,
			identity.ExecutableSHA256,
			expected.ExecutableSHA256,
			identity.SchemaVersion,
			expected.SchemaVersion,
			identity.ControlProtocol,
			expected.ControlProtocol,
			identity.PFSLocalMajor,
			identity.PFSLocalMinor,
			expected.PFSLocalMajor,
			expected.PFSLocalMinor,
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

type fskitEnsureAttachRequest struct {
	AttachRef    string `json:"attachRef"`
	VolumeID     string `json:"volumeId"`
	AuthorityURL string `json:"authorityUrl"`
	AuthToken    string `json:"authToken"`
	// AuthTokenExpiresAtMs is the access lease's own stated expiry for
	// AuthToken (unix ms), the deadline that bounds the daemon-side UNPROVEN
	// credential state. Omitted (0) states no deadline.
	AuthTokenExpiresAtMs int64  `json:"authTokenExpiresAtMs,omitempty"`
	DataPlaneTransport   string `json:"dataPlaneTransport"`
	DataPlaneServerName  string `json:"dataPlaneServerName,omitempty"`
	TLSCAPEM             string `json:"tlsCaPem,omitempty"`
	TLSCASHA256          string `json:"tlsCaSha256,omitempty"`
	MountPath            string `json:"mountPath"`
	// V3 selects the daemon-owned authority-v3 attach (portablefsd's
	// v3AttachRequest; see vcs/internal/portablefsd/v3attach.go). The daemon —
	// never the FSKit extension — receives the mutual-TLS identity and dials
	// the authority with it.
	V3 *fskitV3AttachRequest `json:"v3,omitempty"`
}

// The daemon receives mutual-TLS identity and the exact route revision.
type fskitV3AttachRequest struct {
	ClientCertPEM  string                         `json:"clientCertPem"`
	ClientKeyPEM   string                         `json:"clientKeyPem"`
	RoutesRevision string                         `json:"routesRevision"`
	Enrollment     *fskitV3MountEnrollmentRequest `json:"enrollment,omitempty"`
}

type fskitV3MountEnrollmentRequest struct {
	ManagerURL                      string `json:"managerUrl"`
	ManagerServerName               string `json:"managerServerName"`
	ManagerCAPEM                    string `json:"managerCaPem"`
	EnrollmentID                    string `json:"enrollmentId"`
	EnrollmentCertificatePEM        string `json:"enrollmentCertificatePem"`
	AuthorityGeneration             uint64 `json:"authorityGeneration"`
	InitialAuthorizationExpiresAtMs int64  `json:"initialAuthorizationExpiresAtMs"`
}

type fskitEnsureAttachReply struct {
	AttachRef              string `json:"attachRef"`
	AuthorizationSessionID string `json:"authorizationSessionId,omitempty"`
}

func (c *fsdControl) ensureAttachDetailed(req fskitEnsureAttachRequest) (fskitEnsureAttachReply, error) {
	status, body, err := c.do(http.MethodPost, "/v2/attaches", req)
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

func (c *fsdControl) stopIfIdle() error {
	status, body, err := c.do(http.MethodPost, daemonctl.LifecycleStopIfIdlePath, nil)
	if err != nil {
		return err
	}
	return daemonctl.ValidateStopIfIdleResponse(status, body)
}

func (c *fsdControl) lifecycleInventory() (daemonctl.LifecycleInventory, error) {
	status, body, err := c.do(http.MethodGet, daemonctl.LifecycleInventoryPath, nil)
	if err != nil {
		return daemonctl.LifecycleInventory{}, err
	}
	if status != http.StatusOK {
		return daemonctl.LifecycleInventory{}, controlError(status, body)
	}
	return daemonctl.DecodeLifecycleInventory(body)
}

// Outgoing service quiescence uses its authenticated release coordinates.
// The operational control version is reported by that release, never supplied
// from this CLI's compiled pairing expectations.
func (c *fsdControl) requireOutgoingIdentityWithin(expected daemonctl.Identity, timeout time.Duration) error {
	c.expectedPeerSHA256 = expected.ExecutableSHA256
	actual, err := c.identityWithin(timeout)
	if err != nil {
		return err
	}
	if actual.SchemaVersion != expected.SchemaVersion || actual.DaemonVersion != expected.DaemonVersion || actual.ExecutableSHA256 != expected.ExecutableSHA256 || actual.PFSLocalMajor != expected.PFSLocalMajor || actual.PFSLocalMinor != expected.PFSLocalMinor {
		return fmt.Errorf("outgoing portablefsd identity does not match the authenticated release")
	}
	return nil
}

func (c *fsdControl) forceDetach(ref string) error {
	status, body, err := c.do(http.MethodPost, "/v2/attaches/"+url.PathEscape(ref)+"/unmount?force=1", nil)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent {
		return controlError(status, body)
	}
	return nil
}

// cliAttachStatus is the slice of portablefsd's attach status the CLI reads
// for `portablefs mounts` and `portablefs doctor`.
type cliAttachStatus struct {
	AttachRef string `json:"attachRef"`
	MountPath string `json:"mountPath"`
	VolumeID  string `json:"volumeId"`
	State     string `json:"state"`
	LastError string `json:"lastError"`
	// SessionTerminal is the daemon's machine-readable verdict that this
	// attach's v3 authority session ended permanently; the mount supervisor's
	// revocation watchdog branches on it.
	SessionTerminal           bool   `json:"sessionTerminal"`
	MountEnrollmentID         string `json:"mountEnrollmentId,omitempty"`
	AuthorizationDeadlineAtMs int64  `json:"authorizationDeadlineAtMs,omitempty"`
	LastReauthorizationAtMs   int64  `json:"lastReauthorizationAtMs,omitempty"`
	NextReauthorizationAtMs   int64  `json:"nextReauthorizationAtMs,omitempty"`
	ReauthorizationFailures   uint64 `json:"reauthorizationFailures,omitempty"`
	ReauthorizationError      string `json:"reauthorizationError,omitempty"`
}

// errFskitAttachIdentityMismatch marks a daemon attach that carries the
// recorded ref but different coordinates. No flag ever overrides it: the ref
// describes somebody else's mount and there is no correct way to detach it.
var errFskitAttachIdentityMismatch = errors.New("recorded FSKit attach identity mismatch")

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
			attach.VolumeID != st.VolumeID {
			return nil, fmt.Errorf(
				"%w: attach %s: daemon has %s at %s, record has %s at %s",
				errFskitAttachIdentityMismatch,
				st.AttachRef,
				attach.VolumeID,
				attach.MountPath,
				st.VolumeID,
				st.MountPath,
			)
		}
		return attach, nil
	}
	return nil, nil
}

func (c *fsdControl) listAttaches() ([]cliAttachStatus, error) {
	status, body, err := c.do(http.MethodGet, "/v2/attaches", nil)
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

func (c *fsdControl) preflightAttach(ref string) error {
	status, body, err := c.do(
		http.MethodPost,
		"/v2/attaches/"+url.PathEscape(ref)+"/frontend-preflight",
		nil,
	)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

func (c *fsdControl) requireNativeFrontendReady(ref string) error {
	status, body, err := c.do(
		http.MethodPost,
		"/v2/attaches/"+url.PathEscape(ref)+"/native-frontend-ready",
		nil,
	)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

func (c *fsdControl) unmountAttach(ref string) error {
	status, body, err := c.do(http.MethodPost, "/v2/attaches/"+url.PathEscape(ref)+"/unmount", nil)
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

func (c *fsdControl) reauthorizeCredential(ref, token string, expiresAtMs int64, sequence uint64, clientCertificatePEM string) (time.Time, error) {
	if sequence == 0 || clientCertificatePEM == "" {
		return time.Time{}, fmt.Errorf("complete hosted reauthorization credential is required")
	}
	status, body, err := c.do(http.MethodPost, "/v2/attaches/"+url.PathEscape(ref)+"/credential",
		map[string]any{
			"authToken": token, "authTokenExpiresAtMs": expiresAtMs,
			"authSequence": sequence, "clientCertPem": clientCertificatePEM,
		})
	if err != nil {
		return time.Time{}, err
	}
	if status < 200 || status >= 300 {
		return time.Time{}, controlError(status, body)
	}
	var response struct {
		AuthorizationDeadlineUnixMs int64 `json:"authorizationDeadlineUnixMs"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return time.Time{}, fmt.Errorf("decode portablefsd reauthorization result: %w", err)
	}
	if response.AuthorizationDeadlineUnixMs == 0 {
		return time.Time{}, fmt.Errorf("portablefsd did not report the installed authorization deadline")
	}
	return time.UnixMilli(response.AuthorizationDeadlineUnixMs), nil
}

func (c *fsdControl) unmountRecordedAttach(st *mountState) error {
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

const macOSPortableFSDRelativePath = "Library/LaunchAgents/PortableFSDService.app/Contents/MacOS/portablefsd"

// exactPortablefsdPath resolves only the daemon inside the sealed service app
// belonging to the exact host that contains this CLI. The CLI is intentionally
// not a sibling of the daemon: the app-like wrapper is what lets
// ServiceManagement launch the entitled daemon under its own release identity.
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
	helpers := filepath.Dir(resolved)
	if filepath.Base(helpers) != "Helpers" {
		return "", fmt.Errorf("portablefs executable is not sealed under Contents/Helpers: %s", resolved)
	}
	contents := filepath.Dir(helpers)
	if filepath.Base(contents) != "Contents" {
		return "", fmt.Errorf("portablefs executable is not sealed under an app Contents directory: %s", resolved)
	}
	return filepath.Join(contents, filepath.FromSlash(macOSPortableFSDRelativePath)), nil
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

// ensurePortablefsd adopts a healthy daemon on the external owner-private
// control socket. When none answers it wakes the exact containing host app;
// only that app may register/start the ServiceManagement agent that holds the
// Data Vault token needed for the FSKit frontend socket. There is deliberately
// no direct CLI spawn path or app-group access fallback.
func ensurePortablefsd(cfg fskitConfig, stateRoot, cliVersion string) (*fsdControl, error) {
	expectedControl := filepath.Join(stateRoot, "portablefsd", "control.sock")
	if cfg.controlSock != expectedControl {
		return nil, fmt.Errorf(
			"portablefsd control socket %q does not match canonical account state %q",
			cfg.controlSock,
			expectedControl,
		)
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
	if cfg.authenticatePeerForTest != nil {
		ctl.authenticatePeer = cfg.authenticatePeerForTest
	}
	if ctl.healthyWithin(time.Second) {
		if err := ctl.requireCompatibleIdentityWithin(cliVersion, daemon.sha256, 2*time.Second); err != nil {
			return nil, err
		}
		return ctl, nil
	}
	if err := daemon.validate(); err != nil {
		return nil, err
	}
	if err := launchExactPortableFSHost(); err != nil &&
		!errors.Is(err, apphost.ErrLaunchCompletionAmbiguous) {
		return nil, fmt.Errorf(
			"wake the exact PortableFS host for its launchd-managed daemon: %w",
			err,
		)
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		probeTimeout := min(250*time.Millisecond, remaining)
		if ctl.healthyWithin(probeTimeout) {
			if err := daemon.validate(); err != nil {
				return nil, err
			}
			if err := ctl.requireCompatibleIdentityWithin(
				cliVersion,
				daemon.sha256,
				min(2*time.Second, remaining),
			); err != nil {
				return nil, err
			}
			return ctl, nil
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			break
		}
		time.Sleep(min(150*time.Millisecond, remaining))
	}
	return nil, fmt.Errorf(
		"launchd-managed portablefsd did not become healthy on %s within 15s; open PortableFS to review Background Items approval",
		cfg.controlSock,
	)
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
	if cfg.authenticatePeerForTest != nil {
		ctl.authenticatePeer = cfg.authenticatePeerForTest
	}
	if !ctl.healthy() {
		return nil, fmt.Errorf("portablefsd is not healthy on %s", cfg.controlSock)
	}
	if err := ctl.requireCompatibleIdentity(cliVersion, daemon.sha256); err != nil {
		return nil, err
	}
	return ctl, nil
}

type fskitMountFailure string

const (
	fskitFailureUnknown        fskitMountFailure = ""
	fskitFailureResourceLoad   fskitMountFailure = "resource-load"
	fskitFailureModuleMissing  fskitMountFailure = "module-unavailable"
	fskitFailureFinalMountStep fskitMountFailure = "final-mount-step"
)

// classifyFSKitMountFailure recognizes only evidence that distinguishes a
// reached extension from the legacy mount-helper fallback. Generic errno text
// is intentionally left unknown: the same errno can be produced by unrelated
// mount point, policy, resource, and extension failures.
//
// Ordering is evidence-strength, not likelihood. mount(8) ALWAYS falls
// through to the legacy helper when its FSKit path fails, so the
// helper-missing lines appear in every FSKit failure and are only meaningful
// when nothing more specific preceded them. Classifying by the fallback text
// first once reported a completed module resolution and activation — the
// failure was in the final mount step, host-side — as "the extension may
// need to be enabled", which sends the operator to a Settings toggle that is
// already on.
func classifyFSKitMountFailure(fsType, message string) fskitMountFailure {
	if strings.Contains(message, "Final mount step") {
		return fskitFailureFinalMountStep
	}
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
	case fskitFailureFinalMountStep:
		return fmt.Errorf("%w\nthe %q FSKit module resolved and its extension activated, but macOS failed the final mount step itself; this is FSKit host state, not PortableFS configuration — a record left by an abnormally ended mount can wedge fskitd until it is restarted (sudo pkill fskitd; it relaunches on demand) or the machine reboots", err, fsType)
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
