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
	fskitTypeEnv    = "PORTABLEFS_FSKIT_TYPE"
	fskitSocketEnv  = "PORTABLEFS_FSKIT_SOCKET"
	fskitControlEnv = "PORTABLEFS_FSKIT_CONTROL_SOCKET"
	fskitDaemonEnv  = "PORTABLEFS_FSKIT_DAEMON"

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
	fsType            string
	controlSock       string
	daemonPathForTest string // tests inject a peer without adding a production override
	legacyStateDir    string // empty only in isolated tests
}

func fskitConfigFromEnv(getenv func(string) string) (fskitConfig, error) {
	controlSocket, err := defaultFskitControlSocket()
	if err != nil {
		return fskitConfig{}, err
	}
	cfg := fskitConfig{
		fsType:      defaultFskitType,
		controlSock: controlSocket,
	}
	if daemonOverride := getenv(fskitDaemonEnv); daemonOverride != "" {
		return fskitConfig{}, fmt.Errorf(
			"%s is unsupported: portablefsd must be the exact sibling embedded with this portablefs executable",
			fskitDaemonEnv,
		)
	}
	for _, variable := range []string{fskitSocketEnv, fskitControlEnv} {
		if value := getenv(variable); value != "" {
			return fskitConfig{}, fmt.Errorf(
				"%s is unsupported: FSKit sockets are fixed by this release's signed app-group identity",
				variable,
			)
		}
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
	return c.requireExactIdentityWithin(daemonctl.Identity{
		SchemaVersion:    daemonctl.IdentitySchemaVersion,
		ControlProtocol:  daemonctl.ControlProtocolVersion,
		DaemonVersion:    cliVersion,
		ExecutableSHA256: executableSHA256,
		PFSLocalMajor:    pfslocal.ProtocolMajor,
		PFSLocalMinor:    pfslocal.ProtocolMinor,
	}, timeout)
}

// requireExactIdentityWithin proves every private paired-release axis before
// the CLI sends an operational control request. Service replacement may pass
// the previously registered identity here after the app bundle has changed;
// that permits read-only attach inventory of exactly that old release without
// trusting or executing an old path.
func (c *fsdControl) requireExactIdentityWithin(
	expected daemonctl.Identity,
	timeout time.Duration,
) error {
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

type fskitEnsureAttachRequest struct {
	AttachRef    string `json:"attachRef"`
	VolumeID     string `json:"volumeId"`
	Branch       string `json:"branch"`
	AuthorityURL string `json:"authorityUrl"`
	AuthToken    string `json:"authToken"`
	// AuthTokenExpiresAtMs is the access lease's own stated expiry for
	// AuthToken (unix ms), the deadline that bounds the daemon-side UNPROVEN
	// credential state. Omitted (0) states no deadline.
	AuthTokenExpiresAtMs int64              `json:"authTokenExpiresAtMs,omitempty"`
	DataPlaneTransport   string             `json:"dataPlaneTransport"`
	DataPlaneServerName  string             `json:"dataPlaneServerName,omitempty"`
	TLSCAPEM             string             `json:"tlsCaPem,omitempty"`
	TLSCASHA256          string             `json:"tlsCaSha256,omitempty"`
	MountPath            string             `json:"mountPath"`
	Options              fskitAttachOptions `json:"options"`
	// V3 selects the daemon-owned authority-v3 attach (portablefsd's
	// v3AttachRequest; see vcs/internal/portablefsd/v3attach.go). The daemon —
	// never the FSKit extension — receives the mutual-TLS identity and dials
	// the authority with it.
	V3 *fskitV3AttachRequest `json:"v3,omitempty"`
}

// fskitV3AttachRequest mirrors portablefsd's v3AttachRequest JSON: the
// mutual-TLS identity the daemon presents, the two numbers the authority
// sizes the visibility barrier from, the declared coherence policy, and the
// 64-hex routing revision this mount runs.
type fskitV3AttachRequest struct {
	ClientCertPEM      string                         `json:"clientCertPem"`
	ClientKeyPEM       string                         `json:"clientKeyPem"`
	CachedNameCapacity uint64                         `json:"cachedNameCapacity"`
	RepairBudgetMillis uint64                         `json:"repairBudgetMillis"`
	CachePolicy        string                         `json:"cachePolicy"`
	RoutesRevision     string                         `json:"routesRevision"`
	Enrollment         *fskitV3MountEnrollmentRequest `json:"enrollment,omitempty"`
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
	AttachRef              string   `json:"attachRef"`
	AuthorizationSessionID string   `json:"authorizationSessionId,omitempty"`
	LocalDirs              []string `json:"localDirs,omitempty"`
	LocalDirsDeclared      bool     `json:"localDirsDeclared,omitempty"`
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
	AttachRef string `json:"attachRef"`
	MountPath string `json:"mountPath"`
	VolumeID  string `json:"volumeId"`
	Branch    string `json:"branch"`
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
			attach.VolumeID != st.VolumeID ||
			attach.Branch != st.Branch {
			return nil, fmt.Errorf(
				"%w: attach %s: daemon has %s@%s at %s, record has %s@%s at %s",
				errFskitAttachIdentityMismatch,
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
// bindMountRoot tells the daemon to open and keep this attach's kernel mount
// root. It is called exactly once, immediately after the mount is proven
// present and serving: the macOS repair actuator runs through the daemon, and
// a daemon that opened the root by path during a coherence barrier would be
// asking the extension to serve a callback for the repair it is waiting on.
func (c *fsdControl) bindMountRoot(ref string) error {
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/bind-root", nil)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return controlError(status, body)
	}
	return nil
}

// preflightAttach asks the authorized daemon to exercise the exact frontend
// socket itself. The shell CLI deliberately cannot dial the Data Vault path.
func (c *fsdControl) preflightAttach(ref string) error {
	status, body, err := c.do(
		http.MethodPost,
		"/v1/attaches/"+url.PathEscape(ref)+"/frontend-preflight",
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

// requireNativeFrontendReady asks portablefsd to attest a live shipping
// `portablefskit` connection which has completed Resolve for this exact native
// attach. Unlike legacy bind-root, this performs no I/O through the mounted
// path and creates no repair-root descriptor channel.
func (c *fsdControl) requireNativeFrontendReady(ref string) error {
	status, body, err := c.do(
		http.MethodPost,
		"/v1/attaches/"+url.PathEscape(ref)+"/native-frontend-ready",
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

func (c *fsdControl) setCredential(ref, token string, expiresAtMs int64) error {
	return c.setCredentialWithMode(ref, token, expiresAtMs, false)
}

func (c *fsdControl) setCredentialIfPending(ref, token string, expiresAtMs int64) error {
	return c.setCredentialWithMode(ref, token, expiresAtMs, true)
}

func (c *fsdControl) reauthorizeCredential(ref, token string, expiresAtMs int64, sequence uint64, clientCertificatePEM string) (time.Time, error) {
	if sequence == 0 || clientCertificatePEM == "" {
		return time.Time{}, fmt.Errorf("complete hosted reauthorization credential is required")
	}
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/credential",
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

// setCredentialWithMode pushes the credential AND the deadline its issuer
// stated for it. The expiry is what bounds the daemon-side UNPROVEN state; a
// zero states no deadline and preserves the pre-expiry behaviour exactly.
func (c *fsdControl) setCredentialWithMode(ref, token string, expiresAtMs int64, onlyIfPending bool) error {
	status, body, err := c.do(http.MethodPost, "/v1/attaches/"+url.PathEscape(ref)+"/credential",
		map[string]any{"authToken": token, "authTokenExpiresAtMs": expiresAtMs, "onlyIfPending": onlyIfPending})
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
		if err := c.setCredentialIfPending(st.AttachRef, st.AccessLease.AccessToken, st.AccessLease.ExpiresAtMs); err != nil {
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
