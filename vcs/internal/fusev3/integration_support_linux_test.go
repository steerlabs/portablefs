//go:build linux

package fusev3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

const (
	envXFSRoot    = "PORTABLEFS_XFS_TEST_ROOT"
	envXFSProject = "PORTABLEFS_XFS_TEST_PROJECT"
	envFUSE       = "PORTABLEFS_FUSE_TEST"
	envWorkload   = "PORTABLEFS_WORKLOAD_TEST"
	// envRequired is set by the privileged CI job. It converts every gate that
	// would otherwise skip into a hard failure.
	envRequired  = "PORTABLEFS_XFS_TEST_REQUIRED"
	envFUSEDebug = "PORTABLEFS_FUSE_DEBUG"
)

type integrationEnv struct {
	xfsRoot   string
	projectID uint32
}

// requireIntegrationEnvironment resolves the privileged XFS and FUSE gates.
//
// Developers may still run this suite by hand with the gates unset, in which
// case it skips. CI sets PORTABLEFS_XFS_TEST_REQUIRED=1, and from then on an
// unprovisioned filesystem, a missing FUSE device, or a root-owned test process
// is a loud failure instead of a skip. A silently skipped privileged test is
// precisely how this suite reached production without ever having run.
func requireIntegrationEnvironment(t *testing.T) integrationEnv {
	t.Helper()
	root, project, fuse := os.Getenv(envXFSRoot), os.Getenv(envXFSProject), os.Getenv(envFUSE)
	required := os.Getenv(envRequired) == "1"
	if root == "" || project == "" || fuse != "1" {
		if required {
			t.Fatalf("%s=1 but the privileged gates are incomplete: %s=%q %s=%q %s=%q",
				envRequired, envXFSRoot, root, envXFSProject, project, envFUSE, fuse)
		}
		t.Skipf("privileged gates are not configured; set %s, %s and %s=1", envXFSRoot, envXFSProject, envFUSE)
	}
	// default_permissions delegates every access decision to the kernel using the
	// attributes this mount reports. Root bypasses all of it through
	// CAP_DAC_OVERRIDE, so a root-owned run would report success for permission
	// assertions it never actually made.
	if required && os.Geteuid() == 0 {
		t.Fatalf("%s=1 requires the unprivileged volume identity; running as root makes every DAC assertion vacuous", envRequired)
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatalf("%s must be an absolute clean path, got %q", envXFSRoot, root)
	}
	parsed, err := strconv.ParseUint(project, 10, 32)
	if err != nil {
		t.Fatalf("%s=%q is not a uint32: %v", envXFSProject, project, err)
	}
	return integrationEnv{xfsRoot: root, projectID: uint32(parsed)}
}

// requireWorkloadEnvironment gates the real-application workloads, which need
// git and sqlite3 on PATH in addition to the privileged filesystem.
func requireWorkloadEnvironment(t *testing.T) integrationEnv {
	t.Helper()
	env := requireIntegrationEnvironment(t)
	if os.Getenv(envWorkload) != "1" {
		if os.Getenv(envRequired) == "1" {
			t.Fatalf("%s=1 but %s is not set to 1", envRequired, envWorkload)
		}
		t.Skipf("application workload gate is not configured; set %s=1", envWorkload)
	}
	for _, tool := range []string{"git", "sqlite3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s=1 requires %s on PATH: %v", envWorkload, tool, err)
		}
	}
	return env
}

const (
	integrationVolumeID       = "integration-volume"
	integrationRequestTimeout = 10 * time.Second
	integrationMaxFrame       = 4 << 20
	integrationReplaySlots    = 64
	integrationMaxInFlight    = 64
	// The transport refuses to run unless the handler advertises exactly the
	// bounds the server enforces, so these are shared by both.
	integrationServerInFlight = 128
	// Frame allocation budget and retained-reply budget. Both must comfortably
	// admit one maximal request and one maximal reply.
	integrationAllocationBudget = 64 << 20
	// The strict cache commitment every mount in this fixture declares.
	integrationCachedNames  = 4096
	integrationRepairBudget = 20 * time.Second
	// The protocol-6 cache-authority bounds, at the production defaults.
	integrationCacheLeaseTTL         = volumeserver.Protocol6MaxLeaseTTL
	integrationCacheLeasesPerSession = 65536
	integrationCacheLeases           = 1 << 20

	// Match the production authority's bounded standard-WRITE admission
	// profile without making the integration fixture a weaker peer than the
	// mount it is qualifying.
	integrationWriteBytesPerSession    = 16 << 30
	integrationWriteBytes              = 64 << 30
	integrationWritesPerSession        = 8
	integrationWrites                  = 4096
	integrationWriteProgressTimeout    = 2 * time.Minute
	integrationWriteAbsoluteTimeout    = 30 * time.Minute
	integrationTerminalDeliveryTimeout = 45 * time.Second
)

type integrationAuthorizer struct{ now func() time.Time }

func (a integrationAuthorizer) Authorize(context.Context, string, []byte) (volumeserver.Authorization, error) {
	// The signed authorization deadline is deliberately far beyond anything a
	// test advances the clock to, so lease expiry is what the session tests
	// observe rather than an incidentally expired grant.
	return volumeserver.Authorization{
		Access:   volumeserver.AccessRead | volumeserver.AccessWrite,
		Deadline: a.now().Add(24 * time.Hour),
	}, nil
}

type integrationConfig struct {
	// Mounts is the number of independent kernel FUSE mounts of the same
	// volume. Defaults to two, the minimum needed to observe coherence.
	Mounts int
	// SessionLease overrides the authority session lease. Only the session
	// lifecycle tests need a short one.
	SessionLease time.Duration
	// Routes is the machine-local route declaration every mount in this fixture
	// activates, in the syntax the volume file carries. Empty means the volume
	// declares nothing and every path is served from the authority.
	Routes string

	// rules is the compiled form of Routes, derived in newIntegrationFixture.
	rules localroutes.RuleSet
}

// recordingMembership is the durable control-plane record the coordinator
// requires, plus the one thing a test needs that production gets from its own
// transport: the session ID the authority just registered. Activate is called
// inside attach, before the reply is written, so the fixture can pair it with
// the client it is dialling.
type recordingMembership struct {
	mu      sync.Mutex
	active  map[volumeserver.SessionID]struct{}
	ordered []volumeserver.SessionID
}

func newRecordingMembership() *recordingMembership {
	return &recordingMembership{active: make(map[volumeserver.SessionID]struct{})}
}

func (m *recordingMembership) Activate(id volumeserver.SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[id] = struct{}{}
	m.ordered = append(m.ordered, id)
	return nil
}

func (m *recordingMembership) Deactivate(id volumeserver.SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, id)
	return nil
}

func (m *recordingMembership) last() (volumeserver.SessionID, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.ordered) == 0 {
		return volumeserver.SessionID{}, false
	}
	return m.ordered[len(m.ordered)-1], true
}

func (m *recordingMembership) activeCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.active)
}

// integrationTransport is the fixture's equivalent of the production mount
// binary's adapter: it carries the session identity the frontend needs to
// recognise its own mutations, and the mount-absence evidence a strict detach
// requires.
type integrationTransport struct {
	*authorityrpc.Client
	session        []byte
	hookMu         sync.Mutex
	beforeMutation func(*authoritypb.Request)
	afterMutation  func(*authoritypb.Request, *authoritypb.Response, error)
}

func (t *integrationTransport) SessionID() []byte { return append([]byte(nil), t.session...) }

func (t *integrationTransport) DetachAfterUnmount(ctx context.Context, proof MountAbsenceProof) error {
	return t.Client.DetachAfterUnmount(ctx, &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: proof.ObservedUnixNanos,
		Observation:       proof.Observation,
		Component:         proof.Component,
	})
}

func (t *integrationTransport) CallMutationWithIdentityRetained(
	ctx context.Context,
	request *authoritypb.Request,
	assigned authorityrpc.MutationAssigned,
	force func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	t.hookMu.Lock()
	before := t.beforeMutation
	t.hookMu.Unlock()
	if before != nil {
		before(request)
	}
	response, consumption, err := t.Client.CallMutationWithIdentityRetained(ctx, request, assigned, force)
	t.hookMu.Lock()
	after := t.afterMutation
	t.hookMu.Unlock()
	if after != nil {
		after(request, response, err)
	}
	return response, consumption, err
}

func (t *integrationTransport) setBeforeMutation(before func(*authoritypb.Request)) {
	t.hookMu.Lock()
	t.beforeMutation = before
	t.hookMu.Unlock()
}

func (t *integrationTransport) setAfterMutation(after func(*authoritypb.Request, *authoritypb.Response, error)) {
	t.hookMu.Lock()
	t.afterMutation = after
	t.hookMu.Unlock()
}

// integrationFixture is one complete authority: a real XFS project directory, a
// volumeserver epoch, a TLS authority RPC server, and N kernel FUSE mounts of
// that single volume. Teardown unwinds strictly in reverse (mounts, then the
// server, then the XFS handle), because a mount that outlives its authority
// would deadlock the unmount it needs to complete.
type integrationFixture struct {
	t   *testing.T
	cfg integrationConfig
	env integrationEnv

	// volumeRoot is a dedicated directory inside the provisioned XFS project.
	// XFS propagates both the project ID and FS_XFLAG_PROJINHERIT to children,
	// so every test gets an isolated tree that still satisfies xfsstore's
	// production project gate, no test can observe another test's names, and the
	// exclusive lock xfsstore takes on a volume root never collides.
	volumeRoot string
	// writeStagingRoot is a sibling of volumeRoot. It inherits the provisioned
	// XFS project but is outside the authoritative namespace, so inert payloads
	// can only exist in private unnamed O_TMPFILE stages.
	writeStagingRoot string
	writeAdmission   *authorityrpc.WriteAdmission
	paths            []string
	// backing is one per-machine tree per mount: these mounts stand in for
	// different machines, and machine-local storage is not shared between them.
	backing []string

	serverTLS *tls.Config
	clientTLS *tls.Config

	// clockSkew drives the authority's clock. Advancing it ages session leases
	// without making the test sleep for real.
	clockSkew atomic.Int64

	store      *xfsstore.Volume
	routes     *authorityrpc.RoutesController
	authority  *volumeserver.Authority
	membership *recordingMembership
	counter    *countingHandler
	listener   net.Listener
	stopServe  context.CancelFunc
	served     chan error
	stopped    bool

	clients    []*authorityrpc.Client
	transports []*integrationTransport
	mounts     []*Mount
}

func newIntegrationFixture(t *testing.T, cfg integrationConfig) *integrationFixture {
	t.Helper()
	if cfg.Mounts <= 0 {
		cfg.Mounts = 2
	}
	if cfg.SessionLease <= 0 {
		cfg.SessionLease = time.Minute
	}
	rules, err := ActivateRoutes([]byte(cfg.Routes))
	if err != nil {
		t.Fatalf("compile route declaration: %v", err)
	}
	cfg.rules = rules
	env := requireIntegrationEnvironment(t)
	f := &integrationFixture{t: t, cfg: cfg, env: env}
	f.serverTLS, f.clientTLS = integrationTLS(t)

	f.volumeRoot = filepath.Join(env.xfsRoot, integrationVolumeDirectory(t))
	if err := os.Mkdir(f.volumeRoot, 0o700); err != nil {
		t.Fatalf("create per-test volume root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(f.volumeRoot); err != nil {
			t.Errorf("remove per-test volume root: %v", err)
		}
	})
	f.writeStagingRoot = f.volumeRoot + ".write-staging"
	if err := os.Mkdir(f.writeStagingRoot, 0o700); err != nil {
		t.Fatalf("create per-test write staging root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(f.writeStagingRoot); err != nil {
			t.Errorf("remove per-test write staging root: %v", err)
		}
	})
	f.writeAdmission, err = authorityrpc.OpenWriteAdmission(f.writeStagingRoot)
	if err != nil {
		t.Fatalf("open per-test write staging root: %v", err)
	}
	t.Cleanup(f.closeWriteStaging)

	mountRoot := t.TempDir()
	for i := range cfg.Mounts {
		path := filepath.Join(mountRoot, fmt.Sprintf("mount-%d", i))
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("create mountpoint: %v", err)
		}
		f.paths = append(f.paths, path)
		// Machine-local backing is per MACHINE, and these mounts stand in for
		// different machines, so each gets its own tree. Sharing one would make
		// a graft look coherent across mounts, which is the one thing it is not
		// and must never appear to be.
		backing := filepath.Join(mountRoot, fmt.Sprintf("local-%d", i))
		if err := os.Mkdir(backing, 0o700); err != nil {
			t.Fatalf("create machine-local backing: %v", err)
		}
		f.backing = append(f.backing, backing)
	}

	t.Cleanup(f.shutdown)
	f.start()
	return f
}

// integrationVolumeDirectory derives a collision-free directory name so that
// repeated runs (-count=N) and every test in the package stay isolated inside
// the one provisioned XFS cell.
func integrationVolumeDirectory(t *testing.T) string {
	sanitized := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, t.Name())
	if len(sanitized) > 96 {
		sanitized = sanitized[:96]
	}
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	return sanitized + "." + hex.EncodeToString(suffix[:])
}

func (f *integrationFixture) now() time.Time {
	return time.Now().Add(time.Duration(f.clockSkew.Load()))
}

// advanceClock ages the authority's view of time. Session leases are evaluated
// against it, so this expires leases deterministically instead of sleeping.
func (f *integrationFixture) advanceClock(d time.Duration) { f.clockSkew.Add(int64(d)) }

// sweepSessions runs the authority's lease sweeper, the same call a production
// worker schedules.
func (f *integrationFixture) sweepSessions() int { return f.authority.Sweep() }

func (f *integrationFixture) mountPath(i int) string { return f.paths[i] }

// join builds a path to the same volume object as seen through mount i.
func (f *integrationFixture) join(i int, elements ...string) string {
	return filepath.Join(append([]string{f.paths[i]}, elements...)...)
}

func (f *integrationFixture) start() {
	t := f.t
	t.Helper()
	store, err := xfsstore.Open(f.volumeRoot, xfsstore.Config{
		ExpectedProjectID: f.env.projectID,
		ExpectedOwnerUID:  uint32(os.Geteuid()),
		ExpectedOwnerGID:  uint32(os.Getegid()),
	})
	if err != nil {
		t.Fatalf("open XFS volume %s: %v", f.volumeRoot, err)
	}
	f.store = store
	authority, err := volumeserver.New(integrationVolumeID, volumeserver.Config{
		SessionLease: f.cfg.SessionLease, MaxReplaySlots: integrationReplaySlots,
		MaxSessions: 8, MaxLockRecords: 4096, Now: f.now,
	})
	if err != nil {
		t.Fatalf("create authority epoch: %v", err)
	}
	f.authority = authority
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f.listener = listener
	f.membership = newRecordingMembership()
	// The authority is the source of truth for the volume's machine-local
	// routing revision, and it refuses every mount whose declared revision is
	// not the active one. The fixture therefore installs the declaration these
	// mounts are about to agree with, through the same assembly and the same
	// barrier a live operator's change would use.
	coordination, err := authorityrpc.NewCoordination(authorityrpc.CoordinationConfig{
		Store: store, Fencer: authority, Locks: authority.Locks(), Membership: f.membership,
		Prior: volumeserver.PriorEpochStrictMountsFenced, ClockSkew: time.Minute,
		MaxCachedNameCapacity: integrationCachedNames, MaxRepairBudget: time.Minute,
		CacheLeaseTTL: integrationCacheLeaseTTL, MaxCacheLeasesPerSession: integrationCacheLeasesPerSession,
		MaxCacheLeases: integrationCacheLeases, Now: f.now,
	})
	if err != nil {
		t.Fatalf("assemble authority coordination: %v", err)
	}
	routes := coordination.Routes
	active, err := routes.Revision()
	if err != nil {
		t.Fatalf("read the active routing revision: %v", err)
	}
	if _, err := routes.Apply(context.Background(), []byte(f.cfg.Routes), active); err != nil {
		t.Fatalf("install the routing declaration: %v", err)
	}
	f.routes = routes
	handler := &authorityrpc.VolumeHandler{
		Store: store, Runtime: authority, Authorizer: integrationAuthorizer{now: f.now},
		MaxFrame: integrationMaxFrame, MaxRead: 1 << 20, MaxWrite: 1 << 20,
		MaxInFlight:        integrationServerInFlight,
		MaxItemsPerSession: 4096, MaxOpensPerSession: 4096, MaxItems: 16384, MaxOpens: 16384,
		MaxRetainedReplyBytes:         integrationAllocationBudget,
		WriteAdmission:                f.writeAdmission,
		MaxWriteBytesPerSession:       integrationWriteBytesPerSession,
		MaxWriteBytesInFlight:         integrationWriteBytes,
		MaxWritesPerSession:           integrationWritesPerSession,
		MaxWrites:                     integrationWrites,
		WriteAdmissionProgressTimeout: integrationWriteProgressTimeout,
		WriteAbsoluteTimeout:          integrationWriteAbsoluteTimeout,
		TerminalDeliveryTimeout:       integrationTerminalDeliveryTimeout,
	}
	coordination.Bind(handler)
	f.counter = &countingHandler{inner: handler}
	ctx, cancel := context.WithCancel(context.Background())
	f.stopServe, f.served, f.stopped = cancel, make(chan error, 1), false
	served := f.served
	go func() {
		served <- (&authorityrpc.Server{
			Handler: f.counter, MaxFrame: integrationMaxFrame,
			MaxInFlight: integrationServerInFlight, MaxConnections: 16,
			MaxFrameBytesInFlight: integrationAllocationBudget,
			HandshakeTimeout:      5 * time.Second, IdleTimeout: 2 * time.Minute, WriteTimeout: 30 * time.Second,
		}).Serve(ctx, listener, f.serverTLS)
	}()

	f.mountAll()
}

// mountAll installs every mountpoint against the running authority, each
// declaring the routing revision the fixture currently carries.
func (f *integrationFixture) mountAll() {
	t := f.t
	t.Helper()
	for i := range f.paths {
		client, transport := f.dialClient()
		mountInstanceID, err := mountid.NewMountInstance()
		if err != nil {
			t.Fatalf("create mount %d identity: %v", i, err)
		}
		mount, err := MountVolume(context.Background(), f.paths[i], transport, Config{
			MountInstanceID: mountInstanceID, RequestTimeout: integrationRequestTimeout,
			MaxBackground: 64, ReclaimQueue: 1024,
			// The frontend reserves its liveness, cleanup, and visibility lanes
			// out of this number, so it must be exactly the transport's bound.
			MaxInFlight:  integrationMaxInFlight,
			PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
			Coherence: CoherenceStrict, CachedNameCapacity: integrationCachedNames,
			RepairBudget: integrationRepairBudget,
			Routes:       f.cfg.rules, LocalBacking: f.backing[i],
			Debug: os.Getenv(envFUSEDebug) == "1",
		})
		if err != nil {
			t.Fatalf("mount %s: %v", f.paths[i], err)
		}
		f.clients = append(f.clients, client)
		f.transports = append(f.transports, transport)
		f.mounts = append(f.mounts, mount)
	}
}

func (f *integrationFixture) dialClient() (*authorityrpc.Client, *integrationTransport) {
	f.t.Helper()
	cfg := authorityrpc.ClientConfig{
		Purpose:         authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT,
		FrontendProfile: authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES,
		Address:         f.listener.Addr().String(), TLS: f.clientTLS.Clone(), VolumeID: integrationVolumeID,
		AccessToken: []byte("test-capability"), ReplaySlots: integrationReplaySlots,
		MaxFrame: integrationMaxFrame, DialTimeout: 5 * time.Second,
		CancelDrainTimeout: 5 * time.Second, MaxInFlight: integrationMaxInFlight,
	}
	// Every mount declares the routing it is about to serve. The authority
	// refuses a mount whose revision is not the volume's active one.
	cfg.RoutesRevision = f.cfg.rules.Revision()
	cfg.RequireLocalSessionEnforcement = true
	cfg.ObservePreKernelMountAbsence = func(context.Context) (*authoritypb.MountAbsenceProof, error) {
		return &authoritypb.MountAbsenceProof{
			ObservedUnixNanos: time.Now().UnixNano(),
			Observation:       []byte("integration fixture exact unique mount source absent before mount"),
			Component:         "fusev3-integration-test/mount-inventory",
		}, nil
	}
	client, err := authorityrpc.DialClient(context.Background(), cfg)
	if err != nil {
		f.t.Fatalf("dial authority: %v", err)
	}
	transport := &integrationTransport{Client: client}
	id, ok := f.membership.last()
	if !ok {
		f.t.Fatal("attach registered no visibility participant")
	}
	transport.session = append([]byte(nil), id[:]...)
	return client, transport
}

// stopAuthority ends the RPC server exactly as an authority process stop or
// crash would: the listener closes and every live connection dies. It is
// idempotent so a test can stop the authority deliberately and still be cleaned
// up correctly.
func (f *integrationFixture) stopAuthority() {
	t := f.t
	t.Helper()
	if f.stopped || f.stopServe == nil {
		return
	}
	f.stopped = true
	f.stopServe()
	select {
	case err := <-f.served:
		if err != nil {
			t.Errorf("authority server: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("authority server did not stop")
	}
	if err := f.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("close authority listener: %v", err)
	}
}

func (f *integrationFixture) closeStore() {
	if f.store == nil {
		return
	}
	if err := f.store.Close(); err != nil {
		f.t.Errorf("close XFS volume: %v", err)
	}
	f.store = nil
}

func (f *integrationFixture) closeWriteStaging() {
	if f.writeAdmission == nil {
		return
	}
	if err := f.writeAdmission.Close(); err != nil {
		f.t.Errorf("close write admission: %v", err)
	}
	f.writeAdmission = nil
}

// shutdown is the cleanup path. It tolerates mounts that already aborted
// themselves, because several tests deliberately destroy the authority.
func (f *integrationFixture) shutdown() {
	for i := len(f.mounts) - 1; i >= 0; i-- {
		if f.mounts[i] == nil {
			continue
		}
		if err := f.mounts[i].Unmount(); err != nil {
			_ = f.mounts[i].Close()
		}
		// Contained, not tolerated. A mount left installed after its owner has
		// released it is reported as a failure here, and then force-detached so
		// it cannot poison every later test in this binary.
		if isMounted(f.t, f.paths[i]) {
			f.t.Errorf("%s was still installed after Unmount and Close (frontend fatal cause: %v)", f.paths[i], f.mounts[i].fatalError())
			_ = exec.Command("fusermount3", "-u", "-z", f.paths[i]).Run()
		}
	}
	f.mounts, f.clients, f.transports = nil, nil, nil
	f.stopAuthority()
	f.closeStore()
	f.closeWriteStaging()
}

// unmountAll releases every mount cleanly, in protocol: each detach carries
// the mount-absence observation the authority requires before it will drop the
// session's topology obligation.
func (f *integrationFixture) unmountAll() {
	t := f.t
	t.Helper()
	for i := len(f.mounts) - 1; i >= 0; i-- {
		if err := f.mounts[i].Unmount(); err != nil {
			t.Fatalf("unmount %s: %v", f.paths[i], err)
		}
	}
	f.mounts, f.clients, f.transports = nil, nil, nil
}

// remount recreates the entire authority on the same XFS directory: mounts are
// unmounted cleanly, the RPC server stops, the volume handle closes, and a fresh
// epoch is established. Nothing but durable XFS state survives it.
func (f *integrationFixture) remount() {
	t := f.t
	t.Helper()
	f.unmountAll()
	f.stopAuthority()
	f.closeStore()
	f.start()
}

// requireSessionEnded asserts that mount i notices an unusable authority within
// bound instead of hanging, and returns the terminal cause the client reports.
func (f *integrationFixture) requireSessionEnded(i int, bound time.Duration) error {
	t := f.t
	t.Helper()
	client := f.clients[i]
	select {
	case <-client.SessionDone():
	case <-time.After(bound):
		t.Fatalf("mount %d did not observe the authority failure within %s", i, bound)
	}
	err := client.SessionError()
	if err == nil {
		t.Fatalf("mount %d ended its session without a diagnosable cause", i)
	}
	return err
}

// isMounted reports whether path is currently a mount point of this process's
// mount namespace. It is how the failure tests distinguish "the mount removed
// itself cleanly" from "the mount is still there and wedged".
func isMounted(t *testing.T, path string) bool {
	t.Helper()
	// The fixture builds mount points under t.TempDir() from characters that
	// mountinfo never escapes, so a literal comparison is exact here.
	if strings.ContainsAny(path, " \t\n\\") {
		t.Fatalf("mount point %q needs mountinfo unescaping", path)
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("read /proc/self/mountinfo: %v", err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		// Field 5 (1-based) of a mountinfo line is the mount point.
		if len(fields) >= 5 && fields[4] == path {
			return true
		}
	}
	return false
}

func waitUntil(t *testing.T, bound time.Duration, what string, ready func() bool) time.Duration {
	t.Helper()
	start := time.Now()
	for {
		if ready() {
			return time.Since(start)
		}
		if time.Since(start) > bound {
			t.Fatalf("%s did not happen within %s", what, bound)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func requireErrno(t *testing.T, err error, want syscall.Errno, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}

func requireContent(t *testing.T, path string, want []byte, what string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: read %s: %v", what, path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s: %s = %q (%d bytes), want %q (%d bytes)", what, path, truncate(got), len(got), truncate(want), len(want))
	}
}

func truncate(value []byte) string {
	if len(value) <= 64 {
		return string(value)
	}
	return string(value[:64]) + "..."
}

func requireSize(t *testing.T, path string, want int64, what string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("%s: stat %s: %v", what, path, err)
	}
	if info.Size() != want {
		t.Fatalf("%s: size of %s = %d, want %d", what, path, info.Size(), want)
	}
}

func requireAbsent(t *testing.T, path, what string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err == nil {
		t.Fatalf("%s: %s still resolves (mode %v, size %d)", what, path, info.Mode(), info.Size())
	}
	requireErrno(t, err, syscall.ENOENT, what+": lstat "+path)
}

func directoryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read directory %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names
}

func requireDirectoryNames(t *testing.T, dir string, want []string, what string) {
	t.Helper()
	sorted := slices.Clone(want)
	slices.Sort(sorted)
	got := directoryNames(t, dir)
	if !slices.Equal(got, sorted) {
		t.Fatalf("%s: listing of %s = %v, want %v", what, dir, got, sorted)
	}
}

// readExactlyAt reads through one descriptor at a fixed offset. Reusing the same
// descriptor is deliberate: it is the strongest place for a stale page or a
// cached attribute to survive a remote mutation.
func readExactlyAt(t *testing.T, file *os.File, offset int64, length int, what string) []byte {
	t.Helper()
	buffer := make([]byte, length)
	n, err := file.ReadAt(buffer, offset)
	if err != nil {
		t.Fatalf("%s: read %d bytes at %d: %v", what, length, offset, err)
	}
	return buffer[:n]
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustOpenFile(t *testing.T, path string, flags int, mode os.FileMode) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, flags, mode)
	if err != nil {
		t.Fatalf("open %s (flags %#x): %v", path, flags, err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

// runWorkload runs a real application against the mounts and, on failure,
// reports the mounts' own health. That distinguishes "the application hit a
// genuine filesystem error" from "the mount had already died underneath it",
// which are diagnosed completely differently.
func (f *integrationFixture) runWorkload(name string, args ...string) {
	f.t.Helper()
	command := exec.Command(name, args...)
	if output, err := command.CombinedOutput(); err != nil {
		f.t.Fatalf("%s %v: %v\n%s\nmount health: %s", name, args, err, output, f.sessionDiagnostics())
	}
}

// sessionDiagnostics summarises whether each mount's authority session is still
// live and, if not, why it ended.
func (f *integrationFixture) sessionDiagnostics() string {
	parts := make([]string, 0, len(f.clients))
	for i, client := range f.clients {
		var frontendErr error
		if i < len(f.mounts) && f.mounts[i] != nil {
			frontendErr = f.mounts[i].fatalError()
		}
		select {
		case <-client.SessionDone():
			parts = append(parts, fmt.Sprintf("mount %d ended: %v (frontend: %v)", i, client.SessionError(), frontendErr))
		default:
			parts = append(parts, fmt.Sprintf("mount %d live (frontend: %v)", i, frontendErr))
		}
	}
	return strings.Join(parts, "; ")
}

func integrationTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PortableFS integration CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, usages []x509.ExtKeyUsage, dns []string) tls.Certificate {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		certificate, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return certificate
	}
	serverCertificate := issue(2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	clientCertificate := issue(3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{serverCertificate}},
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{clientCertificate}, ServerName: "localhost"}
}

// countingHandler is the fixture's RPC meter. It sits where the transport
// server calls into the authority, so it counts exactly the requests that
// crossed the wire -- which is the number the whole caching argument is about.
type countingHandler struct {
	inner authorityrpc.Handler

	mu           sync.Mutex
	byKind       map[string]int
	beforeHandle func(*authoritypb.Request)
}

func (h *countingHandler) Epoch() []byte                        { return h.inner.Epoch() }
func (h *countingHandler) Bounds() authorityrpc.TransportBounds { return h.inner.Bounds() }
func (h *countingHandler) SessionStateForTransport(id volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return h.inner.SessionStateForTransport(id)
}
func (h *countingHandler) SessionTerminalForTransport(id volumeserver.SessionID) (<-chan struct{}, bool) {
	return h.inner.SessionTerminalForTransport(id)
}

func (h *countingHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	h.mu.Lock()
	if h.byKind == nil {
		h.byKind = make(map[string]int)
	}
	h.byKind[requestKind(request)]++
	before := h.beforeHandle
	h.mu.Unlock()
	if before != nil {
		before(request)
	}
	return h.inner.Handle(ctx, request)
}

func (h *countingHandler) setBeforeHandle(before func(*authoritypb.Request)) {
	h.mu.Lock()
	h.beforeHandle = before
	h.mu.Unlock()
}

func (h *countingHandler) count(kind string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.byKind[kind]
}

// requestKind names only the request shapes the coherence assertions read.
// Everything else is one bucket, because a test that asserted on the exact
// spelling of every opcode would fail for reasons that have nothing to do with
// coherence.
func requestKind(request *authoritypb.Request) string {
	switch {
	case request.GetLookup() != nil:
		return "lookup"
	case request.GetGetAttr() != nil:
		return "getattr"
	case request.GetNextLeaseEvent() != nil:
		return "next-lease-event"
	case request.GetAcknowledgeLeaseEvent() != nil:
		return "ack-lease-event"
	case request.GetReclaim() != nil:
		return "reclaim"
	case request.GetKeepAlive() != nil:
		return "keepalive"
	case request.GetMkdir() != nil:
		return "mkdir"
	case request.GetCreate() != nil:
		return "create"
	case request.GetTmpfile() != nil:
		return "tmpfile"
	case request.GetUnlink() != nil:
		if request.GetUnlink().GetDirectory() {
			return "rmdir"
		}
		return "unlink"
	case request.GetSymlink() != nil:
		return "symlink"
	case request.GetLink() != nil:
		return "link"
	case request.GetRename() != nil:
		return "rename"
	case request.GetOpen() != nil:
		return "open"
	case request.GetClose() != nil:
		return "close"
	case request.GetReadDir() != nil:
		return "readdir"
	case request.GetWrite() != nil:
		return "write"
	case request.GetFallocate() != nil:
		return "fallocate"
	case request.GetCopyFileRange() != nil:
		return "copy-file-range"
	case request.GetRead() != nil:
		return "read"
	case request.GetSetAttr() != nil:
		return "setattr"
	case request.GetRemoveXattr() != nil:
		return "remove-xattr"
	case request.GetStatFs() != nil:
		return "statfs"
	default:
		return "other"
	}
}

// countRequests reports how many of one request kind crossed the wire while fn
// ran.
func (f *integrationFixture) countRequests(kind string, fn func()) int {
	before := f.counter.count(kind)
	fn()
	return f.counter.count(kind) - before
}
