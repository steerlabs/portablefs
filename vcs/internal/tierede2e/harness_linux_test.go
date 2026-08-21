//go:build linux

package tierede2e

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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	"github.com/steerlabs/portablefs/vcs/internal/restoremode"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

const (
	envXFSRoot    = "PORTABLEFS_XFS_TEST_ROOT"
	envXFSProject = "PORTABLEFS_XFS_TEST_PROJECT"
	envFUSE       = "PORTABLEFS_FUSE_TEST"
	// envRequired is set by the privileged CI job. It converts every gate that
	// would otherwise skip into a hard failure.
	envRequired = "PORTABLEFS_XFS_TEST_REQUIRED"
)

type privilegedEnv struct {
	xfsRoot   string
	projectID uint32
}

// requirePrivilegedEnvironment resolves the privileged XFS and FUSE gates on
// exactly the terms the rest of the privileged suite uses
// (fusev3/integration_support_linux_test.go, xfsstore/production_linux_test.go).
// A developer may run this by hand with the gates unset, in which case it
// skips; CI sets PORTABLEFS_XFS_TEST_REQUIRED=1 and from then on an
// unprovisioned filesystem, a missing FUSE device, or a root-owned test process
// is a loud failure instead of a skip.
func requirePrivilegedEnvironment(t *testing.T) privilegedEnv {
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
	// default_permissions delegates every access decision to the kernel. Root
	// bypasses all of it through CAP_DAC_OVERRIDE, which would make every
	// permission assertion vacuous - in particular the restricted-mode stage,
	// where hydration must land in an inode this identity genuinely cannot open
	// for writing. CI therefore runs the suite as the volume identity and grants
	// it nothing beyond CAP_DAC_READ_SEARCH, which is the archiver's capability
	// and bypasses read and search only; write is still refused, so the
	// authority's descriptor binding is proved rather than assumed.
	if required && os.Geteuid() == 0 {
		t.Fatalf("%s=1 requires the unprivileged volume identity; running as root makes every DAC assertion vacuous", envRequired)
	}
	// The archiver's capability, and nothing beyond it. The tree this suite
	// archives contains inodes whose modes deny their own owner, which is a
	// shape a real workspace produces and the archive format promises to carry;
	// reading them is the archiver's job, and the archiver unit is the one
	// component in the cell that holds CAP_DAC_READ_SEARCH. Its absence is a
	// provisioning fault rather than a reason to prove less, so under
	// PORTABLEFS_XFS_TEST_REQUIRED it is a failure named at the top of the
	// suite instead of an EACCES from somewhere deep inside the archiver.
	if !holdsDACReadSearch(t) {
		if required {
			t.Fatalf("%s=1 but this process does not hold CAP_DAC_READ_SEARCH; the archiver's capability is provisioned by scripts/xfs-fuse-integration.sh", envRequired)
		}
		t.Skip("the tiered suite needs the archiver's CAP_DAC_READ_SEARCH; run it through scripts/xfs-fuse-integration.sh")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatalf("%s must be an absolute clean path, got %q", envXFSRoot, root)
	}
	parsed, err := strconv.ParseUint(project, 10, 32)
	if err != nil {
		t.Fatalf("%s=%q is not a uint32: %v", envXFSProject, project, err)
	}
	return privilegedEnv{xfsRoot: root, projectID: uint32(parsed)}
}

// holdsDACReadSearch reports whether this process can actually read and search
// past a mode that denies it. Capabilities are per-thread, but nothing in this
// suite raises or lowers one, so every thread carries what exec handed it.
func holdsDACReadSearch(t *testing.T) bool {
	t.Helper()
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var payload [2]unix.CapUserData
	if err := unix.Capget(&header, &payload[0]); err != nil {
		t.Fatalf("read this process's capability sets: %v", err)
	}
	return payload[0].Effective&(1<<unix.CAP_DAC_READ_SEARCH) != 0
}

// newVolumeDirectory creates a collision-free directory inside the provisioned
// XFS project. XFS propagates both the project ID and FS_XFLAG_PROJINHERIT to
// children, so every such directory is an independent volume that still
// satisfies xfsstore's production project gate — which is what lets the restore
// target be a genuinely different placement from the archived source.
func newVolumeDirectory(t *testing.T, env privilegedEnv, role string) string {
	t.Helper()
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.xfsRoot, "tierede2e-"+role+"."+hex.EncodeToString(suffix[:]))
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create the %s volume directory: %v", role, err)
	}
	t.Cleanup(func() {
		// Restricted modes are deliberate in this tree; make the leftovers
		// removable before removing them.
		_ = filepath.WalkDir(path, func(name string, entry os.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				_ = os.Chmod(name, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(path); err != nil {
			t.Errorf("remove the %s volume directory: %v", role, err)
		}
	})
	return path
}

// shortStateDir creates the per-volume state directory. It must be short: it
// holds the AF_UNIX socket the authority dials, and sun_path is capped near a
// hundred bytes, which a test temporary directory often exceeds on its own.
func shortStateDir(t *testing.T, prefix string) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", prefix)
	if err != nil {
		directory, err = os.MkdirTemp("", prefix)
		if err != nil {
			t.Fatalf("create the state directory: %v", err)
		}
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("restrict the state directory: %v", err)
	}
	if length := len(filepath.Join(directory, restoremode.HydratorSocket)); length > 100 {
		t.Fatalf("the state directory yields a %d byte socket path, which AF_UNIX cannot carry", length)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

// ---------------------------------------------------------------------------
// The parkable restore store.
// ---------------------------------------------------------------------------

// parkableStore wraps the real authority-side write path
// (*xfsstore.RestoreFiles) and can report every entry as unlinked. That is the
// one state the drain loop is contracted to back off on without fetching and
// without holding a chunk lock, so it parks the background sweep and leaves
// demand recall — which never consults Linked — completely untouched.
//
// It is the test's pacing lever, never a correctness claim: without it, drain
// would race every "this read was served cold" assertion into meaninglessness.
type parkableStore struct {
	inner  *xfsstore.RestoreFiles
	parked struct {
		sync.RWMutex
		value bool
	}
}

func newParkableStore(inner *xfsstore.RestoreFiles) *parkableStore {
	store := &parkableStore{inner: inner}
	store.parked.value = true
	return store
}

func (s *parkableStore) park(parked bool) {
	s.parked.Lock()
	defer s.parked.Unlock()
	s.parked.value = parked
}

func (s *parkableStore) isParked() bool {
	s.parked.RLock()
	defer s.parked.RUnlock()
	return s.parked.value
}

func (s *parkableStore) LogicalSize(entry uint32) (int64, error) { return s.inner.LogicalSize(entry) }
func (s *parkableStore) PWrite(entry uint32, off int64, data []byte) error {
	return s.inner.PWrite(entry, off, data)
}
func (s *parkableStore) Fdatasync(entry uint32) error    { return s.inner.Fdatasync(entry) }
func (s *parkableStore) RestoreMtime(entry uint32) error { return s.inner.RestoreMtime(entry) }
func (s *parkableStore) Linked(entry uint32) (bool, error) {
	if s.isParked() {
		return false, nil
	}
	return s.inner.Linked(entry)
}
func (s *parkableStore) DiscardUnlinked(entry uint32) (bool, error) {
	if s.isParked() {
		return false, nil
	}
	return s.inner.DiscardUnlinked(entry)
}

// ---------------------------------------------------------------------------
// One authority over one XFS volume, with one kernel FUSE mount.
// ---------------------------------------------------------------------------

const (
	harnessRequestTimeout = 20 * time.Second
	harnessMaxFrame       = 4 << 20
	harnessReplaySlots    = 64
	harnessMaxInFlight    = 64
	harnessServerInFlight = 128
	harnessBudget         = 64 << 20
)

type authorizer struct{}

func (authorizer) Authorize(context.Context, string, []byte) (volumeserver.Authorization, error) {
	return volumeserver.Authorization{
		Access:   volumeserver.AccessRead | volumeserver.AccessWrite,
		Deadline: time.Now().Add(24 * time.Hour),
	}, nil
}

type membershipRecorder struct {
	mu     sync.Mutex
	active map[volumeserver.SessionID]struct{}
}

func newMembershipRecorder() *membershipRecorder {
	return &membershipRecorder{active: map[volumeserver.SessionID]struct{}{}}
}

func (m *membershipRecorder) Activate(id volumeserver.SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[id] = struct{}{}
	return nil
}

func (m *membershipRecorder) Deactivate(id volumeserver.SessionID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.active, id)
	return nil
}

// transport is this harness's equivalent of the production mount binary's
// adapter over the authority client.
type transport struct{ *authorityrpc.Client }

func (t *transport) SessionID() []byte { return nil }

func (t *transport) DetachAfterUnmount(ctx context.Context, proof fusev3.MountAbsenceProof) error {
	return t.Client.DetachAfterUnmount(ctx, &authoritypb.MountAbsenceProof{
		ObservedUnixNanos: proof.ObservedUnixNanos,
		Observation:       proof.Observation,
		Component:         proof.Component,
	})
}

// restoreWiring is the authority-side restore stack for one epoch: the inode
// bindings resolved out of the materialized namespace, the parkable store over
// them, and the Mode the handler consults. It is assembled by the caller from
// the same exported calls cmd/portablefs-authority makes.
type restoreWiring struct {
	mode  *restoremode.Mode
	files *xfsstore.RestoreFiles
	park  *parkableStore
}

// serving is one complete authority epoch over one XFS volume directory, plus
// one real kernel FUSE mount of it. It is wired exactly as
// cmd/portablefs-authority wires production, including the state-driven restore
// activation: restore is non-nil only when the caller's wire callback builds
// one, and the caller decides that from restoremode.Active, never from a flag.
type serving struct {
	t         *testing.T
	mountPath string

	store     *xfsstore.Volume
	listener  net.Listener
	client    *authorityrpc.Client
	mount     *fusev3.Mount
	restore   *restoreWiring
	stopServe context.CancelFunc
	served    chan error
	stopped   bool
	unmounted bool
}

func startServing(t *testing.T, env privilegedEnv, volumeID, volumeRoot string,
	wire func(*testing.T, *xfsstore.Volume) *restoreWiring) *serving {
	t.Helper()
	s := &serving{t: t}
	serverTLS, clientTLS := harnessTLS(t)

	store, err := xfsstore.Open(volumeRoot, xfsstore.Config{
		ExpectedProjectID: env.projectID,
		ExpectedOwnerUID:  uint32(os.Geteuid()),
		ExpectedOwnerGID:  uint32(os.Getegid()),
	})
	if err != nil {
		t.Fatalf("open XFS volume %s: %v", volumeRoot, err)
	}
	s.store = store
	var restore *restoremode.Mode
	if wire != nil {
		s.restore = wire(t, store)
		if s.restore != nil {
			restore = s.restore.mode
		}
	}

	authority, err := volumeserver.New(volumeID, volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: harnessReplaySlots,
		MaxSessions: 8, MaxLockRecords: 4096,
	})
	if err != nil {
		t.Fatalf("create authority epoch: %v", err)
	}

	membership := newMembershipRecorder()
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: membership, Fencer: authority,
		MaxCachedNameCapacity: 4096, MaxRepairBudget: time.Minute, MaxClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatalf("create visibility coordinator: %v", err)
	}
	// The authority is the source of truth for the volume's machine-local
	// routing revision and refuses every mount whose declared revision is not
	// the active one — for both coherence profiles. This volume declares no
	// routes, but it still has to install that declaration through the same
	// barrier a live operator's change would use, and the mount still has to
	// declare agreement with it.
	routes, err := authorityrpc.NewRoutesController(store, visibility)
	if err != nil {
		t.Fatalf("create routing controller: %v", err)
	}
	if err := routes.Load(); err != nil {
		t.Fatalf("load the volume's routing declaration: %v", err)
	}
	active, err := routes.Revision()
	if err != nil {
		t.Fatalf("read the active routing revision: %v", err)
	}
	if _, err := routes.Apply(context.Background(), []byte(""), active); err != nil {
		t.Fatalf("install the routing declaration: %v", err)
	}
	rules, err := fusev3.ActivateRoutes([]byte(""))
	if err != nil {
		t.Fatalf("compile the routing declaration: %v", err)
	}

	handler := &authorityrpc.VolumeHandler{
		Store: store, Runtime: authority, Authorizer: authorizer{},
		Visibility: visibility, Routes: routes, Restore: restore,
		MaxFrame: harnessMaxFrame, MaxRead: 1 << 20, MaxWrite: 1 << 20,
		MaxInFlight:        harnessServerInFlight,
		MaxItemsPerSession: 4096, MaxOpensPerSession: 4096, MaxItems: 16384, MaxOpens: 16384,
		MaxRetainedReplyBytes: harnessBudget,
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.listener = listener
	ctx, cancel := context.WithCancel(context.Background())
	s.stopServe, s.served = cancel, make(chan error, 1)
	served := s.served
	go func() {
		served <- (&authorityrpc.Server{
			Handler: handler, MaxFrame: harnessMaxFrame,
			MaxInFlight: harnessServerInFlight, MaxConnections: 16,
			MaxFrameBytesInFlight: harnessBudget,
			HandshakeTimeout:      5 * time.Second, IdleTimeout: 2 * time.Minute, WriteTimeout: 30 * time.Second,
		}).Serve(ctx, listener, serverTLS)
	}()

	client, err := authorityrpc.DialClient(context.Background(), authorityrpc.ClientConfig{
		Address: listener.Addr().String(), TLS: clientTLS.Clone(), VolumeID: volumeID,
		AccessToken: []byte("tiered-e2e-capability"), ReplaySlots: harnessReplaySlots,
		MaxFrame: harnessMaxFrame, DialTimeout: 5 * time.Second,
		CancelDrainTimeout: 5 * time.Second, MaxInFlight: harnessMaxInFlight,
		RoutesRevision: rules.Revision(),
	})
	if err != nil {
		t.Fatalf("dial authority: %v", err)
	}
	s.client = client

	mountRoot := t.TempDir()
	s.mountPath = filepath.Join(mountRoot, "mnt")
	if err := os.Mkdir(s.mountPath, 0o700); err != nil {
		t.Fatalf("create mountpoint: %v", err)
	}
	instance, err := mountid.NewMountInstance()
	if err != nil {
		t.Fatalf("create mount identity: %v", err)
	}
	mount, err := fusev3.MountVolume(context.Background(), s.mountPath, &transport{Client: client}, fusev3.Config{
		MountInstanceID: instance, RequestTimeout: harnessRequestTimeout,
		MaxBackground: 64, ReclaimQueue: 1024, MaxInFlight: harnessMaxInFlight,
		PresentedUID: uint32(os.Geteuid()), PresentedGID: uint32(os.Getegid()),
		// Uncached is deliberate: every read and every getattr must reach the
		// authority, so a cold recall is provably a recall and an mtime
		// assertion cannot be answered out of a kernel cache.
		Coherence: fusev3.CoherenceUncached,
		Routes:    rules,
	})
	if err != nil {
		t.Fatalf("mount %s: %v", s.mountPath, err)
	}
	s.mount = mount
	t.Cleanup(s.stop)
	return s
}

// join builds a path to a volume object as seen through the kernel mount.
func (s *serving) join(elements ...string) string {
	return filepath.Join(append([]string{s.mountPath}, elements...)...)
}

// unmount removes the kernel mount and releases the authority session. It is
// idempotent so a test can unmount deliberately and still be cleaned up.
func (s *serving) unmount() {
	if s.unmounted || s.mount == nil {
		return
	}
	s.unmounted = true
	if err := s.mount.Unmount(); err != nil {
		_ = s.mount.Close()
		s.t.Errorf("unmount %s: %v", s.mountPath, err)
	}
	if isMounted(s.t, s.mountPath) {
		s.t.Errorf("%s was still installed after Unmount", s.mountPath)
		_ = exec.Command("fusermount3", "-u", "-z", s.mountPath).Run()
	}
}

// stop unwinds strictly in reverse: the mount, then the RPC server, then the
// XFS handle. A mount that outlived its authority would deadlock the unmount it
// needs to complete.
func (s *serving) stop() {
	if s.stopped {
		return
	}
	s.stopped = true
	s.unmount()
	if s.stopServe != nil {
		s.stopServe()
		select {
		case err := <-s.served:
			if err != nil {
				s.t.Errorf("authority server: %v", err)
			}
		case <-time.After(30 * time.Second):
			s.t.Error("authority server did not stop")
		}
	}
	if s.listener != nil {
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			s.t.Errorf("close authority listener: %v", err)
		}
	}
	// Restore mode holds descriptors into the volume and writes through them,
	// so it must be shut down before the volume handle it writes into.
	if s.restore != nil {
		if s.restore.mode != nil {
			if err := s.restore.mode.Close(); err != nil {
				s.t.Errorf("close restore mode: %v", err)
			}
		}
		if s.restore.files != nil {
			if err := s.restore.files.Close(); err != nil {
				s.t.Errorf("close restore bindings: %v", err)
			}
		}
		s.restore = nil
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			s.t.Errorf("close XFS volume: %v", err)
		}
		s.store = nil
	}
}

func isMounted(t *testing.T, path string) bool {
	t.Helper()
	if strings.ContainsAny(path, " \t\n\\") {
		t.Fatalf("mount point %q needs mountinfo unescaping", path)
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatalf("read /proc/self/mountinfo: %v", err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[4] == path {
			return true
		}
	}
	return false
}

func harnessTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PortableFS tiered e2e CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
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
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
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
	server := issue(2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	client := issue(3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool,
			Certificates: []tls.Certificate{server}},
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{client}, ServerName: "localhost"}
}

// waitFor polls a real signal — a marker file, a durable record, a package
// predicate — until it holds or the bound expires. It is never used to wait out
// a race: every caller names a condition the system itself publishes.
func waitFor(t *testing.T, within time.Duration, what string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if ready() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", within, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func mustReadAt(t *testing.T, path string, offset int64, length int, what string) []byte {
	t.Helper()
	payload, err := rawReadAt(path, offset, length)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if len(payload) != length {
		t.Fatalf("%s: %s delivered %d of %d bytes at %d", what, path, len(payload), length, offset)
	}
	return payload
}

func mustReadFile(t *testing.T, path, what string) []byte {
	t.Helper()
	payload, err := rawReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return payload
}

// rawReadAt reads through the raw open/pread syscalls rather than through the
// os package.
//
// A restore-blocked content read is answered with EIO under
// FAILURE_CLASS_RESTORE — EIO precisely because this suite once proved that
// the earlier EAGAIN mapping parked Go's poller on the FUSE file's poll
// descriptor forever. The raw syscalls stay: they observe the filesystem's
// exact errno with no runtime translation in between, which is what a
// regression in that mapping would need to be caught by.
func rawReadAt(path string, offset int64, length int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	buffer := make([]byte, length)
	n, err := unix.Pread(fd, buffer, offset)
	if err != nil {
		return nil, fmt.Errorf("read %s at %d: %w", path, offset, err)
	}
	return buffer[:n], nil
}

// rawReadFile reads a whole file through the raw syscalls, for the same reason
// rawReadAt exists: every read of this volume may legitimately be answered with
// the restore class, and a test must be able to see that answer rather than
// disappear into the runtime's retry-when-readable path.
func rawReadFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var out []byte
	buffer := make([]byte, 1<<16)
	offset := int64(0)
	for {
		n, err := unix.Pread(fd, buffer, offset)
		if err != nil {
			return nil, fmt.Errorf("read %s at %d: %w", path, offset, err)
		}
		if n == 0 {
			return out, nil
		}
		out = append(out, buffer[:n]...)
		offset += int64(n)
	}
}

func describeBytes(payload []byte) string {
	if len(payload) <= 32 {
		return fmt.Sprintf("%x", payload)
	}
	return fmt.Sprintf("%x... (%d bytes)", payload[:32], len(payload))
}
