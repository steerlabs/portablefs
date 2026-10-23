//go:build linux

package workspacemount

import (
	"bytes"
	"context"
	"encoding/base64"
	encodingbinary "encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceclock"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

// Wall and elapsed clocks advance normally; this fixture never changes the
// machine clock. It exercises the real shared measurement and child reader.
type advancingClock struct{}

func (advancingClock) ReadUTC() (time.Time, error) { return time.Now().Truncate(time.Second), nil }
func (advancingClock) CorrectWall(time.Time) error { return nil }
func (advancingClock) Wall() time.Time             { return time.Now() }
func (advancingClock) Elapsed() time.Duration {
	var v unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &v) != nil {
		return -1
	}
	return time.Duration(v.Nano())
}
func (advancingClock) Close() error { return nil }

type cleanupTestHost struct{ Host }

func (*cleanupTestHost) Terminal(*pb.MountID, string, []*pb.Loss) error { return nil }
func (*cleanupTestHost) Cleanup(*pb.MountID, CleanupProof) error        { return nil }

func realCLI(t *testing.T) string {
	t.Helper()
	if existing := os.Getenv("PFS_WORKSPACE_TEST_CLI"); existing != "" {
		return existing
	}
	directory, err := os.MkdirTemp("/tmp", "pfs-final-fix-sol-binary-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	if err = os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(directory, "portablefs")
	if out, err := exec.Command("go", "build", "-o", binary, "../../cmd/portablefs").CombinedOutput(); err != nil {
		t.Fatalf("build real CLI: %v %s", err, out)
	}
	return binary
}

func TestRootProvisionOnlyAndRemovedReconciliation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root and UID 1000 independent inventory join")
	}
	binary := realCLI(t)
	for _, removed := range []bool{false, true} {
		t.Run("removed-"+strconvBool(removed), func(t *testing.T) {
			s, id := store(t)
			if err := s.AcceptProvision(t.Context(), provision(t, id, false), ready); err != nil {
				t.Fatal(err)
			}
			i := inventory(t)
			root, err := os.MkdirTemp("/tmp", "pfs-final-fix-sol-reconcile-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			os.Chmod(root, 0755)
			for _, dir := range []string{"targets", "clients"} {
				if err = os.Mkdir(filepath.Join(root, dir), 0755); err != nil {
					t.Fatal(err)
				}
			}
			m := &Manager{Identity: s, Inventory: i, Binary: binary, Targets: filepath.Join(root, "targets"), Clients: filepath.Join(root, "clients")}
			if removed {
				run := desired(1)
				run.Mount = id.Mount
				run.KernelBoot = "previous-kernel-boot"
				run.Witness.Target = filepath.Join(m.Targets, id.Mount.VolumeId)
				if err = i.CommitDesired(run); err != nil {
					t.Fatal(err)
				}
				if err = i.Reconcile(id.Mount, func(*Desired) error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			// Replay the Removed -> Reissue crash window as well as provision-only boot.
			if err = m.Reconcile(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err = m.Reconcile(t.Context()); err != nil {
				t.Fatal("replay", err)
			}
			next, err := s.EnsureIdentity(request())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(next.PublicKey, id.PublicKey) || next.RenewalEpoch != id.RenewalEpoch {
				t.Fatal("persistent identity changed")
			}
			if err = s.AcceptProvision(t.Context(), provision(t, next, false), ready); err != nil {
				t.Fatal("fresh provision refused", err)
			}
		})
	}
}
func strconvBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// Requires the disposable native authority fixture, using only generated PKI.
// It runs the production CLI child, fails its actual kernel INIT, and follows
// ownership through child exit, both inventory removals and metadata ACK.
func TestRootRealCLIFailedINITFinalizesBothInventories(t *testing.T) {
	fixture := os.Getenv("PFS_WORKSPACE_FIXTURE_ROOT")
	if os.Geteuid() != 0 || fixture == "" {
		t.Skip("disposable real XFS authority fixture required")
	}
	binary := realCLI(t)
	s, err := Open(filepath.Join(t.TempDir(), "identities"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.EnsureIdentity(&pb.IdentityRequest{AuthorityId: bytes.Repeat([]byte{4}, 32), VolumeId: "native-managed"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := proto.Marshal(id)
	material, err := exec.Command(filepath.Join(fixture, "bin/pfs-workspace-fixture"), "provision", filepath.Join(fixture, "home/test-pki"), "127.0.0.1:17443", base64.StdEncoding.EncodeToString(raw)).Output()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(material)))
	if err != nil {
		t.Fatal(err)
	}
	p := new(pb.Provision)
	if err = proto.Unmarshal(decoded, p); err != nil {
		t.Fatal(err)
	}
	if err = s.AcceptProvision(t.Context(), p, ready); err != nil {
		t.Fatal(err)
	}
	i := inventory(t)
	root, err := os.MkdirTemp("/tmp", "pfs-final-fix-sol-cli-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	os.Chmod(root, 0755)
	if err = os.MkdirAll("/workspaces", 0755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"clients", "backing"} {
		if err = os.Mkdir(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	clock, err := workspaceclock.NewShared(advancingClock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	if err = clock.Begin(0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	clockDone := make(chan struct{})
	go func() { defer close(clockDone); clock.Maintain(ctx, nil) }()
	defer func() { cancel(); <-clockDone }()
	m := &Manager{Host: &cleanupTestHost{}, Identity: s, Inventory: i, Clock: clock, Boot: bytesID(1), HostService: bytesID(2), GuestService: bytesID(3), Binary: binary, Targets: "/workspaces", Clients: filepath.Join(root, "clients"), Backing: filepath.Join(root, "backing")}
	d, err := m.start(ctx, id.Mount, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !d.cleaned.Load() {
			d.child.Process.Kill()
			<-d.exited
		}
		if d.kernel != nil {
			_ = d.kernel.Remove(true)
			_ = d.kernel.Finalize()
		}
		d.target.Close()
		d.gate.Dispose()
		os.Remove(d.bound().Target)
	}()
	b := d.binding()
	b.OperationID = "1"
	if _, err = d.exchange(ctx, "workspace-prepare", b, nil, nil); err != nil {
		t.Fatal(err)
	}
	var observed *mountcontrol.WorkspaceResponse
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		observed, err = d.exchange(ctx, "workspace-observe", b, nil, nil)
		if err == nil && observed.Phases != nil && observed.Phases.Install.Progress == "offered" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if observed == nil || observed.Phases == nil || observed.Phases.Install.Progress != "offered" {
		t.Fatal("real CLI did not offer INIT", err)
	}
	if err = d.acceptEvidence(observed); err != nil {
		t.Fatal(err)
	}
	action := observed.Phases.Install.Action
	var stat unix.Stat_t
	if err = unix.Fstat(int(d.target.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	d.kernel, err = fusev3.InstallClosedFUSE(d.target, d.bound().Target, d.bound().Intent, action.Options, uint64(stat.Dev), stat.Ino)
	if err != nil {
		t.Fatal(err)
	}
	files, err := d.kernel.Handoff()
	if err != nil {
		t.Fatal(err)
	}
	defer files[0].Close()
	defer files[1].Close()
	frame := make([]byte, 8192)
	n, err := unix.Read(int(files[0].Fd()), frame)
	if err != nil || n < 40 || encodingbinary.LittleEndian.Uint32(frame[4:]) != 26 {
		t.Fatal("missing real INIT", n, err)
	}
	reply := make([]byte, 16)
	encodingbinary.LittleEndian.PutUint32(reply, 16)
	errno := -int32(syscall.EPROTO)
	encodingbinary.LittleEndian.PutUint32(reply[4:], uint32(errno))
	copy(reply[8:], frame[8:16])
	if _, err = unix.Write(int(files[0].Fd()), reply); err != nil {
		t.Fatal(err)
	}
	// Abort only this retained connection so the real child's INIT read returns
	// the kernel failure instead of waiting for a second request after EPROTO.
	if _, err = files[1].Write([]byte("1")); err != nil {
		t.Fatal(err)
	}
	d.bootstrapAttempted = true
	copyAction := *action
	copyAction.Options = append([]string(nil), action.Options...)
	d.bootstrapAction = &copyAction
	w := d.bound()
	w.Kernel = d.kernel.Witness()
	if _, err = d.bindWitness(w); err != nil {
		t.Fatal(err)
	}
	if err = d.actions(ctx, b, observed); err != nil && !errors.Is(err, syscall.EPROTO) {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) {
		observed, err = d.exchange(ctx, "workspace-observe", b, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.acceptEvidence(observed); err != nil {
			t.Fatal(err)
		}
		if err = d.actions(ctx, b, observed); err != nil {
			t.Fatal(err)
		}
		if observed.State == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if observed.State != "failed" {
		t.Fatal("failed INIT owner did not settle", observed.State)
	}
	if !reflect.DeepEqual(d.bootstrapAction, &copyAction) {
		t.Fatal("bootstrap owner changed")
	}
	d.sequence.Store(1)
	s.mu.Lock()
	s.failed = errors.New("injected identity completion failure")
	s.mu.Unlock()
	failedProof, failedErr := d.remove(ctx, "terminal")
	if failedErr == nil || d.cleaned.Load() || failedProof.ProcessExited || !i.Snapshot()[0].Removed {
		t.Fatal("identity failure published completed cleanup", failedProof, failedErr)
	}
	s.mu.Lock()
	s.failed = nil
	s.mu.Unlock()
	proof, err := d.remove(ctx, "terminal")
	if err != nil {
		t.Fatal("real CLI cleanup after clean failed INIT", err)
	}
	if !proof.ProcessExited || !proof.KernelAbsent || proof.Outcome == nil {
		t.Fatal(proof)
	}
	if len(i.Snapshot()) != 1 || !i.Snapshot()[0].Removed {
		t.Fatal("root removal unproven")
	}
	if err = m.Acknowledge([]*pb.MountID{id.Mount}); err != nil {
		t.Fatal(err)
	}
	if len(i.Snapshot()) != 0 {
		t.Fatal("root inventory retained")
	}
	if _, err = os.Stat(filepath.Join(m.Clients, d.bound().Intent)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("CLI inventory retained", err)
	}
}

func TestRootFailedControlStartupTransfersExactOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root startup and UID 1000 real CLI")
	}
	binary := realCLI(t)
	s, id := store(t)
	if err := s.AcceptProvision(t.Context(), provision(t, id, false), ready); err != nil {
		t.Fatal(err)
	}
	i := inventory(t)
	root, err := os.MkdirTemp("/tmp", "pfs-final-fix-sol-startup-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	os.Chmod(root, 0755)
	for _, dir := range []string{"targets", "clients", "backing"} {
		if err = os.Mkdir(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	clock, err := workspaceclock.NewShared(advancingClock{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clock.Close()
	if err = clock.Begin(0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	clockDone := make(chan struct{})
	go func() { defer close(clockDone); clock.Maintain(ctx, nil) }()
	defer func() { cancel(); <-clockDone }()
	// A real child refuses this launch outside its protected namespace before
	// reporting control availability. It never attaches or installs a kernel mount.
	m := &Manager{Host: &cleanupTestHost{}, Identity: s, Inventory: i, Clock: clock, Boot: bytesID(1), HostService: bytesID(2), GuestService: bytesID(3), Binary: binary, Targets: filepath.Join(root, "targets"), Clients: filepath.Join(root, "clients"), Backing: filepath.Join(root, "backing")}
	err = m.Run(ctx, &pb.MountJob{Mount: id.Mount, Operation: "mount"}, nil)
	var failure *StartupFailure
	if !errors.As(err, &failure) || failure.Owner == nil {
		t.Fatal("startup resource owner was not transferred", err)
	}
	p := failure.Proof
	if !p.ProcessExited || !p.KernelAbsent || p.Outcome == nil || p.Witness.Process == "" {
		t.Fatal("exact startup absence/evidence missing", p)
	}
	if len(i.Snapshot()) != 1 || !i.Snapshot()[0].Removed {
		t.Fatal("startup root record not exactly removed")
	}
	if err = m.Acknowledge([]*pb.MountID{id.Mount}); err != nil {
		t.Fatal(err)
	}
	if len(i.Snapshot()) != 0 {
		t.Fatal("startup ACK leaked root record")
	}
}
