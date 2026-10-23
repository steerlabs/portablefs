//go:build linux

package workspacemount

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/mountcontrol"
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceclock"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type Host interface {
	Register(context.Context, *pb.MountID, Witness, Mount) error
	BindWitness(*pb.MountID, Witness) (Witness, error)
	Activate(context.Context, *pb.MountID, uint64) error
	Terminal(*pb.MountID, string, []*pb.Loss) error
	Cleanup(*pb.MountID, CleanupProof) error
	Replace(context.Context, *pb.MountID, *pb.MountID, Witness, Mount) error
	RecoveryRequired(*pb.MountID, uint64, uint64, string) error
	Registered(*pb.MountID) bool
}
type Manager struct {
	Host                              Host
	Identity                          *Store
	Inventory                         *Inventory
	Clock                             *workspaceclock.Owner
	Boot, HostService, GuestService   []byte
	Binary, Targets, Clients, Backing string
	mu                                sync.Mutex
	allocationMu                      sync.Mutex
	mounts                            map[string]*Driver
}

// Driver owns one process and one once-only kernel bootstrap. A new daemon
// cannot adopt it, and uncertain socket delivery cannot create another mount.
type Driver struct {
	registered         atomic.Bool
	terminalCleanup    atomic.Bool
	cleaned            atomic.Bool
	removals           [2]*rootRemoval
	manager            *Manager
	id                 *pb.MountID
	gate               *workspaceadmission.Supervisor
	mu                 sync.Mutex
	witness            Witness
	generation, serial uint64
	operation          *mountcontrol.Workspace
	sequence           atomic.Uint64
	serving            atomic.Bool
	opMu, effectMu     sync.Mutex
	cleanupMu          sync.Mutex
	bootstrapAttempted bool
	bootstrapAction    *mountcontrol.KernelAction
	kernel             *fusev3.ManagedKernel
	target             *os.File
	socket             string
	child              *exec.Cmd
	exited             chan struct{}
	exitErr            error
}
type rootRemoval struct {
	id  string
	err error
}

func (m *Manager) snapshotMounts() map[string]*Driver {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]*Driver, len(m.mounts))
	for key, d := range m.mounts {
		out[key] = d
	}
	return out
}

func (m *Manager) pruneMounts() {
	// Host registration takes the supervisor lock. Clock invalidation can call
	// back into this manager while that lock is held, so no Host method may run
	// under the map lock. Cleaned incarnations cannot register again.
	for key, prior := range m.snapshotMounts() {
		if prior.cleaned.Load() && !m.Host.Registered(prior.id) {
			m.mu.Lock()
			if m.mounts[key] == prior {
				delete(m.mounts, key)
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) Run(ctx context.Context, j *pb.MountJob, _ *pb.Provision) error {
	key := control.MountKey(j.Mount)
	switch j.Operation {
	case "mount":
		m.pruneMounts()
		m.mu.Lock()
		if m.mounts == nil {
			m.mounts = map[string]*Driver{}
		}
		old := m.mounts[key]
		m.mu.Unlock()
		if old != nil {
			return errors.New("workspace incarnation already owns a child")
		}
		d, err := m.start(ctx, j.Mount, j.Generation)
		if err != nil {
			if d != nil {
				m.mu.Lock()
				m.mounts[key] = d
				m.mu.Unlock()
				return &StartupFailure{Cause: err, Owner: d, Proof: d.cleanupProof()}
			}
			return err
		}
		m.mu.Lock()
		m.mounts[key] = d
		m.mu.Unlock()
		var predecessor *Driver
		for _, prior := range m.snapshotMounts() {
			if prior != d && prior.cleaned.Load() && string(prior.id.AuthorityId) == string(j.Mount.AuthorityId) && prior.id.VolumeId == j.Mount.VolumeId && m.Host.Registered(prior.id) {
				predecessor = prior
				break
			}
		}
		if predecessor != nil {
			err = m.Host.Replace(ctx, predecessor.id, j.Mount, d.bound(), d)
		} else {
			err = m.Host.Register(ctx, j.Mount, d.bound(), d)
		}
		if err != nil {
			return &StartupFailure{Cause: err, Owner: d, Proof: d.cleanupProof()}
		}
		d.registered.Store(true)
		if predecessor != nil {
			m.mu.Lock()
			delete(m.mounts, control.MountKey(predecessor.id))
			m.mu.Unlock()
		}
		err = m.Host.Activate(ctx, j.Mount, j.Generation)
		if err != nil {
			terminalErr := m.Host.Terminal(j.Mount, "initial workspace preparation did not complete", nil)
			proof, cleanupErr := d.Cleanup(context.Background(), d.bound())
			cleanupErr = errors.Join(cleanupErr, m.Host.Cleanup(j.Mount, proof))
			return errors.Join(err, terminalErr, cleanupErr)
		}
		return nil
	case "umount":
		m.mu.Lock()
		d := m.mounts[key]
		m.mu.Unlock()
		if d == nil {
			return errors.New("workspace mount not owned")
		}
		if err := m.Host.Terminal(j.Mount, "voluntary unmount requested", nil); err != nil {
			return err
		}
		mode := "voluntary"
		d.effectMu.Lock()
		if d.removals[0] != nil {
			mode = "terminal"
		}
		d.effectMu.Unlock()
		p, err := d.remove(ctx, mode)
		err = errors.Join(err, m.Host.Cleanup(j.Mount, p))
		if err != nil {
			return err
		}
		m.mu.Lock()
		delete(m.mounts, key)
		m.mu.Unlock()
		return nil
	default:
		return errors.New("unsupported workspace driver job")
	}
}
func (m *Manager) start(ctx context.Context, id *pb.MountID, g uint64) (owner *Driver, result error) {
	if m.Host == nil || m.Identity == nil || m.Inventory == nil || m.Clock == nil || os.Geteuid() != 0 {
		return nil, errors.New("workspace root owners unavailable")
	}
	p, key, err := m.Identity.Provisioned(id)
	if err != nil {
		return nil, err
	}
	if err = m.Clock.Wait(ctx, g); err != nil {
		return nil, err
	}
	path := filepath.Join(m.Targets, id.VolumeId)
	m.allocationMu.Lock()
	allocating := true
	defer func() {
		if allocating {
			m.allocationMu.Unlock()
		}
	}()
	if err = m.Inventory.CanReserve(id, path); err != nil {
		return nil, err
	}
	target, st, err := m.protectedTarget(id)
	if err != nil {
		return nil, err
	}
	instance := "mnt_" + base64.RawURLEncoding.EncodeToString(id.Incarnation)
	d := &Driver{manager: m, id: proto.Clone(id).(*pb.MountID), target: target, generation: g, exited: make(chan struct{}), witness: Witness{Intent: instance, Source: "portablefs:" + instance, Target: path}}
	desiredRecorded := false
	defer func() {
		if result == nil {
			return
		}
		if d.child != nil && d.child.Process != nil {
			_ = d.child.Process.Kill()
			<-d.exited
		} else {
			close(d.exited)
		}
		// No Prepare can run before control availability and registration. Join
		// the unattached child, reconcile both stores, and release only an exact
		// absence proof. A failed persistence/identity proof retains the intent.
		if !desiredRecorded {
			for _, run := range m.Inventory.Snapshot() {
				if proto.Equal(run.Mount, id) {
					desiredRecorded = true
					break
				}
			}
		}
		if desiredRecorded && (d.child == nil || d.child.Process == nil || d.bound().Process != "") {
			for _, run := range m.Inventory.Snapshot() {
				if !proto.Equal(run.Mount, id) {
					continue
				}
				neverSpawned := d.child == nil || d.child.Process == nil
				_, cleanupErr := m.reconcileCLI(context.Background(), run, d.bound().Process, neverSpawned)
				if cleanupErr == nil {
					cleanupErr = m.Inventory.Reconcile(id, func(*Desired) error { return d.proveExitedAbsent() })
				}
				if cleanupErr == nil {
					cleanupErr = m.Identity.Reissue(&pb.IdentityRequest{AuthorityId: id.AuthorityId, VolumeId: id.VolumeId}, false, d.proveExitedAbsent)
				}
				result = errors.Join(result, cleanupErr)
				if cleanupErr == nil {
					d.cleaned.Store(true)
				}
				break
			}
		}
		if desiredRecorded {
			owner = d
		}
		if !desiredRecorded || d.cleaned.Load() {
			if d.gate != nil {
				_ = d.gate.Dispose()
			}
			_ = target.Close()
		}
	}()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	if err = m.Inventory.CommitDesired(&Desired{KernelBoot: strings.TrimSpace(string(boot)), Mount: id, Boot: m.Boot, Witness: d.witness, TargetDevice: uint64(st.Dev), TargetInode: st.Ino, Outcome: control.UnknownOutcome()}); err != nil {
		target.Close()
		return nil, err
	}
	desiredRecorded = true
	allocating = false
	m.allocationMu.Unlock()
	start, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		return nil, err
	}
	b := workspaceadmission.Binding{SupervisorPID: int32(os.Getpid()), SupervisorStart: start}
	copy(b.Boot[:], m.Boot)
	copy(b.HostService[:], m.HostService)
	copy(b.GuestService[:], m.GuestService)
	copy(b.Incarnation[:], id.Incarnation)
	d.gate, err = workspaceadmission.New(b)
	if err != nil {
		return nil, err
	}
	files, err := d.gate.ChildFiles()
	if err != nil {
		return nil, err
	}
	defer files[0].Close()
	defer files[1].Close()
	clock, clockBinding, err := m.Clock.ChildFile()
	if err != nil {
		return nil, err
	}
	defer clock.Close()
	input, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer input.Close()
	defer writer.Close()
	ready, readyWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer ready.Close()
	defer readyWriter.Close()
	stateDir := filepath.Join(m.Clients, instance)
	if err = os.Mkdir(stateDir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chown(stateDir, 1000, 1000); err != nil {
		return nil, err
	}
	backing, err := m.backingRoot(id)
	if err != nil {
		return nil, err
	}
	d.child = exec.Command(m.Binary, "mount", "--foreground", "--workspace-gate-fd=3", "--workspace-owner-fd=4", "--workspace-bootstrap-fd=5", "--workspace-clock-fd=6", "--workspace-ready-fd=7", id.VolumeId, path)
	d.child.Env = []string{"HOME=/home/workspace", "PATH=/usr/local/bin:/usr/bin:/bin"}
	d.child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	d.child.ExtraFiles = []*os.File{files[0], files[1], input, clock, readyWriter}
	d.child.Stderr = os.Stderr
	if err = d.child.Start(); err != nil {
		return nil, err
	}
	files[0].Close()
	files[1].Close()
	input.Close()
	clock.Close()
	readyWriter.Close()
	go func() { d.exitErr = d.child.Wait(); close(d.exited) }()
	processStart, err := mountcontrol.ProcessStart(int32(d.child.Process.Pid))
	if err != nil {
		return nil, err
	}
	d.witness.Process = strconv.Itoa(d.child.Process.Pid) + ":" + strconv.FormatUint(processStart, 10)
	if err = m.Inventory.BindWitness(id, d.witness); err != nil {
		return nil, err
	}
	launch := Launch{Binding: b, ClockBinding: clockBinding, Provision: p, PrivateKey: key, StateDirectory: stateDir, BackingRoot: backing, TargetDevice: uint64(st.Dev), TargetInode: st.Ino}
	if err = json.NewEncoder(writer).Encode(launch); err != nil {
		return nil, errors.New("workspace child launch handoff failed")
	}
	writer.Close()
	if err = ready.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	var r ChildReady
	if err = json.NewDecoder(ready).Decode(&r); err != nil {
		return nil, fmt.Errorf("workspace child control startup: %w", err)
	}
	if !strings.HasPrefix(r.Socket, "@portablefs-reauthorization-") {
		return nil, errors.New("workspace child control address invalid")
	}
	d.socket = r.Socket
	go d.watch()
	return d, nil
}

// Reconcile runs only on a new kernel boot. It commits partial CLI evidence
// before permitting that inventory's removal, independently proves absence,
// and preserves the crashed run's unknown outcome. No old process is resumed.
func (m *Manager) Reconcile(ctx context.Context) error {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	for _, run := range m.Inventory.Snapshot() {
		if run.Removed {
			if m.Identity != nil {
				if _, err = m.reconcileCLI(ctx, run, run.Witness.Process, run.Witness.Process == ""); err != nil {
					return err
				}
				if err = m.Identity.Reissue(&pb.IdentityRequest{AuthorityId: run.Mount.AuthorityId, VolumeId: run.Mount.VolumeId}, false, func() error {
					_, e := fusev3.ObservePlannedKernelMountAbsent(run.Witness.Source, run.Witness.Target)
					return e
				}); err != nil {
					return err
				}
			}
			continue
		}
		if run.KernelBoot == "" || run.KernelBoot == strings.TrimSpace(string(boot)) {
			return errors.New("workspace inventory belongs to this kernel boot; exact VM discard required")
		}
		if _, err = fusev3.ObservePlannedKernelMountAbsent(run.Witness.Source, run.Witness.Target); err != nil {
			return err
		}
		if run.Witness.Target != filepath.Join(m.Targets, run.Mount.VolumeId) {
			return errors.New("workspace reconciliation target differs from protected namespace")
		}
		// /workspaces is volatile. Recreate only the closed directory after
		// proving old kernel absence; this never adopts the old inode or child.
		target, _, err := m.protectedTarget(run.Mount)
		if err != nil {
			return err
		}
		if err = target.Close(); err != nil {
			return err
		}
		if _, err = m.reconcileCLI(ctx, run, "", false); err != nil {
			return err
		}
		err = m.Inventory.Reconcile(run.Mount, func(current *Desired) error {
			if current.KernelBoot == strings.TrimSpace(string(boot)) {
				return errors.New("workspace old process boot still live")
			}
			_, err := fusev3.ObservePlannedKernelMountAbsent(current.Witness.Source, current.Witness.Target)
			return err
		})
		if err != nil {
			return err
		}
		if m.Identity != nil {
			err = m.Identity.Reissue(&pb.IdentityRequest{AuthorityId: run.Mount.AuthorityId, VolumeId: run.Mount.VolumeId}, false, func() error {
				_, err := fusev3.ObservePlannedKernelMountAbsent(run.Witness.Source, run.Witness.Target)
				return err
			})
			if err != nil {
				return err
			}
		}
	}
	if m.Identity != nil {
		return m.Identity.ReconcileProvisioning(func(id *pb.MountID) error {
			// Any recorded owner was reconciled above. An unrecorded grant must prove
			// absence independently in the CLI inventory as well as the kernel.
			instance := "mnt_" + base64.RawURLEncoding.EncodeToString(id.Incarnation)
			run := &Desired{Mount: id, KernelBoot: strings.TrimSpace(string(boot)), Witness: Witness{Intent: instance, Source: "portablefs:" + instance, Target: filepath.Join(m.Targets, id.VolumeId)}, Outcome: control.UnknownOutcome()}
			if _, e := fusev3.ObservePlannedKernelMountAbsent(run.Witness.Source, run.Witness.Target); e != nil {
				return e
			}
			_, e := m.reconcileCLI(ctx, run, "", true)
			return e
		})
	}
	return nil
}
func (m *Manager) reconcileCLI(ctx context.Context, run *Desired, exitedProcess string, neverSpawned bool) (Witness, error) {
	recorded := false
	for _, current := range m.Inventory.Snapshot() {
		if proto.Equal(current.Mount, run.Mount) {
			recorded = true
			break
		}
	}
	if !recorded && !neverSpawned {
		return Witness{}, errors.New("workspace reconciliation has no root owner")
	}
	input, writer, err := os.Pipe()
	if err != nil {
		return Witness{}, err
	}
	cmd := exec.CommandContext(ctx, m.Binary, "mount", "--workspace-reconcile-fd=3", run.Mount.VolumeId, run.Witness.Target)
	cmd.Env = []string{"HOME=/home/workspace", "PATH=/usr/local/bin:/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	cmd.ExtraFiles = []*os.File{input}
	cmd.Stderr = os.Stderr
	ack, err := cmd.StdinPipe()
	if err != nil {
		input.Close()
		writer.Close()
		return Witness{}, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		writer.Close()
		ack.Close()
		return Witness{}, err
	}
	if err = cmd.Start(); err != nil {
		input.Close()
		writer.Close()
		ack.Close()
		return Witness{}, err
	}
	input.Close()
	writeErr := json.NewEncoder(writer).Encode(Reconciliation{Desired: run, StateDirectory: filepath.Join(m.Clients, run.Witness.Intent), ExitedProcess: exitedProcess, NeverSpawned: neverSpawned})
	writer.Close()
	var result Reconciled
	err = json.NewDecoder(io.LimitReader(out, 2<<20)).Decode(&result)
	witness := result.Witness
	if err == nil && writeErr == nil {
		if recorded {
			err = m.Inventory.BindWitness(run.Mount, witness)
		} else if witness != run.Witness || result.Evidence != nil {
			err = errors.New("provision-only reconciliation discovered owned resources")
		}
	}
	if err == nil && writeErr == nil && result.Evidence != nil {
		e := result.Evidence
		if !proto.Equal(e.Mount, run.Mount) || control.Outcome(e.Outcome) != nil || control.Losses(e.Loss) != nil {
			err = errors.New("workspace CLI outcome binding invalid")
		} else if control.RetainsLoss(e.Loss, run.Loss) {
			err = m.Inventory.RetainOutcome(run.Mount, e.Loss, e.Outcome)
		} else if !control.RetainsLoss(run.Loss, e.Loss) {
			err = errors.New("workspace CLI outcome conflicts with retained loss")
		}
	}
	if err == nil && writeErr == nil {
		_, err = ack.Write([]byte{'c'})
	}
	ack.Close()
	waitErr := cmd.Wait()
	if err = errors.Join(err, writeErr, waitErr); err != nil {
		return Witness{}, fmt.Errorf("workspace CLI inventory reconciliation: %w", err)
	}
	return witness, nil
}

func (d *Driver) bound() Witness { d.mu.Lock(); defer d.mu.Unlock(); return d.witness }
func (d *Driver) CloseAdmission(g uint64) uint64 {
	var serial uint64
	if d.gate != nil {
		serial = d.gate.Close(g)
	}
	d.serving.Store(false)
	d.mu.Lock()
	d.generation = max(d.generation, g)
	d.serial = serial
	d.mu.Unlock()
	return serial
}
func (d *Driver) OpenAdmission(g, serial uint64) error {
	if err := d.manager.Clock.Check(g); err != nil {
		return err
	}
	if err := d.gate.Open(g, serial); err != nil {
		return err
	}
	d.serving.Store(true)
	return nil
}
func (d *Driver) next() (uint64, error) {
	for {
		old := d.sequence.Load()
		if old >= math.MaxUint64-1 {
			return 0, errors.New("workspace operation sequence exhausted")
		}
		if d.sequence.CompareAndSwap(old, old+1) {
			return old + 1, nil
		}
	}
}

type localRequestUnsent struct{ error }

func (e *localRequestUnsent) Unwrap() error { return e.error }

func (d *Driver) exchange(ctx context.Context, op string, b mountcontrol.Workspace, phase *mountcontrol.Phase, rights *mountcontrol.Rights) (_ *mountcontrol.WorkspaceResponse, result error) {
	sent := false
	defer func() {
		if result != nil && !sent {
			result = &localRequestUnsent{result}
		}
	}()
	// Transactions belong only to their start. Observations and action replies
	// name that operation through its binding, without resubmitting its body.
	if op != "workspace-suspend" && op != "workspace-recover" {
		b.Transaction, b.HostRequestID = "", ""
	}
	id, err := d.next()
	if err != nil {
		return nil, err
	}
	b.RequestID = strconv.FormatUint(id, 10)
	b.Phase = phase
	if strings.HasPrefix(op, "workspace-") && op != "workspace-observe" && op != "workspace-install-kernel" && op != "workspace-unmount-complete" {
		b.RequestID = b.OperationID
	}
	deadline := time.Now().Add(2 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if !deadline.After(time.Now()) {
		return nil, context.DeadlineExceeded
	}
	stream, err := (&net.Dialer{Deadline: deadline}).DialContext(ctx, "unix", d.socket)
	if err != nil {
		return nil, err
	}
	conn := stream.(*net.UnixConn)
	defer conn.Close()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	peer, err := mountcontrol.Credentials(conn)
	if err != nil || peer.UID != 1000 || peer.PID != int32(d.child.Process.Pid) {
		return nil, errors.New("workspace child socket owner mismatch")
	}
	start, err := mountcontrol.ProcessStart(peer.PID)
	if err != nil || d.bound().Process != strconv.Itoa(int(peer.PID))+":"+strconv.FormatUint(start, 10) {
		return nil, errors.New("workspace child process start mismatch")
	}
	b.BudgetNanos = strconv.FormatInt(time.Until(deadline).Nanoseconds(), 10)
	if op == "workspace-suspend" {
		end, ok := ctx.Deadline()
		if !ok || !end.After(time.Now()) {
			return nil, context.DeadlineExceeded
		}
		b.DrainBudgetNanos = strconv.FormatInt(time.Until(end).Nanoseconds(), 10)
	}
	q := mountcontrol.Request{Operation: op, MountInstanceID: d.bound().Intent, Workspace: &b}
	err = q.ValidateWorkspace()
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	sent = true
	if rights != nil {
		_, _, err = conn.WriteMsgUnix(raw, unix.UnixRights(rights.FDs...), nil)
	} else {
		_, err = conn.Write(raw)
	}
	if err != nil {
		return nil, err
	}
	if err = conn.CloseWrite(); err != nil {
		return nil, err
	}
	body, received, err := mountcontrol.Receive(conn, mountcontrol.MaxWorkspaceResponse)
	defer received.Close()
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	r, err := mountcontrol.DecodeResponse(body, true)
	if err != nil {
		return nil, err
	}
	if r.MountInstanceID != q.MountInstanceID || r.Workspace == nil || r.Workspace.Binding != b.ResponseBinding() {
		return nil, errors.New("workspace observation binding mismatch")
	}
	return r.Workspace, nil
}

func (d *Driver) binding() mountcontrol.Workspace {
	d.mu.Lock()
	defer d.mu.Unlock()
	return mountcontrol.Workspace{Version: 8, BootID: hex.EncodeToString(d.manager.Boot), HostServiceID: hex.EncodeToString(d.manager.HostService), GuestServiceID: hex.EncodeToString(d.manager.GuestService), Generation: strconv.FormatUint(d.generation, 10), GateSerial: strconv.FormatUint(d.serial, 10)}
}
func (d *Driver) acceptEvidence(r *mountcontrol.WorkspaceResponse) error {
	w := d.bound()
	n := r.Witness
	next := Witness{Intent: w.Intent, Process: n.Process, Source: n.Source, Target: n.Target, Kernel: n.Kernel, Session: n.Session, Enrollment: n.Enrollment}
	if n.RoutesRevision != "" {
		raw, err := hex.DecodeString(n.RoutesRevision)
		if err != nil || len(raw) != 32 {
			return errors.New("workspace route witness invalid")
		}
		copy(next.RoutesRevision[:], raw)
	}
	_, err := d.bindWitness(next)
	if err != nil {
		return err
	}
	loss, outcome, err := decodeEvidence(r)
	if err != nil {
		return err
	}
	return d.manager.Inventory.RetainOutcome(d.id, loss, outcome)
}

func (d *Driver) bindWitness(next Witness) (Witness, error) {
	var bound Witness
	var err error
	if d.registered.Load() {
		bound, err = d.manager.Host.BindWitness(d.id, next)
	} else {
		bound, err = MergeWitness(d.bound(), next)
		err = errors.Join(err, d.manager.Inventory.BindWitness(d.id, bound))
	}
	d.mu.Lock()
	d.witness = bound
	d.mu.Unlock()
	return bound, err
}
func decodeEvidence(r *mountcontrol.WorkspaceResponse) ([]*pb.Loss, *pb.MountOutcome, error) {
	debt, err := strconv.ParseUint(r.Outcome.CleanupDebt, 10, 64)
	if err != nil {
		return nil, nil, err
	}
	o := &pb.MountOutcome{Durability: r.Outcome.Durability, Observation: r.Outcome.Observation, Release: r.Outcome.Release, CleanupDebt: debt}
	var loss []*pb.Loss
	for _, l := range r.Loss {
		seq, e := strconv.ParseUint(l.Sequence, 10, 64)
		if e != nil {
			return nil, nil, e
		}
		entries, e := strconv.ParseUint(l.AcceptedEntries, 10, 64)
		if e != nil {
			return nil, nil, e
		}
		size, e := strconv.ParseUint(l.AcceptedBytes, 10, 64)
		if e != nil {
			return nil, nil, e
		}
		loss = append(loss, &pb.Loss{Sequence: seq, AcceptedEntries: entries, AcceptedBytes: size, Reason: l.Reason, Aggregated: l.Aggregated})
	}
	return loss, o, control.Outcome(o)
}
func (d *Driver) actions(ctx context.Context, b mountcontrol.Workspace, r *mountcontrol.WorkspaceResponse) error {
	if r.Phases == nil {
		return nil
	}
	d.effectMu.Lock()
	defer d.effectMu.Unlock()
	install := r.Phases.Install
	if install.Progress == "offered" {
		p := install.Action.WithWitness(r.Witness)
		if d.bootstrapAction != nil && !reflect.DeepEqual(d.bootstrapAction, install.Action) {
			return errors.New("workspace bootstrap action changed")
		}
		if !d.bootstrapAttempted {
			d.bootstrapAttempted = true
			action := *install.Action
			action.Options = append([]string(nil), install.Action.Options...)
			d.bootstrapAction = &action
			var st unix.Stat_t
			if err := unix.Fstat(int(d.target.Fd()), &st); err != nil {
				return err
			}
			k, err := fusev3.InstallClosedFUSE(d.target, d.bound().Target, d.bound().Intent, p.Options, uint64(st.Dev), st.Ino)
			d.kernel = k
			if k != nil && k.Witness() != "" {
				w := d.bound()
				w.Kernel = k.Witness()
				_, bindErr := d.bindWitness(w)
				err = errors.Join(err, bindErr)
			}
			if err != nil {
				return err
			}
		}
		if d.kernel == nil {
			return errors.New("workspace bootstrap uncertainty requires cleanup")
		}
		files, err := d.kernel.Handoff()
		if err != nil {
			return err
		}
		defer files[0].Close()
		defer files[1].Close()
		_, err = d.exchange(ctx, "workspace-install-kernel", b, p, &mountcontrol.Rights{FDs: []int{int(files[0].Fd()), int(files[1].Fd())}})
		if err != nil {
			return err
		}
	}
	if d.kernel != nil && (install.Progress == "running" || install.Progress == "complete" || install.Progress == "failed" && install.Failure != "stopped") {
		if err := d.kernel.ChildOwnsFUSE(); err != nil {
			return err
		}
	}
	for _, s := range []mountcontrol.ActionStatus{r.Phases.VoluntaryRemoval, r.Phases.TerminalRemoval} {
		if s.Progress == "offered" {
			p := s.Action.WithWitness(r.Witness)
			if err := d.removeKernelLocked(p.Mode, p.ActionID); err != nil {
				return err
			}
			p.Removal = &mountcontrol.Removal{KernelAbsent: true, AbortCompleted: p.Mode == "terminal"}
			_, err := d.exchange(ctx, "workspace-unmount-complete", b, p, nil)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// All managed removal effects consume the same fixed root action slot. A
// joined dead child cannot acknowledge it, but cannot erase the original owner.
func (d *Driver) removeKernelLocked(mode, id string) error {
	index := 0
	if mode == "terminal" {
		index = 1
	}
	attempt := d.removals[index]
	if attempt == nil {
		attempt = &rootRemoval{id: id}
		d.removals[index] = attempt
		if d.kernel != nil {
			attempt.err = d.kernel.Remove(mode == "terminal")
		} else {
			w := d.bound()
			_, attempt.err = fusev3.ObservePlannedKernelMountAbsent(w.Source, w.Target)
		}
	}
	if attempt.id != id {
		return errors.New("workspace removal action changed")
	}
	if mode == "terminal" && attempt.err != nil {
		// Retry only this fixed terminal action with its original descriptions.
		// ManagedKernel retains successful abort independently from alias absence;
		// disappearance of an alias cannot fabricate a successful abort.
		if d.kernel != nil {
			attempt.err = d.kernel.Remove(true)
		} else if _, err := fusev3.ObservePlannedKernelMountAbsent(d.bound().Source, d.bound().Target); err == nil {
			attempt.err = nil
		}
	}
	return attempt.err
}
func (d *Driver) job(ctx context.Context, op string, transaction proto.Message, mode string) (*mountcontrol.WorkspaceResponse, error) {
	d.opMu.Lock()
	defer d.opMu.Unlock()
	id, err := d.next()
	if err != nil {
		return nil, err
	}
	b := d.binding()
	b.OperationID = strconv.FormatUint(id, 10)
	if transaction != nil {
		b.Transaction, err = mountcontrol.EncodeTransaction(transaction)
		if err != nil {
			return nil, err
		}
		b.HostRequestID = b.OperationID
	}
	var p *mountcontrol.Phase
	if op == "workspace-cleanup" {
		w := d.bound()
		p = &mountcontrol.Phase{Mode: mode, Reason: "exact managed removal", Witness: localWitness(w)}
	}
	d.mu.Lock()
	d.operation = &b
	d.mu.Unlock()
	accepted, uncertain := false, false
	var persistenceErr error
	for {
		select {
		case <-d.exited:
			return nil, errors.New("workspace child exited before lifecycle completion")
		default:
		}
		if !accepted && !uncertain {
			r, e := d.exchange(ctx, op, b, p, nil)
			if e == nil && r.State == "accepted" {
				accepted = true
			} else if e == nil && r.Refusal != "occupied" {
				return r, fmt.Errorf("workspace start refused: %s", r.Refusal)
			}
			if e != nil {
				var unsent *localRequestUnsent
				if errors.As(e, &unsent) {
					if ctx.Err() != nil || !authorityrpc.TransientTransport(e) {
						return nil, errors.Join(ctx.Err(), e)
					}
				} else {
					// Once delivery is uncertain, only observation can prove that
					// there is no local owner. Caller expiry is not that proof.
					uncertain = true
				}
			}
			if !accepted && !uncertain && ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if accepted || uncertain {
			// Socket and caller deadlines cannot discharge the local lifecycle
			// owner. Observation continues until the actual worker settles.
			r, e := d.exchange(context.Background(), "workspace-observe", b, nil, nil)
			if e == nil && r.State == "refused" && r.Refusal == "not-accepted" {
				uncertain = false
				if ctx.Err() != nil {
					return r, ctx.Err()
				}
			}
			if e == nil && r.State != "refused" {
				accepted, uncertain = true, false
				if err = d.acceptEvidence(r); err != nil {
					if op != "workspace-cleanup" {
						return r, err
					}
					persistenceErr = err
				}
				if err = d.actions(context.Background(), b, r); err != nil {
					if authorityrpc.TransientTransport(err) {
						// Delivery does not change action ownership. The next snapshot
						// decides whether to hand off original copies or only observe.
						time.Sleep(20 * time.Millisecond)
						continue
					}
					if op == "workspace-cleanup" {
						return r, err
					}
					d.CloseAdmission(d.bindingGeneration())
					// The child independently observes the changed serial and joins
					// this defeated job before a successor can own cleanup.
					for {
						snap, e := d.exchange(context.Background(), "workspace-observe", b, nil, nil)
						if e == nil && snap.State == "failed" {
							return snap, err
						}
						select {
						case <-d.exited:
							return r, err
						case <-time.After(20 * time.Millisecond):
						}
					}
				}
				switch r.State {
				case "prepared", "cold", "cleanup-finalized":
					return r, errors.Join(ctx.Err(), persistenceErr)
				case "failed":
					return r, errors.New(r.Reason)
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func localWitness(w Witness) mountcontrol.Witness {
	r := ""
	if w.RoutesRevision != [32]byte{} {
		r = hex.EncodeToString(w.RoutesRevision[:])
	}
	return mountcontrol.Witness{Process: w.Process, Source: w.Source, Target: w.Target, Kernel: w.Kernel, Session: w.Session, Enrollment: w.Enrollment, RoutesRevision: r}
}
func (d *Driver) recovery(ctx context.Context, g uint64, op string, t proto.Message) (Recovery, error) {
	r, err := d.job(ctx, op, t, "")
	out := Recovery{Generation: g}
	if r == nil {
		return out, err
	}
	out.GateSerial, _ = strconv.ParseUint(r.Binding.GateSerial, 10, 64)
	out.Loss, out.Outcome, _ = decodeEvidence(r)
	if r.State != "prepared" || r.Readiness == nil {
		return out, err
	}
	n := r.Readiness
	out.State = "ready"
	out.SessionID = r.Witness.Session
	ns, _ := strconv.ParseInt(r.AuthorizationDeadlineUnixNanos, 10, 64)
	out.AuthorizationDeadline = time.Unix(0, ns)
	out.Standalone = n.Standalone
	out.SessionValidated = n.SessionValidated
	out.AuthorizationValidated = n.AuthorizationValidated
	out.ColdSubscriptionInstalled = n.SubscriptionIncarnation != "0"
	seq, _ := strconv.ParseUint(n.Renewal.InstalledSequence, 10, 64)
	out.Renewal = mountenrollment.RenewalReadiness{State: n.Renewal.State, InstalledSequence: seq, Permit: mountenrollment.Permit{Generation: g, GateSerial: out.GateSerial}, SessionID: out.SessionID, AuthorizationDeadline: out.AuthorizationDeadline}
	if err == nil {
		proof, e := d.gate.Recovery(g)
		if e == nil {
			if proof.Serial() != out.GateSerial {
				e = workspaceadmission.ErrClosed
			} else {
				e = d.gate.Prepared(proof)
			}
		}
		err = e
	}
	return out, err
}
func (d *Driver) Prepare(ctx context.Context, g uint64) (Recovery, error) {
	return d.recovery(ctx, g, "workspace-prepare", nil)
}
func (d *Driver) Recover(ctx context.Context, t *pb.ResumeToken) (Recovery, error) {
	return d.recovery(ctx, t.Suspension.Generation, "workspace-recover", t)
}
func (d *Driver) Suspend(ctx context.Context, s *pb.Suspension) (ColdResult, error) {
	r, err := d.job(ctx, "workspace-suspend", s, "")
	out := ColdResult{Generation: s.Generation}
	if r != nil {
		out.ColdComplete = r.State == "cold" && r.ColdComplete
		out.Loss, out.Outcome, _ = decodeEvidence(r)
	}
	return out, err
}
func (d *Driver) Cleanup(_ context.Context, _ Witness) (CleanupProof, error) {
	return d.remove(context.Background(), "terminal")
}

// cleanupProof reads the existing inventory, including evidence acquired by a
// failed finalization. It does not infer removal from an outcome observation.
func (d *Driver) cleanupProof() CleanupProof {
	p := CleanupProof{Witness: d.bound()}
	for _, run := range d.manager.Inventory.Snapshot() {
		if proto.Equal(run.Mount, d.id) {
			p.Loss, p.Outcome = run.Loss, run.Outcome
			break
		}
	}
	if d.cleaned.Load() {
		p.ProcessExited, p.KernelAbsent = true, true
	}
	return p
}
func (d *Driver) remove(ctx context.Context, mode string) (proof CleanupProof, result error) {
	defer func() { evidence := d.cleanupProof(); proof.Loss, proof.Outcome = evidence.Loss, evidence.Outcome }()
	d.cleanupMu.Lock()
	defer d.cleanupMu.Unlock()
	if d.cleaned.Load() {
		return CleanupProof{Witness: d.bound(), ProcessExited: true, KernelAbsent: true}, nil
	}
	d.CloseAdmission(d.bindingGeneration())
	_, err := d.job(ctx, "workspace-cleanup", nil, mode)
	if err != nil {
		select {
		case <-d.exited:
		default:
			return CleanupProof{Witness: d.bound()}, err
		}
		if absentErr := d.proveExitedAbsent(); absentErr != nil {
			d.effectMu.Lock()
			removeErr := d.removeKernelLocked("terminal", "3")
			d.effectMu.Unlock()
			if removeErr != nil {
				return CleanupProof{Witness: d.bound()}, errors.Join(err, absentErr, removeErr)
			}
			if absentErr = d.proveExitedAbsent(); absentErr != nil {
				return CleanupProof{Witness: d.bound()}, absentErr
			}
		}
	} else {
		<-d.exited
	}
	var run *Desired
	for _, r := range d.manager.Inventory.Snapshot() {
		if proto.Equal(r.Mount, d.id) {
			run = r
			break
		}
	}
	if run == nil {
		return CleanupProof{Witness: d.bound()}, errors.New("workspace cleanup intent missing")
	}
	w, err := d.manager.reconcileCLI(context.Background(), run, d.bound().Process, d.bound().Process == "")
	if err != nil {
		return CleanupProof{Witness: d.bound()}, err
	}
	w, err = d.bindWitness(w)
	if err != nil {
		return CleanupProof{Witness: w}, err
	}
	d.mu.Lock()
	d.witness = w
	d.mu.Unlock()
	err = d.manager.Inventory.Reconcile(d.id, func(run *Desired) error {
		if run.Witness != w {
			return errors.New("workspace cleanup witness disagreement")
		}
		if d.kernel != nil {
			return d.kernel.Absent()
		}
		_, err := fusev3.ObservePlannedKernelMountAbsent(w.Source, w.Target)
		return err
	})
	if err != nil {
		return CleanupProof{Witness: w}, err
	}
	if d.kernel != nil {
		if err = d.kernel.Finalize(); err != nil {
			return CleanupProof{Witness: w}, err
		}
	}
	if err = d.manager.Identity.Reissue(&pb.IdentityRequest{AuthorityId: d.id.AuthorityId, VolumeId: d.id.VolumeId}, false, d.proveExitedAbsent); err != nil {
		return CleanupProof{Witness: w}, err
	}
	d.cleaned.Store(true)
	d.target.Close()
	if d.gate != nil {
		d.gate.Dispose()
	}
	return CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true}, nil
}
func (d *Driver) bindingGeneration() uint64 { d.mu.Lock(); defer d.mu.Unlock(); return d.generation }

func (d *Driver) proveExitedAbsent() error {
	select {
	case <-d.exited:
	default:
		return errors.New("workspace process still owned")
	}
	if d.kernel != nil {
		return d.kernel.Absent()
	}
	w := d.bound()
	_, err := fusev3.ObservePlannedKernelMountAbsent(w.Source, w.Target)
	return err
}

// Called synchronously by the shared clock owner outside its mutex. No disk
// or child wait is allowed on this boundary.
func (m *Manager) ClockUnavailable() {
	m.mu.Lock()
	var mounts []*Driver
	for _, d := range m.mounts {
		mounts = append(mounts, d)
	}
	m.mu.Unlock()
	for _, d := range mounts {
		d.CloseAdmission(d.bindingGeneration())
	}
}
func (d *Driver) watch() {
	t := time.NewTicker(25 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-d.exited:
			if d.registered.Load() && !d.cleaned.Load() {
				d.CloseAdmission(d.bindingGeneration())
				_ = d.manager.Host.Terminal(d.id, "workspace child exited", nil)
				if d.terminalCleanup.CompareAndSwap(false, true) {
					proof, _ := d.remove(context.Background(), "terminal")
					_ = d.manager.Host.Cleanup(d.id, proof)
				}
			}
			return
		case <-t.C:
		}
		d.mu.Lock()
		var b mountcontrol.Workspace
		if d.operation != nil {
			b = *d.operation
		}
		d.mu.Unlock()
		if b.OperationID == "" {
			continue
		}
		r, err := d.exchange(context.Background(), "workspace-observe", b, nil, nil)
		if err != nil {
			continue
		}
		terminal := r.Phases != nil && r.Phases.TerminalRemoval.Progress == "offered"
		if terminal && d.terminalCleanup.CompareAndSwap(false, true) {
			_ = d.manager.Host.Terminal(d.id, "workspace terminal removal required", nil)
			go func() {
				proof, _ := d.remove(context.Background(), "terminal")
				_ = d.manager.Host.Cleanup(d.id, proof)
			}()
		} else if r.State == "recovery-required" {
			g, _ := strconv.ParseUint(b.Generation, 10, 64)
			serial, _ := strconv.ParseUint(b.GateSerial, 10, 64)
			_ = d.manager.Host.RecoveryRequired(d.id, g, serial, "workspace clock or subscription proof unavailable")
		}
	}
}
