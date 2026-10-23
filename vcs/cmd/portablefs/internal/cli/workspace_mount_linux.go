//go:build linux

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"path/filepath"
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
	"github.com/steerlabs/portablefs/vcs/internal/mountv3"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceclock"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceguest"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

type workspaceChild struct {
	client        *authorityrpc.Client
	renewCancel   context.CancelFunc
	renewDone     chan struct{}
	launch        workspacemount.Launch
	reader        *workspaceadmission.Reader
	clock         *workspaceclock.Reader
	clockBinding  workspaceclock.Binding
	control       *workspaceControlConfig
	fence         *authorityrpc.DispatchFence
	renewer       *mountenrollment.Renewer
	manager       *mountenrollment.Client
	generation    atomic.Uint64
	localOpen     atomic.Bool
	mounted       atomic.Pointer[fuseV3Mount]
	install       chan *mountcontrol.Rights
	installed     chan error
	finalized     chan struct{}
	mu            sync.Mutex
	state         mountState
	kernelWitness string
	operation     *mountOperation
	outcomes      *workspaceguest.OutcomeInventory
}

func (e *cmdEnv) runWorkspaceMount(o *mountOpts, volume, path string) int {
	seen := map[int]bool{}
	for _, fd := range []int{o.workspaceGateFD, o.workspaceOwnerFD, o.workspaceBootstrapFD, o.workspaceClockFD, o.workspaceReadyFD} {
		if fd < 3 || seen[fd] {
			return e.fail("mount", errors.New("workspace requires five distinct inherited descriptors"))
		}
		seen[fd] = true
		syscall.CloseOnExec(fd)
	}
	if os.Geteuid() != 1000 || os.Getegid() != 1000 || !o.foreground {
		return e.fail("mount", errors.New("workspace child requires UID/GID 1000 foreground mode"))
	}
	input := os.NewFile(uintptr(o.workspaceBootstrapFD), "workspace private launch")
	launch, err := workspacemount.ReadLaunch(input)
	input.Close()
	if err != nil {
		return e.fail("mount", err)
	}
	if err = control.Provision(launch.Provision); err != nil {
		return e.fail("mount", err)
	}
	if volume != launch.Provision.Mount.VolumeId || path != filepath.Join("/workspaces", volume) || base64.RawURLEncoding.EncodeToString(launch.Binding.Incarnation[:]) != base64.RawURLEncoding.EncodeToString(launch.Provision.Mount.Incarnation) {
		return e.fail("mount", errors.New("workspace launch target or incarnation mismatch"))
	}
	c := &workspaceChild{launch: launch, install: make(chan *mountcontrol.Rights), installed: make(chan error, 1), finalized: make(chan struct{}), fence: authorityrpc.NewDispatchFence()}
	reader, err := workspaceadmission.Adopt(os.NewFile(uintptr(o.workspaceGateFD), "workspace gate"), os.NewFile(uintptr(o.workspaceOwnerFD), "workspace owner"), launch.Binding, func() {
		c.localOpen.Store(false)
		if m := c.mounted.Load(); m != nil {
			m.mount.RevokeWorkspace(errors.New("workspace owner pipe ended"))
		}
	})
	if err != nil {
		return e.fail("mount", err)
	}
	c.reader = reader
	defer reader.Retire()
	c.clock, err = workspaceclock.OpenReader(os.NewFile(uintptr(o.workspaceClockFD), "workspace TLS clock"), launch.ClockBinding)
	if err != nil {
		return e.fail("mount", err)
	}
	defer c.clock.Close()
	c.clockBinding = workspaceclock.Binding{Owner: c.clock, Generation: c.generation.Load, Current: c.current}
	if launch.Provision.HostedEnrollment != nil {
		h := launch.Provision.HostedEnrollment
		c.manager, err = mountenrollment.NewClient(mountenrollment.Config{Managed: true, AwaitTLS: c.clockBinding.AwaitTLS, ManagerURL: h.ManagerOrigin, ManagerServerName: h.ManagerServerName, ManagerCAPEM: h.ManagerCa, EnrollmentID: h.EnrollmentId, EnrollmentCertificatePEM: h.EnrollmentCertificate, ClientKeyPEM: launch.PrivateKey, VolumeID: volume, AuthorityGeneration: h.AuthorityGeneration})
		if err != nil {
			return e.fail("mount", err)
		}
		c.renewer = &mountenrollment.Renewer{Managed: true, Source: c.manager, CheckPermit: c.current, WallChanges: c.clock.Corrections}
	}
	c.outcomes, err = workspaceguest.OpenOutcomeInventory(filepath.Join(launch.StateDirectory, "outcomes.json"))
	if err != nil {
		return e.fail("mount", err)
	}
	start, err := processStartIdentity(os.Getpid())
	if err != nil {
		return e.fail("mount", err)
	}
	instance := reader.MountInstanceID()
	c.state = mountState{MountPath: path, VolumeID: volume, PID: os.Getpid(), ProcessStartIdentity: start, Strategy: "fuse", Engine: mountEngineFuseV3, MountInstanceID: instance, MountTargetDevice: launch.TargetDevice, MountTargetInode: launch.TargetInode, MountMechanism: "direct", AuthorityURL: launch.Provision.AuthorityEndpoint, DataPlaneTransport: dataPlaneTransportTLSPrivateCA, DataPlaneServerName: launch.Provision.ServerName, StartedAtMs: time.Now().UnixMilli()}
	caHash := sha256.Sum256(launch.Provision.CaCertificate)
	c.state.DataPlaneCASHA256 = hex.EncodeToString(caHash[:])
	c.state.DataPlaneCAPath = filepath.Join(launch.StateDirectory, "authority-ca.pem")
	if err = os.WriteFile(c.state.DataPlaneCAPath, launch.Provision.CaCertificate, 0600); err != nil {
		return e.fail("mount", err)
	}
	c.operation, err = acquireMountOperation(launch.StateDirectory, path, volume, "fuse")
	if err != nil {
		return e.fail("mount", err)
	}
	defer c.operation.close(false)
	hydrateMountOperationFromState(c.operation, &c.state)
	if err = c.operation.writeIntent("mounting", os.Getpid(), start); err != nil {
		return e.fail("mount", err)
	}
	pidStart, err := mountcontrol.ProcessStart(int32(os.Getpid()))
	if err != nil {
		return e.fail("mount", err)
	}
	w := mountcontrol.Witness{Process: strconv.Itoa(os.Getpid()) + ":" + strconv.FormatUint(pidStart, 10), Source: "portablefs:" + instance, Target: path}
	c.control = &workspaceControlConfig{Supervisor: mountcontrol.Peer{UID: 0, PID: launch.Binding.SupervisorPID, Start: launch.Binding.SupervisorStart}}
	c.control.Owner = mountcontrol.Owner{CheckPermit: func(b mountcontrol.Workspace) bool {
		if b.BootID != hex.EncodeToString(launch.Binding.Boot[:]) || b.HostServiceID != hex.EncodeToString(launch.Binding.HostService[:]) || b.GuestServiceID != hex.EncodeToString(launch.Binding.GuestService[:]) {
			return false
		}
		g, _ := strconv.ParseUint(b.Generation, 10, 64)
		s, _ := strconv.ParseUint(b.GateSerial, 10, 64)
		_, err := c.reader.Recovery(g, s)
		return err == nil
	}, CloseAdmission: func() {
		c.localOpen.Store(false)
		if m := c.mounted.Load(); m != nil {
			m.mount.CloseWorkspaceAdmission()
		}
	}, Driver: mountcontrol.Driver{Run: c.run, ValidateInstall: func(rights *mountcontrol.Rights, p mountcontrol.Phase) error {
		return fusev3.ValidateManagedDescriptors(rights.FDs[0], rights.FDs[1], p.Witness.Source, p.Witness.Target)
	}, Install: c.adoptKernel}}
	if err = c.control.Owner.Record(mountcontrol.Facts{Witness: w}); err != nil {
		return e.fail("mount", err)
	}
	listener, err := startFuseMountControl(nil, nil, c.control)
	if err != nil {
		return e.fail("mount", err)
	}
	defer listener.Close()
	c.state.ReauthorizationControlSocket = listener.SocketPath()
	ready := os.NewFile(uintptr(o.workspaceReadyFD), "workspace control ready")
	err = json.NewEncoder(ready).Encode(workspacemount.ChildReady{Socket: listener.SocketPath()})
	ready.Close()
	if err != nil {
		return e.fail("mount", err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.monitor(lifetime)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-c.finalized:
		return 0
	case <-reader.Done():
		// The root is gone. Keep the same offered action and evidence; the host
		// must discard this VM. This child has no path-based unmount authority.
		<-c.finalized
		return 1
	case <-signals:
		_ = c.control.Owner.RequireRemoval(context.Background(), "terminal", "workspace child signal")
		<-c.finalized
		return 0
	}
}
func (c *workspaceChild) current(p mountenrollment.Permit) bool {
	if !c.localOpen.Load() || c.generation.Load() != p.Generation {
		return false
	}
	proof, err := c.reader.Recovery(p.Generation, p.GateSerial)
	return err == nil || c.reader.Installed(proof)
}
func (c *workspaceChild) adoptKernel(ctx context.Context, j *mountcontrol.Job, r *mountcontrol.Rights) (mountcontrol.Witness, error) {
	q := j.Request()
	w := q.Workspace.Phase
	_ = w
	select {
	case c.install <- r:
	case <-ctx.Done():
		return mountcontrol.Witness{}, ctx.Err()
	}
	err := <-c.installed
	r.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.witnessLocked(), err
}
func (c *workspaceChild) witnessLocked() mountcontrol.Witness {
	start, _ := mountcontrol.ProcessStart(int32(os.Getpid()))
	w := mountcontrol.Witness{Process: strconv.Itoa(os.Getpid()) + ":" + strconv.FormatUint(start, 10), Source: "portablefs:" + c.state.MountInstanceID, Target: c.state.MountPath, Session: c.state.AuthorizationSessionID, Enrollment: c.state.MountEnrollmentID, RoutesRevision: c.state.LocalRouteRevision}
	if c.state.KernelMountID != "" {
		w.Kernel = c.kernelWitness
	}
	return w
}
func (c *workspaceChild) facts(o fusev3.WorkspaceObservation) mountcontrol.Facts {
	c.mu.Lock()
	w := c.witnessLocked()
	c.mu.Unlock()
	f := mountcontrol.Facts{Witness: w, AuthorizationDeadlineUnixNanos: "0", Outcome: mountcontrol.Outcome{Durability: "unresolved", Observation: "unobserved", Release: "unresolved", CleanupDebt: "0"}}
	if m := c.mounted.Load(); m != nil {
		f.AuthorizationDeadlineUnixNanos = strconv.FormatInt(m.AuthorizationDeadline().UnixNano(), 10)
	}
	if o.Outcome != nil {
		f.Outcome = mountcontrol.Outcome{Durability: o.Outcome.Durability, Observation: o.Outcome.Observation, Release: o.Outcome.Release, CleanupDebt: strconv.FormatUint(o.Outcome.CleanupDebt, 10)}
	}
	for _, l := range o.Loss {
		f.Loss = append(f.Loss, mountcontrol.Loss{Sequence: strconv.FormatUint(l.Sequence, 10), AcceptedEntries: strconv.FormatUint(l.AcceptedEntries, 10), AcceptedBytes: strconv.FormatUint(l.AcceptedBytes, 10), Reason: l.Reason, Aggregated: l.Aggregated})
	}
	if o.Prepared {
		proof := mountenrollment.RenewalReadiness{State: "not-required"}
		if c.renewer != nil {
			proof = c.renewer.Readiness()
		}
		f.Readiness = &mountcontrol.Prepared{SessionValidated: true, AuthorizationValidated: true, Standalone: c.renewer == nil, Renewal: mountcontrol.Renewal{State: proof.State, InstalledSequence: strconv.FormatUint(proof.InstalledSequence, 10)}, SubscriptionIncarnation: strconv.FormatUint(o.SubscriptionIncarnation, 10)}
	}
	return f
}
func (c *workspaceChild) persist(o fusev3.WorkspaceObservation) error {
	return c.outcomes.Commit(&pb.MountStatus{Mount: c.launch.Provision.Mount, Outcome: o.Outcome, Loss: o.Loss})
}
func (c *workspaceChild) run(ctx context.Context, j *mountcontrol.Job) mountcontrol.LifecycleResult {
	q := j.Request()
	g, _ := strconv.ParseUint(q.Workspace.Generation, 10, 64)
	serial, _ := strconv.ParseUint(q.Workspace.GateSerial, 10, 64)
	c.generation.Store(g)
	var o fusev3.WorkspaceObservation
	var err error
	switch q.Operation {
	case "workspace-prepare":
		c.localOpen.Store(true)
		err = c.prepare(ctx, j, g, serial)
		if err != nil {
			return authorityrpc.LifecycleCompletion(ctx, err)
		}
		o, err = c.mounted.Load().mount.PrepareWorkspace(ctx, g, serial)
	case "workspace-recover":
		c.localOpen.Store(true)
		m := c.mounted.Load()
		if m == nil {
			return authorityrpc.LifecycleCompletion(ctx, errors.New("workspace recovery has no installed mount"))
		}
		o, err = m.mount.RecoverWorkspace(ctx, g, serial)
	case "workspace-suspend":
		m := c.mounted.Load()
		if m == nil {
			return authorityrpc.LifecycleCompletion(ctx, errors.New("workspace suspension has no installed mount"))
		}
		o, err = m.mount.SuspendWorkspace(ctx, g, serial, j.DrainDeadline())
	case "workspace-cleanup":
		mode := q.Workspace.Phase.Mode
		err = c.control.Owner.RequireRemoval(ctx, mode, "managed cleanup")
		if err == nil && c.renewer != nil {
			err = c.renewer.Park(ctx)
			if err == nil && c.renewCancel != nil {
				c.renewCancel()
				<-c.renewDone
			}
		}
		if err == nil {
			if m := c.mounted.Load(); m != nil {
				m.Wait()
				err = m.Close()
			} else if c.client != nil {
				var proof fusev3.MountAbsenceProof
				proof, err = fusev3.ObservePlannedKernelMountAbsent("portablefs:"+c.state.MountInstanceID, c.state.MountPath)
				if err == nil {
					err = mountv3.NewTransport(c.client).DetachAfterUnmount(ctx, proof)
				}
				c.client.FinishLocalSessionEnforcement()
				err = errors.Join(err, c.client.Close())
			}
		}
		if err == nil && c.manager != nil {
			err = c.manager.Close(ctx, "workspace mount removed")
		}
		if err == nil {
			err = removeMountState(c.launch.StateDirectory, c.state.MountPath)
		}
		if err == nil {
			err = c.operation.close(true)
		}
		if err == nil {
			err = j.Publish("cleanup-finalized", c.facts(fusev3.WorkspaceObservation{}))
		}
		if err == nil {
			close(c.finalized)
		}
		return authorityrpc.LifecycleCompletion(ctx, err)
	default:
		return authorityrpc.LifecycleCompletion(ctx, errors.New("unknown workspace lifecycle"))
	}
	state := "prepared"
	if q.Operation == "workspace-suspend" {
		state = "cold"
	}
	if err == nil {
		err = j.Publish(state, c.facts(o))
	}
	if err != nil {
		return authorityrpc.LifecycleCompletion(ctx, err)
	}
	return o.Result
}
func (c *workspaceChild) prepare(ctx context.Context, j *mountcontrol.Job, g, serial uint64) error {
	if err := c.clockBinding.Wait(ctx, mountenrollment.Permit{Generation: g, GateSerial: serial}); err != nil {
		return err
	}
	if err := c.fence.Resume(func() error { return c.clockBinding.Check(mountenrollment.Permit{Generation: g, GateSerial: serial}) }); err != nil {
		return err
	}
	p := c.launch.Provision
	cert, err := tls.X509KeyPair(p.ClientCertificate, c.launch.PrivateKey)
	if err != nil {
		return errors.New("workspace client identity invalid")
	}
	identity := &clientTLSIdentity{certificate: cert, keyPEM: c.launch.PrivateKey}
	transport := dataPlaneTransport{Mode: dataPlaneTransportTLSPrivateCA, ServerName: p.ServerName, CAPEM: string(p.CaCertificate), CASHA256: c.state.DataPlaneCASHA256}
	accepted := false
	m, _, _, err := mountFUSEv3(ctx, fuseV3Config{addr: p.AuthorityEndpoint, token: string(p.Capability), transport: transport, identity: identity, volumeID: p.Mount.VolumeId, mountPath: c.state.MountPath, mountInstanceID: c.state.MountInstanceID, backingRoot: c.launch.BackingRoot, requireMountEnrollment: c.renewer != nil, awaitTLS: c.clockBinding.AwaitTLS, dispatchFence: c.fence, beforeKernel: func(client *authorityrpc.Client, routes mountRoutes) (*fusev3.ManagedConfig, error) {
		c.client = client
		revision := routes.rules.Revision()
		if !bytes.Equal(revision[:], p.RoutesRevision) {
			return nil, errors.New("workspace route revision changed before bootstrap")
		}
		c.mu.Lock()
		c.state.AuthorizationSessionID = sessionString(client)
		c.state.LocalRouteRevision = routes.revision
		c.state.LocalRoutes = routes.rules.Patterns()
		if p.HostedEnrollment != nil {
			c.state.MountEnrollmentID = p.HostedEnrollment.EnrollmentId
		}
		w := c.witnessLocked()
		c.mu.Unlock()
		if err := j.Publish("preparing", mountcontrol.Facts{Witness: w}); err != nil {
			return nil, err
		}
		if err := j.OfferInstall(mountcontrol.Phase{ActionID: "1", Options: fusev3.ManagedKernelOptions(clientMaxRead(client)), Witness: w}); err != nil {
			return nil, err
		}
		var rights *mountcontrol.Rights
		select {
		case rights = <-c.install:
			accepted = true
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		kernel, err := fusev3.ObserveManagedKernelIdentity(w.Source, w.Target)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.kernelWitness = kernel
		c.state.KernelMountID = strings.Split(kernel, "@")[0]
		hydrateMountOperationFromState(c.operation, &c.state)
		err = c.operation.writeIntent("mounting", os.Getpid(), c.state.ProcessStartIdentity)
		w = c.witnessLocked()
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if err = c.control.Owner.Record(mountcontrol.Facts{Witness: w}); err != nil {
			return nil, err
		}
		return &fusev3.ManagedConfig{Admission: c.reader, Permit: mountenrollment.Permit{Generation: g, GateSerial: serial}, Clock: c.clockBinding, Renewer: c.renewer, Standalone: c.renewer == nil, Persist: c.persist, FUSE: rights.FDs[0], Abort: rights.FDs[1], Remove: func(mode string) error {
			return c.control.Owner.RequireRemoval(context.Background(), mode, "kernel removal required")
		}}, nil
	}})
	if accepted {
		c.installed <- err
	}
	if err != nil {
		return err
	}
	c.mounted.Store(m)
	c.mu.Lock()
	c.state.AuthorizationDeadlineAtMs = m.AuthorizationDeadline().UnixMilli()
	err = writeMountState(c.launch.StateDirectory, c.state)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if c.renewer != nil {
		renewCtx, cancel := context.WithCancel(context.Background())
		c.renewCancel = cancel
		c.renewDone = make(chan struct{})
		go func() {
			defer close(c.renewDone)
			_ = c.renewer.Run(renewCtx, m.AuthorizationSessionID(), m.InitialAuthorizationDeadline(), m.Reauthorize)
		}()
	}
	return j.WaitInstall(ctx)
}
func (c *workspaceChild) monitor(ctx context.Context) {
	timer := time.NewTicker(20 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		c.control.Owner.PollPermit()
		m := c.mounted.Load()
		if m == nil {
			continue
		}
		o := m.mount.WorkspaceObservation()
		if c.renewer != nil && c.localOpen.Load() {
			cut := c.renewer.ParkBefore()
			if !cut.IsZero() && !time.Now().Before(cut) {
				c.control.Owner.InvalidatePrepared("renewal parking boundary")
				_ = c.renewer.Park(ctx)
			}
		}
		if o.State == fusev3.WorkspaceRecoveryRequired {
			c.control.Owner.InvalidatePrepared("workspace proof unavailable")
			if c.renewer != nil {
				_ = c.renewer.Park(ctx)
			}
		}
		if o.State == fusev3.WorkspaceTerminal {
			_ = c.control.Owner.RequireRemoval(ctx, "terminal", "terminal workspace mount")
		}
	}
}

func sessionString(c *authorityrpc.Client) string {
	id := c.AuthorizationSessionID()
	return base64.RawURLEncoding.EncodeToString(id[:])
}
func clientMaxRead(c *authorityrpc.Client) uint32 { r, _ := c.IOLimits(); return r }
