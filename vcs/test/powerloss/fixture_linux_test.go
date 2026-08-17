//go:build linux

package powerloss

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The two-process fixture: a real portablefs-authority and a real
// portablefs-mount-v3, started from binaries built out of this tree, over a
// real XFS cell provisioned by the production provisioner.
//
// It is modelled on scripts/coherence-matrix-linux.sh and for the same reason:
// nothing in this harness may be able to agree with itself. A kill has to
// remove a real process, an fsync has to cross a real kernel FUSE mount and a
// real socket, and the bytes have to land on a real filesystem. An in-process
// fixture could not be killed the way this one is.
//
// The test process is root because it owns the device layer. Everything in the
// data path is spawned as the unprivileged volume identity, exactly as the
// deployment runs it.

type cell struct {
	gate       authorityGate
	runner     commandRunner
	root       string // the XFS cell mount point
	volumeRoot string // the provisioned volume directory inside it
	home       string // the service identity's scratch directory
	staging    string // the write-staging bind mount the authority is given
	// stagingBound is ownership, not a cached observation: the fixture sets it
	// only after mount --bind succeeds and clears it only after exact absence is
	// proved. The device instrument must discharge this ownership before it can
	// claim the dm target is free for a cut.
	stagingBound bool
	logDir       string
	ledgerDir    string // where the unprivileged driver writes its ledgers
}

// commandRunner is deliberately smaller than Runner so the teardown contract
// can be unit tested without creating mounts. The privileged tests still pass
// the real narrated Runner.
type commandRunner interface {
	Run(string, ...string) (string, error)
}

// provisionCell runs the production provisioner over an already-mounted XFS
// cell and prepares everything the authority needs to start.
//
// The provisioner is the shipped script rather than a copy of its steps, so
// this harness exercises what a deployment runs. A private reimplementation
// could drift and let a power-cut result be attributed to a filesystem layout
// nobody deploys.
func provisionCell(t *testing.T, gate authorityGate, mountpoint string) *cell {
	t.Helper()
	c := &cell{
		gate:       gate,
		runner:     gate.runner,
		root:       mountpoint,
		volumeRoot: filepath.Join(mountpoint, gate.volume),
		home:       filepath.Join(gate.workDir, "service"),
		staging:    filepath.Join(gate.workDir, "service", "write-staging"),
		logDir:     filepath.Join(gate.workDir, "logs"),
		ledgerDir:  filepath.Join(gate.workDir, "ledgers"),
	}
	for _, directory := range []string{c.home, c.staging, c.logDir, c.ledgerDir, filepath.Join(c.home, "tmp")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("creating %s: %v", directory, err)
		}
		if err := os.Chown(directory, int(gate.serviceUID), int(gate.serviceGID)); err != nil {
			t.Fatalf("giving %s to the service identity: %v", directory, err)
		}
	}
	if _, err := gate.runner.Run("bash", gate.provisioner, mountpoint, gate.volume,
		fmt.Sprint(gate.projectID), fmt.Sprint(gate.serviceUID), fmt.Sprint(gate.serviceGID), "1g", "200000"); err != nil {
		t.Fatalf("provisioning the volume: %v", err)
	}
	// The authority's staging root is a service-owned 0700 directory in
	// production, presented through a bind mount out of the cell's root-owned
	// control directory. privatepath opens every component and would refuse the
	// 0711 control directory, so the harness reproduces the same bind rather
	// than relaxing the layout the product validates.
	source := filepath.Join(mountpoint, ".portablefs-control", gate.volume, "write-staging")
	if _, err := gate.runner.Run("mount", "--bind", source, c.staging); err != nil {
		t.Fatalf("binding the write-staging directory: %v", err)
	}
	c.stagingBound = true
	t.Cleanup(func() {
		if err := c.releaseWriteStaging(); err != nil {
			t.Errorf("releasing the write-staging bind mount: %v", err)
		}
	})
	return c
}

// asService builds a command that runs as the unprivileged volume identity
// with a clean environment, the way the deployment's service unit does.
func (c *cell) asService(name string, arguments ...string) *exec.Cmd {
	command := exec.Command(name, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: c.gate.serviceUID, Gid: c.gate.serviceGID},
		// A private process group is what lets a kill reach a whole process
		// tree without reaching the test binary that started it.
		Setpgid: true,
	}
	command.Env = []string{
		"HOME=" + c.home,
		"PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin",
		"TMPDIR=" + filepath.Join(c.home, "tmp"),
	}
	command.Dir = c.home
	return command
}

// process is a spawned data-plane process together with the log it wrote, so a
// failure can print what it said before it died.
//
// exit is CLOSED rather than written once, because both wait and kill observe
// it and a one-shot channel would make whichever came second block forever on
// a process that had already gone.
type process struct {
	name    string
	command *exec.Cmd
	logPath string
	exit    chan struct{}
	err     error
}

func (p *process) reap(wait func() error) {
	p.err = wait()
	close(p.exit)
}

// exited reports whether the process is already gone, without blocking.
func (p *process) exited() bool {
	select {
	case <-p.exit:
		return true
	default:
		return false
	}
}

// start spawns one data-plane binary. label distinguishes repeated starts of
// the same binary so a later round cannot overwrite the log an earlier failure
// needs.
func (c *cell) start(t *testing.T, name, label string, arguments ...string) *process {
	t.Helper()
	logPath := filepath.Join(c.logDir, name+"-"+label+".log")
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("creating the %s log: %v", name, err)
	}
	defer func() { _ = logFile.Close() }()
	command := c.asService(filepath.Join(c.gate.binDir, name), arguments...)
	command.Stdout = logFile
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		t.Fatalf("starting %s: %v", name, err)
	}
	spawned := &process{name: name + " (" + label + ")", command: command, logPath: logPath, exit: make(chan struct{})}
	go spawned.reap(command.Wait)
	t.Cleanup(func() {
		// Any failure in this test prints every data-plane log. A power-loss
		// failure is almost never explicable from the assertion alone, and the
		// process that actually refused something is usually not the one the
		// assertion names.
		if t.Failed() {
			spawned.dump(t)
		}
		// A surviving process holds descriptors into the cell, and the cell
		// cannot be unmounted while it does - which leaves the device-mapper
		// target and both loop devices behind for the next run on this machine.
		spawned.terminate()
	})
	return spawned
}

// kill delivers SIGKILL to the whole process group and waits for it to be
// gone. Nothing here is graceful on purpose: the instrument is a power cut,
// and a process given a chance to flush would be measuring shutdown rather
// than durability.
func (p *process) kill(t *testing.T) {
	t.Helper()
	if err := p.forceKill(30 * time.Second); err != nil {
		t.Fatal(err)
	}
}

// forceKill is the evidence-producing half of kill. Waiting for Wait to reap
// the process is essential: sending SIGKILL is an intention, not proof that a
// process holding the cell has stopped doing so.
func (p *process) forceKill(bound time.Duration) error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return errors.New("process absence cannot be proved for a process that was never started")
	}
	if p.exited() {
		return nil
	}
	_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
	_ = syscall.Kill(p.command.Process.Pid, syscall.SIGKILL)
	select {
	case <-p.exit:
		return nil
	case <-time.After(bound):
		return fmt.Errorf("%s survived SIGKILL for %s; process absence was not proved", p.name, bound)
	}
}

// stop asks a process to perform its ordinary shutdown and requires both a
// clean exit and the caller's time bound. It is used only after a restart
// probe, where an authenticated Detach is part of the setup for the next
// authority epoch; the crash points themselves always use forceKill.
func (p *process) stop(bound time.Duration) error {
	if p == nil || p.command == nil || p.command.Process == nil {
		return nil
	}
	if !p.exited() {
		_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGTERM)
		_ = syscall.Kill(p.command.Process.Pid, syscall.SIGTERM)
		select {
		case <-p.exit:
		case <-time.After(bound):
			return fmt.Errorf("%s did not complete clean shutdown within %s", p.name, bound)
		}
	}
	if p.err != nil {
		return fmt.Errorf("%s clean shutdown: %w", p.name, p.err)
	}
	return nil
}

// terminate is kill without a testing.T. Teardown runs after the assertions
// are done, and a teardown that fails the test for a process that was already
// on its way out would report the wrong thing.
func (p *process) terminate() {
	if p == nil || p.command == nil || p.command.Process == nil || p.exited() {
		return
	}
	_ = p.forceKill(30 * time.Second)
}

func (p *process) dump(t *testing.T) {
	t.Helper()
	content, err := os.ReadFile(p.logPath)
	if err != nil {
		t.Logf("==== %s log unreadable: %v", p.name, err)
		return
	}
	t.Logf("==== %s log ====\n%s", p.name, strings.TrimSpace(string(content)))
}

// priorStrictMountsFenced is the harness's local operator evidence. The
// authority deliberately cannot verify --prior-strict-mounts-fenced itself;
// the fixture may make that assertion only after it has reaped the mount
// process and proved the exact kernel mount absent.
type priorStrictMountsFenced struct {
	mountpoint         string
	mountProcessExited bool
	kernelMountAbsent  bool
}

func (fence priorStrictMountsFenced) validate() error {
	if fence.mountpoint == "" || !fence.mountProcessExited || !fence.kernelMountAbsent {
		return errors.New("prior strict mount fencing requires a reaped mount process and an absent exact kernel mount")
	}
	return nil
}

func priorStrictMountFenceArguments(fence *priorStrictMountsFenced) ([]string, error) {
	if fence == nil {
		return nil, nil
	}
	if err := fence.validate(); err != nil {
		return nil, err
	}
	return []string{"--prior-strict-mounts-fenced"}, nil
}

// startAuthority brings up an initial authority epoch. A replacement after an
// unclean mount loss must use startAuthorityAfterFence instead.
func (c *cell) startAuthority(t *testing.T, label string) *process {
	return c.startAuthorityEpoch(t, label, nil)
}

// startAuthorityAfterFence consumes the proof required by the production
// restart contract and makes the same audited operator assertion the control
// plane would make after fencing a host.
func (c *cell) startAuthorityAfterFence(t *testing.T, label string, fence priorStrictMountsFenced) *process {
	t.Helper()
	if err := fence.validate(); err != nil {
		t.Fatalf("starting a replacement authority: %v", err)
	}
	return c.startAuthorityEpoch(t, label, &fence)
}

// startAuthorityEpoch uses the same command shape as the coherence matrix.
// The optional assertion is added only through a validated fencing receipt,
// never because an authority happened to stop listening.
func (c *cell) startAuthorityEpoch(t *testing.T, label string, fence *priorStrictMountsFenced) *process {
	t.Helper()
	gate := c.gate
	fenceArguments, err := priorStrictMountFenceArguments(fence)
	if err != nil {
		t.Fatalf("starting authority epoch: %v", err)
	}
	arguments := []string{
		"--listen", fmt.Sprintf("127.0.0.1:%d", gate.port),
		"--volume-id", gate.volume,
		"--root", c.volumeRoot,
		"--project-id", fmt.Sprint(gate.projectID),
		"--tls-cert", filepath.Join(gate.credsDir, "server.crt"),
		"--tls-key", filepath.Join(gate.credsDir, "server.key"),
		"--client-ca", filepath.Join(gate.credsDir, "ca.pem"),
		"--capability-public-key", filepath.Join(gate.credsDir, "capability-public.pem"),
		"--visibility-membership-file", filepath.Join(c.root, ".portablefs-control", gate.volume, "strict-membership"),
		"--write-staging-dir", c.staging,
		// The bound the authority enforces must be strictly wider than the
		// window the credential set was minted with, not equal to it: the
		// minting tool back-dates not_before by a second, so a token asking for
		// exactly this lifetime declares a window one second longer and the
		// authority refuses it as absurd. That refusal arrives as EPERM on
		// attach, which reads exactly like a durability harness that cannot
		// mount. See envCapabilityLifetime.
		"--capability-max-lifetime", gate.capabilityBound().String(),
	}
	arguments = append(arguments, fenceArguments...)
	authority := c.start(t, "portablefs-authority", label, arguments...)
	listening := waitFor(30*time.Second, func() bool {
		connection, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", gate.port), time.Second)
		if err != nil {
			return false
		}
		_ = connection.Close()
		return true
	})
	if !listening {
		authority.dump(t)
		t.Fatal("the authority never listened; nothing later in this run could be measured")
	}
	return authority
}

// startMount brings up one kernel FUSE mount and waits for the kernel to carry
// it. A mount that never appears is a failure: a workload against a plain empty
// directory would report a green run having tested nothing.
func (c *cell) startMount(t *testing.T, name, token string) (*process, string) {
	t.Helper()
	gate := c.gate
	// Each mount gets its own directory. A killed mount is detached lazily and
	// its mountpoint stays occupied until the kernel drops the last reference,
	// so reusing one path across rounds would mount over a corpse.
	mountpoint := filepath.Join(c.home, "mount-"+name)
	if err := os.MkdirAll(mountpoint, 0o700); err != nil {
		t.Fatalf("creating %s: %v", mountpoint, err)
	}
	if err := os.Chown(mountpoint, int(gate.serviceUID), int(gate.serviceGID)); err != nil {
		t.Fatalf("giving %s to the service identity: %v", mountpoint, err)
	}
	mount := c.start(t, "portablefs-mount-v3", name,
		"--authority", fmt.Sprintf("127.0.0.1:%d", gate.port),
		"--volume-id", gate.volume,
		"--mountpoint", mountpoint,
		"--access-token-file", filepath.Join(gate.credsDir, token),
		"--tls-cert", filepath.Join(gate.credsDir, "client.crt"),
		"--tls-key", filepath.Join(gate.credsDir, "client.key"),
		"--tls-server-ca", filepath.Join(gate.credsDir, "ca.pem"),
		"--tls-server-name", "authority.portablefs.test",
		"--coherence", "strict",
	)
	// A dead mount holds its mountpoint, and a live server can keep descriptors
	// into the cell after lazy detach. Every fallback teardown therefore reaps
	// the server before releasing its kernel mount. Contract-bearing paths do
	// the same work explicitly and this cleanup then becomes idempotent.
	t.Cleanup(func() {
		mount.terminate()
		releaseMount(c.gate.runner, mountpoint)
	})
	// A mount that has already exited will never appear, so waiting the full
	// bound for it would only delay the report of why it refused.
	waitFor(45*time.Second, func() bool { return mount.exited() || isFUSE(c.gate.runner, mountpoint) })
	if !isFUSE(c.gate.runner, mountpoint) {
		// One reason a mount never appears is not a defect and not this
		// harness's business: a strict mount pins one exact FUSE protocol
		// version, and a kernel that offers another cannot carry it at all.
		// That is a prerequisite of the machine, so it is reported through the
		// same gate as every other prerequisite - which means the CI job, which
		// sets the REQUIRED switch, still fails on it.
		if reason := pinnedProtocolRefusal(mount.logPath); reason != "" {
			skipOrFail(t, "this kernel cannot carry a strict mount: %s", reason)
		}
		mount.dump(t)
		t.Fatalf("the kernel never carried a FUSE mount at %s", mountpoint)
	}
	return mount, mountpoint
}

// pinnedProtocolRefusal returns the mount's own words when it refused because
// the kernel offers a FUSE protocol the strict contract does not pin, or "".
func pinnedProtocolRefusal(logPath string) string {
	content, err := os.ReadFile(logPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, "strict coherence requires the pinned FUSE protocol") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func isFUSE(runner Runner, mountpoint string) bool {
	output, err := runner.Run("findmnt", "-n", "-r", "-o", "FSTYPE", "--target", mountpoint)
	if err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(output), "fuse")
}

// processKiller is the part of a data-plane process needed to prove that it no
// longer holds a descriptor into the cell.
type processKiller interface {
	forceKill(time.Duration) error
}

// exactMountPresent distinguishes a mount at mountpoint from its containing
// filesystem. It parses a complete successful findmnt inventory: command
// failure and malformed output are errors, never mistaken for mount absence.
func exactMountPresent(runner commandRunner, mountpoint string) (bool, error) {
	output, err := runner.Run("findmnt", "--json", "--output", "TARGET")
	if err != nil {
		return false, fmt.Errorf("inspect the mount namespace for %s: %w", mountpoint, err)
	}
	var inventory struct {
		Filesystems []findmntFilesystem `json:"filesystems"`
	}
	if err := json.Unmarshal([]byte(output), &inventory); err != nil {
		return false, fmt.Errorf("parse mount namespace for %s: %w", mountpoint, err)
	}
	clean := filepath.Clean(mountpoint)
	for _, filesystem := range inventory.Filesystems {
		if filesystem.contains(clean) {
			return true, nil
		}
	}
	return false, nil
}

type findmntFilesystem struct {
	Target   string              `json:"target"`
	Children []findmntFilesystem `json:"children"`
}

func (filesystem findmntFilesystem) contains(mountpoint string) bool {
	if filepath.Clean(filesystem.Target) == mountpoint {
		return true
	}
	for _, child := range filesystem.Children {
		if child.contains(mountpoint) {
			return true
		}
	}
	return false
}

// forceFenceStrictMount implements the local equivalent of production host
// fencing: make the userspace server impossible to revive, detach its exact
// kernel mount, and verify both facts before issuing an operator assertion.
// fusermount's lazy forced detach is the normal path. umount -l is a bounded
// escalation, not the proof; exact namespace absence below is the proof.
func forceFenceStrictMount(runner commandRunner, mount processKiller, mountpoint string) (priorStrictMountsFenced, error) {
	if mount == nil {
		return priorStrictMountsFenced{}, errors.New("strict mount fencing requires its mount process")
	}
	if err := mount.forceKill(30 * time.Second); err != nil {
		return priorStrictMountsFenced{}, err
	}

	_, detachErr := runner.Run("fusermount3", "-uz", mountpoint)
	present, inspectErr := exactMountPresent(runner, mountpoint)
	if inspectErr != nil {
		return priorStrictMountsFenced{}, inspectErr
	}
	if present {
		if _, err := runner.Run("umount", "-l", mountpoint); err != nil {
			failures := []error{fmt.Errorf("lazy-detach strict mount %s: %w", mountpoint, err)}
			if detachErr != nil {
				failures = append([]error{fmt.Errorf("force-detach strict mount %s: %w", mountpoint, detachErr)}, failures...)
			}
			return priorStrictMountsFenced{}, errors.Join(failures...)
		}
		present, inspectErr = exactMountPresent(runner, mountpoint)
		if inspectErr != nil {
			return priorStrictMountsFenced{}, inspectErr
		}
	}
	if present {
		return priorStrictMountsFenced{}, fmt.Errorf("strict kernel mount %s remains installed after forced detach", mountpoint)
	}
	return priorStrictMountsFenced{
		mountpoint:         mountpoint,
		mountProcessExited: true,
		kernelMountAbsent:  true,
	}, nil
}

// releaseMount is cleanup only. Contract-bearing paths use
// forceFenceStrictMount or cleanlyDischargeMount and check their errors.
func releaseMount(runner commandRunner, mountpoint string) {
	_, _ = runner.Run("fusermount3", "-uz", mountpoint)
	present, err := exactMountPresent(runner, mountpoint)
	if err == nil && present {
		_, _ = runner.Run("umount", "-l", mountpoint)
	}
}

// releaseWriteStaging removes the bind mount whose source lies on the cell.
// It must run before the cell filesystem is unmounted for a device cut; doing
// it only in t.Cleanup leaves a live reference to the dm target.
func (c *cell) releaseWriteStaging() error {
	if c == nil || !c.stagingBound {
		return nil
	}
	unmountErr := error(nil)
	if _, err := c.runner.Run("umount", c.staging); err != nil {
		unmountErr = fmt.Errorf("unmount %s: %w", c.staging, err)
	}
	present, err := exactMountPresent(c.runner, c.staging)
	if err != nil {
		return errors.Join(unmountErr, err)
	}
	if present {
		return errors.Join(unmountErr, fmt.Errorf("write-staging bind mount %s remains installed", c.staging))
	}
	c.stagingBound = false
	return nil
}

// releaseForPowerCut establishes the complete device-release precondition in
// one ordered operation. The authority is killed first so it cannot dirty the
// XFS after the cut begins; the FUSE server is then killed and detached; only
// then is the last service bind into the cell removed.
func (c *cell) releaseForPowerCut(authority, mount processKiller, mountpoint string) (priorStrictMountsFenced, error) {
	if authority == nil {
		return priorStrictMountsFenced{}, errors.New("a power cut requires its authority process")
	}
	if err := authority.forceKill(30 * time.Second); err != nil {
		return priorStrictMountsFenced{}, err
	}
	fence, err := forceFenceStrictMount(c.runner, mount, mountpoint)
	if err != nil {
		return priorStrictMountsFenced{}, err
	}
	if err := c.releaseWriteStaging(); err != nil {
		return priorStrictMountsFenced{}, err
	}
	return fence, nil
}

// cleanlyDischargeMount preserves the other half of the membership contract:
// when the authority is live, the mount must use its ordinary shutdown path so
// authenticated Detach deactivates its durable membership record. Exact mount
// absence verifies that shutdown completed before the next epoch begins.
func cleanlyDischargeMount(runner commandRunner, mount *process, mountpoint string) error {
	if err := mount.stop(30 * time.Second); err != nil {
		return err
	}
	present, err := exactMountPresent(runner, mountpoint)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("cleanly stopped mount %s remains installed", mountpoint)
	}
	return nil
}

// runDriver runs the workload driver as the service identity and services its
// mark requests from this process, which has the privilege to take them.
//
// The pipe is the ordering guarantee. The driver blocks on the acknowledgement
// before it issues the next write, so a mark always lands in the write log
// after the fsync it belongs to and before anything that follows.
func (c *cell) runDriver(t *testing.T, mountpoint, ledgerPath string, instrument Instrument, mark func(string) error, arguments ...string) *process {
	t.Helper()
	base := []string{
		"--mount", mountpoint,
		"--volume", c.gate.volume,
		"--ledger", ledgerPath,
		"--instrument", string(instrument),
	}
	logPath := filepath.Join(c.logDir, "driver-"+filepath.Base(ledgerPath)+".log")
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("creating the driver log: %v", err)
	}
	command := c.asService(filepath.Join(c.gate.binDir, "pfs-powerloss-driver"), append(base, arguments...)...)
	requests, err := command.StdoutPipe()
	if err != nil {
		t.Fatalf("opening the driver's mark request channel: %v", err)
	}
	acks, err := command.StdinPipe()
	if err != nil {
		t.Fatalf("opening the driver's acknowledgement channel: %v", err)
	}
	command.Stderr = logFile
	if err := command.Start(); err != nil {
		t.Fatalf("starting the workload driver: %v", err)
	}
	driver := &process{name: "driver", command: command, logPath: logPath, exit: make(chan struct{})}
	go driver.reap(func() error {
		defer func() { _ = logFile.Close() }()
		return serviceMarks(requests, acks, mark, command)
	})
	return driver
}

// serviceMarks answers the driver's mark requests until it exits. A refusal is
// reported to the driver rather than swallowed, so the driver stops writing
// checkpoints no cut could ever assert.
func serviceMarks(requests io.Reader, acks io.WriteCloser, mark func(string) error, command *exec.Cmd) error {
	scanner := bufio.NewScanner(requests)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		label, found := strings.CutPrefix(line, "mark ")
		if !found {
			_, _ = fmt.Fprintf(acks, "error: unrecognised request %q\n", line)
			continue
		}
		reply := "ok"
		if mark != nil {
			if err := mark(label); err != nil {
				reply = "error: " + err.Error()
			}
		}
		if _, err := fmt.Fprintln(acks, reply); err != nil {
			break
		}
	}
	_ = acks.Close()
	return command.Wait()
}

// wait returns the driver's exit status, or fails the test if it outlives the
// bound. It is separated from kill because a driver that finishes its
// checkpoints on its own and one that is cut short are both legitimate, and
// only the caller knows which it asked for.
func (p *process) wait(t *testing.T, bound time.Duration) error {
	t.Helper()
	select {
	case <-p.exit:
		return p.err
	case <-time.After(bound):
		p.dump(t)
		t.Fatalf("%s did not finish within %s", p.name, bound)
		return nil
	}
}
