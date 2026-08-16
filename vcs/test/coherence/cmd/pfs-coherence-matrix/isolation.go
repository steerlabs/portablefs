package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// isolatedChildArgument is intentionally not a public harness mode. The
// driver is the sole owner of the child protocol and sends its specification on
// stdin, so paths and shell-based observation capabilities are not copied into
// a process listing.
const isolatedChildArgument = "--pfs-internal-isolated-child"

const isolatedChildReapBound = 5 * time.Second

type isolatedMode string

const (
	isolatedProbe isolatedMode = "probe"
	isolatedCase  isolatedMode = "case"
)

// isolatedSpec contains everything an owned worker needs. Each case opens new
// local/remote actors and exits after that case, so a timed-out syscall, a case
// goroutine, an open descriptor, an ssh client, or a shell helper cannot survive
// into a later case.
type isolatedSpec struct {
	Mode           isolatedMode `json:"mode"`
	CaseName       string       `json:"case_name,omitempty"`
	MountA         string       `json:"mount_a"`
	MountB         string       `json:"mount_b"`
	SSHTarget      string       `json:"ssh_target,omitempty"`
	SSHBinary      string       `json:"ssh_binary,omitempty"`
	StaleCheck     bool         `json:"stale_check,omitempty"`
	ExpectDisjoint bool         `json:"expect_disjoint,omitempty"`
	RunID          string       `json:"run_id"`
	AltGID         int          `json:"alt_gid,omitempty"`
	FenceCmd       string       `json:"fence_command,omitempty"`
	Replaces       int          `json:"atomic_replace_rounds,omitempty"`
	LocalRoute     string       `json:"local_route,omitempty"`
	RoutesContract string       `json:"routes_contract_command,omitempty"`
}

type isolatedReply struct {
	Outcome *outcome `json:"outcome,omitempty"`
	Error   string   `json:"error,omitempty"`
}

type isolatedExecution struct {
	reply     isolatedReply
	timedOut  bool
	exitErr   error
	decodeErr error
	stderr    string
	duration  time.Duration
}

// serveIsolatedChild is the entire child-side protocol. There is exactly one
// request and one response per process. A panic deliberately escapes this
// function: the parent then records a crashed case worker instead of accepting
// a partially assembled PASS.
func serveIsolatedChild(reader io.Reader, writer io.Writer) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var spec isolatedSpec
	if err := decoder.Decode(&spec); err != nil {
		return fmt.Errorf("decode specification: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode specification: more than one JSON value")
		}
		return fmt.Errorf("decode specification trailer: %w", err)
	}

	reply := isolatedReply{}
	switch spec.Mode {
	case isolatedProbe:
		reply.Error = errorString(runProbeInChild(spec))
	case isolatedCase:
		entry, ok := findCase(spec.CaseName)
		if !ok {
			reply.Error = fmt.Sprintf("unknown case %q", spec.CaseName)
			break
		}
		result, err := runCaseInChild(entry, spec)
		if err != nil {
			reply.Error = err.Error()
		} else {
			reply.Outcome = &result
		}
	default:
		reply.Error = fmt.Sprintf("unknown isolated mode %q", spec.Mode)
	}
	return json.NewEncoder(writer).Encode(reply)
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func findCase(name string) (coherenceCase, bool) {
	for _, entry := range allCases() {
		if entry.name == name {
			return entry, true
		}
	}
	return coherenceCase{}, false
}

func openIsolatedActors(spec isolatedSpec) (actor, actor, func(), error) {
	localA, err := newLocalActor("mount-A", spec.MountA)
	if err != nil {
		return nil, nil, nil, err
	}
	first := actor(localA)
	if spec.StaleCheck {
		first = newStaleActor(localA)
	}

	var second actor
	if spec.SSHTarget != "" {
		remote, remoteErr := newRemoteActor(
			"mount-B", spec.SSHTarget, spec.SSHBinary, spec.MountB,
			[]string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"},
		)
		if remoteErr != nil {
			_ = localA.close()
			return nil, nil, nil, fmt.Errorf("attach the second mount over ssh: %w", remoteErr)
		}
		second = remote
	} else {
		localB, localErr := newLocalActor("mount-B", spec.MountB)
		if localErr != nil {
			_ = localA.close()
			return nil, nil, nil, localErr
		}
		second = localB
	}

	cleanup := func() {
		_ = second.close()
		_ = localA.close()
	}
	return first, second, cleanup, nil
}

func runProbeInChild(spec isolatedSpec) error {
	if spec.RunID == "" {
		return fmt.Errorf("probe requires a run ID")
	}
	// The stale-view control belongs to individual semantic cases. Namespace
	// topology is a harness precondition, so its probe always observes the real
	// actor rather than an injected stale answer.
	spec.StaleCheck = false
	first, second, cleanup, err := openIsolatedActors(spec)
	if err != nil {
		return err
	}
	defer cleanup()

	if out, execErr := first.exec(request{Op: "mkdirall", Path: spec.RunID, Mode: 0o755}); execErr != nil {
		return fmt.Errorf("create the run directory %s on mount-A: %w", spec.RunID, execErr)
	} else if out.Err != "" {
		return fmt.Errorf("create the run directory %s on mount-A: %s", spec.RunID, out.Err)
	}

	// The two roots must actually be the same volume. Running the matrix
	// against unrelated directories would produce failures that look like
	// product defects. The explicit disjoint control inverts the assertion.
	out, execErr := second.exec(request{Op: "stat", Path: spec.RunID})
	if execErr != nil {
		return fmt.Errorf("probe the run directory from the second mount: %w", execErr)
	}
	if out.Err != "" && !spec.ExpectDisjoint {
		return fmt.Errorf("the second mount cannot see %s created by the first (%s); the two roots do not share a namespace, so this run would measure nothing — fix the mounts or pass -expect-disjoint-namespace for the control phase", spec.RunID, out.Err)
	}
	if out.Err == "" && spec.ExpectDisjoint {
		return fmt.Errorf("-expect-disjoint-namespace was passed but the second root can see %s created by the first; a disjoint control pointed at the real volume proves nothing", spec.RunID)
	}
	return nil
}

func runCaseInChild(entry coherenceCase, spec isolatedSpec) (outcome, error) {
	if spec.RunID == "" {
		return outcome{}, fmt.Errorf("case requires a run ID")
	}
	first, second, cleanup, err := openIsolatedActors(spec)
	if err != nil {
		return outcome{}, err
	}
	defer cleanup()
	return executeCaseDirect(entry, first, second, spec.RunID, caseInputs{
		altGID:         spec.AltGID,
		fenceCmd:       spec.FenceCmd,
		replaces:       spec.Replaces,
		localRoute:     spec.LocalRoute,
		routesContract: spec.RoutesContract,
	}), nil
}

// executeCaseDirect has no wall-clock goroutine. The process containing it is
// the deadline primitive; if any syscall or case-owned goroutine wedges, the
// driver kills and reaps the whole process before it starts another case.
func executeCaseDirect(entry coherenceCase, a, b actor, runID string, inputs caseInputs) (result outcome) {
	run := &caseRun{
		a: a, b: b, dir: runID + "/" + entry.name,
		altGID: inputs.altGID, fenceCmd: inputs.fenceCmd, replaces: inputs.replaces,
		localRoute: inputs.localRoute, routesContract: inputs.routesContract,
	}
	result = outcome{Name: entry.name, What: entry.what}
	started := time.Now()
	defer func() {
		notes, failures, skip := run.snapshot()
		result.DurationMs = time.Since(started).Milliseconds()
		result.Notes, result.Failures = notes, failures
		if recovered := recover(); recovered != nil {
			aborted, ok := recovered.(abortCase)
			if !ok {
				panic(recovered)
			}
			if skip != "" {
				result.Status = statusSkip
				result.Reason = skip
				return
			}
			result.Status = statusFail
			result.Failures = append(result.Failures, "aborted: "+aborted.reason)
			return
		}
		if skip != "" {
			result.Status = statusSkip
			result.Reason = skip
			return
		}
		if len(failures) != 0 {
			result.Status = statusFail
			return
		}
		result.Status = statusPass
	}()

	if out, err := a.exec(request{Op: "mkdirall", Path: run.dir, Mode: 0o755}); err != nil {
		run.abort("create the case directory: %v", err)
	} else if out.Err != "" {
		run.abort("create the case directory: %s", out.Err)
	}
	entry.run(run)
	return result
}

func executeIsolatedProbe(base isolatedSpec, timeout time.Duration) error {
	spec := base
	spec.Mode = isolatedProbe
	execution, err := invokeIsolatedChild(spec, timeout)
	if err != nil {
		return fmt.Errorf("isolate the shared-namespace probe: %w", err)
	}
	if execution.timedOut {
		return fmt.Errorf("shared-namespace probe did not complete within %s; its worker was killed and reaped", timeout)
	}
	if execution.exitErr != nil {
		return fmt.Errorf("shared-namespace probe worker exited: %v%s", execution.exitErr, stderrSuffix(execution.stderr))
	}
	if execution.decodeErr != nil {
		return fmt.Errorf("shared-namespace probe returned an invalid result: %v%s", execution.decodeErr, stderrSuffix(execution.stderr))
	}
	if execution.reply.Error != "" {
		return errors.New(execution.reply.Error)
	}
	if execution.reply.Outcome != nil {
		return fmt.Errorf("shared-namespace probe returned an unexpected case outcome")
	}
	return nil
}

func executeIsolatedCase(entry coherenceCase, base isolatedSpec, inputs caseInputs, timeout time.Duration) (outcome, error) {
	spec := base
	spec.Mode = isolatedCase
	spec.CaseName = entry.name
	spec.AltGID = inputs.altGID
	spec.FenceCmd = inputs.fenceCmd
	spec.Replaces = inputs.replaces
	spec.LocalRoute = inputs.localRoute
	spec.RoutesContract = inputs.routesContract

	execution, err := invokeIsolatedChild(spec, timeout)
	if err != nil {
		return outcome{}, err
	}
	failure := func(message string) outcome {
		return outcome{
			Name:       entry.name,
			What:       entry.what,
			Status:     statusFail,
			Failures:   []string{message},
			DurationMs: execution.duration.Milliseconds(),
		}
	}
	if execution.timedOut {
		return failure(fmt.Sprintf("case did not complete within %s; its worker process group was killed and confirmed gone before the next case", timeout)), nil
	}
	if execution.exitErr != nil {
		return failure(fmt.Sprintf("case worker exited without a result: %v%s", execution.exitErr, stderrSuffix(execution.stderr))), nil
	}
	if execution.decodeErr != nil {
		return failure(fmt.Sprintf("case worker returned an invalid result: %v%s", execution.decodeErr, stderrSuffix(execution.stderr))), nil
	}
	if execution.reply.Error != "" {
		return failure("case worker could not initialize: " + execution.reply.Error), nil
	}
	if execution.reply.Outcome == nil {
		return failure("case worker returned no outcome"), nil
	}
	result := *execution.reply.Outcome
	result.DurationMs = execution.duration.Milliseconds()
	if result.Name != entry.name || result.What != entry.what {
		return failure(fmt.Sprintf("case worker identified its result as %q (%q), want %q (%q)", result.Name, result.What, entry.name, entry.what)), nil
	}
	switch result.Status {
	case statusPass, statusFail, statusSkip:
	default:
		return failure(fmt.Sprintf("case worker returned invalid status %q", result.Status)), nil
	}
	return result, nil
}

func invokeIsolatedChild(spec isolatedSpec, timeout time.Duration) (isolatedExecution, error) {
	encoded, err := json.Marshal(spec)
	if err != nil {
		return isolatedExecution{}, err
	}
	executable, err := os.Executable()
	if err != nil {
		return isolatedExecution{}, err
	}
	command := exec.Command(executable, isolatedChildArgument)
	return executeIsolatedCommand(command, encoded, timeout)
}

// executeIsolatedCommand owns a complete process group. It never reports a
// timeout until SIGKILL has been delivered, the direct child has been reaped,
// and no member of its process group remains. If the kernel will not establish
// all three facts, the matrix stops here instead of starting a later case beside
// an operation whose lifetime it cannot prove.
func executeIsolatedCommand(command *exec.Cmd, input []byte, timeout time.Duration) (isolatedExecution, error) {
	if timeout <= 0 {
		return isolatedExecution{}, fmt.Errorf("worker timeout must be positive")
	}
	configureIsolatedProcess(command)
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	started := time.Now()
	if err := command.Start(); err != nil {
		return isolatedExecution{}, fmt.Errorf("start isolated worker: %w", err)
	}

	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	execution := isolatedExecution{}
	select {
	case execution.exitErr = <-waited:
	case <-timer.C:
		// Prefer a just-completed Wait result over signaling a process group
		// whose leader has already been reaped.
		select {
		case execution.exitErr = <-waited:
		default:
			execution.timedOut = true
			killErr := killIsolatedProcessGroup(command.Process.Pid)
			reapTimer := time.NewTimer(isolatedChildReapBound)
			select {
			case execution.exitErr = <-waited:
				reapTimer.Stop()
			case <-reapTimer.C:
				return isolatedExecution{}, fmt.Errorf("worker process group %d received SIGKILL but its leader was not reaped within %s; refusing to run a later case", command.Process.Pid, isolatedChildReapBound)
			}
			if killErr != nil {
				return isolatedExecution{}, fmt.Errorf("kill timed-out worker process group %d: %w", command.Process.Pid, killErr)
			}
			if err := waitIsolatedProcessGroupGone(command.Process.Pid, isolatedChildReapBound); err != nil {
				return isolatedExecution{}, err
			}
		}
	}
	execution.duration = time.Since(started)
	execution.stderr = strings.TrimSpace(stderr.String())
	if !execution.timedOut && execution.exitErr == nil {
		decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&execution.reply); err != nil {
			execution.decodeErr = err
		} else {
			var extra any
			if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
				if err == nil {
					execution.decodeErr = fmt.Errorf("more than one JSON value")
				} else {
					execution.decodeErr = err
				}
			}
		}
	}
	return execution, nil
}

func stderrSuffix(stderr string) string {
	if stderr == "" {
		return ""
	}
	const limit = 2048
	if len(stderr) > limit {
		stderr = stderr[len(stderr)-limit:]
	}
	return "; worker stderr: " + stderr
}
