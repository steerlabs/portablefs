//go:build linux

package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/fusev3"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
)

// This new process reconciles inventories after a cold boot. It never resumes,
// signals or dials for the old client, and never opens a numeric abort path.
func (e *cmdEnv) runWorkspaceReconcile(fd int, volume, path string) int {
	fail := func(err error) int { return e.fail("mount", err) }
	if fd < 3 || os.Geteuid() != 1000 {
		return fail(errors.New("workspace reconciliation requires an inherited request and UID 1000"))
	}
	syscall.CloseOnExec(fd)
	f := os.NewFile(uintptr(fd), "workspace reconcile request")
	defer f.Close()
	var q workspacemount.Reconciliation
	d := json.NewDecoder(io.LimitReader(f, 2<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&q); err != nil {
		return fail(errors.New("invalid workspace reconciliation"))
	}
	if d.Decode(new(any)) != io.EOF || q.Desired == nil || q.Desired.Witness.Target != path || q.Desired.Mount.VolumeId != volume {
		return fail(errors.New("workspace reconciliation binding mismatch"))
	}
	run := q.Desired
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return fail(err)
	}
	if run.KernelBoot == "" {
		return fail(errors.New("workspace kernel boot witness missing"))
	}
	if q.NeverSpawned && (run.Witness.Process != "" || q.ExitedProcess != "") {
		return fail(errors.New("unstarted workspace has a process witness"))
	}
	if run.KernelBoot == strings.TrimSpace(string(boot)) && !q.NeverSpawned {
		if q.ExitedProcess == "" || q.ExitedProcess != run.Witness.Process {
			return fail(errors.New("workspace reconciliation requires joined process exit"))
		}
		pidText, startText, ok := strings.Cut(q.ExitedProcess, ":")
		pid, e := strconv.Atoi(pidText)
		if !ok || e != nil || pid <= 0 {
			return fail(errors.New("workspace process witness malformed"))
		}
		if current, e := processStartIdentity(pid); e == nil && current == startText {
			return fail(errors.New("workspace old child still alive"))
		} else if e != nil && !errors.Is(e, os.ErrNotExist) {
			return fail(e)
		}
	}
	if _, err = fusev3.ObservePlannedKernelMountAbsent(run.Witness.Source, path); err != nil {
		return fail(err)
	}
	if _, err = os.Lstat(q.StateDirectory); errors.Is(err, os.ErrNotExist) {
		if err = json.NewEncoder(e.stdout).Encode(run.Witness); err != nil {
			return fail(err)
		}
		var ack [1]byte
		if _, err = io.ReadFull(os.Stdin, ack[:]); err != nil || ack[0] != 'c' {
			return fail(errors.New("workspace inventory commit unconfirmed"))
		}
		return 0
	} else if err != nil {
		return fail(err)
	}
	state, err := readMountState(q.StateDirectory, path)
	if err != nil {
		return fail(err)
	}
	_, intentPath := mountOperationPaths(q.StateDirectory, path)
	intent, err := readMountIntent(intentPath, path)
	if err != nil {
		return fail(err)
	}
	if q.NeverSpawned && (state != nil || intent != nil) {
		return fail(errors.New("unstarted workspace has CLI ownership records"))
	}
	w := run.Witness
	if state != nil {
		if state.MountInstanceID != w.Intent || state.MountPath != w.Target || state.VolumeID != volume {
			return fail(errors.New("workspace CLI inventory disagrees with startup intent"))
		}
		if w.Process != "" && w.Process != strconv.Itoa(state.PID)+":"+state.ProcessStartIdentity {
			return fail(errors.New("workspace CLI process witness changed"))
		}
		if w.Kernel != "" && strings.Split(w.Kernel, "@")[0] != state.KernelMountID {
			return fail(errors.New("workspace CLI kernel witness changed"))
		}
		if intent != nil {
			if err = verifyMountIntentMatchesState(intent, state); err != nil {
				return fail(err)
			}
		}
		if err = verifyRecordedMountIdentity(state); !errors.Is(err, errRecordedMountAbsent) {
			return fail(errors.New("workspace CLI kernel absence not independently established"))
		}
		next := workspacemount.Witness{Session: state.AuthorizationSessionID, Enrollment: state.MountEnrollmentID}
		if state.LocalRouteRevision != "" {
			raw, e := hex.DecodeString(state.LocalRouteRevision)
			if e != nil || len(raw) != 32 {
				return fail(errors.New("invalid workspace CLI route witness"))
			}
			copy(next.RoutesRevision[:], raw)
		}
		w, err = workspacemount.MergeWitness(w, next)
		if err != nil {
			return fail(err)
		}
	}
	if intent != nil {
		if intent.MountInstanceID != "" && intent.MountInstanceID != w.Intent {
			return fail(errors.New("workspace CLI intent incarnation changed"))
		}
		if err = e.reconcileMountIntentWithProcess(intent, false, false); err != nil {
			return fail(err)
		}
	}
	// The root commits partial CLI evidence before authorizing its removal.
	if err = json.NewEncoder(e.stdout).Encode(w); err != nil {
		return fail(err)
	}
	var ack [1]byte
	if _, err = io.ReadFull(os.Stdin, ack[:]); err != nil || ack[0] != 'c' {
		return fail(errors.New("workspace inventory commit unconfirmed"))
	}
	if err = removeMountState(q.StateDirectory, path); err != nil {
		return fail(err)
	}
	if intent != nil {
		if err = os.Remove(intentPath); err != nil {
			return fail(err)
		}
	}
	directory, err := os.Open(filepath.Dir(intentPath))
	if err != nil {
		return fail(err)
	}
	defer directory.Close()
	if err = directory.Sync(); err != nil {
		return fail(err)
	}
	return 0
}
