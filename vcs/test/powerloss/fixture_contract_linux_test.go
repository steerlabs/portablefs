//go:build linux

package powerloss

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type contractRunner struct {
	events   []string
	timeline *[]string
	mounts   map[string]string
	fail     map[string]error
}

func (runner *contractRunner) Run(name string, arguments ...string) (string, error) {
	event := strings.TrimSpace(name + " " + strings.Join(arguments, " "))
	runner.events = append(runner.events, event)
	if runner.timeline != nil {
		*runner.timeline = append(*runner.timeline, event)
	}
	if err := runner.fail[event]; err != nil {
		return "", err
	}
	switch name {
	case "fusermount3", "umount":
		delete(runner.mounts, arguments[len(arguments)-1])
		return "", nil
	case "findmnt":
		filesystems := make([]map[string]string, 0, len(runner.mounts))
		for mountpoint := range runner.mounts {
			filesystems = append(filesystems, map[string]string{"target": mountpoint})
		}
		output, err := json.Marshal(map[string]any{"filesystems": filesystems})
		return string(output), err
	default:
		return "", fmt.Errorf("unexpected command %s", event)
	}
}

type recordingKiller struct {
	name   string
	events *[]string
	err    error
}

func (process recordingKiller) forceKill(time.Duration) error {
	*process.events = append(*process.events, "kill "+process.name)
	return process.err
}

func TestReleaseForPowerCutDischargesEveryDeviceHolderInOrder(t *testing.T) {
	var timeline []string
	runner := &contractRunner{timeline: &timeline, mounts: map[string]string{
		"/mount":   "fuse.portablefs",
		"/staging": "none",
	}}
	cell := &cell{runner: runner, staging: "/staging", stagingBound: true}

	fence, err := cell.releaseForPowerCut(
		recordingKiller{name: "authority", events: &timeline},
		recordingKiller{name: "mount", events: &timeline},
		"/mount",
	)
	if err != nil {
		t.Fatalf("releaseForPowerCut: %v", err)
	}
	if err := fence.validate(); err != nil {
		t.Fatalf("fencing receipt: %v", err)
	}
	if cell.stagingBound {
		t.Fatal("the cell still owns its write-staging bind after release")
	}

	var releaseEvents []string
	for _, event := range timeline {
		if strings.HasPrefix(event, "kill ") || strings.HasPrefix(event, "fusermount3 ") || strings.HasPrefix(event, "umount ") {
			releaseEvents = append(releaseEvents, event)
		}
	}
	want := []string{"kill authority", "kill mount", "fusermount3 -uz /mount", "umount /staging"}
	if !reflect.DeepEqual(releaseEvents, want) {
		t.Fatalf("device-holder release order = %v, want %v (all events %v)", releaseEvents, want, timeline)
	}
}

func TestReleaseForPowerCutRefusesAStillBoundStagingDirectory(t *testing.T) {
	var timeline []string
	runner := &contractRunner{
		mounts: map[string]string{
			"/mount":   "fuse.portablefs",
			"/staging": "none",
		},
		fail: map[string]error{"umount /staging": errors.New("target is busy")},
	}
	cell := &cell{runner: runner, staging: "/staging", stagingBound: true}

	if _, err := cell.releaseForPowerCut(
		recordingKiller{name: "authority", events: &timeline},
		recordingKiller{name: "mount", events: &timeline},
		"/mount",
	); err == nil {
		t.Fatal("the cut was released while write-staging still held the cell")
	}
	if !cell.stagingBound {
		t.Fatal("a failed staging unmount was recorded as released")
	}
}

func TestForceFenceStrictMountRequiresExactKernelAbsence(t *testing.T) {
	var processEvents []string
	runner := &contractRunner{
		mounts: map[string]string{"/mount": "fuse.portablefs"},
		fail: map[string]error{
			"fusermount3 -uz /mount": errors.New("forced detach refused"),
			"umount -l /mount":       errors.New("lazy detach refused"),
		},
	}
	fence, err := forceFenceStrictMount(runner, recordingKiller{name: "mount", events: &processEvents}, "/mount")
	if err == nil {
		t.Fatal("fencing produced a receipt while the exact kernel mount remained installed")
	}
	if fence.validate() == nil {
		t.Fatal("failed fencing produced a valid prior-mount assertion")
	}
	if got := processEvents; !reflect.DeepEqual(got, []string{"kill mount"}) {
		t.Fatalf("process events = %v", got)
	}
}

func TestForceFenceStrictMountEscalatesOnlyAfterTheServerIsGone(t *testing.T) {
	var timeline []string
	runner := &contractRunner{
		timeline: &timeline,
		mounts:   map[string]string{"/mount": "fuse.portablefs"},
		fail: map[string]error{
			"fusermount3 -uz /mount": errors.New("forced detach refused"),
		},
	}
	fence, err := forceFenceStrictMount(runner, recordingKiller{name: "mount", events: &timeline}, "/mount")
	if err != nil {
		t.Fatalf("forceFenceStrictMount: %v", err)
	}
	if err := fence.validate(); err != nil {
		t.Fatalf("fencing receipt: %v", err)
	}
	var actions []string
	for _, event := range timeline {
		if strings.HasPrefix(event, "kill ") || strings.HasPrefix(event, "fusermount3 ") || strings.HasPrefix(event, "umount ") {
			actions = append(actions, event)
		}
	}
	want := []string{"kill mount", "fusermount3 -uz /mount", "umount -l /mount"}
	if !reflect.DeepEqual(actions, want) {
		t.Fatalf("fencing actions = %v, want %v", actions, want)
	}
}

func TestPriorStrictMountsFlagRequiresCompleteFencingEvidence(t *testing.T) {
	if arguments, err := priorStrictMountFenceArguments(nil); err != nil || len(arguments) != 0 {
		t.Fatalf("initial epoch arguments = %v, %v", arguments, err)
	}
	for name, fence := range map[string]priorStrictMountsFenced{
		"no mount":            {},
		"process not reaped":  {mountpoint: "/mount", kernelMountAbsent: true},
		"mount still present": {mountpoint: "/mount", mountProcessExited: true},
	} {
		t.Run(name, func(t *testing.T) {
			if arguments, err := priorStrictMountFenceArguments(&fence); err == nil {
				t.Fatalf("incomplete evidence produced arguments %v", arguments)
			}
		})
	}
	complete := priorStrictMountsFenced{mountpoint: "/mount", mountProcessExited: true, kernelMountAbsent: true}
	arguments, err := priorStrictMountFenceArguments(&complete)
	if err != nil {
		t.Fatalf("complete evidence: %v", err)
	}
	if want := []string{"--prior-strict-mounts-fenced"}; !reflect.DeepEqual(arguments, want) {
		t.Fatalf("arguments = %v, want %v", arguments, want)
	}
}
