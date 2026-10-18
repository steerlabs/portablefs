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

// TestReleaseForPowerCutDischargesEveryDeviceHolderInOrder pins the device
// release precondition: authority reaped first, then the mount server, then
// the exact FUSE mount detached and proved absent. Any failure stops the
// release before the next holder is touched and yields no fencing receipt.
func TestReleaseForPowerCutDischargesEveryDeviceHolderInOrder(t *testing.T) {
	tests := []struct {
		name         string
		authorityErr error
		mountRemains bool
		wantErr      bool
		wantEvents   []string
	}{
		{
			name:       "every holder released",
			wantEvents: []string{"kill authority", "kill mount", "fusermount3 -uz /mount"},
		},
		{
			name:         "the authority survives its kill",
			authorityErr: errors.New("authority survived SIGKILL"),
			wantErr:      true,
			wantEvents:   []string{"kill authority"},
		},
		{
			name:         "the FUSE mount stays installed",
			mountRemains: true,
			wantErr:      true,
			wantEvents:   []string{"kill authority", "kill mount", "fusermount3 -uz /mount", "umount -l /mount"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var timeline []string
			runner := &contractRunner{timeline: &timeline, mounts: map[string]string{"/mount": "fuse.portablefs"}}
			if test.mountRemains {
				runner.fail = map[string]error{
					"fusermount3 -uz /mount": errors.New("forced detach refused"),
					"umount -l /mount":       errors.New("lazy detach refused"),
				}
			}
			cell := &cell{runner: runner}
			fence, err := cell.releaseForPowerCut(
				recordingKiller{name: "authority", events: &timeline, err: test.authorityErr},
				recordingKiller{name: "mount", events: &timeline},
				"/mount",
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("releaseForPowerCut error = %v, want error %v", err, test.wantErr)
			}
			if test.wantErr && fence.validate() == nil {
				t.Fatal("a failed release produced a valid prior-mount assertion")
			}
			if !test.wantErr {
				if err := fence.validate(); err != nil {
					t.Fatalf("fencing receipt: %v", err)
				}
			}
			var releaseEvents []string
			for _, event := range timeline {
				if strings.HasPrefix(event, "kill ") || strings.HasPrefix(event, "fusermount3 ") || strings.HasPrefix(event, "umount ") {
					releaseEvents = append(releaseEvents, event)
				}
			}
			if !reflect.DeepEqual(releaseEvents, test.wantEvents) {
				t.Fatalf("device-holder release order = %v, want %v (all events %v)", releaseEvents, test.wantEvents, timeline)
			}
		})
	}
}

func TestReleaseAuthorityForPowerCutRequiresTheAuthorityReaped(t *testing.T) {
	var timeline []string
	if err := releaseAuthorityForPowerCut(recordingKiller{name: "authority", events: &timeline}); err != nil {
		t.Fatalf("releaseAuthorityForPowerCut: %v", err)
	}
	if !reflect.DeepEqual(timeline, []string{"kill authority"}) {
		t.Fatalf("events = %v", timeline)
	}
	if err := releaseAuthorityForPowerCut(recordingKiller{name: "authority", events: &timeline, err: errors.New("still running")}); err == nil {
		t.Fatal("the FSKit cut was released while its authority could still write")
	}
	if err := releaseAuthorityForPowerCut(nil); err == nil {
		t.Fatal("the FSKit cut was released with no authority to reap")
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
