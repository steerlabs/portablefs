package cli

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestPlatformUnmountLinuxDecisionTable(t *testing.T) {
	tests := []struct {
		name      string
		mechanism string
		directErr error
		helper    string
		helperErr error
		wantCalls []string
		wantErr   string
	}{
		{"direct mount", "direct", nil, "", nil, []string{"direct"}, ""},
		{"legacy helper", "helper", nil, "/usr/bin/fusermount", nil, []string{"/usr/bin/fusermount -u /mnt/pfs"}, ""},
		{"modern helper", "helper", nil, "/usr/bin/fusermount3", nil, []string{"/usr/bin/fusermount3 -u /mnt/pfs"}, ""},
		{"no mechanism", "", nil, "", nil, nil, "no deterministic"},
		{"direct failure does not fall back", "direct", syscall.EPERM, "/usr/bin/fusermount3", nil, []string{"direct"}, "direct umount"},
		{"helper failure does not try direct", "helper", nil, "/usr/bin/fusermount3", errors.New("exit 1"), []string{"/usr/bin/fusermount3 -u /mnt/pfs"}, "exit 1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			ops := unmountOps{
				goos: "linux",
				direct: func(path string, flags int) error {
					calls = append(calls, "direct")
					if path != "/mnt/pfs" || flags != 0 {
						t.Fatalf("direct = %q, %d", path, flags)
					}
					return tc.directErr
				},
				combinedOut: func(name string, args ...string) ([]byte, error) {
					calls = append(calls, strings.Join(append([]string{name}, args...), " "))
					return []byte("helper output"), tc.helperErr
				},
				validateHelper: func(string) error { return nil },
			}
			err := platformUnmountWith(&mountState{
				Strategy: "fuse", MountPath: "/mnt/pfs",
				MountMechanism: tc.mechanism, FUSEHelperPath: tc.helper,
			}, ops)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(calls, tc.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, tc.wantCalls)
			}
		})
	}
}

func TestPlatformUnmountDarwinUsesSystemUmount(t *testing.T) {
	var call string
	ops := unmountOps{
		goos: "darwin",
		direct: func(string, int) error {
			t.Fatal("darwin must not use Linux direct detach")
			return nil
		},
		combinedOut: func(name string, args ...string) ([]byte, error) {
			call = fmt.Sprint(append([]string{name}, args...))
			return nil, nil
		},
	}
	if err := platformUnmountWith(&mountState{Strategy: "fskit", MountPath: "/Volumes/pfs", MountMechanism: "fskit-system"}, ops); err != nil {
		t.Fatal(err)
	}
	if call != "[/sbin/umount /Volumes/pfs]" {
		t.Fatalf("call = %s", call)
	}
}

func TestPlatformUnmountRejectsStrategyOSMismatch(t *testing.T) {
	never := unmountOps{
		goos:        "linux",
		direct:      func(string, int) error { return nil },
		combinedOut: func(string, ...string) ([]byte, error) { return nil, nil },
	}
	if err := platformUnmountWith(&mountState{Strategy: "fskit", MountPath: "/mnt"}, never); err == nil {
		t.Fatal("FSKit on Linux did not fail")
	}
	if err := platformUnmountWith(&mountState{Strategy: "unknown", MountPath: "/mnt"}, never); err == nil {
		t.Fatal("unknown strategy did not fail")
	}
}

func TestSelectedFUSEHelperRefusesResolutionChangeAtMountBoundary(t *testing.T) {
	err := validateSelectedFUSEHelperWith(
		"/usr/bin/fusermount3",
		func(string) error { return nil },
		func() (string, bool) { return "/hostile/bin/fusermount3", true },
	)
	if err == nil || !strings.Contains(err.Error(), "resolution changed") {
		t.Fatalf("PATH change error = %v", err)
	}
}
