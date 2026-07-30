package mounthost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSelectTransportDoesNotInspectHost(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		goos     string
		want     Transport
		wantErr  string
	}{
		{"darwin auto", "auto", "darwin", FSKit, ""},
		{"linux auto", "auto", "linux", FUSE, ""},
		{"empty is auto", "", "linux", FUSE, ""},
		{"explicit fskit", "fskit", "darwin", FSKit, ""},
		{"explicit fuse", "fuse", "linux", FUSE, ""},
		{"fskit wrong os", "fskit", "linux", "", "requires darwin"},
		{"fuse wrong os", "fuse", "darwin", "", "requires linux"},
		{"unsupported", "auto", "freebsd", "", "not supported"},
		{"unknown", "nfs", "linux", "", "unknown --strategy"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectTransport(tc.explicit, tc.goos)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("SelectTransport = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestLinuxClassificationNeverInfersVerified(t *testing.T) {
	denied := errors.New("permission denied")
	tests := []struct {
		name      string
		input     linuxObservation
		state     State
		issue     Issue
		mechanism string
	}{
		{"device missing", linuxObservation{device: deviceMissing}, Blocked, IssueFUSEDeviceMissing, ""},
		{"denied no helper", linuxObservation{device: deviceDenied, deviceErr: denied}, Blocked, IssueFUSEDeviceDenied, ""},
		// A privileged helper can open the device on the caller's behalf, so
		// the caller's EACCES is evidence rather than a false blocker.
		{"denied with helper", linuxObservation{device: deviceDenied, deviceErr: denied, helper: "/usr/bin/fusermount3"}, Unverified, IssueNone, "helper"},
		{"device unavailable", linuxObservation{device: deviceUnavailable, deviceErr: errors.New("no device")}, Blocked, IssueFUSEDeviceUnavailable, ""},
		{"unknown probe direct", linuxObservation{device: deviceUnknown, deviceErr: errors.New("too many open files"), capability: capabilityPresent}, Unverified, IssueNone, "direct"},
		{"unknown probe helper", linuxObservation{device: deviceUnknown, deviceErr: errors.New("too many open files"), capability: capabilityAbsent, helper: "/usr/bin/fusermount3"}, Unverified, IssueNone, "helper"},
		{"unknown probe unknown capability", linuxObservation{device: deviceUnknown, deviceErr: errors.New("too many open files"), capability: capabilityUnknown}, Unverified, IssueNone, "direct"},
		{"unknown probe blocked", linuxObservation{device: deviceUnknown, deviceErr: errors.New("too many open files"), capability: capabilityAbsent}, Blocked, IssueFUSEMountUnavailable, ""},
		{"device only", linuxObservation{device: deviceUsable, capability: capabilityAbsent}, Blocked, IssueFUSEMountUnavailable, ""},
		{"unknown capability", linuxObservation{device: deviceUsable, capability: capabilityUnknown}, Unverified, IssueNone, "direct"},
		{"direct evidence", linuxObservation{device: deviceUsable, capability: capabilityPresent}, Unverified, IssueNone, "direct"},
		{"helper evidence", linuxObservation{device: deviceUsable, helper: "/usr/bin/fusermount"}, Unverified, IssueNone, "helper"},
		{"both mechanisms", linuxObservation{device: deviceUsable, helper: "/usr/bin/fusermount3", capability: capabilityPresent}, Unverified, IssueNone, "direct"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyLinux(tc.input)
			if got.State != tc.state || got.Issue != tc.issue {
				t.Fatalf("classifyLinux = state %q issue %q (%s), want %q %q", got.State, got.Issue, got.Summary, tc.state, tc.issue)
			}
			if got.MountMechanism != tc.mechanism {
				t.Fatalf("classifyLinux mechanism = %q, want %q (%+v)", got.MountMechanism, tc.mechanism, got)
			}
			if got.State == Verified {
				t.Fatal("static Linux facts claimed verified")
			}
		})
	}
}

func TestLinuxClassificationAlwaysSelectsExactlyOneMechanismOrBlocks(t *testing.T) {
	devices := []deviceState{deviceUsable, deviceMissing, deviceDenied, deviceUnavailable, deviceUnknown}
	capabilities := []capabilityState{capabilityPresent, capabilityAbsent, capabilityUnknown}
	helpers := []string{"", "/usr/bin/fusermount3"}
	for _, device := range devices {
		for _, capability := range capabilities {
			for _, helper := range helpers {
				facts := classifyLinux(linuxObservation{
					device: device, deviceErr: errors.New("probe"), capability: capability, helper: helper,
				})
				switch facts.State {
				case Blocked:
					if facts.MountMechanism != "" || facts.HelperPath != "" {
						t.Fatalf("%s/%s/%q blocked with mechanism %+v", device, capability, helper, facts)
					}
				case Unverified:
					if facts.MountMechanism != "direct" && facts.MountMechanism != "helper" {
						t.Fatalf("%s/%s/%q has no deterministic mechanism: %+v", device, capability, helper, facts)
					}
					if (facts.MountMechanism == "helper") != (facts.HelperPath != "") {
						t.Fatalf("%s/%s/%q has inconsistent helper identity: %+v", device, capability, helper, facts)
					}
				default:
					t.Fatalf("%s/%s/%q returned unsupported state %+v", device, capability, helper, facts)
				}
			}
		}
	}
}

func TestFUSEHelperResolutionUsesAbsoluteTrustedPaths(t *testing.T) {
	calls := []string{}
	lookup := func(name string) (string, error) {
		calls = append(calls, name)
		switch name {
		case "fusermount3":
			return "relative/bin/fusermount3", nil
		case "/bin/fusermount3":
			return "", errors.New("absent")
		case "fusermount":
			return "/custom/bin/fusermount", nil
		default:
			return "", errors.New("unexpected")
		}
	}
	got, ok := findFUSEHelperWith(lookup, func(path string) bool {
		return filepath.IsAbs(path) && !strings.Contains(path, "relative")
	})
	if !ok || got != "/custom/bin/fusermount" {
		t.Fatalf("helper = %q, %v; calls=%v", got, ok, calls)
	}
	wantCalls := []string{"fusermount3", "/bin/fusermount3", "fusermount"}
	if strings.Join(calls, "|") != strings.Join(wantCalls, "|") {
		t.Fatalf("calls = %v, want %v", calls, wantCalls)
	}
}

func TestFUSEHelperRejectsHostilePATHExecutable(t *testing.T) {
	hostile := filepath.Join(t.TempDir(), "fusermount3")
	if err := os.WriteFile(hostile, []byte("#!/bin/sh\nexit 1\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) (string, error) {
		if name == "fusermount3" {
			return hostile, nil
		}
		return "", errors.New("absent")
	}
	if got, ok := findFUSEHelper(lookup); ok {
		t.Fatalf("hostile PATH helper was selected: %s", got)
	}
	if err := ValidateFUSEHelper(hostile); err == nil {
		t.Fatal("world-writable account PATH helper was trusted")
	}
}

func TestFactsJSONUsesStableTypedState(t *testing.T) {
	data, err := json.Marshal(Facts{
		Transport: FUSE,
		State:     Unverified,
		Summary:   "mount attempt required",
		Details:   []Detail{{Key: "helper", Value: "/usr/bin/fusermount3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{`"transport":"fuse"`, `"state":"unverified"`, `"summary":"mount attempt required"`, `"details"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON %s missing %s", text, want)
		}
	}
	if strings.Contains(text, `"issue"`) {
		t.Fatalf("empty issue was not omitted: %s", text)
	}
}
