package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/mounthost"
)

func TestObserveMountHostSeparatesFactsFromVerification(t *testing.T) {
	static := func(transport mounthost.Transport) mounthost.Facts {
		return mounthost.Facts{
			Transport: transport,
			State:     mounthost.Unverified,
			Summary:   "prerequisites are only evidence",
		}
	}
	facts, err := observeMountHost("linux", "auto", static, func(mounthost.Transport) (string, bool, error) {
		return "", false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if facts.Transport != mounthost.FUSE || facts.State != mounthost.Unverified {
		t.Fatalf("facts = %+v", facts)
	}

	facts, err = observeMountHost("linux", "auto", static, func(transport mounthost.Transport) (string, bool, error) {
		if transport != mounthost.FUSE {
			t.Fatalf("verification transport = %s", transport)
		}
		return "/mnt/work", true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if facts.State != mounthost.Verified || facts.Issue != mounthost.IssueNone ||
		!strings.Contains(facts.Summary, "/mnt/work") {
		t.Fatalf("verified facts = %+v", facts)
	}
}

func TestObserveMountHostPropagatesInventoryFailure(t *testing.T) {
	static := func(transport mounthost.Transport) mounthost.Facts {
		return mounthost.Facts{Transport: transport, State: mounthost.Unverified, Summary: "static facts"}
	}
	_, err := observeMountHost("linux", "auto", static, func(mounthost.Transport) (string, bool, error) {
		return "", false, errors.New("corrupt inventory")
	})
	if err == nil || !strings.Contains(err.Error(), "corrupt inventory") {
		t.Fatalf("inventory error was downgraded: %v", err)
	}

	e, _, _ := testEnv(t)
	e.stateDir = filepath.Join(t.TempDir(), "state")
	mountsDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(mountsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.verifiedMount(mounthost.FUSE); err == nil {
		t.Fatal("unsafe mount-state root was reported as merely unverified")
	}
}

func TestMountCheckJSONGoldenEnvelopes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var buf bytes.Buffer
		facts := mounthost.Facts{
			Transport: mounthost.FUSE,
			State:     mounthost.Unverified,
			Summary:   "mount attempt required",
		}
		envelope := mountCheckEnvelope{SchemaVersion: mountCheckSchemaVersion, Facts: &facts}
		if err := json.NewEncoder(&buf).Encode(envelope); err != nil {
			t.Fatal(err)
		}
		want := `{"schemaVersion":1,"facts":{"transport":"fuse","state":"unverified","summary":"mount attempt required"}}` + "\n"
		if buf.String() != want {
			t.Fatalf("success envelope:\n%s\nwant:\n%s", buf.String(), want)
		}
	})
	t.Run("blocked", func(t *testing.T) {
		var buf bytes.Buffer
		envelope := mountCheckEnvelope{
			SchemaVersion: mountCheckSchemaVersion,
			Error: &mountCheckError{
				Kind:    "blocked",
				Code:    mounthost.IssueFUSEDeviceMissing,
				Message: "/dev/fuse does not exist",
			},
		}
		if err := json.NewEncoder(&buf).Encode(envelope); err != nil {
			t.Fatal(err)
		}
		want := `{"schemaVersion":1,"error":{"kind":"blocked","code":"fuse-device-missing","message":"/dev/fuse does not exist"}}` + "\n"
		if buf.String() != want {
			t.Fatalf("blocked envelope:\n%s\nwant:\n%s", buf.String(), want)
		}
	})
}

func TestObserveMountHostPreservesBlockerWithoutLiveMount(t *testing.T) {
	facts, err := observeMountHost("linux", "fuse", func(transport mounthost.Transport) mounthost.Facts {
		return mounthost.Facts{
			Transport: transport,
			State:     mounthost.Blocked,
			Issue:     mounthost.IssueFUSEDeviceMissing,
			Summary:   "/dev/fuse does not exist",
		}
	}, func(mounthost.Transport) (string, bool, error) { return "", false, nil })
	if err != nil {
		t.Fatal(err)
	}
	if facts.State != mounthost.Blocked || facts.Issue != mounthost.IssueFUSEDeviceMissing {
		t.Fatalf("facts = %+v", facts)
	}
	if err := mountHostBlockedError(facts); err == nil ||
		!strings.Contains(err.Error(), "fuse-device-missing") ||
		!strings.Contains(err.Error(), "make /dev/fuse available") {
		t.Fatalf("blocked error = %v", err)
	}
}

func TestMountCheckCommandRegistered(t *testing.T) {
	if _, ok := findCommand("mount-check"); !ok {
		t.Fatal("mount-check must be registered")
	}
	help, ok := commandHelp("mount-check")
	if !ok {
		t.Fatal("mount-check help missing")
	}
	for _, want := range []string{"VERIFIED", "BLOCKED", "UNVERIFIED", "stable issue codes"} {
		if !strings.Contains(help, want) {
			t.Fatalf("mount-check help missing %q", want)
		}
	}
}
