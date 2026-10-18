package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
)

type lifecycleRoundTrip func(*http.Request) (*http.Response, error)

func (f lifecycleRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func lifecycleTestControl(t *testing.T, status int, body string, path string) *fsdControl {
	t.Helper()
	return &fsdControl{httpClient: &http.Client{Transport: lifecycleRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != path {
			t.Fatalf("unexpected lifecycle path %q", r.URL.Path)
		}
		if r.Header.Get(daemonctl.ControlProtocolHeader) != "" {
			t.Fatal("lifecycle request used operational version equality")
		}
		if r.Body != nil {
			data, err := io.ReadAll(r.Body)
			if err != nil || len(data) != 0 {
				t.Fatalf("lifecycle request body %q, %v", data, err)
			}
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
}

func TestLifecycleInventoryRequiresExactStatusAndCompleteStrictBody(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"empty", 200, `{"attachment_count":0}`, true},
		{"persisted and terminal", 200, `{"attachment_count":3}`, true},
		{"missing endpoint", 404, `{"attachment_count":0}`, false},
		{"redirect", 302, `{"attachment_count":0}`, false},
		{"wrong success", 204, `{"attachment_count":0}`, false},
		{"extra", 200, `{"attachment_count":0,"unknown":0}`, false},
		{"duplicate", 200, `{"attachment_count":1,"attachment_count":0}`, false},
		{"null", 200, `{"attachment_count":null}`, false},
		{"too large", 200, strings.Repeat(" ", daemonctl.MaxLifecycleBodyBytes) + `{"attachment_count":0}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctl := lifecycleTestControl(t, test.status, test.body, daemonctl.LifecycleInventoryPath)
			_, err := ctl.lifecycleInventory()
			if (err == nil) != test.want {
				t.Fatalf("inventory error = %v", err)
			}
		})
	}
}

func TestLifecycleStopRequiresEmpty204AndPreservesBusy(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		want   bool
	}{{204, "", true}, {204, " ", false}, {200, "", false}, {409, "busy", false}, {404, "", false}} {
		ctl := lifecycleTestControl(t, test.status, test.body, daemonctl.LifecycleStopIfIdlePath)
		if err := ctl.stopIfIdle(); (err == nil) != test.want {
			t.Fatalf("stop %d %q: %v", test.status, test.body, err)
		}
	}
}

func TestOutgoingLifecycleUsesAuthenticatedActualVersions(t *testing.T) {
	for _, version := range []struct {
		control      int
		major, minor uint32
	}{{19, 23, 0}, {71, 98, 37}} {
		actual := daemonctl.Identity{SchemaVersion: 1, ControlProtocol: version.control, DaemonVersion: "authenticated-release", ExecutableSHA256: strings.Repeat("a", 64), PFSLocalMajor: version.major, PFSLocalMinor: version.minor}
		data, err := daemonctl.EncodeIdentity(actual)
		if err != nil {
			t.Fatal(err)
		}
		expected := actual
		expected.ControlProtocol = 0 // supplied fields carry no incoming compiled control number
		ctl := lifecycleTestControl(t, 200, string(data), daemonctl.LifecycleIdentityPath)
		if err := ctl.requireOutgoingIdentityWithin(expected, time.Second); err != nil {
			t.Fatal(err)
		}
		if err := ctl.requireCompatibleIdentityWithin(actual.DaemonVersion, actual.ExecutableSHA256, time.Second); err == nil {
			t.Fatal("ordinary operations admitted an unequal pair")
		}
		actual.ExecutableSHA256 = strings.Repeat("b", 64)
		data, _ = json.Marshal(actual)
		ctl = lifecycleTestControl(t, 200, string(data), daemonctl.LifecycleIdentityPath)
		if err := ctl.requireOutgoingIdentityWithin(expected, time.Second); err == nil {
			t.Fatal("claimed identity spoof accepted")
		}
	}
	ctl := lifecycleTestControl(t, 404, "", daemonctl.LifecycleIdentityPath)
	if _, err := ctl.identityWithin(time.Second); err == nil {
		t.Fatal("missing lifecycle endpoint accepted")
	}
	if _, _, err := ctl.doContext(context.Background(), http.MethodGet, daemonctl.LifecycleIdentityPath, nil); err != nil {
		t.Fatal(err)
	}
}
