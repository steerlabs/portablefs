package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/hostctl"
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
		expected := hostctl.ReleaseIdentity{DaemonVersion: actual.DaemonVersion, ExecutableSHA256: actual.ExecutableSHA256, CodeDirectoryHash: strings.Repeat("a", 40)}
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

func TestUnmountCompletionRequiresEmpty204(t *testing.T) {
	for _, test := range []struct {
		status int
		body   string
		valid  bool
	}{{204, "", true}, {204, " ", false}, {204, `{}`, false}, {200, "", false}, {202, "", false}, {404, "", false}} {
		for _, force := range []bool{false, true} {
			ctl := &fsdControl{httpClient: &http.Client{Transport: lifecycleRoundTrip(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: make(http.Header)}, nil
			})}}
			ctl.pairOnce.Do(func() {})
			var err error
			if force {
				err = ctl.forceDetach("att_AAAAAAAAAAAAAAAAAAAAAA")
			} else {
				err = ctl.unmountAttach("att_AAAAAAAAAAAAAAAAAAAAAA")
			}
			if (err == nil) != test.valid {
				t.Fatalf("status=%d body=%q force=%t error=%v", test.status, test.body, force, err)
			}
		}
	}
}

func TestExternalAbsenceRequiresAuthenticatedInventoryAfter404(t *testing.T) {
	st := validFSKitMountState(t, "/test/mount")
	for _, inventory := range []string{`{"attaches":[]}`, `{"attaches":[{"attachRef":"` + st.AttachRef + `","mountPath":"/test/mount","volumeId":"` + st.VolumeID + `"}]}`, `not-json`} {
		ctl := &fsdControl{httpClient: &http.Client{Transport: lifecycleRoundTrip(func(r *http.Request) (*http.Response, error) {
			status, body := 404, ""
			if r.URL.Path == "/v2/attaches" {
				status, body = 200, inventory
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
		})}}
		ctl.pairOnce.Do(func() {})
		err := finalizeExternallyAbsentFSKit(ctl, &st)
		if (err == nil) != (inventory == `{"attaches":[]}`) {
			t.Fatalf("inventory=%s error=%v", inventory, err)
		}
	}
}

func TestAttachInventoryCannotTurnMalformedRepliesIntoAbsence(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"unknown":[]}`, `{"attaches":[],"unknown":0}`, `{"attaches":[],"attaches":[]}`, `{"attaches":{}}`, `{"attaches":[null]}`, `{"attaches":[{}]}`, `{"attaches":[{"attachRef":null}]}`} {
		if _, err := decodeAttachInventory([]byte(body)); err == nil {
			t.Fatalf("malformed inventory proved absence: %s", body)
		}
	}
	for _, body := range []string{`{"attaches":[]}`, `{"attaches":null}`} {
		if inventory, err := decodeAttachInventory([]byte(body)); err != nil || len(inventory) != 0 {
			t.Fatalf("paired empty inventory %s: %v", body, err)
		}
	}
}

func TestAttachInventoryRejectsAmbiguousIdentityMembers(t *testing.T) {
	st := validFSKitMountState(t, "/test/mount")
	for _, member := range []struct {
		name, alias, escaped, replacement string
	}{
		{"attachRef", "AttachRef", `attach\u0052ef`, "att_BBBBBBBBBBBBBBBBBBBBBB"},
		{"mountPath", "MountPath", `mount\u0050ath`, "/test/replacement"},
		{"volumeId", "VolumeId", `volume\u0049d`, "replacement"},
	} {
		for _, spelling := range []string{member.alias, strings.ToUpper(member.name), member.name, member.escaped} {
			for _, extraFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/extraFirst=%t", member.name, spelling, extraFirst), func(t *testing.T) {
					canonical := fmt.Sprintf(`"attachRef":%q,"mountPath":%q,"volumeId":%q`, st.AttachRef, st.MountPath, st.VolumeID)
					extra := fmt.Sprintf(`"%s":%q`, spelling, member.replacement)
					members := canonical + "," + extra
					if extraFirst {
						members = extra + "," + canonical
					}
					body := `{"attaches":[{` + members + `}]}`
					if _, err := decodeAttachInventory([]byte(body)); err == nil {
						t.Fatalf("ambiguous inventory accepted: %s", body)
					}
					ctl := &fsdControl{httpClient: &http.Client{Transport: lifecycleRoundTrip(func(r *http.Request) (*http.Response, error) {
						status, response := http.StatusNotFound, ""
						if r.URL.Path == "/v2/attaches" {
							status, response = http.StatusOK, body
						}
						return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
					})}}
					ctl.pairOnce.Do(func() {})
					if err := finalizeExternallyAbsentFSKit(ctl, &st); err == nil {
						t.Fatal("ambiguous inventory authorized cleanup after 404")
					}
				})
			}
		}
	}
	// Escaped canonical keys are valid once; duplicate detection runs after
	// JSON unescaping, and unknown producer status fields remain ignorable.
	body := fmt.Sprintf(`{"attaches":[{"attach\u0052ef":%q,"mount\u0050ath":%q,"volume\u0049d":%q,"state":"mounted","sessionTerminal":true,"reauthorizationFailures":3,"unknown":{}}]}`, st.AttachRef, st.MountPath, st.VolumeID)
	got, err := decodeAttachInventory([]byte(body))
	if err != nil || len(got) != 1 || got[0].AttachRef != st.AttachRef || got[0].MountPath != st.MountPath || got[0].VolumeID != st.VolumeID || got[0].State != "mounted" || !got[0].SessionTerminal || got[0].ReauthorizationFailures != 3 {
		t.Fatalf("exact escaped inventory=%+v error=%v", got, err)
	}
}
