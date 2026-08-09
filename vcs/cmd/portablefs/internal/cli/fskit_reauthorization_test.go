package cli

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
)

type fsdReauthorizationRoundTripFunc func(*http.Request) (*http.Response, error)

func (f fsdReauthorizationRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestFSKitReauthorizationReturnsDaemonInstalledDeadline(t *testing.T) {
	authorityDeadline := time.Now().UTC().Truncate(time.Second).Add(10 * time.Minute)
	callerClaimedDeadline := authorityDeadline.Add(20 * time.Minute)
	control := &fsdControl{httpClient: &http.Client{Transport: fsdReauthorizationRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/attaches/attach-ref/credential" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if got := request.Header.Get(daemonctl.ControlProtocolHeader); got == "" {
			t.Fatal("control protocol header is missing")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"authorizationDeadlineUnixMs":` +
					strconv.FormatInt(authorityDeadline.UnixMilli(), 10) + `}`,
			)),
		}, nil
	})}}

	deadline, err := control.reauthorizeCredential(
		"attach-ref", "capability", callerClaimedDeadline.UnixMilli(), 2, "certificate",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.Equal(authorityDeadline) {
		t.Fatalf("reported deadline = %s, want authority deadline %s (caller claimed %s)",
			deadline, authorityDeadline, callerClaimedDeadline)
	}
}
