package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

func validResponse() *ntp.Response {
	stamp := time.Date(2026, 10, 26, 0, 0, 0, 123456789, time.UTC)
	return &ntp.Response{Version: 4, Stratum: 1, Time: stamp, ReferenceTime: stamp,
		Timestamps: ntp.ProtocolTimestamps{ServerXmit: stamp},
		RootDelay:  3, RootDispersion: 100, Precision: 1}
}

func TestJSONContract(t *testing.T) {
	r, err := authenticatedReference("time.cloudflare.com", validResponse())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(observation{References: []reference{r}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"references":[{"server":"time.cloudflare.com","protocol":"NTS","authenticated":true,"unix_ns":1792972800123456789,"uncertainty_ns":103}]}`
	if string(encoded) != want {
		t.Fatalf("JSON contract\ngot  %s\nwant %s", encoded, want)
	}
}

func TestInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*ntp.Response)
	}{
		{"unsynchronized", func(r *ntp.Response) { r.Leap = ntp.LeapNotInSync }},
		{"kiss of death", func(r *ntp.Response) { r.Stratum = 0 }},
		{"other protocol", func(r *ntp.Response) { r.Version = 3 }},
		{"negative dispersion", func(r *ntp.Response) { r.RootDispersion = -1 }},
		{"excess uncertainty", func(r *ntp.Response) { r.RootDelay = time.Second; r.RootDispersion = time.Second }},
		{"duration overflow", func(r *ntp.Response) { r.RootDelay = time.Duration(1<<63 - 1) }},
		{"old timestamp", func(r *ntp.Response) { r.Timestamps.ServerXmit = time.Unix(0, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validResponse()
			tc.edit(r)
			if _, err := authenticatedReference("time.cloudflare.com", r); err == nil {
				t.Fatal("invalid response became authenticated evidence")
			}
		})
	}
}

func TestCollectionFailsClosed(t *testing.T) {
	servers := []string{"time.cloudflare.com", "nts.netnod.se", "ptbtime1.ptb.de"}
	for _, tc := range []struct {
		name    string
		servers []string
		fail    map[string]bool
		want    int
	}{
		{"three operators", servers, nil, 3},
		{"one unavailable", servers, map[string]bool{servers[2]: true}, 2},
		{"single response", servers, map[string]bool{servers[1]: true, servers[2]: true}, 0},
		{"unauthenticated", servers, map[string]bool{servers[0]: true, servers[1]: true, servers[2]: true}, 0},
		{"single operator", servers[:1], nil, 0},
		{"duplicate operator", []string{servers[0], servers[0]}, nil, 0},
		{"alias", []string{servers[0], "TIME.CLOUDFLARE.COM"}, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var diagnostics bytes.Buffer
			result, err := collect(tc.servers, time.Second, func(server string, _ time.Duration) (queriedResponse, error) {
				if tc.fail[server] {
					return queriedResponse{}, nts.ErrAuthFailedOnClient
				}
				return queriedResponse{validResponse(), 100, 200}, nil
			}, &diagnostics)
			if (err == nil) != (tc.want >= 2) || len(result.References) != tc.want {
				t.Fatalf("references=%d, error=%v", len(result.References), err)
			}
			for _, ref := range result.References {
				if ref.QueryBeganNS != 100 || ref.QueryEndedNS != 200 {
					t.Fatal("NTP sample interval was not retained", ref)
				}
			}
			if tc.fail != nil && !strings.Contains(diagnostics.String(), nts.ErrAuthFailedOnClient.Error()) {
				t.Fatal("authentication failure was not diagnosed")
			}
		})
	}
	if _, err := collect(servers, time.Second, func(string, time.Duration) (queriedResponse, error) {
		return queriedResponse{}, errors.New("TLS certificate verification failed")
	}, io.Discard); err == nil {
		t.Fatal("failed key exchange produced evidence")
	}
}
