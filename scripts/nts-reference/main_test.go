package main

import (
	"context"
	"encoding/json"
	"io"
	"sync"
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

func TestCollectionGroupsRetriesAndRetainsDisagreement(t *testing.T) {
	servers := []string{"time.cloudflare.com", "nts.netnod.se", "sth1.nts.netnod.se", "ptbtime1.ptb.de", "ntppool1.time.nl", "a.st1.ntp.br"}
	var mu sync.Mutex
	calls := map[string]int{}
	result, err := collect(servers, time.Second, func(ctx context.Context, server, family string) ([]reference, []exchange) {
		mu.Lock()
		calls[server]++
		mu.Unlock()
		if server == "ptbtime1.ptb.de" || server == "nts.netnod.se" {
			return nil, []exchange{{Server: server, Error: nts.ErrAuthFailedOnClient.Error()}}
		}
		response := validResponse()
		if server == "ntppool1.time.nl" {
			response.Timestamps.ServerXmit = response.Timestamps.ServerXmit.Add(5 * time.Second)
		}
		ref, e := authenticatedReference(server, response)
		if e != nil {
			t.Error(e)
		}
		ref.QueryBeganNS = 100
		ref.QueryEndedNS = 200
		return []reference{ref}, nil
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if calls["nts.netnod.se"] != 2 || calls["sth1.nts.netnod.se"] != 2 || calls["ptbtime1.ptb.de"] != 4 {
		t.Fatal(calls)
	}
	counts := map[string]int{}
	for _, ref := range result.References {
		counts[ref.Operator]++
		if ref.QueryBeganNS != 100 {
			t.Fatal(ref)
		}
	}
	if len(counts) != 4 || counts["Netnod"] != 2 || counts["SIDN/TimeNL"] != 2 {
		t.Fatal(counts)
	}
	if result.References == nil {
		t.Fatal("authenticated disagreement was discarded")
	}
}

func TestPolicyAndAggregateDeadline(t *testing.T) {
	for _, servers := range [][]string{{"time.cloudflare.com"}, {"nts.netnod.se", "sth2.nts.netnod.se"}, {"time.cloudflare.com", "time.cloudflare.com"}, {"time.cloudflare.com", "pilot.time.nl"}, {"time.cloudflare.com", "TIME.CLOUDFLARE.COM"}} {
		_, err := collect(servers, time.Second, nil, io.Discard)
		if err == nil {
			t.Fatal("accepted", servers)
		}
	}
	began := time.Now()
	result, err := collect([]string{"time.cloudflare.com", "nts.netnod.se"}, 20*time.Millisecond,
		func(ctx context.Context, _, _ string) ([]reference, []exchange) { <-ctx.Done(); return nil, nil }, io.Discard)
	if err != nil || len(result.References) != 0 || time.Since(began) > time.Second {
		t.Fatal(result, err, time.Since(began))
	}
	if len(policy.Operators) != 5 {
		t.Fatal("policy groups", len(policy.Operators))
	}
}
