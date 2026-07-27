package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
)

func proofRequest() BaseProvenanceRequest {
	return BaseProvenanceRequest{
		TenantID: "tenant-a", CommitID: "commit-a", GenerationID: "generation-a",
		BaseSeq: 7, BaseDigest: strings.Repeat("a", 64),
		RecordCodec: "pfj3", ControlCodec: "pfc2",
	}
}

func validPft2Proof() map[string]any {
	return map[string]any{
		"v": "1", "kind": "pft2", "baseMode": "adopted",
		"tenantId": "tenant-a", "commitId": "commit-a", "volumeId": "volume-a",
		"branchId": "branch-a", "generationId": "generation-a", "baseSeq": "7",
		"baseDigest": strings.Repeat("a", 64), "recordCodec": "pfj3", "controlCodec": "pfc2",
		"root": map[string]any{
			"digest": strings.Repeat("b", 64), "size": "64", "maxInoSeen": "9",
		},
		"anchor": map[string]any{
			"anchorId": "anchor-a", "asOfSeq": "7",
			"recoveryRootDigest": strings.Repeat("c", 64), "recoveryRootSize": "64",
			"controlRootDigest": strings.Repeat("d", 64), "controlRootSize": "64",
			"inodeNamespace": "2", "nextLocal": "10", "maxInoSeen": "9",
		},
	}
}

func proofServer(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(handler))
	return NewClient(srv.URL, "tenant-token"), srv.Close
}

func TestBaseProvenanceStrictExactTuple(t *testing.T) {
	client, closeServer := proofServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tenant-token" {
			t.Fatalf("authorization = %q", got)
		}
		if r.URL.Path != "/v1/history/base-provenance/commit-a" ||
			r.URL.Query().Get("generationId") != "generation-a" ||
			r.URL.Query().Get("baseSeq") != "7" {
			t.Fatalf("unexpected request %s", r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"provenance": validPft2Proof()})
	})
	defer closeServer()

	proof, err := client.BaseProvenance(context.Background(), proofRequest())
	if err != nil {
		t.Fatal(err)
	}
	if proof.Kind != "pft2" || proof.BaseMode != "adopted" || proof.Anchor == nil {
		t.Fatalf("unexpected proof %#v", proof)
	}
	if ref, err := proof.RootRef(); err != nil || ref.Size != 64 {
		t.Fatalf("root ref %#v, %v", ref, err)
	}
}

func TestBaseProvenanceRejectsUnknownMismatchAndNoncanonicalFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown field", func(p map[string]any) { p["surprise"] = true }},
		{"tenant mismatch", func(p map[string]any) { p["tenantId"] = "tenant-b" }},
		{"generation mismatch", func(p map[string]any) { p["generationId"] = "generation-b" }},
		{"noncanonical decimal", func(p map[string]any) { p["baseSeq"] = "07" }},
		{"wrong codec", func(p map[string]any) { p["controlCodec"] = "pfc1" }},
		{"missing live anchor", func(p map[string]any) { delete(p, "anchor") }},
		{"anchor sequence mismatch", func(p map[string]any) { p["anchor"].(map[string]any)["asOfSeq"] = "6" }},
		{"root overflow", func(p map[string]any) { p["root"].(map[string]any)["size"] = fmt.Sprint(pft2.MaxNodeBytes + 1) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proof := validPft2Proof()
			tc.mutate(proof)
			client, closeServer := proofServer(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"provenance": proof})
			})
			defer closeServer()
			if _, err := client.BaseProvenance(context.Background(), proofRequest()); err == nil {
				t.Fatal("malformed proof accepted")
			}
		})
	}
}

func TestBaseProvenance404IsTypedAnd503Retries(t *testing.T) {
	t.Run("404", func(t *testing.T) {
		client, closeServer := proofServer(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not found", http.StatusNotFound)
		})
		defer closeServer()
		_, err := client.BaseProvenance(context.Background(), proofRequest())
		if !errors.Is(err, ErrBaseProvenanceNotFound) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("retry", func(t *testing.T) {
		var calls atomic.Int32
		client, closeServer := proofServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if calls.Add(1) == 1 {
				http.Error(w, "temporary", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"provenance": validPft2Proof()})
		})
		defer closeServer()
		if _, err := client.BaseProvenance(context.Background(), proofRequest()); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 {
			t.Fatalf("calls = %d", calls.Load())
		}
	})
}

func TestBaseProvenanceRejectsChunkedBodyBeyondHardBound(t *testing.T) {
	client, closeServer := proofServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.(http.Flusher).Flush()
		_ = json.NewEncoder(w).Encode(map[string]any{"provenance": validPft2Proof()})
		_, _ = w.Write([]byte(strings.Repeat(" ", maxProvenanceBytes)))
	})
	defer closeServer()

	_, err := client.BaseProvenance(context.Background(), proofRequest())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized chunked provenance error = %v", err)
	}
}

func TestHistoryObjectUsesExpectedSizeAsHardBound(t *testing.T) {
	good := []byte("bounded-pft2-object")
	sum := sha256.Sum256(good)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	t.Run("valid", func(t *testing.T) {
		client, closeServer := proofServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("content-length", fmt.Sprint(len(good)))
			_, _ = w.Write(good)
		})
		defer closeServer()
		got, err := client.HistoryObject(context.Background(), digest, uint64(len(good)))
		if err != nil || string(got) != string(good) {
			t.Fatalf("got %q, %v", got, err)
		}
	})

	t.Run("chunked oversize", func(t *testing.T) {
		client, closeServer := proofServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.(http.Flusher).Flush()
			_, _ = w.Write(append(append([]byte(nil), good...), '!'))
		})
		defer closeServer()
		if _, err := client.HistoryObject(context.Background(), digest, uint64(len(good))); err == nil {
			t.Fatal("chunked oversized object accepted")
		}
	})

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"short", good[:len(good)-1]},
		{"oversize", append(append([]byte(nil), good...), '!')},
		{"corrupt", append([]byte(nil), good...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if tc.name == "corrupt" {
				body[0] ^= 0xff
			}
			client, closeServer := proofServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("content-length", fmt.Sprint(len(body)))
				_, _ = w.Write(body)
			})
			defer closeServer()
			if _, err := client.HistoryObject(context.Background(), digest, uint64(len(good))); err == nil {
				t.Fatal("invalid object accepted")
			}
		})
	}
	if _, err := NewClient("http://unused", "").HistoryObject(
		context.Background(), digest, pft2.MaxPackBytes+1,
	); err == nil {
		t.Fatal("oversized allocation bound accepted")
	}
}

type boundedFetcherClient struct {
	want uint64
	data []byte
}

func (f *boundedFetcherClient) HistoryObject(_ context.Context, _ string, size uint64) ([]byte, error) {
	f.want = size
	return append([]byte(nil), f.data...), nil
}

func TestPft2FetcherPassesRefSizeAsReadBound(t *testing.T) {
	data := []byte("exact-ref")
	ref := pft2.RefOf(data)
	client := &boundedFetcherClient{data: data}
	got, err := NewPft2Fetcher(client).Fetch(context.Background(), ref)
	if err != nil || string(got) != string(data) {
		t.Fatalf("got %q, %v", got, err)
	}
	if client.want != ref.Size {
		t.Fatalf("bound = %d, want %d", client.want, ref.Size)
	}
}
