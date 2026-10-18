package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
)

// writeStreams records a tiny correlated run (daemon and authority) through
// real Recorders and returns the two stream paths.
func writeStreams(t *testing.T, dir string) (daemon, authority string) {
	t.Helper()
	record := func(name string, layer lantrace.Layer, events ...lantrace.Event) string {
		path := filepath.Join(dir, name)
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		r, err := lantrace.NewRecorder(f, "cli-run", layer, "proc", lantrace.RecorderConfig{})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if err := r.Emit(e); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return path
	}
	send := lantrace.Event{Kind: lantrace.KindAuthority, Phase: lantrace.PhaseSend, Session: "s-1", AuthorityRequest: 1, AuthorityOp: lantrace.AuthorityLookup}
	receive := lantrace.Event{Kind: lantrace.KindAuthority, Phase: lantrace.PhaseReceive, Session: "s-1", AuthorityRequest: 1, AuthorityOp: lantrace.AuthorityLookup}
	return record("daemon.jsonl", lantrace.LayerDaemon, send), record("authority.jsonl", lantrace.LayerAuthority, receive)
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	daemon, authority := writeStreams(t, dir)
	collection := filepath.Join(dir, "run.collection.jsonl")
	if code := run([]string{"collect", "-o", collection, daemon, authority}, &bytes.Buffer{}, &bytes.Buffer{}); code != exitOK {
		t.Fatalf("collect exit %d", code)
	}
	// A daemon stream alone, without its trailer, is an incomplete run.
	daemonData, err := os.ReadFile(daemon)
	if err != nil {
		t.Fatal(err)
	}
	truncated := writeFile(t, filepath.Join(dir, "truncated.jsonl"), strings.Join(strings.SplitAfter(string(daemonData), "\n")[:2], ""))
	incomplete := filepath.Join(dir, "incomplete.collection.jsonl")
	if code := run([]string{"collect", "-o", incomplete, truncated}, &bytes.Buffer{}, &bytes.Buffer{}); code != exitOK {
		t.Fatalf("collect incomplete exit %d", code)
	}
	counters := writeFile(t, filepath.Join(dir, "counters.json"), `{"authority_lookup": 1, "lost": 0}`)
	wrongCounters := writeFile(t, filepath.Join(dir, "wrong.json"), `{"authority_lookup": 2, "lost": 0}`)
	mapping := writeFile(t, filepath.Join(dir, "map.json"), `{"authority_lookup": "daemon.authority.lookup", "lost": "trace.lost_events"}`)
	garbage := writeFile(t, filepath.Join(dir, "garbage.jsonl"), "not json\n")
	existing := writeFile(t, filepath.Join(dir, "existing.jsonl"), "keep me\n")

	cases := []struct {
		name   string
		args   []string
		code   int
		stdout string
	}{
		{"no subcommand", nil, exitUsage, ""},
		{"unknown subcommand", []string{"merge"}, exitUsage, ""},
		{"collect without output", []string{"collect", daemon}, exitUsage, ""},
		{"collect refuses to overwrite", []string{"collect", "-o", existing, daemon}, exitInvalid, ""},
		{"collect invalid input", []string{"collect", "-o", filepath.Join(dir, "bad.collection.jsonl"), garbage}, exitInvalid, ""},
		{"report", []string{"report", collection}, exitOK, "attribution: exact"},
		{"report json", []string{"report", "-json", collection}, exitOK, `"attribution_valid": true`},
		{"report strict valid", []string{"report", "-strict", collection}, exitOK, "attribution: exact"},
		{"report invalid attribution", []string{"report", incomplete}, exitOK, "ATTRIBUTION INVALID"},
		{"report strict invalid attribution", []string{"report", "-strict", incomplete}, exitFinding, "ATTRIBUTION INVALID"},
		{"report producer stream", []string{"report", daemon}, exitInvalid, ""},
		{"report usage", []string{"report"}, exitUsage, ""},
		{"reconcile match", []string{"reconcile", "-counters", counters, "-map", mapping, collection}, exitOK, "match"},
		{"reconcile mismatch", []string{"reconcile", "-counters", wrongCounters, "-map", mapping, collection}, exitFinding, "mismatch"},
		{"reconcile invalid attribution", []string{"reconcile", "-counters", counters, "-map", mapping, incomplete}, exitFinding, "ATTRIBUTION INVALID"},
		{"reconcile bad counters", []string{"reconcile", "-counters", garbage, "-map", mapping, collection}, exitInvalid, ""},
		{"reconcile usage", []string{"reconcile", collection}, exitUsage, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != tc.code {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, tc.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.stdout) {
				t.Fatalf("stdout lacks %q:\n%s", tc.stdout, stdout.String())
			}
		})
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "keep me\n" {
		t.Fatalf("collect touched an existing file: %q %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bad.collection.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("failed collect left its output behind: %v", err)
	}
}
