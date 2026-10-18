// Command pfs-lan-trace collects, reports and reconciles the bounded
// correlated LAN diagnostic trace defined by package lantrace.
//
//	pfs-lan-trace collect -o run.collection.jsonl frontend.jsonl daemon.jsonl authority.jsonl
//	pfs-lan-trace report [-json] [-strict] run.collection.jsonl
//	pfs-lan-trace reconcile -counters counters.json -map mapping.json run.collection.jsonl
//
// counters.json is a flat object of product counter names to non-negative
// integers; mapping.json maps each counter name to a report aggregate key
// (report -json lists the keys a run produced).
//
// The command only reads its inputs, writes collect's -o file (created, never
// overwritten) and standard output. Exit status: 0 success; 1 invalid input
// or I/O failure; 2 usage; 3 exact attribution invalid under report -strict,
// or reconcile found a mismatch or an attribution-invalid run.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
)

const (
	exitOK      = 0
	exitInvalid = 1
	exitUsage   = 2
	exitFinding = 3
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: pfs-lan-trace collect|report|reconcile [flags] files")
		return exitUsage
	}
	switch args[0] {
	case "collect":
		return collect(args[1:], stdout, stderr)
	case "report":
		return report(args[1:], stdout, stderr)
	case "reconcile":
		return reconcile(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "pfs-lan-trace: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

func collect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "collection output file; created, never overwritten")
	maxEvents := fs.Int64("max-events", lantrace.DefaultMaxEvents, "maximum events written; later events are dropped and counted")
	maxBytes := fs.Int64("max-bytes", lantrace.DefaultMaxBytes, "maximum event bytes written; later events are dropped and counted")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *out == "" || fs.NArg() == 0 || *maxEvents <= 0 || *maxBytes <= 0 {
		fmt.Fprintln(stderr, "usage: pfs-lan-trace collect -o OUTPUT [-max-events N] [-max-bytes N] STREAM...")
		return exitUsage
	}
	inputs := make([]lantrace.Input, 0, fs.NArg())
	for _, name := range fs.Args() {
		f, err := os.Open(name)
		if err != nil {
			fmt.Fprintf(stderr, "pfs-lan-trace: open input: %v\n", err)
			return exitInvalid
		}
		defer f.Close()
		inputs = append(inputs, lantrace.Input{Name: name, Reader: f})
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "pfs-lan-trace: create output: %v\n", err)
		return exitInvalid
	}
	sum, err := lantrace.Collect(f, inputs, lantrace.CollectConfig{MaxEvents: *maxEvents, MaxBytes: *maxBytes})
	if closeErr := f.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("close output: %w", closeErr)
	}
	if err != nil {
		// A partial collection has no summary and would be refused anyway;
		// remove it so it cannot be mistaken for a finished one.
		_ = os.Remove(*out)
		fmt.Fprintf(stderr, "pfs-lan-trace: %v\n", err)
		return exitInvalid
	}
	fmt.Fprintf(stdout, "collected run %s: %d streams, %d events, %d dropped, %d rejected, %d producer-lost, %d incomplete streams, %d inconsistent streams\n",
		sum.Run, sum.Streams, sum.Events, sum.Dropped, sum.Rejected, sum.ProducerLost, sum.IncompleteStreams, sum.InconsistentStreams)
	return exitOK
}

func report(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	strict := fs.Bool("strict", false, "exit 3 when exact attribution is invalid")
	window := fs.Int("join-window", lantrace.DefaultJoinWindow, "unmatched anchors held per correlation join")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 || *window <= 0 {
		fmt.Fprintln(stderr, "usage: pfs-lan-trace report [-json] [-strict] [-join-window N] COLLECTION")
		return exitUsage
	}
	rep, err := buildReport(fs.Arg(0), *window)
	if err != nil {
		fmt.Fprintf(stderr, "pfs-lan-trace: %v\n", err)
		return exitInvalid
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		err = enc.Encode(rep)
	} else {
		err = rep.WriteText(stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "pfs-lan-trace: write report: %v\n", err)
		return exitInvalid
	}
	if *strict && !rep.AttributionValid {
		return exitFinding
	}
	return exitOK
}

func reconcile(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	countersPath := fs.String("counters", "", "counters snapshot: JSON object of counter name to integer")
	mappingPath := fs.String("map", "", "mapping: JSON object of counter name to report aggregate key")
	window := fs.Int("join-window", lantrace.DefaultJoinWindow, "unmatched anchors held per correlation join")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 1 || *countersPath == "" || *mappingPath == "" || *window <= 0 {
		fmt.Fprintln(stderr, "usage: pfs-lan-trace reconcile -counters FILE -map FILE [-join-window N] COLLECTION")
		return exitUsage
	}
	var counters map[string]uint64
	if err := readJSONObject(*countersPath, &counters); err != nil {
		fmt.Fprintf(stderr, "pfs-lan-trace: counters: %v\n", err)
		return exitInvalid
	}
	var mapping map[string]string
	if err := readJSONObject(*mappingPath, &mapping); err != nil {
		fmt.Fprintf(stderr, "pfs-lan-trace: mapping: %v\n", err)
		return exitInvalid
	}
	if len(mapping) == 0 {
		fmt.Fprintln(stderr, "pfs-lan-trace: mapping is empty")
		return exitInvalid
	}
	rep, err := buildReport(fs.Arg(0), *window)
	if err != nil {
		fmt.Fprintf(stderr, "pfs-lan-trace: %v\n", err)
		return exitInvalid
	}
	lines, ok := lantrace.Reconcile(rep, counters, mapping)
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if rep.AttributionValid {
		fmt.Fprintln(tw, "attribution: exact for this run")
	} else {
		fmt.Fprintln(tw, "ATTRIBUTION INVALID: trace totals are lower bounds; see pfs-lan-trace report")
	}
	fmt.Fprintln(tw, "counter\taggregate\tcounter value\ttrace value\tstatus")
	for _, l := range lines {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", l.Counter, l.Aggregate, l.CounterValue, l.TraceValue, l.Status)
	}
	if err := tw.Flush(); err != nil {
		fmt.Fprintf(stderr, "pfs-lan-trace: write reconciliation: %v\n", err)
		return exitInvalid
	}
	if !ok || !rep.AttributionValid {
		return exitFinding
	}
	return exitOK
}

func buildReport(path string, window int) (*lantrace.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open collection: %w", err)
	}
	defer f.Close()
	return lantrace.BuildReport(f, lantrace.ReportConfig{JoinWindow: window})
}

// readJSONObject decodes exactly one JSON object from path into v.
func readJSONObject(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("decode %s: data after the object", path)
	}
	return nil
}
