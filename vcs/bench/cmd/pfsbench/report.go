package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// cmdReport prints a markdown table across every result JSON in a directory.
// Ratios are computed against the "local" transport result with the same
// profile (the local-disk baseline).
func cmdReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	dir := fs.String("dir", "results", "directory of pfsbench JSON results")
	_ = fs.Parse(args)

	paths, err := filepath.Glob(filepath.Join(*dir, "*.json"))
	if err != nil || len(paths) == 0 {
		log.Fatalf("pfsbench report: no results in %s", *dir)
	}
	sort.Strings(paths)
	var results []resultFile
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			log.Fatal(err)
		}
		var r resultFile
		if err := json.Unmarshal(b, &r); err != nil {
			log.Fatalf("pfsbench report: %s: %v", p, err)
		}
		if r.Transport == "" || len(r.Phases) == 0 {
			// Not a pfsbench run result (e.g. a pfstorture report sharing the
			// results directory); skip instead of rendering an empty section.
			continue
		}
		results = append(results, r)
	}
	fmt.Print(renderReport(results))
}

func renderReport(results []resultFile) string {
	var b strings.Builder
	// Baseline p50s: local transport, keyed by profile+workload+phase.
	base := map[string]float64{}
	for _, r := range results {
		if r.Transport != "local" {
			continue
		}
		for _, ph := range r.Phases {
			base[r.Profile.Name+"/"+ph.Workload+"/"+ph.Phase] = ph.P50Sec
		}
	}
	if len(results) > 0 {
		m := results[0].Machine
		fmt.Fprintf(&b, "Machine: %s (%s/%s, %d CPU, %.0f GiB RAM, %s)\n\n",
			m.CPU, m.GOOS, m.GOARCH, m.NumCPU, float64(m.MemBytes)/(1<<30), m.GoVersion)
	}
	for _, r := range results {
		fmt.Fprintf(&b, "### label=%s transport=%s profile=%s n=%d\n\n", r.Label, r.Transport, r.Profile.Name, r.N)
		fmt.Fprintf(&b, "| workload | phase | p50 | ops/s | RPCs | vs local | top server ops |\n")
		fmt.Fprintf(&b, "|---|---|---|---|---|---|---|\n")
		for _, ph := range r.Phases {
			ratio := "-"
			if bl, ok := base[r.Profile.Name+"/"+ph.Workload+"/"+ph.Phase]; ok && bl > 0 && r.Transport != "local" {
				ratio = fmt.Sprintf("%.1fx", ph.P50Sec/bl)
			}
			rpcs := "-"
			if r.Transport != "local" {
				rpcs = fmt.Sprintf("%d", ph.RPCs)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
				ph.Workload, ph.Phase, fmtDur(ph.P50Sec), fmtOps(ph.OpsPerSec), rpcs, ratio, topServerOps(ph.ServerOps, 3))
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func fmtDur(sec float64) string {
	switch {
	case sec >= 1:
		return fmt.Sprintf("%.2fs", sec)
	case sec >= 0.001:
		return fmt.Sprintf("%.1fms", sec*1000)
	default:
		return fmt.Sprintf("%.0fµs", sec*1e6)
	}
}

func fmtOps(ops float64) string {
	switch {
	case ops >= 1e6:
		return fmt.Sprintf("%.1fM", ops/1e6)
	case ops >= 1e3:
		return fmt.Sprintf("%.1fk", ops/1e3)
	default:
		return fmt.Sprintf("%.0f", ops)
	}
}

func topServerOps(m map[string]int64, k int) string {
	if len(m) == 0 {
		return "-"
	}
	type kv struct {
		name string
		n    int64
	}
	all := make([]kv, 0, len(m))
	for name, n := range m {
		all = append(all, kv{name, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n != all[j].n {
			return all[i].n > all[j].n
		}
		return all[i].name < all[j].name
	})
	if len(all) > k {
		all = all[:k]
	}
	parts := make([]string, len(all))
	for i, e := range all {
		parts[i] = fmt.Sprintf("%s:%d", e.name, e.n)
	}
	return strings.Join(parts, " ")
}
