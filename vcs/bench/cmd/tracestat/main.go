// Command tracestat summarizes a portablefsd log that was produced with
// PFSD_TRACE=1 and/or PFS_WIRE_TRACE=1.
//
// The two traces sit on opposite sides of the same operation:
//
//	pfsd-trace  <op> "<path>" eno=0 duration=<d>   — daemon-side service time
//	WIRETRACE op=<op> path="<path>" ms=<n>         — one authority round trip
//
// Subtracting them attributes an operation's latency to daemon work vs the
// wire, and counting WIRETRACE lines per daemon op gives the round trips per
// operation that the roadmap is priced on.
//
//	go run ./bench/cmd/tracestat -log /tmp/pfsd-trace.log
//	go run ./bench/cmd/tracestat -log /tmp/pfsd-trace.log -from 1200      # skip warmup lines
//
// Read-only.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	pfsdRe = regexp.MustCompile(`pfsd-trace (\S+)\s+(?:"([^"]*)"|dir="([^"]*)")?.*?duration=([0-9.]+)(µs|ms|s|ns)`)
	wireRe = regexp.MustCompile(`WIRETRACE op=(\S+) path="([^"]*)" ms=(\d+)`)
)

type dist struct {
	name string
	v    []float64
}

func (d *dist) add(x float64) { d.v = append(d.v, x) }

func (d *dist) line() string {
	if len(d.v) == 0 {
		return ""
	}
	sort.Float64s(d.v)
	var sum float64
	for _, x := range d.v {
		sum += x
	}
	return fmt.Sprintf("%-26s %7d %10.3f %10.3f %10.3f %10.3f %12.1f",
		d.name, len(d.v), d.v[0], pct(d.v, 50), pct(d.v, 90), d.v[len(d.v)-1], sum)
}

func pct(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	i := (p*len(sorted))/100 - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func main() {
	logPath := flag.String("log", "", "portablefsd log written with PFSD_TRACE=1 / PFS_WIRE_TRACE=1")
	from := flag.Int("from", 0, "skip this many leading lines (drop mount warmup)")
	flag.Parse()
	if *logPath == "" {
		fmt.Fprintln(os.Stderr, "tracestat: -log required")
		os.Exit(2)
	}
	f, err := os.Open(*logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	daemon := map[string]*dist{}
	wire := map[string]*dist{}
	var dOrder, wOrder []string

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		if ln <= *from {
			continue
		}
		line := sc.Text()
		if m := wireRe.FindStringSubmatch(line); m != nil {
			d, ok := wire[m[1]]
			if !ok {
				d = &dist{name: m[1]}
				wire[m[1]] = d
				wOrder = append(wOrder, m[1])
			}
			v, _ := strconv.ParseFloat(m[3], 64)
			d.add(v)
			continue
		}
		if m := pfsdRe.FindStringSubmatch(line); m != nil {
			op := strings.TrimPrefix(m[1], "*pfslocal.")
			d, ok := daemon[op]
			if !ok {
				d = &dist{name: op}
				daemon[op] = d
				dOrder = append(dOrder, op)
			}
			v, _ := strconv.ParseFloat(m[4], 64)
			d.add(v * unitToMs(m[5]))
		}
	}

	fmt.Println("== daemon-side service time (ms) — PFSD_TRACE")
	header()
	dump(daemon, dOrder)

	fmt.Println()
	fmt.Println("== authority round trips (ms) — PFS_WIRE_TRACE")
	header()
	dump(wire, wOrder)

	var wireCalls int
	var wireMs float64
	for _, d := range wire {
		wireCalls += len(d.v)
		for _, x := range d.v {
			wireMs += x
		}
	}
	var dCalls int
	for _, d := range daemon {
		dCalls += len(d.v)
	}
	fmt.Printf("\ntotals: %d daemon ops, %d authority round trips (%.2f RTT per daemon op), %.1f s on the wire\n",
		dCalls, wireCalls, float64(wireCalls)/math.Max(float64(dCalls), 1), wireMs/1000)
}

func header() {
	fmt.Printf("%-26s %7s %10s %10s %10s %10s %12s\n", "op", "n", "min", "p50", "p90", "max", "total_ms")
}

func dump(m map[string]*dist, order []string) {
	sort.Slice(order, func(i, j int) bool { return len(m[order[i]].v) > len(m[order[j]].v) })
	for _, k := range order {
		if s := m[k].line(); s != "" {
			fmt.Println(s)
		}
	}
}

func unitToMs(u string) float64 {
	switch u {
	case "ns":
		return 1e-6
	case "µs":
		return 1e-3
	case "s":
		return 1e3
	default:
		return 1
	}
}
