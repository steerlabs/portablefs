// Command netprobe measures the raw network floor between this machine and a
// PortableFS data-plane authority endpoint: TCP connect RTT, TLS handshake
// cost, and sustained upload throughput into the TCP path.
//
// It is deliberately protocol-free. Everything it reports is a LOWER BOUND on
// what any PortableFS operation over the same path can cost, so a measured
// op latency can be attributed to "the wire" vs "the protocol".
//
//	go run ./bench/cmd/netprobe -addr sakura.proxy.rlwy.net:45100 -n 30
//	go run ./bench/cmd/netprobe -addr sakura.proxy.rlwy.net:45100 -tls -n 30
//	go run ./bench/cmd/netprobe -addr sakura.proxy.rlwy.net:45100 -upload 32
//
// Reproducible: no state, no writes, no mutation of any volume.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"time"
)

func main() {
	addr := flag.String("addr", "", "host:port of the authority data plane")
	n := flag.Int("n", 20, "number of connect samples")
	useTLS := flag.Bool("tls", false, "also measure the TLS handshake")
	uploadMB := flag.Int("upload", 0, "if >0, push this many MiB into one connection and report achieved MB/s")
	flag.Parse()
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "netprobe: -addr required")
		os.Exit(2)
	}

	if *uploadMB > 0 {
		uploadProbe(*addr, *uploadMB, *useTLS)
		return
	}

	tcp := make([]float64, 0, *n)
	tlsh := make([]float64, 0, *n)
	for i := 0; i < *n; i++ {
		t0 := time.Now()
		c, err := net.DialTimeout("tcp", *addr, 10*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial: %v\n", err)
			continue
		}
		tcp = append(tcp, ms(time.Since(t0)))
		if *useTLS {
			t1 := time.Now()
			tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // measurement only
			if err := tc.Handshake(); err == nil {
				tlsh = append(tlsh, ms(time.Since(t1)))
			}
			_ = tc.Close()
		} else {
			_ = c.Close()
		}
		time.Sleep(20 * time.Millisecond)
	}

	fmt.Printf("addr=%s samples=%d\n", *addr, len(tcp))
	report("tcp-connect-rtt", tcp)
	if *useTLS {
		report("tls-handshake", tlsh)
	}
}

// uploadProbe measures how fast bytes can be pushed into the TCP path. Once
// the receive window and socket buffers fill, the write rate equals the path's
// achievable upload bandwidth — the ceiling any flusher can reach.
func uploadProbe(addr string, mb int, useTLS bool) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()
	var w net.Conn = c
	if useTLS {
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // measurement only
		if err := tc.Handshake(); err != nil {
			fmt.Fprintf(os.Stderr, "tls: %v\n", err)
			os.Exit(1)
		}
		w = tc
	}
	buf := make([]byte, 1<<20)
	_ = c.SetWriteDeadline(time.Now().Add(60 * time.Second))
	t0 := time.Now()
	sent := 0
	for i := 0; i < mb; i++ {
		nw, err := w.Write(buf)
		sent += nw
		if err != nil {
			break
		}
	}
	d := time.Since(t0)
	fmt.Printf("upload addr=%s tls=%v sent=%.1fMiB elapsed=%.3fs rate=%.1fMB/s\n",
		addr, useTLS, float64(sent)/(1<<20), d.Seconds(), float64(sent)/(1<<20)/d.Seconds())
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func report(label string, v []float64) {
	if len(v) == 0 {
		fmt.Printf("%-18s no samples\n", label)
		return
	}
	sort.Float64s(v)
	var sum float64
	for _, x := range v {
		sum += x
	}
	fmt.Printf("%-18s n=%d min=%.2f p50=%.2f p90=%.2f p99=%.2f max=%.2f mean=%.2f ms\n",
		label, len(v), v[0], pct(v, 50), pct(v, 90), pct(v, 99), v[len(v)-1], sum/float64(len(v)))
}

func pct(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return math.NaN()
	}
	i := (p * len(sorted)) / 100
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}
