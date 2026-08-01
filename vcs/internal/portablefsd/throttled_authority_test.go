package portablefsd

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// serveThrottledAuthority puts a byte-rate limiter in front of a real
// authority.
//
// It exists because an in-process authority over loopback applies as fast as
// the client can write, so a "data flood" against it never builds a backlog:
// the write-back engine's credit control never paces anything, the flusher's
// watermark never falls behind, and the whole regime the live battery measured
// — 4-6 MB/s applied, tens of MiB unshipped, metadata competing with it — is
// simply absent. A contract test that only ever runs in that regime proves
// nothing about the contract.
//
// The limiter is a token bucket on the CLIENT→AUTHORITY direction, which is
// where bulk write payloads travel. bytesPerSec is the sustained apply rate the
// daemon can achieve; burst is one bucket refill quantum.
func serveThrottledAuthority(t *testing.T, bytesPerSec int) string {
	t.Helper()
	upstream := serveAuthority(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			server, err := net.Dial("tcp", upstream)
			if err != nil {
				_ = client.Close()
				continue
			}
			wg.Add(2)
			go func() {
				defer wg.Done()
				defer func() { _ = server.Close() }()
				defer func() { _ = client.Close() }()
				_, _ = io.Copy(server, newRateLimitedReader(client, bytesPerSec))
			}()
			go func() {
				defer wg.Done()
				defer func() { _ = client.Close() }()
				defer func() { _ = server.Close() }()
				_, _ = io.Copy(client, server)
			}()
		}
	}()
	return ln.Addr().String()
}

// rateLimitedReader paces reads at a sustained byte rate using a token bucket
// refilled every rateQuantum. It never returns a short-read error: it sleeps
// until tokens exist, which is exactly how a slow uplink presents.
type rateLimitedReader struct {
	src      io.Reader
	perSec   int
	tokens   int
	lastFill time.Time
}

const rateQuantum = 20 * time.Millisecond

func newRateLimitedReader(src io.Reader, bytesPerSec int) io.Reader {
	return &rateLimitedReader{
		src:      src,
		perSec:   bytesPerSec,
		tokens:   bytesPerSec / int(time.Second/rateQuantum),
		lastFill: time.Now(),
	}
}

func (r *rateLimitedReader) Read(p []byte) (int, error) {
	per := r.perSec / int(time.Second/rateQuantum)
	if per <= 0 {
		per = 1
	}
	for r.tokens <= 0 {
		elapsed := time.Since(r.lastFill)
		if elapsed < rateQuantum {
			time.Sleep(rateQuantum - elapsed)
		}
		quanta := int(time.Since(r.lastFill) / rateQuantum)
		if quanta < 1 {
			quanta = 1
		}
		r.tokens += quanta * per
		if r.tokens > 4*per {
			r.tokens = 4 * per
		}
		r.lastFill = time.Now()
	}
	if len(p) > r.tokens {
		p = p[:r.tokens]
	}
	n, err := r.src.Read(p)
	r.tokens -= n
	return n, err
}
