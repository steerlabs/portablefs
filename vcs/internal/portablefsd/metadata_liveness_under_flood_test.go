package portablefsd

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// metadataLatencyContract is the campaign's make-or-break promise, stated
// mechanically instead of in prose: METADATA STAYS INTERACTIVE UNDER A DATA
// FLOOD. Round-4 scenario 2 measured cold p99 19.58s / max 38.02s (open_creat)
// and warm max 27.04s (mkdir) while the uplink was HEALTHY for 13 of the 14
// events over one second — so the residual waits were publication/handoff
// family, not credit pacing.
const (
	metadataP99Contract = 1 * time.Second
	metadataMaxContract = 5 * time.Second
)

// TestMetadataStaysInteractiveUnderADataFlood reproduces the shape of the live
// battery's scenario 2 in process, over the production frontend socket: several
// connections stream bulk data through the write-back engine while one probe
// connection runs the metadata mix from the battery harness (probe4.py) against
// both a WARM directory (already delegated, revisited every cycle) and a COLD
// one (a brand-new subtree each cycle, so every cycle pays a fresh delegation
// acquire and, on the unlink→rmdir pair, a delegation RELEASE and its frontend
// handoff).
//
// The cold rmdir is the operation the round-4 harness had to DEFER by 12s to
// keep measuring anything at all: undeferred it wedged (see
// TestColdScopeRemoveSequenceSurvivesAnUnacknowledgedPublication). This test
// does NOT defer it — the whole point is that the four-syscall cold sequence is
// now interactive while data floods.
func TestMetadataStaysInteractiveUnderADataFlood(t *testing.T) {
	if testing.Short() {
		t.Skip("flood contract test is not short")
	}
	t.Run("fast uplink", func(t *testing.T) {
		runMetadataFloodContract(t, 0)
	})
	t.Run("throttled uplink", func(t *testing.T) {
		// ── THE CONFIGURATION THE CONTRACT IS ACTUALLY ABOUT ────────────────
		//
		// An in-process authority over loopback applies as fast as the client
		// can write, so the fast-uplink variant above never builds a backlog
		// and therefore never tests the ordering the contract is about. This
		// one throttles the uplink to the 4 MB/s the live battery measured
		// while calling it HEALTHY, and reproduces the live numbers exactly.
		//
		// It ran behind PORTABLEFS_CONTRACT_B=1 through rounds 4-6 as a
		// REPRODUCTION of an open defect. Round 7 closed the defect, so it runs
		// by default: it is the contract, not a diagnostic.
		//
		//	46a5e8d   cold p99 18.38s  max 18.38s    28 ops in 12s
		//	35f0e1a   cold p99 18.99s  max 18.99s    14 ops in 12s
		//	live      cold p99 19.58s  max 38.02s   (round-4 scenario 2)
		//	round 7   cold p99  0.15s  max  0.20s   770 ops in 12s
		//
		// WHAT THE DEFECT WAS. finishRelease waits for the releasing SCOPE's
		// own tail — round 3 already narrowed the target from the STREAM's
		// tail — but the applied watermark was a STREAM watermark and
		// sendBatch shipped a strict PREFIX of one hash-chained stream. So
		// "apply through this scope's tail" transitively meant "apply every
		// record admitted before it", including every megabyte of unrelated
		// bulk data. A metadata-only scope's release inherited the whole bulk
		// backlog's drain time.
		//
		// WHAT FIXED IT. Lane separation in the stream itself: the namespace
		// lane has its own dense sequence, its own digest chain, its own
		// authority watermark and its own flush worker, so a metadata-only
		// scope's release drains against the namespace watermark alone. See
		// writeback/lane_separation_test.go for the mechanism, piece by piece.
		runMetadataFloodContract(t, 4<<20)
	})
}

func runMetadataFloodContract(t *testing.T, throttleBytesPerSec int) {
	authority := serveAuthority(t)
	if throttleBytesPerSec > 0 {
		authority = serveThrottledAuthority(t, throttleBytesPerSec)
	}
	cfg, hc, _ := startDaemonNoAttach(t, authority)
	ref := ensureAttachWithPolicyOptions(
		t, hc, authority, "vol-flood", "main",
		"/Volumes/Flood", "writeback",
		// The WAL budget must be REALISTIC, not the package fixture's 512 KiB.
		// This contract is about LANE FAIRNESS under load; a cap smaller than a
		// couple of metadata frames makes the namespace lane's reserve
		// meaningless for reasons that have nothing to do with the contract
		// (the gate's own worst-case demand alone is an eighth of it). 256 MB
		// of disk cache is the engine's ordinary 128 MiB WAL budget.
		map[string]any{"flushIntervalMs": int64(10), "diskCacheMb": int64(256)},
	)

	const (
		writers  = 4
		duration = 12 * time.Second
		chunk    = 256 << 10
	)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// THE FLOOD. Each writer owns its own frontend connection, so the daemon
	// sees genuinely concurrent logical operations rather than one serialized
	// client.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			c := dialPFS(t, cfg.FrontendSocket)
			defer c.close()
			c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "flood-writer"})
			root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
			dir := c.call(&pfslocal.MkdirRequest{
				Dir: root, Name: []byte(fmt.Sprintf("flood%d", w)), Mode: 0o755,
			}).(*pfslocal.MkdirReply)
			payload := make([]byte, chunk)
			for i := range payload {
				payload[i] = byte(i)
			}
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				created, errReply := c.callMaybe(&pfslocal.CreateRequest{
					Dir:       dir.Attr.Item,
					Name:      []byte(fmt.Sprintf("blob%d", n)),
					Mode:      0o644,
					Exclusive: true,
				})
				if errReply != nil {
					return
				}
				handle := created.(*pfslocal.CreateReply).Handle
				for off := 0; off < 4; off++ {
					if _, errReply := c.callMaybe(&pfslocal.WriteRequest{
						Handle: handle,
						Offset: uint64(off * chunk),
						Data:   payload,
					}); errReply != nil {
						break
					}
				}
				c.call(&pfslocal.CloseRequest{Handle: handle})
			}
		}(w)
	}

	// THE PROBE. One connection, the harness's op mix, no deferral.
	type sample struct {
		scope string
		op    string
		dt    time.Duration
		err   *pfslocal.ErrorReply
	}
	var (
		mu      sync.Mutex
		samples []sample
	)
	record := func(scope, op string, dt time.Duration, err *pfslocal.ErrorReply) {
		mu.Lock()
		samples = append(samples, sample{scope: scope, op: op, dt: dt, err: err})
		mu.Unlock()
	}

	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		c := dialPFS(t, cfg.FrontendSocket)
		defer c.close()
		c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "metadata-probe"})
		root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
		warm := c.call(&pfslocal.MkdirRequest{
			Dir: root, Name: []byte("warm"), Mode: 0o755,
		}).(*pfslocal.MkdirReply)
		coldRoot := c.call(&pfslocal.MkdirRequest{
			Dir: root, Name: []byte("cold"), Mode: 0o755,
		}).(*pfslocal.MkdirReply)
		seed := c.call(&pfslocal.CreateRequest{
			Dir: warm.Attr.Item, Name: []byte("seed.txt"), Mode: 0o644, Exclusive: true,
		}).(*pfslocal.CreateReply)
		c.call(&pfslocal.CloseRequest{Handle: seed.Handle})

		timed := func(scope, op string, body any) any {
			started := time.Now()
			reply, errReply := c.callMaybe(body)
			record(scope, op, time.Since(started), errReply)
			return reply
		}

		deadline := time.Now().Add(duration)
		for i := 0; time.Now().Before(deadline); i++ {
			// WARM: an already-delegated directory revisited every cycle.
			timed("warm", "listdir", &pfslocal.EnumerateRequest{
				Dir: warm.Attr.Item, MaxEntries: 64,
			})
			timed("warm", "stat", &pfslocal.GetAttrRequest{Item: seed.Attr.Item})
			wd := timed("warm", "mkdir", &pfslocal.MkdirRequest{
				Dir: warm.Attr.Item, Name: []byte(fmt.Sprintf("d%d", i)), Mode: 0o755,
			})
			wf := timed("warm", "open_creat", &pfslocal.CreateRequest{
				Dir:       warm.Attr.Item,
				Name:      []byte(fmt.Sprintf("t%d", i)),
				Mode:      0o644,
				Exclusive: true,
			})
			if wf != nil {
				created := wf.(*pfslocal.CreateReply)
				mtime := time.Now().UnixMilli()
				timed("warm", "utimes", &pfslocal.SetAttrRequest{
					Item: created.Attr.Item, MtimeMs: &mtime,
				})
				c.call(&pfslocal.CloseRequest{Handle: created.Handle})
				timed("warm", "unlink", &pfslocal.RemoveRequest{
					Dir: warm.Attr.Item, Name: []byte(fmt.Sprintf("t%d", i)),
				})
			}
			if wd != nil {
				timed("warm", "rmdir", &pfslocal.RemoveRequest{
					Dir:       warm.Attr.Item,
					Name:      []byte(fmt.Sprintf("d%d", i)),
					Directory: true,
				})
			}

			// COLD: a brand-new subtree every cycle, and the undeferred
			// unlink→rmdir pair that used to wedge.
			cd := timed("cold", "mkdir", &pfslocal.MkdirRequest{
				Dir: coldRoot.Attr.Item, Name: []byte(fmt.Sprintf("c%d", i)), Mode: 0o755,
			})
			if cd == nil {
				continue
			}
			cold := cd.(*pfslocal.MkdirReply)
			cf := timed("cold", "open_creat", &pfslocal.CreateRequest{
				Dir: cold.Attr.Item, Name: []byte("f"), Mode: 0o644, Exclusive: true,
			})
			if cf != nil {
				created := cf.(*pfslocal.CreateReply)
				mtime := time.Now().UnixMilli()
				timed("cold", "utimes", &pfslocal.SetAttrRequest{
					Item: created.Attr.Item, MtimeMs: &mtime,
				})
				c.call(&pfslocal.CloseRequest{Handle: created.Handle})
				timed("cold", "listdir", &pfslocal.EnumerateRequest{
					Dir: cold.Attr.Item, MaxEntries: 64,
				})
				timed("cold", "stat", &pfslocal.GetAttrRequest{Item: created.Attr.Item})
				timed("cold", "unlink", &pfslocal.RemoveRequest{
					Dir: cold.Attr.Item, Name: []byte("f"),
				})
			}
			timed("cold", "rmdir", &pfslocal.RemoveRequest{
				Dir:       coldRoot.Attr.Item,
				Name:      []byte(fmt.Sprintf("c%d", i)),
				Directory: true,
			})
			time.Sleep(50 * time.Millisecond)
		}
	}()

	<-probeDone
	close(stop)
	wg.Wait()

	if len(samples) < 50 {
		// Report it and keep going: the distribution below is the evidence,
		// and a starved probe has the most interesting distribution of all.
		t.Errorf(
			"probe completed only %d operations in %s: the flood starved the "+
				"metadata lane", len(samples), duration,
		)
	}

	report := func(scope string) (p99, max time.Duration, worst sample, n int) {
		var d []time.Duration
		for _, s := range samples {
			if scope != "" && s.scope != scope {
				continue
			}
			d = append(d, s.dt)
			if s.dt > max {
				max, worst = s.dt, s
			}
		}
		n = len(d)
		if n == 0 {
			return 0, 0, worst, 0
		}
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		idx := (n*99 + 99) / 100
		if idx >= n {
			idx = n - 1
		}
		return d[idx], max, worst, n
	}

	for _, scope := range []string{"warm", "cold", ""} {
		p99, max, worst, n := report(scope)
		name := scope
		if name == "" {
			name = "all"
		}
		t.Logf("metadata %s: n=%d p99=%s max=%s (worst %s/%s)",
			name, n, p99.Round(time.Millisecond), max.Round(time.Millisecond),
			worst.scope, worst.op)
		if p99 > metadataP99Contract {
			t.Errorf(
				"metadata %s p99=%s exceeds the %s interactive contract under a data flood",
				name, p99.Round(time.Millisecond), metadataP99Contract,
			)
		}
		if max > metadataMaxContract {
			t.Errorf(
				"metadata %s max=%s (%s/%s) exceeds the %s ceiling under a data flood",
				name, max.Round(time.Millisecond), worst.scope, worst.op,
				metadataMaxContract,
			)
		}
	}
	for _, s := range samples {
		if s.err != nil {
			t.Errorf("metadata %s/%s failed under the flood: %+v", s.scope, s.op, s.err)
		}
	}
}
