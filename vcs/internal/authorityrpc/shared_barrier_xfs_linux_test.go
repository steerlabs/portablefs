//go:build linux

package authorityrpc

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// This is a bounded measurement, not a latency acceptance threshold. The fixture
// must provision a second service-owned project on A's actual XFS filesystem.
func TestSharedXFSBarrierLatency(t *testing.T) {
	neighbor := os.Getenv("PORTABLEFS_XFS_NEIGHBOR_ROOT")
	if neighbor == "" {
		t.Skip("a second provisioned XFS project is required")
	}
	if os.Geteuid() == 0 {
		t.Fatal("barrier measurement must run as the authority service owner")
	}
	project, err := strconv.ParseUint(os.Getenv("PORTABLEFS_XFS_NEIGHBOR_PROJECT"), 10, 32)
	if err != nil || project == 0 || strconv.FormatUint(project, 10) == os.Getenv("PORTABLEFS_XFS_TEST_PROJECT") {
		t.Fatal("neighbor must have a distinct provisioned project ID")
	}
	neighborStore, err := xfsstore.Open(neighbor, xfsstore.Config{ExpectedProjectID: uint32(project), ExpectedOwnerUID: uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = neighborStore.Close() })
	const workers, iterations = 4, 12
	observations := make(chan xfsstore.StorageSync, 2*workers*iterations*3)
	var dropped atomic.Uint64
	f := newObservedKernelAuthorityFixture(t, func(s xfsstore.StorageSync) {
		select {
		case observations <- s:
		default:
			dropped.Add(1)
		}
	}, workers)
	var a, b syscall.Stat_t
	if err := syscall.Stat(f.path, &a); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(neighbor, &b); err != nil {
		t.Fatal(err)
	}
	if a.Dev != b.Dev {
		t.Fatal("neighbor is not on the same filesystem")
	}
	path := filepath.Join(neighbor, fmt.Sprintf("dirty-%d", os.Getpid()))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close(); _ = os.Remove(path) })
	buffer := make([]byte, 1<<20)
	if err := file.Truncate(32 << 20); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	var requestID atomic.Uint64
	requestID.Store(100)
	var sequences [workers]uint64
	for _, phase := range []string{"quiet", "dirty-neighbor"} {
		var dirtyBytes atomic.Uint64
		stop, ready, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
		if phase == "dirty-neighbor" {
			go func() {
				var offset int64
				first := true
				for {
					select {
					case <-stop:
						finished <- nil
						return
					default:
					}
					n, err := file.WriteAt(buffer, offset)
					if err != nil {
						if first {
							close(ready)
						}
						finished <- err
						return
					}
					dirtyBytes.Add(uint64(n))
					if first {
						close(ready)
						first = false
					}
					offset = (offset + int64(n)) % (32 << 20)
				}
			}()
			<-ready
		}
		latencies := make(chan time.Duration, workers*iterations*3)
		failures := make(chan error, workers)
		var wait sync.WaitGroup
		started := time.Now()
		for worker := range workers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				call := func(body *authoritypb.Request) (*authoritypb.Response, bool) {
					sequences[worker]++
					body.RequestId, body.Epoch, body.Session = requestID.Add(1), f.epoch, f.proof
					body.Mutation = &authoritypb.Mutation{Slot: uint32(worker), Sequence: sequences[worker]}
					begin := time.Now()
					reply := f.h.Handle(f.ctx, body)
					if reply.GetErrno() != 0 || reply.GetUncertain() {
						failures <- fmt.Errorf("%s worker %d: %v", phase, worker, reply)
						return nil, false
					}
					if body.GetReclaim() == nil {
						latencies <- time.Since(begin)
					}
					return reply, true
				}
				for i := range iterations {
					name := []byte(fmt.Sprintf("%s-%d-%d", phase, worker, i))
					reply, ok := call(&authoritypb.Request{Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{Parent: f.root, Name: name, Mode: 0700}}})
					if !ok {
						return
					}
					token := reply.GetMkdir().GetItem().GetToken()
					mode := uint32(0)
					if _, ok = call(&authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: token, Mode: &mode}}}); !ok {
						return
					}
					if _, ok = call(&authoritypb.Request{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{Parent: f.root, Name: name, Directory: true}}}); !ok {
						return
					}
					if _, ok = call(&authoritypb.Request{Body: &authoritypb.Request_Reclaim{Reclaim: &authoritypb.ReclaimRequest{Items: [][]byte{token}}}}); !ok {
						return
					}
				}
			}()
		}
		wait.Wait()
		elapsed := time.Since(started)
		if phase == "dirty-neighbor" {
			close(stop)
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
		}
		close(failures)
		for err := range failures {
			t.Error(err)
		}
		if t.Failed() {
			return
		}
		var callbacks, syscalls []time.Duration
		close(latencies)
		for d := range latencies {
			callbacks = append(callbacks, d)
		}
		waiters := 0
		for len(observations) != 0 {
			s := <-observations
			if s.Kind != "syncfs" {
				t.Fatalf("handleless operation used %q", s.Kind)
			}
			syscalls, waiters = append(syscalls, s.Elapsed), waiters+s.Waiters
		}
		if len(callbacks) != workers*iterations*3 || waiters != len(callbacks) || len(syscalls) == 0 || dropped.Load() != 0 {
			t.Fatalf("incomplete accounting: callbacks=%d syscalls=%d waiters=%d dropped=%d", len(callbacks), len(syscalls), waiters, dropped.Load())
		}
		slices.Sort(callbacks)
		slices.Sort(syscalls)
		t.Logf("%s: mutations=%d workers=%d wall=%s throughput=%.1f/s neighbor_bytes=%d actual_syncfs=%d actual_fsync=0 barrier_waiters=%d callback_p50=%s callback_p95=%s callback_max=%s syscall_p50=%s syscall_p95=%s syscall_max=%s", phase, len(callbacks), workers, elapsed, float64(len(callbacks))/elapsed.Seconds(), dirtyBytes.Load(), len(syscalls), waiters, callbacks[len(callbacks)/2], callbacks[len(callbacks)*95/100], callbacks[len(callbacks)-1], syscalls[len(syscalls)/2], syscalls[len(syscalls)*95/100], syscalls[len(syscalls)-1])
	}
}
