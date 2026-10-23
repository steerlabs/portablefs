//go:build linux

package workspaceclock

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This test binary runs as init in a disposable native qualification VM. No
// benchmark code or duplicate RTC reader ships in the service executable.
func init() {
	if os.Getpid() != 1 {
		return
	}
	for _, mount := range []struct{ name, kind string }{{"/dev", "devtmpfs"}, {"/proc", "proc"}, {"/sys", "sysfs"}} {
		if err := unix.Mount(mount.kind, mount.name, mount.kind, 0, ""); err != nil {
			panic(err)
		}
	}
	os.Args = []string{os.Args[0], "-test.run=^TestNativeRTCContention$", "-test.v"}
}

type Qualification struct {
	RTCIdentity
	Readers int           `json:"readers"`
	Samples int           `json:"samples"`
	P50     time.Duration `json:"p50_ns"`
	P99     time.Duration `json:"p99_ns"`
	Maximum time.Duration `json:"maximum_ns"`
}

func TestNativeRTCContention(t *testing.T) {
	if os.Getpid() != 1 {
		t.Skip("native qualification initramfs only")
	}
	fd, err := unix.Open("/dev/rtc0", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := &RTC{file: os.NewFile(uintptr(fd), "qualification RTC")}
	defer r.Close()
	identity, err := r.inspect()
	if err != nil {
		t.Fatal(err)
	}
	q, err := qualifyRTC(r, identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("RTC_QUALIFICATION=" + string(raw))
	fmt.Println("PASS: rtc-contention-qualification")
	// The host stops this VM after the complete result. PID 1 must not exit.
	for {
		time.Sleep(time.Hour)
	}
}

func qualifyRTC(r *RTC, identity RTCIdentity) (Qualification, error) {
	q := Qualification{RTCIdentity: identity}
	q.Readers = 8
	const each = 1000
	results := make(chan []time.Duration, q.Readers)
	failures := make(chan error, q.Readers)
	var wg sync.WaitGroup
	for i := 0; i < q.Readers; i++ {
		fd, e := unix.FcntlInt(r.file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if e != nil {
			return q, e
		}
		reader := &RTC{file: os.NewFile(uintptr(fd), "duplicate RTC qualification")}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer reader.Close()
			samples := make([]time.Duration, 0, each)
			for n := 0; n < each; n++ {
				start := time.Now()
				utc, e := reader.ReadUTC()
				samples = append(samples, time.Since(start))
				if e != nil || utc.Year() < 2020 || utc.Year() > 2100 {
					failures <- errors.New("duplicate RTC read failed")
					return
				}
			}
			results <- samples
		}()
	}
	wg.Wait()
	close(failures)
	for e := range failures {
		return q, e
	}
	close(results)
	var all []time.Duration
	for samples := range results {
		all = append(all, samples...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	q.Samples = len(all)
	q.P50 = all[len(all)/2]
	q.P99 = all[len(all)*99/100]
	q.Maximum = all[len(all)-1]
	if q.Maximum > MaxSampleAge {
		return q, errors.New("RTC read-only or contention allocation failed")
	}
	return q, nil
}
