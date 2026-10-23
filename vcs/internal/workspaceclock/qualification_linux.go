//go:build linux

package workspaceclock

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Qualification records exact-device observations, not a UTC accuracy verdict.
// The duplicate readers are a diagnostic of the one retained open description;
// production wall correction still has exactly one owner.
type Qualification struct {
	Source         string        `json:"source"`
	ReadOnly       bool          `json:"read_only"`
	SecondOpenBusy bool          `json:"second_open_busy"`
	Readers        int           `json:"readers"`
	Samples        int           `json:"samples"`
	P50            time.Duration `json:"p50_ns"`
	P99            time.Duration `json:"p99_ns"`
	Maximum        time.Duration `json:"maximum_ns"`
}

func (o *Owner) Qualify() (Qualification, error) {
	o.sampleMu.Lock()
	defer o.sampleMu.Unlock()
	r, ok := o.backend.(*RTC)
	if !ok {
		return Qualification{}, errors.New("qualification requires the exact RTC backend")
	}
	var q Qualification
	source, err := os.ReadFile("/sys/class/rtc/rtc0/name")
	if err != nil {
		return q, fmt.Errorf("identify RTC source: %w", err)
	}
	q.Source = string(source)
	flags, err := unix.FcntlInt(r.file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return q, err
	}
	q.ReadOnly = flags&unix.O_ACCMODE == unix.O_RDONLY
	second, err := unix.Open("/dev/rtc0", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		unix.Close(second)
		return q, errors.New("RTC unexpectedly admitted a second opening")
	}
	q.SecondOpenBusy = errors.Is(err, unix.EBUSY)
	if !q.SecondOpenBusy {
		return q, fmt.Errorf("second RTC opening: %w", err)
	}
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
	if !q.ReadOnly || q.Maximum > MaxSampleAge {
		return q, errors.New("RTC read-only or contention allocation failed")
	}
	return q, nil
}
