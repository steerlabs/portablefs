//go:build linux

package workspaceclock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// RTCIdentity describes ownership, without sampling or qualifying UTC accuracy.
type RTCIdentity struct {
	Source         string `json:"source"`
	ReadOnly       bool   `json:"read_only"`
	SecondOpenBusy bool   `json:"second_open_busy"`
}

func (o *Owner) InspectRTC() (RTCIdentity, error) {
	o.sampleMu.Lock()
	defer o.sampleMu.Unlock()
	r, ok := o.backend.(*RTC)
	if !ok {
		return RTCIdentity{}, errors.New("inspection requires RTC backend")
	}
	return r.inspect()
}
func (r *RTC) inspect() (q RTCIdentity, err error) {
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
	if !q.ReadOnly {
		return q, errors.New("RTC opening is not read-only")
	}
	second, err := unix.Open("/dev/rtc0", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		unix.Close(second)
		return q, errors.New("RTC unexpectedly admitted a second opening")
	}
	q.SecondOpenBusy = errors.Is(err, unix.EBUSY)
	if !q.SecondOpenBusy {
		return q, fmt.Errorf("second RTC opening: %w", err)
	}
	return q, nil
}
