//go:build darwin && cgo

package portablefsd

/*
#include <mach/mach_time.h>
#include <stdint.h>

static uint64_t portablefs_continuous_ticks(void) { return mach_continuous_time(); }

static int portablefs_continuous_timebase(uint32_t *numer, uint32_t *denom) {
	mach_timebase_info_data_t info;
	if (mach_timebase_info(&info) != KERN_SUCCESS) {
		return -1;
	}
	*numer = info.numer;
	*denom = info.denom;
	return 0;
}
*/
import "C"

import (
	"errors"
	"sync"
)

var (
	v3TimebaseOnce  sync.Once
	v3TimebaseNumer uint64
	v3TimebaseDenom uint64
	v3TimebaseErr   error
)

// v3ContinuousNanos reads mach_continuous_time, which keeps advancing while
// the Mac sleeps; Go's monotonic clock on Darwin does not, so a horizon timed
// with it would survive a sleep that outlasted the authority's promise.
func v3ContinuousNanos() (uint64, error) {
	v3TimebaseOnce.Do(func() {
		var numer, denom C.uint32_t
		if C.portablefs_continuous_timebase(&numer, &denom) != 0 || numer == 0 || denom == 0 {
			v3TimebaseErr = errors.New("portablefsd: mach timebase is unavailable")
			return
		}
		v3TimebaseNumer, v3TimebaseDenom = uint64(numer), uint64(denom)
	})
	if v3TimebaseErr != nil {
		return 0, v3TimebaseErr
	}
	return v3TicksToNanos(uint64(C.portablefs_continuous_ticks()), v3TimebaseNumer, v3TimebaseDenom)
}
