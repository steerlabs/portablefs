package fsproto

// Timing-neutral diagnostic trace for the handoff race. The hot path (trace) does ONE atomic
// increment and ONE store of a fixed-size struct into a pre-allocated ring — no allocation, no
// formatting, no mutex, no I/O. (log.Printf and even an in-memory append-with-Sprintf perturb
// the timing enough to hide the race; this should not.) Formatting happens only at dump time,
// post-mortem, via DumpTrace (wired to SIGUSR1 in cmd/vcs). Enable with VCS_TRACE=1.

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

var traceOn = os.Getenv("VCS_TRACE") != ""

const traceRingSize = 1 << 16 // power of two; ring overwrites oldest

type tev struct {
	op       uint8
	id, own  uint64 // prefix-tags of the sessionID / owner (distinguish A vs B, which subtree)
	ep, x, y uint64 // op-specific numerics (epoch, seq, through, ...)
}

var (
	traceRing [traceRingSize]tev
	traceIdx  uint64
)

// tag packs the first 8 bytes of s into a uint64 (cheap, no hashing) — enough to tell distinct
// owners/sessions apart in the dump without storing strings on the hot path.
func tag(s string) uint64 {
	var b [8]byte
	copy(b[:], s)
	return binary.BigEndian.Uint64(b[:])
}

func trace(op uint8, id, own, ep, x, y uint64) {
	if !traceOn {
		return
	}
	i := atomic.AddUint64(&traceIdx, 1) - 1
	traceRing[i&(traceRingSize-1)] = tev{op, id, own, ep, x, y}
}

const (
	evFlushRecv = iota + 1
	evFlushOK
	evFlushStale
	evFlushResend
	evFlushGap
	evFlushOwner
	evCheckoutOK
	evCheckoutBusy
	evCheckinOK
	evCheckinNo
	evRelease
)

func opName(op uint8) string {
	switch op {
	case evFlushRecv:
		return "flush-recv"
	case evFlushOK:
		return "flush-OK"
	case evFlushStale:
		return "flush-STALE"
	case evFlushResend:
		return "flush-RESEND"
	case evFlushGap:
		return "flush-GAP"
	case evFlushOwner:
		return "flush-OWNERREJ"
	case evCheckoutOK:
		return "checkout-OK"
	case evCheckoutBusy:
		return "checkout-BUSY"
	case evCheckinOK:
		return "checkin-OK"
	case evCheckinNo:
		return "checkin-NOTHELD"
	case evRelease:
		return "RELEASEOWNER"
	default:
		return "?"
	}
}

// DumpTrace formats the ring in chronological order (post-mortem; not on the hot path).
func DumpTrace() string {
	n := atomic.LoadUint64(&traceIdx)
	start := uint64(0)
	if n > traceRingSize {
		start = n - traceRingSize
	}
	var sb strings.Builder
	for i := start; i < n; i++ {
		e := traceRing[i&(traceRingSize-1)]
		fmt.Fprintf(&sb, "%6d %-14s id=%016x own=%016x ep=%d x=%d y=%d\n",
			i, opName(e.op), e.id, e.own, e.ep, e.x, e.y)
	}
	return sb.String()
}
