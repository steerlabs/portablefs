package lantrace

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// GoMonotonicClock is the clock label of every Recorder stream: the Go
// runtime's monotonic clock, as an offset from the recorder's creation.
const GoMonotonicClock Label = "go-monotonic"

const (
	// DefaultQueueEvents is the default Recorder queue capacity.
	DefaultQueueEvents = 8192
	// DefaultByteBudget is the default bound on the bytes of events one
	// Recorder accepts over its lifetime.
	DefaultByteBudget = 256 << 20
)

// ErrClosed is returned by Emit after Close.
var ErrClosed = errors.New("lantrace: recorder is closed")

// RecorderConfig bounds a Recorder. Zero fields take the defaults.
type RecorderConfig struct {
	// QueueEvents is the fixed capacity of the queue between Emit and the
	// writer goroutine. An event that finds it full is lost.
	QueueEvents int
	// ByteBudget bounds the total bytes of event lines the Recorder accepts.
	// An event that would exceed it is lost. The header and trailer are not
	// charged, so the stream is at most ByteBudget plus two short lines.
	ByteBudget int64
}

// Recorder is a bounded producer of one stream. Emit never waits for the
// sink: it validates, stamps seq and t_ns, and either enqueues the encoded
// line or counts the event as lost. One goroutine drains the queue to the
// writer, and Close writes the trailer with the final emitted and lost
// counts. A Recorder holds no per-request, per-name or per-callback state.
type Recorder struct {
	layer Layer
	now   func() Nanos
	queue chan []byte
	done  chan struct{}
	lost  atomic.Uint64

	mu     sync.Mutex
	closed bool
	seq    uint64
	budget int64

	// Owned by the drain goroutine until done is closed.
	emitted uint64
	err     error
}

// NewRecorder starts a Recorder that writes one stream to w. The header uses
// GoMonotonicClock. w is written only by the Recorder's goroutine.
func NewRecorder(w io.Writer, run Label, layer Layer, process Label, cfg RecorderConfig) (*Recorder, error) {
	start := time.Now()
	return newRecorder(w, Header{Run: run, Layer: layer, Process: process, Clock: GoMonotonicClock}, cfg,
		func() Nanos { return Nanos(time.Since(start)) })
}

func newRecorder(w io.Writer, h Header, cfg RecorderConfig, now func() Nanos) (*Recorder, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	if cfg.QueueEvents < 0 || cfg.ByteBudget < 0 {
		return nil, errors.New("lantrace: recorder bounds must not be negative")
	}
	if cfg.QueueEvents == 0 {
		cfg.QueueEvents = DefaultQueueEvents
	}
	if cfg.ByteBudget == 0 {
		cfg.ByteBudget = DefaultByteBudget
	}
	r := &Recorder{
		layer:  h.Layer,
		now:    now,
		queue:  make(chan []byte, cfg.QueueEvents),
		done:   make(chan struct{}),
		budget: cfg.ByteBudget,
	}
	go r.drain(w, encodeHeader(0, h))
	return r, nil
}

// Emit records e. It returns an error only for an event the grammar rejects,
// which is also counted as lost; an event dropped for capacity returns nil,
// because producers must not change behavior on diagnostic pressure.
//
// Every event accepted before Close consumes the next sequence number,
// whether it is written or lost (invalid, over budget, queue full, or a sink
// failure). That is the stream sequence rule in the package documentation:
// the trailer's emitted plus lost equals the last number allocated, and every
// gap in the written numbers is a lost event.
func (r *Recorder) Emit(e Event) error {
	_, invalid := e.validate(r.layer)
	var body []byte
	if invalid == nil {
		var err error
		if body, err = json.Marshal(&e); err != nil {
			invalid = fmt.Errorf("lantrace: encode event: %w", err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	// Stamping under the lock that orders the queue keeps seq and t_ns
	// non-decreasing in the written stream, and accounting a loss under it
	// keeps every loss ahead of the trailer Close writes.
	r.seq++
	if invalid != nil {
		r.lost.Add(1)
		return invalid
	}
	line := appendEvent(make([]byte, 0, len(body)+64), 0, r.seq, r.now(), body)
	if int64(len(line)) > r.budget || len(line) > MaxLineBytes {
		r.lost.Add(1)
		return nil
	}
	select {
	case r.queue <- line:
		r.budget -= int64(len(line))
	default:
		r.lost.Add(1)
	}
	return nil
}

// Lost returns the number of events lost so far, for the producer's own
// low-cardinality counters.
func (r *Recorder) Lost() uint64 { return r.lost.Load() }

// Close stops accepting events, drains the queue, writes the trailer and
// returns the first sink error. It blocks until the sink accepts the
// remaining bytes; a producer that cannot wait must unblock its writer.
func (r *Recorder) Close() error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.queue)
	}
	r.mu.Unlock()
	<-r.done
	return r.err
}

func (r *Recorder) drain(w io.Writer, header []byte) {
	defer close(r.done)
	bw := bufio.NewWriterSize(w, 64<<10)
	write := func(b []byte) bool {
		if r.err != nil {
			return false
		}
		if _, err := bw.Write(b); err != nil {
			r.err = fmt.Errorf("lantrace: write trace: %w", err)
			return false
		}
		return true
	}
	flush := func() {
		if r.err == nil {
			if err := bw.Flush(); err != nil {
				r.err = fmt.Errorf("lantrace: flush trace: %w", err)
			}
		}
	}
	write(header)
	for {
		var line []byte
		var ok bool
		select {
		case line, ok = <-r.queue:
		default:
			// Flush before waiting so a quiet producer's events reach the
			// sink promptly; a slow sink stalls only this goroutine.
			flush()
			line, ok = <-r.queue
		}
		if !ok {
			break
		}
		if write(line) {
			r.emitted++
		} else {
			r.lost.Add(1)
		}
	}
	// Close holds the queue closed, so no Emit can still change lost.
	write(encodeProducerTrailer(r.emitted, r.lost.Load()))
	flush()
}
