package authorityrpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

var (
	ErrFrameBounds = errors.New("authorityrpc: frame length is outside negotiated bounds")
	ErrFrameBudget = errors.New("authorityrpc: worker frame allocation budget is exhausted")
)

// frameBudget bounds the bytes concurrently allocated for inbound frame
// payloads across every connection a worker accepts. Without it the only bound
// on attacker-paced transient allocation is MaxConnections multiplied by the
// largest legal frame, which is not a number any deployment sizes.
type frameBudget struct {
	mu        sync.Mutex
	available uint64
	// changed is closed and replaced on every release so that every waiter,
	// not just one, re-evaluates its own reservation size.
	changed chan struct{}
}

func newFrameBudget(limit uint64) *frameBudget {
	return &frameBudget{available: limit, changed: make(chan struct{})}
}

// acquire reserves n bytes, waiting at most until ctx is done or wait elapses.
// It never partially reserves.
func (b *frameBudget) acquire(ctx context.Context, n uint32, wait time.Duration) error {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		b.mu.Lock()
		if b.available >= uint64(n) {
			b.available -= uint64(n)
			b.mu.Unlock()
			return nil
		}
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return ErrFrameBudget
		}
	}
}

func (b *frameBudget) release(n uint32) {
	b.mu.Lock()
	b.available += uint64(n)
	close(b.changed)
	b.changed = make(chan struct{})
	b.mu.Unlock()
}

// readFrame decodes one length-prefixed protobuf message. budget may be nil on
// a peer whose concurrent frame count is already bounded by its own in-flight
// admission (a client owns exactly one connection); a server must always pass
// one.
func readFrame(r io.Reader, max uint32, budget *frameBudget, wait time.Duration, message proto.Message) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > max {
		return fmt.Errorf("%w: %d (max %d)", ErrFrameBounds, size, max)
	}
	if budget != nil {
		if err := budget.acquire(context.Background(), size, wait); err != nil {
			return err
		}
		defer budget.release(size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	// Unmarshal copies every scalar and bytes field out of payload, so the
	// reservation covers the whole lifetime of the transient allocation.
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, message); err != nil {
		return fmt.Errorf("decode protobuf frame: %w", err)
	}
	return nil
}

func writeFrame(w io.Writer, max uint32, message proto.Message) error {
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode protobuf frame: %w", err)
	}
	if len(payload) == 0 || uint64(len(payload)) > uint64(max) {
		return fmt.Errorf("%w: %d (max %d)", ErrFrameBounds, len(payload), max)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := w.Write(payload)
		if n < 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
