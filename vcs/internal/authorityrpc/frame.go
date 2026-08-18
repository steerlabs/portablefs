package authorityrpc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

var (
	ErrFrameBounds   = errors.New("authorityrpc: frame length is outside negotiated bounds")
	ErrFrameBudget   = errors.New("authorityrpc: worker frame allocation budget is exhausted")
	ErrFramePayload  = errors.New("authorityrpc: frame bulk payload does not match its protobuf carrier")
	ErrFrameEncoding = errors.New("authorityrpc: protobuf metadata is outside the exact wire grammar")
)

const frameHeaderBytes = 8

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

// framePoolGranularity is the width of one recycled payload class. Classes are
// linear rather than powers of two because the size that matters is a maximal
// bulk body plus a small protobuf header: a power-of-two class would round that
// to twice the frame, and Go satisfies a fresh multi-megabyte allocation out of
// already-zero pages, so an oversized class loses more on a pool miss than the
// pool wins on a hit. At 64 KiB a maximal 1 MiB write stays within 6% of its
// exact size.
const framePoolGranularity = 64 << 10

// framePoolClasses covers 64 KiB through 4 MiB, which spans every frame a legal
// authority bound can produce. A smaller frame is a control-sized message whose
// allocation never shows up next to the TLS record work that produced it, and a
// larger one is allocated directly rather than parked in a class no other
// reader would draw from.
const framePoolClasses = 64

var framePools [framePoolClasses]sync.Pool

// framePoolClass is the pool whose buffers are exactly large enough for size,
// or -1 when size has no class. framePoolBytes is that class's buffer size.
func framePoolClass(size int) int {
	if size < framePoolGranularity {
		return -1
	}
	class := (size+framePoolGranularity-1)/framePoolGranularity - 1
	if class < 0 || class >= framePoolClasses {
		return -1
	}
	return class
}

func framePoolBytes(class int) int { return (class + 1) * framePoolGranularity }

// acquireFramePayload returns a size-length buffer whose every byte the caller
// immediately overwrites with the frame it is reading. A pooled buffer is
// deliberately not cleared: zeroing a megabyte in order to read a megabyte over
// it is the cost this pool exists to remove, and a payload is only ever exposed
// through io.ReadFull, which fails rather than leave a byte unwritten.
func acquireFramePayload(size int) ([]byte, int) {
	class := framePoolClass(size)
	if class < 0 {
		return make([]byte, size), class
	}
	if pooled, _ := framePools[class].Get().(*[]byte); pooled != nil {
		return (*pooled)[:size], class
	}
	return make([]byte, framePoolBytes(class))[:size], class
}

func releaseFramePayload(payload []byte, class int) {
	if class < 0 {
		return
	}
	full := payload[:cap(payload)]
	framePools[class].Put(&full)
}

// readFrame decodes one framed protobuf message. A frame has two lengths:
// protobuf metadata followed by an optional out-of-line bulk body. Only
// WriteTransactionRequest.Data, OneShotWriteRequest.Data, and ReadReply.Data
// are the only legal bulk bodies. Keeping the payload outside protobuf removes
// the full-size marshal and unmarshal copies from
// the data path without creating a second protocol or weakening replay: the
// reconstructed Request is exactly what the authority's canonical replay
// fingerprint authenticates.
//
// budget may be nil on a peer whose concurrent frame count is already bounded
// by its own in-flight admission (a client owns exactly one connection). A
// server uses readFrameRetained so its reservation covers the lifetime of the
// zero-copy bulk slice through handler execution.
func readFrame(r io.Reader, max uint32, budget *frameBudget, wait time.Duration, message proto.Message) error {
	// The decoded message keeps the frame's bulk slice and this caller has no
	// later boundary at which that slice dies, so the payload is not recycled.
	release, err := readFrameInto(r, max, budget, wait, message, false)
	if release != nil {
		release()
	}
	return err
}

// readFrameRetained reads one frame whose payload the caller keeps until it
// runs the returned release. release is the payload's exact end of life: it
// drops the bulk slice from message and hands the buffer to the next reader, so
// a caller must be finished with message before running it.
func readFrameRetained(r io.Reader, max uint32, budget *frameBudget, wait time.Duration, message proto.Message) (func(), error) {
	return readFrameInto(r, max, budget, wait, message, true)
}

func readFrameInto(r io.Reader, max uint32, budget *frameBudget, wait time.Duration, message proto.Message, recycle bool) (func(), error) {
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	metadataSize := binary.BigEndian.Uint32(header[:4])
	bulkSize := binary.BigEndian.Uint32(header[4:])
	total := uint64(metadataSize) + uint64(bulkSize)
	if metadataSize == 0 || total > uint64(max) {
		return nil, fmt.Errorf("%w: metadata %d + bulk %d (max %d)", ErrFrameBounds, metadataSize, bulkSize, max)
	}
	if budget != nil {
		if err := budget.acquire(context.Background(), uint32(total), wait); err != nil {
			return nil, err
		}
	}
	var payload []byte
	class := -1
	if recycle {
		payload, class = acquireFramePayload(int(total))
	} else {
		payload = make([]byte, int(total))
	}
	// retained is the carrier that aliases payload once the frame is decoded.
	// Clearing it in release makes the end of the bulk slice's life explicit
	// instead of a convention a handler could quietly outlive.
	var retained *[]byte
	released := false
	release := func() {
		if released {
			return
		}
		released = true
		if recycle {
			if retained != nil {
				*retained = nil
			}
			releaseFramePayload(payload, class)
		}
		if budget != nil {
			budget.release(uint32(total))
		}
	}
	fail := func(err error) (func(), error) {
		release()
		return nil, err
	}
	if _, err := io.ReadFull(r, payload); err != nil {
		return fail(err)
	}
	metadata := payload[:metadataSize]
	bulk := payload[metadataSize:]
	if err := validateWireMessage(metadata, message.ProtoReflect().Descriptor()); err != nil {
		return fail(err)
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(metadata, message); err != nil {
		return fail(fmt.Errorf("decode protobuf frame: %w", err))
	}
	carrier, err := frameBulkCarrier(message)
	if err != nil {
		return fail(err)
	}
	if carrier != nil && len(*carrier) != 0 {
		return fail(fmt.Errorf("%w: bulk data was encoded inside protobuf", ErrFramePayload))
	}
	if bulkSize != 0 {
		if carrier == nil {
			return fail(fmt.Errorf("%w: %d bytes have no legal carrier", ErrFramePayload, bulkSize))
		}
		*carrier = bulk
		retained = carrier
	}
	return release, nil
}

type frameBoundaryWriter interface {
	beginFrameWrite() error
	endFrameWrite() error
}

func writeFrame(w io.Writer, max uint32, message proto.Message) (err error) {
	carrier, err := frameBulkCarrier(message)
	if err != nil {
		return err
	}
	var bulk []byte
	if carrier != nil {
		bulk = *carrier
		// The caller owns the message for the duration of writeFrame. Restore it
		// before any bytes are written so a same-epoch replay sees the identical
		// request even when a later network write fails.
		*carrier = nil
	}
	// Keep the fixed header and small protobuf metadata in one TLS write. The
	// bulk body remains a second write so it is never copied into a staging
	// buffer merely to recover writev-like shape above TLS.
	prefix := make([]byte, frameHeaderBytes, frameHeaderBytes+proto.Size(message))
	prefix, err = proto.MarshalOptions{Deterministic: true}.MarshalAppend(prefix, message)
	if carrier != nil {
		*carrier = bulk
	}
	if err != nil {
		return fmt.Errorf("encode protobuf frame: %w", err)
	}
	metadata := prefix[frameHeaderBytes:]
	if err := validateWireMessage(metadata, message.ProtoReflect().Descriptor()); err != nil {
		return err
	}
	total := uint64(len(metadata)) + uint64(len(bulk))
	if len(metadata) == 0 || total > uint64(max) || len(metadata) > int(^uint32(0)) || len(bulk) > int(^uint32(0)) {
		return fmt.Errorf("%w: metadata %d + bulk %d (max %d)", ErrFrameBounds, len(metadata), len(bulk), max)
	}
	binary.BigEndian.PutUint32(prefix[:4], uint32(len(metadata)))
	binary.BigEndian.PutUint32(prefix[4:8], uint32(len(bulk)))
	if buffered, ok := w.(frameBoundaryWriter); ok {
		if err := buffered.beginFrameWrite(); err != nil {
			return err
		}
		defer func() {
			if flushErr := buffered.endFrameWrite(); err == nil {
				err = flushErr
			}
		}()
	}
	if err := writeAll(w, prefix); err != nil {
		return err
	}
	return writeAll(w, bulk)
}

// frameBulkCarrier returns the only schema field a frame may transport out of
// line. A non-bulk message returns nil. Both directions are handled here so the
// wire invariant cannot drift between reader and writer.
func frameBulkCarrier(message proto.Message) (*[]byte, error) {
	switch typed := message.(type) {
	case *authoritypb.Request:
		if transaction := typed.GetWriteTransaction(); transaction != nil {
			return &transaction.Data, nil
		}
		if write := typed.GetOneShotWrite(); write != nil {
			return &write.Data, nil
		}
	case *authoritypb.Response:
		if read := typed.GetRead(); read != nil {
			return &read.Data, nil
		}
	default:
		return nil, fmt.Errorf("%w: unsupported message type %T", ErrFramePayload, message)
	}
	return nil, nil
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
