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

// readFrame decodes one framed protobuf message. A frame has two lengths:
// protobuf metadata followed by an optional out-of-line bulk body. Only
// WriteTransactionRequest.Data and ReadReply.Data are the only legal bulk
// bodies. Keeping the payload
// body outside protobuf removes the full-size marshal and unmarshal copies from
// the data path without creating a second protocol or weakening replay: the
// reconstructed Request is exactly what the authority's canonical replay
// fingerprint authenticates.
//
// budget may be nil on a peer whose concurrent frame count is already bounded
// by its own in-flight admission (a client owns exactly one connection). A
// server uses readFrameRetained so its reservation covers the lifetime of the
// zero-copy bulk slice through handler execution.
func readFrame(r io.Reader, max uint32, budget *frameBudget, wait time.Duration, message proto.Message) error {
	release, err := readFrameRetained(r, max, budget, wait, message)
	if release != nil {
		release()
	}
	return err
}

func readFrameRetained(r io.Reader, max uint32, budget *frameBudget, wait time.Duration, message proto.Message) (func(), error) {
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
	released := false
	release := func() {
		if budget != nil && !released {
			released = true
			budget.release(uint32(total))
		}
	}
	fail := func(err error) (func(), error) {
		release()
		return nil, err
	}
	payload := make([]byte, int(total))
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
	}
	return release, nil
}

func writeFrame(w io.Writer, max uint32, message proto.Message) error {
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
		if appendRequest := typed.GetWriteTransaction(); appendRequest != nil {
			return &appendRequest.Data, nil
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
