package restoremode

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type hydratorClient struct {
	path     string
	maxFrame uint32
	limit    int

	mu     sync.Mutex
	opened int
	idle   chan net.Conn
	closed bool
}

func newHydratorClient(path string, limit int, maxFrame uint32) *hydratorClient {
	return &hydratorClient{path: path, limit: limit, maxFrame: maxFrame, idle: make(chan net.Conn, limit)}
}

func (c *hydratorClient) acquire(ctx context.Context) (net.Conn, error) {
	select {
	case conn := <-c.idle:
		if conn != nil {
			return conn, nil
		}
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		return c.acquire(ctx)
	default:
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	if c.opened < c.limit {
		c.opened++
		c.mu.Unlock()
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "unix", c.path)
		if err != nil {
			c.mu.Lock()
			c.opened--
			c.mu.Unlock()
			return nil, err
		}
		return conn, nil
	}
	c.mu.Unlock()
	select {
	case conn := <-c.idle:
		if conn == nil {
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return nil, net.ErrClosed
			}
			return c.acquire(ctx)
		}
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *hydratorClient) release(conn net.Conn, healthy bool) {
	if conn == nil {
		return
	}
	if !healthy {
		_ = conn.Close()
		c.mu.Lock()
		c.opened--
		if !c.closed {
			select {
			case c.idle <- nil:
			default:
			}
		}
		c.mu.Unlock()
		return
	}
	_ = conn.SetDeadline(time.Time{})
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return
	}
	select {
	case c.idle <- conn:
		c.mu.Unlock()
	default:
		_ = conn.Close()
		c.opened--
		c.mu.Unlock()
	}
}

func (c *hydratorClient) roundTrip(ctx context.Context, typ byte, payload []byte) (byte, []byte, error) {
	conn, err := c.acquire(ctx)
	if err != nil {
		return 0, nil, hydratorTransportError(ctx, err)
	}
	healthy := false
	defer func() { c.release(conn, healthy) }()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()
	deadline, ok := ctx.Deadline()
	if ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return 0, nil, hydratorTransportError(ctx, err)
		}
	}
	if err := writeHydratorFrame(conn, c.maxFrame, typ, payload); err != nil {
		if errors.Is(err, ErrProtocol) {
			return 0, nil, err
		}
		return 0, nil, hydratorTransportError(ctx, err)
	}
	replyType, reply, err := readHydratorFrame(conn, c.maxFrame)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, hydratorTransportError(ctx, err)
	}
	healthy = true
	if replyType == FrameError {
		return replyType, nil, parseProtocolError(reply)
	}
	return replyType, reply, nil
}

// Socket failures describe archive availability, not the health of XFS. Strip
// any transport errno from the unwrap chain so an AF_UNIX EIO can never enter
// the authority's fatal-storage classifier. Every shape of transport timeout
// — the ctx deadline, an os.ErrDeadlineExceeded read, or any net.Error that
// reports Timeout — normalizes to the deadline, so the caller's recall
// classification never depends on which timer happened to fire first.
func hydratorTransportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var netErr net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return context.DeadlineExceeded
	}
	return &stateError{base: ErrBlocked, detail: err.Error()}
}

func (c *hydratorClient) info(ctx context.Context, maxDrainPairs uint64) (InfoPage, error) {
	typ, raw, err := c.roundTrip(ctx, FrameInfo, nil)
	if err != nil {
		return InfoPage{}, err
	}
	if typ != FrameInfoOK {
		return InfoPage{}, ErrProtocol
	}
	first, err := UnmarshalInfoPage(raw)
	if err != nil {
		return InfoPage{}, err
	}
	if first.PageSize != 8192 || first.DrainCount > maxDrainPairs || first.DrainCount > uint64(^uint(0)>>1) {
		return InfoPage{}, ErrProtocol
	}
	result := first
	result.Order = make([][2]uint32, 0, int(first.DrainCount))
	next := uint64(0)
	for pages := 0; next < first.DrainCount; pages++ {
		if pages > 1<<20 {
			return InfoPage{}, errors.New("restoremode: INFO page bound exceeded")
		}
		payload := appendU64(nil, next)
		typ, raw, err = c.roundTrip(ctx, FrameInfoNext, payload)
		if err != nil {
			return InfoPage{}, err
		}
		if typ != FrameDrainPage {
			return InfoPage{}, ErrProtocol
		}
		page, err := unmarshalDrainPage(raw)
		if err != nil || page.Cursor != next || len(page.Order) == 0 || len(page.Order) > int(first.PageSize) {
			return InfoPage{}, ErrProtocol
		}
		result.Order = append(result.Order, page.Order...)
		next += uint64(len(page.Order))
		if next > first.DrainCount || page.More != (next < first.DrainCount) {
			return InfoPage{}, ErrProtocol
		}
	}
	if uint64(len(result.Order)) != first.DrainCount {
		return InfoPage{}, ErrProtocol
	}
	return result, nil
}

func (c *hydratorClient) fetch(ctx context.Context, key chunkKey, chunkSize uint32) (Chunk, error) {
	payload := appendU32(nil, key.entry)
	payload = appendU32(payload, key.chunk)
	typ, raw, err := c.roundTrip(ctx, FrameFetch, payload)
	if err != nil {
		return Chunk{}, err
	}
	if typ != FrameChunk {
		return Chunk{}, ErrProtocol
	}
	return UnmarshalChunk(raw, chunkSize)
}

func (c *hydratorClient) health(ctx context.Context) error {
	typ, raw, err := c.roundTrip(ctx, FrameHealth, nil)
	if err != nil {
		return err
	}
	if typ != FrameHealthOK || len(raw) != 0 {
		return ErrProtocol
	}
	return nil
}

func (c *hydratorClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.idle)
	c.mu.Unlock()
	var result error
	for conn := range c.idle {
		if conn != nil {
			result = errors.Join(result, conn.Close())
		}
	}
	return result
}

func writeHydratorFrame(w io.Writer, max uint32, typ byte, payload []byte) error {
	length := uint64(len(payload)) + 1
	if length == 0 || length > uint64(max) {
		return ErrProtocol
	}
	var header [5]byte
	binary.LittleEndian.PutUint32(header[:4], uint32(length))
	header[4] = typ
	if err := writeFull(w, header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func writeFull(w io.Writer, raw []byte) error {
	for len(raw) != 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

func readHydratorFrame(r io.Reader, max uint32) (byte, []byte, error) {
	var rawLength [4]byte
	if _, err := io.ReadFull(r, rawLength[:]); err != nil {
		return 0, nil, err
	}
	length := binary.LittleEndian.Uint32(rawLength[:])
	if length == 0 || length > max {
		return 0, nil, fmt.Errorf("%w: frame length %d", ErrProtocol, length)
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(r, raw); err != nil {
		return 0, nil, err
	}
	return raw[0], raw[1:], nil
}
