// Package authorityrpc implements the bounded, multiplexed protobuf transport
// for the v3 authority protocol. TLS authentication is mandatory at the public
// Serve boundary; the framing helper is independently testable with net.Pipe.
package authorityrpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

var ErrFrameBounds = errors.New("authorityrpc: frame length is outside negotiated bounds")

func readFrame(r io.Reader, max uint32, message proto.Message) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > max {
		return fmt.Errorf("%w: %d (max %d)", ErrFrameBounds, size, max)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
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
