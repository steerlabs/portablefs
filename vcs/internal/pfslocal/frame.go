package pfslocal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrFrameTooLarge = errors.New("pfslocal: frame too large")

func ReadFrame(r io.Reader) (*Envelope, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return UnmarshalEnvelope(buf)
}

func WriteFrame(w io.Writer, e *Envelope) error {
	payload, err := MarshalEnvelope(e)
	if err != nil {
		return err
	}
	if len(payload) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	n, err := w.Write(payload)
	if err != nil {
		return err
	}
	if n != len(payload) {
		return fmt.Errorf("pfslocal: short frame write")
	}
	return nil
}

func EncodeFrame(e *Envelope) ([]byte, error) {
	payload, err := MarshalEnvelope(e)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxFrameBytes {
		return nil, ErrFrameTooLarge
	}
	out := make([]byte, 4, 4+len(payload))
	binary.LittleEndian.PutUint32(out, uint32(len(payload)))
	out = append(out, payload...)
	return out, nil
}
