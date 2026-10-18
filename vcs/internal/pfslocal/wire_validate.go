package pfslocal

import (
	"bytes"
	"fmt"
	"math"
	"reflect"
	"time"
	"unicode/utf8"
)

type localField struct {
	number   int
	name     string
	kind     byte
	repeated bool
	oneof    int
	message  string
	values   []int32
}

type localWireState struct{ fields int }

// Validate before the hand decoder allocates repeated entries or byte slices.
// The generated table owns grammar; the hand codec owns the concrete Go values.
func validateLocalWire(raw []byte) error {
	if len(raw) > MaxFrameBytes {
		return ErrFrameTooLarge
	}
	state := localWireState{}
	return validateLocalMessage(raw, ".pfslocal.v1.Envelope", 0, false, &state)
}

func validateLocalMessage(raw []byte, name string, depth int, listing bool, state *localWireState) error {
	if depth >= 16 {
		return fmt.Errorf("%w: nesting bound", ErrMalformed)
	}
	fields, ok := localSchema[name]
	if !ok || len(fields) > 64 {
		return ErrMalformed
	}
	var counts [64]int
	var oneofs [64]bool
	var scalars [64]uint64
	var data [64][]byte
	previous := 0
	if name == ".pfslocal.v1.EnumerateEntriesReply" {
		listing = true
	}
	for len(raw) > 0 {
		number, wt, rest, err := consumeTag(raw)
		if err != nil {
			return err
		}
		if number < previous {
			return fmt.Errorf("%w: field order", ErrMalformed)
		}
		previous = number
		index := -1
		for i, f := range fields {
			if f.number == number {
				index = i
				break
			}
		}
		if index < 0 {
			return fmt.Errorf("%w: unknown %s field %d", ErrMalformed, name, number)
		}
		f := fields[index]
		counts[index]++
		state.fields++
		if state.fields > 262144 || counts[index] > 4096 || (!f.repeated && counts[index] > 1) {
			return fmt.Errorf("%w: cardinality", ErrMalformed)
		}
		if f.oneof != 0 {
			if f.oneof >= len(oneofs) || oneofs[f.oneof] {
				return fmt.Errorf("%w: duplicate oneof", ErrMalformed)
			}
			oneofs[f.oneof] = true
		}
		if f.kind == 'm' || f.kind == 's' || f.kind == 'x' {
			if wt != wireBytes {
				return ErrMalformed
			}
			size, tail, err := consumeVarint(rest)
			if err != nil || size > uint64(len(tail)) {
				return ErrMalformed
			}
			value := tail[:int(size)]
			raw = tail[int(size):]
			data[index] = value
			if f.kind == 's' && !utf8.Valid(value) {
				return ErrMalformed
			}
			if f.kind == 'm' {
				if err := validateLocalMessage(value, f.message, depth+1, listing, state); err != nil {
					return err
				}
			}
		} else {
			if wt != wireVarint {
				return ErrMalformed
			}
			value, tail, err := consumeVarint(rest)
			if err != nil {
				return err
			}
			raw = tail
			scalars[index] = value
			switch f.kind {
			case 'u':
				if value > math.MaxUint32 {
					return ErrMalformed
				}
			case 'i':
				if uint64(int64(int32(value))) != value {
					return ErrMalformed
				}
			case 'b':
				if value > 1 {
					return ErrMalformed
				}
			case 'e':
				found := false
				for _, v := range f.values {
					if uint64(int64(v)) == value {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("%w: unknown enum", ErrMalformed)
				}
			}
		}
	}
	numberIndex := func(n int) int {
		for i, f := range fields {
			if f.number == n {
				return i
			}
		}
		panic("unknown validation field")
	}
	u := func(n int) uint64 { return scalars[numberIndex(n)] }
	b := func(n int) []byte { return data[numberIndex(n)] }
	has := func(n int) bool { return counts[numberIndex(n)] != 0 }
	nonzero := func(v []byte) bool { return len(v) == 16 && !bytes.Equal(v, make([]byte, 16)) }
	switch name {
	case ".pfslocal.v1.Envelope":
		if !oneofs[1] {
			return fmt.Errorf("%w: missing body", ErrMalformed)
		}
	case ".pfslocal.v1.Event":
		if !oneofs[1] {
			return fmt.Errorf("%w: missing event", ErrMalformed)
		}
	case ".pfslocal.v1.Hello", ".pfslocal.v1.HelloReply":
		if u(1) != ProtocolMajor || u(2) != ProtocolMinor {
			return fmt.Errorf("%w: unequal protocol version", ErrMalformed)
		}
		if name == ".pfslocal.v1.HelloReply" && u(4) == 0 {
			return fmt.Errorf("%w: missing request deadline", ErrMalformed)
		}
	case ".pfslocal.v1.ResolveReply":
		if !has(1) || !has(2) || !has(7) {
			return fmt.Errorf("%w: incomplete Resolve", ErrMalformed)
		}
	case ".pfslocal.v1.V3CoherenceContract":
		if !nonzero(b(2)) || !nonzero(b(3)) || string(b(4)) != CachePolicy || u(7) == 0 || u(7) > uint64(math.MaxInt64/int64(time.Millisecond)) {
			return fmt.Errorf("%w: invalid mount contract", ErrMalformed)
		}
	case ".pfslocal.v1.V3LivenessRequest", ".pfslocal.v1.V3LivenessReply":
		if !nonzero(b(1)) || !nonzero(b(2)) {
			return fmt.Errorf("%w: invalid mount incarnation", ErrMalformed)
		}
	case ".pfslocal.v1.Item":
		if listing {
			if has(1) || has(2) || has(3) {
				return fmt.Errorf("%w: owning listing item", ErrMalformed)
			}
		} else if u(1) == 0 || u(2) == 0 || !nonzero(b(3)) {
			return fmt.Errorf("%w: invalid owning item", ErrMalformed)
		}
	case ".pfslocal.v1.Attr":
		if listing && has(13) {
			return fmt.Errorf("%w: owning listing parent", ErrMalformed)
		}
	}
	return nil
}

func validateLocalEnvelope(e *Envelope) error {
	if e == nil || e.Body == nil {
		return ErrMalformed
	}
	value := reflect.ValueOf(e.Body)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return ErrMalformed
	}
	return nil
}
