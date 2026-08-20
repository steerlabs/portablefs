package archivestore

import (
	"bytes"
	"errors"
	"math/bits"
	"math/rand/v2"
	"strings"
	"testing"
)

// referenceCRC64NVME is a deliberately different formulation of the same CRC:
// bit-by-bit, MSB-first, with input and output reflection applied explicitly
// rather than folded into a precomputed reflected table. It shares no code with
// crc64nvme.go beyond the polynomial constant.
func referenceCRC64NVME(data []byte) uint64 {
	register := ^uint64(0)
	for _, b := range data {
		register ^= uint64(bits.Reverse8(b)) << 56
		for i := 0; i < 8; i++ {
			if register&(1<<63) != 0 {
				register = register<<1 ^ crc64NVMEPolynomial
			} else {
				register <<= 1
			}
		}
	}
	return bits.Reverse64(register) ^ ^uint64(0)
}

func TestCRC64NVMEVectors(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		want  uint64
	}{
		// The published CRC-64/NVME check value.
		{"catalogue check string", []byte("123456789"), 0xae8b14860a799888},
		{"empty", nil, 0x0000000000000000},
		{"single zero byte", []byte{0x00}, referenceCRC64NVME([]byte{0x00})},
		{"single 0xff byte", []byte{0xff}, referenceCRC64NVME([]byte{0xff})},
		{"one chunk of zeros", bytes.Repeat([]byte{0}, 8<<10), referenceCRC64NVME(bytes.Repeat([]byte{0}, 8<<10))},
		{"ascii", []byte("portablefs tiered storage"), referenceCRC64NVME([]byte("portablefs tiered storage"))},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ChecksumCRC64NVME(testCase.input); got != testCase.want {
				t.Fatalf("ChecksumCRC64NVME = %#016x, want %#016x", got, testCase.want)
			}
			if got := referenceCRC64NVME(testCase.input); got != testCase.want {
				t.Fatalf("referenceCRC64NVME = %#016x, want %#016x", got, testCase.want)
			}
		})
	}
}

func TestCRC64NVMEStreamingMatchesWholeBuffer(t *testing.T) {
	source := rand.New(rand.NewPCG(0x5eed, 0x1234))
	payload := make([]byte, 1<<16)
	for i := range payload {
		payload[i] = byte(source.UintN(256))
	}
	whole := ChecksumCRC64NVME(payload)
	if reference := referenceCRC64NVME(payload); whole != reference {
		t.Fatalf("table implementation disagrees with the bitwise reference: %#016x vs %#016x", whole, reference)
	}
	digest := NewCRC64NVME()
	offset := 0
	for offset < len(payload) {
		step := 1 + int(source.UintN(4096))
		if offset+step > len(payload) {
			step = len(payload) - offset
		}
		if _, err := digest.Write(payload[offset : offset+step]); err != nil {
			t.Fatalf("write: %v", err)
		}
		offset += step
	}
	if got := digest.Sum64(); got != whole {
		t.Fatalf("streaming digest = %#016x, want %#016x", got, whole)
	}
	if got := digest.Sum(nil); len(got) != CRC64Size {
		t.Fatalf("Sum returned %d bytes, want %d", len(got), CRC64Size)
	}
	if got, want := digest.Sum(nil), []byte{byte(whole >> 56), byte(whole >> 48), byte(whole >> 40), byte(whole >> 32),
		byte(whole >> 24), byte(whole >> 16), byte(whole >> 8), byte(whole)}; !bytes.Equal(got, want) {
		t.Fatalf("Sum = %x, want big-endian %x", got, want)
	}
	digest.Reset()
	if got := digest.Sum64(); got != 0 {
		t.Fatalf("reset digest = %#016x, want 0", got)
	}
	if digest.Size() != CRC64Size || digest.BlockSize() != 1 {
		t.Fatalf("unexpected hash geometry")
	}
}

func TestCRC64EncodingRoundTrips(t *testing.T) {
	values := []uint64{0, 1, 0xae8b14860a799888, ^uint64(0), 0x00000000000000ff}
	for _, value := range values {
		hexForm := CRC64Hex(value)
		base64Form := CRC64Base64(value)
		if len(hexForm) != 16 || strings.ToLower(hexForm) != hexForm {
			t.Fatalf("CRC64Hex(%#x) = %q", value, hexForm)
		}
		if base64Form != base64Padded(value) {
			t.Fatalf("CRC64Base64(%#x) = %q, want %q", value, base64Form, base64Padded(value))
		}
		if got, err := ParseCRC64Hex(hexForm); err != nil || got != value {
			t.Fatalf("ParseCRC64Hex(%q) = %#x, %v", hexForm, got, err)
		}
		if got, err := ParseCRC64Base64(base64Form); err != nil || got != value {
			t.Fatalf("ParseCRC64Base64(%q) = %#x, %v", base64Form, got, err)
		}
		converted, err := CRC64HexToBase64(hexForm)
		if err != nil || converted != base64Form {
			t.Fatalf("CRC64HexToBase64(%q) = %q, %v", hexForm, converted, err)
		}
		back, err := CRC64Base64ToHex(base64Form)
		if err != nil || back != hexForm {
			t.Fatalf("CRC64Base64ToHex(%q) = %q, %v", base64Form, back, err)
		}
	}
}

func TestCRC64ParsingIsStrict(t *testing.T) {
	badHex := []string{"", "AE8B14860A799888", "ae8b14860a79988", "ae8b14860a7998888", "zzzzzzzzzzzzzzzz"}
	for _, value := range badHex {
		if _, err := ParseCRC64Hex(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ParseCRC64Hex(%q) accepted a malformed digest", value)
		}
	}
	badBase64 := []string{
		"",
		"rosUhgp5mIg",      // unpadded
		"rosUhgp5mIg=x",    // trailing junk
		"AAAAAAAAAAAAAA==", // decodes to more than eight bytes
		"rosUhgp5mIg=-5",   // composite multipart form
	}
	for _, value := range badBase64 {
		if _, err := ParseCRC64Base64(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ParseCRC64Base64(%q) accepted a malformed digest", value)
		}
	}
}
