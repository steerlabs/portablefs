package archive

import (
	"strings"
	"testing"
)

// TestXXH64Vectors pins the in-package hash against the published XXH64 check
// values. The implementation exists so the module does not take a dependency
// for a hundred lines of arithmetic; these vectors are what make that trade
// safe, and the zstd round-trip tests independently confirm the low 32 bits by
// letting a foreign decoder verify frames this package checksummed.
func TestXXH64Vectors(t *testing.T) {
	cases := []struct {
		input string
		want  uint64
	}{
		{"", 0xEF46DB3751D8E999},
		{"a", 0xD24EC4F1A98C6E5B},
		{"abc", 0x44BC2CF5AD770999},
	}
	for _, testCase := range cases {
		if got := XXH64Sum([]byte(testCase.input)); got != testCase.want {
			t.Fatalf("XXH64(%q) = %#016x, want %#016x", testCase.input, got, testCase.want)
		}
	}
}

// TestXXH64StreamingMatchesOneShot proves the streaming state is correct at
// every write boundary, including boundaries that split the 32-byte stripe and
// the tail. Frames are hashed as they are assembled, so a boundary bug would
// only appear on frames written in a particular sequence of pieces.
func TestXXH64StreamingMatchesOneShot(t *testing.T) {
	rng := newRNG(0x5eed)
	data := rng.bytes(4096)
	for _, split := range []int{1, 2, 3, 7, 8, 15, 16, 31, 32, 33, 63, 64, 100, 1000, 4095} {
		hash := newXXH64()
		for offset := 0; offset < len(data); offset += split {
			end := offset + split
			if end > len(data) {
				end = len(data)
			}
			if _, err := hash.Write(data[offset:end]); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if got, want := hash.Sum64(), XXH64Sum(data); got != want {
			t.Fatalf("split %d: streaming %#016x, one-shot %#016x", split, got, want)
		}
	}
	for length := 0; length <= 64; length++ {
		hash := newXXH64()
		if _, err := hash.Write(data[:length]); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := hash.Sum64(), XXH64Sum(data[:length]); got != want {
			t.Fatalf("length %d: streaming %#016x, one-shot %#016x", length, got, want)
		}
	}
}

// TestCRC64NVMEVector pins the pack object checksum against the CRC catalogue's
// check value. It is the number declared at CreateMultipartUpload and compared
// against HeadObject, so a wrong polynomial would only be discovered by an
// object store rejecting an upload.
func TestCRC64NVMEVector(t *testing.T) {
	if got, want := CRC64NVMESum([]byte("123456789")), uint64(0xAE8B14860A799888); got != want {
		t.Fatalf("CRC64NVME(123456789) = %#016x, want %#016x", got, want)
	}
	if got := CRC64NVMESum(nil); got != 0 {
		t.Fatalf("CRC64NVME of no bytes = %#016x, want 0", got)
	}
}

// TestCRC64NVMEStreamingMatchesOneShot proves the running checksum a pack
// writer keeps equals the checksum of the finished object, so a pack is never
// read back to compute it.
func TestCRC64NVMEStreamingMatchesOneShot(t *testing.T) {
	data := []byte(strings.Repeat("pack bytes ", 997))
	for _, split := range []int{1, 7, 64, 1024, 4096} {
		var running crc64NVME
		for offset := 0; offset < len(data); offset += split {
			end := offset + split
			if end > len(data) {
				end = len(data)
			}
			if _, err := running.Write(data[offset:end]); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if got, want := running.Sum64(), CRC64NVMESum(data); got != want {
			t.Fatalf("split %d: streaming %#016x, one-shot %#016x", split, got, want)
		}
	}
}
