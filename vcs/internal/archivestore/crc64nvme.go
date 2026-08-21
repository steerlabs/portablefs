package archivestore

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"strings"
)

// CRC-64/NVME (also published as CRC-64/Rocksoft): polynomial
// 0xad93d23594c93659, reflected input and output, init and xorout all-ones.
// The reflected algorithm shifts right, so the table is built from the
// bit-reversed polynomial; the check value for "123456789" is
// 0xae8b14860a799888 and is pinned by a test.
const crc64NVMEPolynomial = 0xad93d23594c93659

// CRC64Size is the width of a CRC-64/NVME digest in bytes.
const CRC64Size = 8

var crc64Table = func() (table [256]uint64) {
	reversed := bits.Reverse64(crc64NVMEPolynomial)
	for index := range table {
		value := uint64(index)
		for bit := 0; bit < 8; bit++ {
			if value&1 != 0 {
				value = value>>1 ^ reversed
			} else {
				value >>= 1
			}
		}
		table[index] = value
	}
	return table
}()

// ChecksumCRC64NVME returns the CRC-64/NVME of one complete buffer.
func ChecksumCRC64NVME(data []byte) uint64 {
	return ^updateCRC64(^uint64(0), data)
}

func updateCRC64(crc uint64, data []byte) uint64 {
	for _, b := range data {
		crc = crc64Table[byte(crc)^b] ^ crc>>8
	}
	return crc
}

// NewCRC64NVME returns a streaming CRC-64/NVME hash. The archiver checksums
// multi-gibibyte packs it never holds in memory, so the streaming form is the
// primary interface and ChecksumCRC64NVME is the convenience wrapper.
func NewCRC64NVME() hash.Hash64 { return &crc64Digest{state: ^uint64(0)} }

type crc64Digest struct{ state uint64 }

func (d *crc64Digest) Write(data []byte) (int, error) {
	d.state = updateCRC64(d.state, data)
	return len(data), nil
}

func (d *crc64Digest) Sum64() uint64 { return ^d.state }

func (d *crc64Digest) Sum(prefix []byte) []byte {
	var digest [CRC64Size]byte
	binary.BigEndian.PutUint64(digest[:], d.Sum64())
	return append(prefix, digest[:]...)
}

func (d *crc64Digest) Reset()         { d.state = ^uint64(0) }
func (d *crc64Digest) Size() int      { return CRC64Size }
func (d *crc64Digest) BlockSize() int { return 1 }

// CRC64Hex renders a digest in the lowercase 16-character hex form used
// throughout the manager state, the signed plan, and this package's Go API.
func CRC64Hex(value uint64) string {
	var digest [CRC64Size]byte
	binary.BigEndian.PutUint64(digest[:], value)
	return hex.EncodeToString(digest[:])
}

// CRC64Base64 renders a digest in the standard-padded base64 form S3 carries in
// x-amz-checksum-crc64nvme. The eight digest bytes are big-endian.
func CRC64Base64(value uint64) string {
	var digest [CRC64Size]byte
	binary.BigEndian.PutUint64(digest[:], value)
	return base64.StdEncoding.EncodeToString(digest[:])
}

// ParseCRC64Hex accepts only the exact 16-character lowercase form; anything
// else is refused rather than normalized, so a malformed digest can never be
// silently compared as equal to a well-formed one.
func ParseCRC64Hex(value string) (uint64, error) {
	if len(value) != 2*CRC64Size || strings.ToLower(value) != value {
		return 0, fmt.Errorf("%w: crc64nvme hex digest must be 16 lowercase hex characters", ErrInvalid)
	}
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != CRC64Size {
		return 0, fmt.Errorf("%w: crc64nvme hex digest is not hexadecimal", ErrInvalid)
	}
	return binary.BigEndian.Uint64(digest), nil
}

// ParseCRC64Base64 accepts only standard-padded base64 decoding to exactly
// eight bytes. A composite ("-N" suffixed) multipart checksum therefore fails
// here rather than being truncated into a plausible full-object value.
func ParseCRC64Base64(value string) (uint64, error) {
	digest, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(digest) != CRC64Size {
		return 0, fmt.Errorf("%w: crc64nvme base64 digest must decode to 8 bytes", ErrInvalid)
	}
	if base64.StdEncoding.EncodeToString(digest) != value {
		return 0, fmt.Errorf("%w: crc64nvme base64 digest is not canonical", ErrInvalid)
	}
	return binary.BigEndian.Uint64(digest), nil
}

// CRC64HexToBase64 converts the Go API form to the wire form.
func CRC64HexToBase64(value string) (string, error) {
	digest, err := ParseCRC64Hex(value)
	if err != nil {
		return "", err
	}
	return CRC64Base64(digest), nil
}

// CRC64Base64ToHex converts the wire form to the Go API form.
func CRC64Base64ToHex(value string) (string, error) {
	digest, err := ParseCRC64Base64(value)
	if err != nil {
		return "", err
	}
	return CRC64Hex(digest), nil
}

var errCompositeChecksum = errors.New("archivestore: store returned a composite (multipart) checksum where a full-object checksum was required")
