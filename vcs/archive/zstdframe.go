package archive

import (
	"errors"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// A pack is a plain concatenation of valid zstd frames, with no exception and
// no container of its own, so stock `zstd -d` decodes every pack ever written.
// This file is the whole of that guarantee: one path compresses through the
// zstd library, the other writes a frame built from raw blocks by hand, and
// both produce frames a conforming decoder accepts.
//
// The raw path is written here rather than coaxed out of the library because
// the format needs the guarantee to be structural. A compressor asked to store
// incompressible data will usually emit raw blocks, but "usually" is not a
// disaster-recovery property, and the rawBlocks flag in the frame table must
// mean something exact. Writing the frame directly makes incompressible content
// a decision this package makes and records, not an emergent behavior of a
// dependency's heuristics.
const (
	zstdMagic       uint32 = 0xFD2FB528
	zstdRawBlockMax        = 128 << 10

	// frameHeaderDescriptor: frame content size in 8 bytes (flag 3, the two
	// high bits), not single-segment, content checksum present, no dictionary.
	// The eight-byte content size is used unconditionally rather than the
	// narrowest encoding that fits, because the chunk size is configurable and
	// one unambiguous header is worth eight bytes per frame.
	frameHeaderDescriptor byte = 0b1100_0100

	blockTypeRaw uint32 = 0
)

// ErrFrameCorrupt reports a frame whose bytes did not survive: a decoder
// rejection, a length that disagrees with the frame table, or a checksum
// mismatch. It is distinct from ErrInvalid because it names damaged storage,
// not a malformed manifest, and the hydrator maps it to RESTORE_CORRUPT.
var ErrFrameCorrupt = errors.New("archive: frame is corrupt")

// encodeCompressedFrame produces one zstd frame from content using the pinned
// deployment parameters. The window size is pinned from the manifest header so
// that every consumer, including a decoder with a bounded window, can size its
// buffers from the header alone.
func encodeCompressedFrame(level int32, windowLog uint32, content []byte) ([]byte, error) {
	encoder, err := frameEncoder(level, windowLog)
	if err != nil {
		return nil, err
	}
	return encoder.EncodeAll(content, nil), nil
}

// encodeRawFrame writes a zstd frame whose every block is a Raw_Block: the
// header, a window descriptor carrying the pinned window log, the exact content
// size, the content split into maximum-size raw blocks, and the four-byte
// content checksum, which is the low 32 bits of XXH64 over the content and
// therefore the same value the frame table records.
func encodeRawFrame(windowLog uint32, content []byte) ([]byte, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("%w: a frame never holds zero bytes", ErrInvalid)
	}
	if windowLog < MinWindowLog || windowLog > MaxWindowLog {
		return nil, fmt.Errorf("%w: window log %d is out of range", ErrInvalid, windowLog)
	}
	blockMax := rawBlockSize(windowLog)
	out := make([]byte, 0, rawFrameSize(len(content), windowLog))
	out = appendLE32(out, zstdMagic)
	out = append(out, frameHeaderDescriptor)
	out = append(out, byte((windowLog-10)<<3))
	out = appendLE64(out, uint64(len(content)))
	for offset := 0; offset < len(content); offset += blockMax {
		end := offset + blockMax
		last := uint32(0)
		if end >= len(content) {
			end = len(content)
			last = 1
		}
		header := uint32(end-offset)<<3 | blockTypeRaw<<1 | last
		out = append(out, byte(header), byte(header>>8), byte(header>>16))
		out = append(out, content[offset:end]...)
	}
	return appendLE32(out, XXH64Lo32Of(content)), nil
}

// XXH64Lo32Of is the frame checksum of one decompressed frame.
func XXH64Lo32Of(content []byte) uint32 { return uint32(XXH64Sum(content)) }

// rawFrameSize is the exact size encodeRawFrame produces, used to size its
// buffer in one allocation and to let a caller reason about the choice without
// making it.
func rawFrameSize(contentLength int, windowLog uint32) int {
	blocks := (contentLength + rawBlockSize(windowLog) - 1) / rawBlockSize(windowLog)
	return 4 + 1 + 1 + 8 + 3*blocks + contentLength + 4
}

// rawBlockSize is the largest block a frame with this window may carry:
// min(windowSize, 128 KiB), which is 128 KiB for every window the format
// permits above 17.
func rawBlockSize(windowLog uint32) int {
	if window := 1 << windowLog; window < zstdRawBlockMax {
		return window
	}
	return zstdRawBlockMax
}

// encodeFrame chooses between the two paths and reports which was taken.
//
// Content is incompressible when compressing it produces a payload no smaller
// than the content itself — that is the whole of the test, and it is made on
// the payload rather than on whole frames because the two paths' frame headers
// differ by a handful of bytes and a decision that turned on header trivia
// would make the recorded flag meaningless. Incompressible content is then
// rebuilt from raw blocks so that the flag says something true and useful: this
// frame decompresses by memcpy. Content that compresses at all keeps the
// compressed frame, which the library may itself have built partly from raw
// blocks; the flag is a hint about the whole frame, not a claim about every
// block in it.
func encodeFrame(level int32, windowLog uint32, content []byte) (encoded []byte, rawBlocks bool, err error) {
	compressed, err := encodeCompressedFrame(level, windowLog, content)
	if err != nil {
		return nil, false, err
	}
	if len(compressed) < len(content) {
		return compressed, false, nil
	}
	raw, err := encodeRawFrame(windowLog, content)
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

// DecodeFrame decompresses one frame's compressed bytes and verifies the frame
// against what the manifest says it is: the decompressed length and the frame
// checksum must both match. A frame that decodes to the wrong size or the wrong
// checksum is corrupt storage, and saying so here means no caller ever hands a
// wrong byte to a slice-digest check and gets a confusing answer.
func DecodeFrame(frame Frame, compressed []byte) ([]byte, error) {
	if uint64(len(compressed)) != frame.CompressedLength {
		return nil, fmt.Errorf("%w: frame is %d bytes, the manifest records %d",
			ErrFrameCorrupt, len(compressed), frame.CompressedLength)
	}
	if frame.UncompressedLength > uint64(MaxChunkSizeBytes) {
		return nil, fmt.Errorf("%w: frame declares %d decompressed bytes", ErrInvalid, frame.UncompressedLength)
	}
	decoder, err := sharedDecoder()
	if err != nil {
		return nil, err
	}
	content, err := decoder.DecodeAll(compressed, make([]byte, 0, frame.UncompressedLength))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrFrameCorrupt, err.Error())
	}
	if uint64(len(content)) != frame.UncompressedLength {
		return nil, fmt.Errorf("%w: frame decoded to %d bytes, the manifest records %d",
			ErrFrameCorrupt, len(content), frame.UncompressedLength)
	}
	if XXH64Lo32Of(content) != frame.XXH64Lo32 {
		return nil, fmt.Errorf("%w: frame checksum does not match the manifest", ErrFrameCorrupt)
	}
	return content, nil
}

// The encoder and decoder are shared because both are goroutine-safe for the
// one-shot EncodeAll/DecodeAll calls this package makes, and because building a
// zstd encoder allocates its whole window. Encoders are keyed by the parameters
// the manifest pins, so an archive written with one configuration never borrows
// an encoder built for another.
type encoderKey struct {
	level     int32
	windowLog uint32
}

var (
	encoderMu    sync.Mutex
	encoderCache = map[encoderKey]*zstd.Encoder{}

	decoderOnce sync.Once
	decoder     *zstd.Decoder
	decoderErr  error
)

func frameEncoder(level int32, windowLog uint32) (*zstd.Encoder, error) {
	if level < MinCompressionLevel || level > MaxCompressionLevel {
		return nil, fmt.Errorf("%w: compression level %d is out of range", ErrInvalid, level)
	}
	if windowLog < MinWindowLog || windowLog > MaxWindowLog {
		return nil, fmt.Errorf("%w: window log %d is out of range", ErrInvalid, windowLog)
	}
	key := encoderKey{level: level, windowLog: windowLog}
	encoderMu.Lock()
	defer encoderMu.Unlock()
	if existing, ok := encoderCache[key]; ok {
		return existing, nil
	}
	encoder, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(int(level))),
		zstd.WithWindowSize(1<<windowLog),
		zstd.WithEncoderCRC(true),
		zstd.WithZeroFrames(false),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		return nil, fmt.Errorf("archive: build zstd encoder: %w", err)
	}
	encoderCache[key] = encoder
	return encoder, nil
}

func sharedDecoder() (*zstd.Decoder, error) {
	decoderOnce.Do(func() {
		decoder, decoderErr = zstd.NewReader(nil,
			zstd.WithDecoderMaxMemory(uint64(MaxChunkSizeBytes)),
			zstd.WithDecoderConcurrency(1),
		)
		if decoderErr != nil {
			decoderErr = fmt.Errorf("archive: build zstd decoder: %w", decoderErr)
		}
	})
	return decoder, decoderErr
}

func appendLE32(out []byte, value uint32) []byte {
	return append(out, byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

func appendLE64(out []byte, value uint64) []byte {
	return append(out, byte(value), byte(value>>8), byte(value>>16), byte(value>>24),
		byte(value>>32), byte(value>>40), byte(value>>48), byte(value>>56))
}
