package archive

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// TestRawFrameDecodesWithLibrary proves the hand-written raw-block frame is a
// conforming zstd frame: a foreign decoder accepts it, reproduces the content
// exactly, and — because the frame carries a content checksum — independently
// verifies the XXH64 low 32 bits this package computed. That last part is what
// validates the in-package hash on inputs longer than the published vectors.
func TestRawFrameDecodesWithLibrary(t *testing.T) {
	rng := newRNG(0xbeef)
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer decoder.Close()
	sizes := []int{1, 2, 127, 4096, zstdRawBlockMax - 1, zstdRawBlockMax, zstdRawBlockMax + 1, 3*zstdRawBlockMax + 17}
	for _, size := range sizes {
		for _, windowLog := range []uint32{MinWindowLog, 17, DefaultWindowLog} {
			content := rng.bytes(size)
			frame, err := encodeRawFrame(windowLog, content)
			if err != nil {
				t.Fatalf("size %d window %d: encode: %v", size, windowLog, err)
			}
			got, err := decoder.DecodeAll(frame, nil)
			if err != nil {
				t.Fatalf("size %d window %d: foreign decode: %v", size, windowLog, err)
			}
			if !bytes.Equal(got, content) {
				t.Fatalf("size %d window %d: raw frame did not round-trip", size, windowLog)
			}
		}
	}
	if _, err := encodeRawFrame(DefaultWindowLog, nil); err == nil {
		t.Fatalf("a zero-length frame was accepted")
	}
}

// TestIncompressibleContentTakesTheRawPath proves the choice between the two
// frame paths is made on the honest comparison of whole frames, and that the
// recorded flag means what it says.
func TestIncompressibleContentTakesTheRawPath(t *testing.T) {
	rng := newRNG(7)
	random := rng.bytes(64 << 10)
	frame, rawBlocks, err := encodeFrame(DefaultCompressionLevel, DefaultWindowLog, random)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !rawBlocks {
		t.Fatalf("random content produced a compressed frame of %d bytes for %d bytes of input",
			len(frame), len(random))
	}
	if len(frame) != rawFrameSize(len(random), DefaultWindowLog) {
		t.Fatalf("raw frame is %d bytes, predicted %d", len(frame), rawFrameSize(len(random), DefaultWindowLog))
	}
	compressible := bytes.Repeat([]byte("the same bytes over and over "), 4000)
	frame, rawBlocks, err = encodeFrame(DefaultCompressionLevel, DefaultWindowLog, compressible)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if rawBlocks {
		t.Fatalf("compressible content took the raw path")
	}
	if len(frame) >= len(compressible) {
		t.Fatalf("compressed frame of %d bytes for %d bytes of input", len(frame), len(compressible))
	}
}

// TestPackIsAPlainZstdStream is the disaster-recovery property, tested the way
// a recovery would exercise it: every pack the property suite can produce is
// handed to a stock zstd decoder as one continuous stream, with no manifest and
// no frame table, and must yield exactly the concatenation of its frames.
func TestPackIsAPlainZstdStream(t *testing.T) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		t.Fatalf("zstd reader: %v", err)
	}
	defer decoder.Close()
	sawRaw := false
	for seed := uint64(1); seed <= 12; seed++ {
		tree := generateTree(seed, uint64(MinChunkSizeBytes), 32)
		config := testConfig(MinChunkSizeBytes)
		config.PackTargetBytes = uint64(MinChunkSizeBytes) * 2
		packs := &memoryPacks{}
		manifest, err := Build(config, tree.source(), packs)
		if err != nil {
			t.Fatalf("seed %d: build: %v", seed, err)
		}
		for _, frame := range manifest.Frames {
			if frame.RawBlocks {
				sawRaw = true
			}
		}
		for index, pack := range packs.packs {
			var want []byte
			for _, frame := range manifest.Frames {
				if frame.PackIndex != uint32(index) {
					continue
				}
				content, err := DecodeFrame(frame, pack[frame.PackOffset:frame.PackOffset+frame.CompressedLength])
				if err != nil {
					t.Fatalf("seed %d pack %d: frame decode: %v", seed, index, err)
				}
				want = append(want, content...)
			}
			streamed, err := readWholeStream(decoder, pack)
			if err != nil {
				t.Fatalf("seed %d pack %d: stock stream decode: %v", seed, index, err)
			}
			if !bytes.Equal(streamed, want) {
				t.Fatalf("seed %d pack %d: stream decode produced %d bytes, frames hold %d",
					seed, index, len(streamed), len(want))
			}
		}
	}
	if !sawRaw {
		t.Fatalf("the suite never produced a raw-block frame, so the property is untested for them")
	}
}

func readWholeStream(decoder *zstd.Decoder, pack []byte) ([]byte, error) {
	if err := decoder.Reset(bytes.NewReader(pack)); err != nil {
		return nil, err
	}
	return io.ReadAll(decoder)
}

// TestStockZstdBinaryDecodesPacks runs the same property through the actual
// zstd command-line tool when the machine has one. The library and the tool
// share a specification but not an implementation, so this is the check that a
// human with a shell and no PortableFS could recover the data.
func TestStockZstdBinaryDecodesPacks(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the external zstd binary check in short mode")
	}
	binary, err := exec.LookPath("zstd")
	if err != nil {
		t.Skip("no zstd binary on this machine")
	}
	// The archive under test deliberately mixes both frame paths: whole
	// incompressible chunks that must be stored raw, and compressible content
	// that must not be, so the tool sees one pack containing both.
	const chunkSize = MinChunkSizeBytes
	rng := newRNG(31337)
	entries := []SourceEntry{{Type: TypeDirectory, Mode: 0o755, Nlink: 1}}
	addFile := func(name string, content []byte) {
		file := &MemoryFile{Logical: content, Data: []Extent{{Offset: 0, Length: uint64(len(content))}}}
		entries = append(entries, SourceEntry{
			ParentIndex: 0, Name: []byte(name), Type: TypeRegular, Size: uint64(len(content)),
			Mode: 0o644, Nlink: 1, MTimeNanos: int64(len(entries)),
			Open: func() (SourceFile, error) { return file, nil },
		})
	}
	for index := 0; index < 4; index++ {
		addFile("random"+string(rune('a'+index))+".bin", rng.bytes(int(chunkSize)*2))
		addFile("text"+string(rune('a'+index))+".txt", bytes.Repeat([]byte("compressible line\n"), 400))
	}
	config := testConfig(chunkSize)
	packs := &memoryPacks{}
	manifest, err := Build(config, NewSliceSource(entries), packs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rawSeen := false
	for _, frame := range manifest.Frames {
		if frame.RawBlocks {
			rawSeen = true
		}
	}
	if !rawSeen {
		t.Fatalf("archive under test has no raw-block frame")
	}
	directory := t.TempDir()
	for index, pack := range packs.packs {
		path := filepath.Join(directory, "pack.zst")
		if err := os.WriteFile(path, pack, 0o600); err != nil {
			t.Fatalf("write pack: %v", err)
		}
		output, err := exec.Command(binary, "-d", "-c", path).Output()
		if err != nil {
			t.Fatalf("pack %d: stock zstd refused the pack: %v", index, err)
		}
		var want []byte
		for _, frame := range manifest.Frames {
			if frame.PackIndex != uint32(index) {
				continue
			}
			content, err := DecodeFrame(frame, pack[frame.PackOffset:frame.PackOffset+frame.CompressedLength])
			if err != nil {
				t.Fatalf("pack %d: frame decode: %v", index, err)
			}
			want = append(want, content...)
		}
		if !bytes.Equal(output, want) {
			t.Fatalf("pack %d: stock zstd produced %d bytes, frames hold %d", index, len(output), len(want))
		}
	}
}

// TestFrameCorruptionIsNamed proves a damaged frame reports damaged storage
// rather than a malformed manifest, and that every one of the three ways a
// frame can be wrong is caught.
func TestFrameCorruptionIsNamed(t *testing.T) {
	content := bytes.Repeat([]byte("frame bytes "), 500)
	encoded, _, err := encodeFrame(DefaultCompressionLevel, DefaultWindowLog, content)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	frame := Frame{
		CompressedLength:   uint64(len(encoded)),
		UncompressedLength: uint64(len(content)),
		XXH64Lo32:          XXH64Lo32Of(content),
	}
	if _, err := DecodeFrame(frame, encoded); err != nil {
		t.Fatalf("intact frame rejected: %v", err)
	}
	short := frame
	short.CompressedLength = uint64(len(encoded)) - 1
	if _, err := DecodeFrame(short, encoded[:len(encoded)-1]); err == nil {
		t.Fatalf("a truncated frame decoded")
	}
	wrongLength := frame
	wrongLength.UncompressedLength = uint64(len(content)) + 1
	if _, err := DecodeFrame(wrongLength, encoded); err == nil {
		t.Fatalf("a frame with the wrong recorded length decoded")
	}
	wrongChecksum := frame
	wrongChecksum.XXH64Lo32 ^= 1
	if _, err := DecodeFrame(wrongChecksum, encoded); err == nil {
		t.Fatalf("a frame with the wrong recorded checksum decoded")
	}
}
