// Command zratio measures how compressible a real agent workload is, at the
// granularity the write-back flusher would actually compress at.
//
// This matters because the flusher ships batches of WAL records
// (writeback/flush.go: flushMaxRecords=128, flushMaxBytes=8MiB). Compressing
// each record on its own gives a much worse ratio than compressing the whole
// batch as one stream, because a 4 KiB record has almost no window to work
// with. Both numbers are reported so the roadmap can price the two designs.
//
// It also reports content-defined chunk dedup potential over the same corpus,
// so compression and dedup can be ranked against each other on one input.
//
//	go run ./bench/cmd/zratio -root /path/to/repo -levels 1,3,9
//
// Read-only: it never writes to -root.
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const maxCorpusBytes = 64 << 20

func main() {
	root := flag.String("root", ".", "directory to sample as the workload corpus")
	levels := flag.String("levels", "1,3,9", "zstd levels to try")
	recordSize := flag.Int("record", 4096, "per-record compression granularity in bytes")
	batchSize := flag.Int("batch", 8<<20, "per-batch compression granularity in bytes")
	chunkAvg := flag.Int("chunk", 8192, "average content-defined chunk size for the dedup estimate")
	skip := flag.String("skip", "node_modules,.git,vendor,dist,build,target,.next", "comma-separated dir names to skip")
	flag.Parse()

	skips := map[string]bool{}
	for _, s := range strings.Split(*skip, ",") {
		if s = strings.TrimSpace(s); s != "" {
			skips[s] = true
		}
	}

	corpus, files, err := collect(*root, skips)
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("corpus root=%s files=%d bytes=%d (%.1f MiB)\n\n",
		*root, files, len(corpus), float64(len(corpus))/(1<<20))

	fmt.Printf("%-8s %-14s %12s %12s %8s %10s\n", "level", "granularity", "raw", "compressed", "ratio", "saved")
	for _, ls := range strings.Split(*levels, ",") {
		lvl, err := strconv.Atoi(strings.TrimSpace(ls))
		if err != nil {
			continue
		}
		for _, g := range []struct {
			name string
			size int
		}{
			{"per-record", *recordSize},
			{"per-batch", *batchSize},
			{"whole-corpus", len(corpus)},
		} {
			out, err := compressChunked(corpus, g.size, lvl)
			if err != nil {
				fmt.Fprintf(os.Stderr, "zstd -%d: %v\n", lvl, err)
				continue
			}
			ratio := float64(len(corpus)) / float64(out)
			fmt.Printf("zstd-%-3d %-14s %12d %12d %7.2fx %9.1f%%\n",
				lvl, fmt.Sprintf("%s(%s)", g.name, human(g.size)), len(corpus), out,
				ratio, 100*(1-float64(out)/float64(len(corpus))))
		}
	}

	fmt.Println()
	dedupReport(corpus, *chunkAvg)
}

func human(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// collect reads a deterministic (sorted) slice of the tree as one byte stream,
// which is what the flusher would see as a stream of write payloads.
func collect(root string, skips map[string]bool) ([]byte, int, error) {
	var paths []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // unreadable subtrees are simply not sampled
		}
		if d.IsDir() {
			if skips[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	n := 0
	for _, p := range paths {
		if buf.Len() >= maxCorpusBytes {
			break
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		buf.Write(b)
		n++
	}
	return buf.Bytes(), n, nil
}

// compressChunked compresses the corpus in independent windows of the given
// size and sums the outputs — exactly what a per-record or per-batch
// compression design would produce on the wire.
func compressChunked(data []byte, window, level int) (int, error) {
	if window <= 0 || window > len(data) {
		window = len(data)
	}
	total := 0
	for off := 0; off < len(data); off += window {
		end := min(off+window, len(data))
		n, err := zstdSize(data[off:end], level)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

func zstdSize(data []byte, level int) (int, error) {
	cmd := exec.Command("zstd", "-"+strconv.Itoa(level), "-c", "-q")
	cmd.Stdin = bytes.NewReader(data)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return 0, err
	}
	return out.Len(), nil
}

// dedupReport estimates content-defined-chunking dedup over the same corpus:
// what fraction of chunks are byte-identical duplicates. This is the ceiling
// for a dedup design, independent of compression.
func dedupReport(data []byte, avg int) {
	bounds := cdcBoundaries(data, avg)
	seen := map[[32]byte]int{}
	var uniqueBytes, dupBytes int
	prev := 0
	for _, b := range bounds {
		chunk := data[prev:b]
		h := sha256.Sum256(chunk)
		if seen[h] == 0 {
			uniqueBytes += len(chunk)
		} else {
			dupBytes += len(chunk)
		}
		seen[h]++
		prev = b
	}
	total := uniqueBytes + dupBytes
	if total == 0 {
		return
	}
	fmt.Printf("content-defined dedup (avg chunk %s): chunks=%d unique=%d dup-bytes=%.1f%% dedup-ratio=%.2fx\n",
		human(avg), len(bounds), len(seen), 100*float64(dupBytes)/float64(total),
		float64(total)/float64(max(uniqueBytes, 1)))
}

// cdcBoundaries is a gear-style content-defined chunker: a rolling hash over a
// 64-entry random table, cutting where the low bits are zero. Boundaries are
// shift-resistant, which is the whole point of CDC over fixed blocks.
func cdcBoundaries(data []byte, avg int) []int {
	var gear [256]uint64
	s := uint64(0x2545F4914F6CDD1D)
	for i := range gear {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		gear[i] = s
	}
	mask := uint64(1)<<uint(bits(avg)) - 1
	minSz, maxSz := avg/4, avg*4
	var out []int
	h := uint64(0)
	last := 0
	for i := 0; i < len(data); i++ {
		h = (h << 1) + gear[data[i]]
		sz := i - last + 1
		if sz < minSz {
			continue
		}
		if (h&mask) == 0 || sz >= maxSz {
			out = append(out, i+1)
			last = i + 1
			h = 0
		}
	}
	if last < len(data) {
		out = append(out, len(data))
	}
	return out
}

func bits(n int) int {
	b := 0
	for n > 1 {
		n >>= 1
		b++
	}
	return b
}
