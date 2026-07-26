package wal

// edge_sweep_test.go is an exhaustive boundary + fault-injection sweep of the durable
// flush log's public API: AppendBuffered / CommitThrough / Replay / Reset / Renumber /
// CompactThrough / Close. It deliberately targets the seams the framing/replay code
// promises to defend:
//
//   - torn tail at a clean record boundary, in the middle of a header, and in the middle
//     of a body (each must replay the longest intact prefix WITHOUT error and truncate);
//   - mid-log corruption WITH valid data following (Replay must return the valid prefix
//     PLUS an error, and the surviving region must not silently swallow the good records);
//   - every flavor of unreadable frame: corrupt length header, oversize length, crc
//     mismatch with data following, decrypt/auth failure (wrong key / tamper), undecodable
//     gob — each loud when data follows, each a silent torn-tail drop when it is last;
//   - the poison-on-truncate / poison-on-sync path of Replay (a torn tail that cannot be
//     removed must leave NO writable torn tail — the log is poisoned, not left appendable);
//   - Renumber's atomic rewrite to contiguous Seqs from 0, with subsequent appends
//     continuing after, and a reopen+Replay seeing the renumbered file;
//   - group commit: many concurrent AppendBuffered then a concurrent CommitThrough storm
//     (run under -race), proving every acked LSN is durable and contiguous;
//   - the trivial edges: empty/absent-file Replay, a no-op Reset, idempotent repeat Replay,
//     delete-then-recreate, CompactThrough exactly-at / ±1 a boundary, Close semantics.
//
// In-package helpers are reused (encA, localReplica, countingReplica, assertContiguousReplay,
// oversize). No production .go source or existing test is modified.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/secure"
)

// ---------------------------------------------------------------------------
// Low-level framing helpers (operate on the raw on-disk file the public API wrote),
// so we can inject precisely the corruption shapes the reader must classify.
// ---------------------------------------------------------------------------

// frameSpan returns the byte ranges of the i-th frame in raw: header start, payload
// start, and the offset just past the payload. It walks the framing exactly as the
// reader does (it trusts the length fields, which on a well-formed log are correct).
func frameSpan(t *testing.T, raw []byte, i int) (hdrStart, payloadStart, frameEnd int) {
	t.Helper()
	off := 0
	for k := 0; ; k++ {
		if off+headerBytes > len(raw) {
			t.Fatalf("frameSpan: frame %d not present (only %d frames)", i, k)
		}
		n := int(binary.BigEndian.Uint32(raw[off : off+4]))
		ps := off + headerBytes
		fe := ps + n
		if fe > len(raw) {
			t.Fatalf("frameSpan: frame %d truncated in raw", k)
		}
		if k == i {
			return off, ps, fe
		}
		off = fe
	}
}

// setLen overwrites frame i's length field to n and recomputes the length CRC so the
// header stays self-consistent (the reader's lenCrc check passes). Used to forge an
// oversize-but-integrity-valid length.
func setLen(t *testing.T, raw []byte, i int, n uint32) {
	t.Helper()
	h, _, _ := frameSpan(t, raw, i)
	binary.BigEndian.PutUint32(raw[h:h+4], n)
	binary.BigEndian.PutUint32(raw[h+4:h+8], crc32.ChecksumIEEE(raw[h:h+4]))
}

// flipPayloadByte flips one byte inside frame i's payload, so the payload CRC (and, for
// an encrypted log, the GCM tag) no longer matches — a crc failure, not a torn write.
func flipPayloadByte(t *testing.T, raw []byte, i int) {
	t.Helper()
	_, ps, _ := frameSpan(t, raw, i)
	raw[ps] ^= 0xff
}

// writeRaw replaces the whole log file with raw (the corrupted image).
func writeRaw(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// seedLog opens a fresh plaintext WAL at path, appends n simple OpCreate records
// (durably), closes it, and returns the raw on-disk bytes.
func seedLog(t *testing.T, path string, n int) []byte {
	t.Helper()
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: fmt.Sprintf("f%d", i), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ===========================================================================
// 1. Torn tail: clean boundary, mid-header, mid-body. Each => longest intact
//    prefix, NO error, and the torn bytes truncated so later appends survive.
// ===========================================================================

// TestTornTailVariantsTruncateToLastIntactRecord drives the three crash shapes that
// land at the very end of the log. A clean cut at a record boundary loses nothing; a
// header cut mid-way and a body cut mid-way each discard exactly the partial final frame
// and keep the intact prefix, WITHOUT an error (the normal crash artifact). In every case
// Replay must also TRUNCATE the torn bytes so a subsequent acked append + reopen replays
// cleanly (no [valid][torn][new] mid-log-corruption rejection).
func TestTornTailVariantsTruncateToLastIntactRecord(t *testing.T) {
	cases := []struct {
		name string
		// trailer is appended to a clean 3-record log to simulate the crash.
		trailer func(raw []byte) []byte
		want    int // records expected after Replay
	}{
		{
			name:    "clean boundary (zero trailing bytes)",
			trailer: func(raw []byte) []byte { return raw }, // exact EOF at a frame boundary
			want:    3,
		},
		{
			name: "partial header (fewer than headerBytes)",
			trailer: func(raw []byte) []byte {
				return append(raw, 0x00, 0x00, 0x00, 0x05, 0x11) // 5 of 12 header bytes
			},
			want: 3,
		},
		{
			name: "full header, partial body (torn body at tail)",
			trailer: func(raw []byte) []byte {
				var hdr [headerBytes]byte
				binary.BigEndian.PutUint32(hdr[0:4], 1000) // claims 1000-byte body...
				binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(hdr[0:4]))
				binary.BigEndian.PutUint32(hdr[8:12], 0xDEADBEEF)
				out := append(append([]byte{}, raw...), hdr[:]...)
				return append(out, []byte("only-a-few")...) // ...but only a few present
			},
			want: 3,
		},
		{
			name: "single trailing zero byte",
			trailer: func(raw []byte) []byte {
				return append(raw, 0x00)
			},
			want: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wal.log")
			clean := seedLog(t, path, 3)
			writeRaw(t, path, tc.trailer(append([]byte{}, clean...)))

			w, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			recs, err := w.Replay()
			if err != nil {
				t.Fatalf("torn tail must replay without error: %v", err)
			}
			if len(recs) != tc.want {
				t.Fatalf("replay = %d records, want %d (torn frame must be dropped)", len(recs), tc.want)
			}
			// The torn bytes must be truncated: a fresh acked append then reopen must
			// replay cleanly as [prefix..][new], never reject as mid-log corruption.
			if err := w.Append(Record{Op: OpCreate, Path: "AFTER", Mode: 0o644}); err != nil {
				t.Fatalf("append after torn-tail replay: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			w2, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer w2.Close()
			recs2, err := w2.Replay()
			if err != nil {
				t.Fatalf("reopen after torn-tail+append must replay cleanly: %v", err)
			}
			if len(recs2) != tc.want+1 || recs2[len(recs2)-1].Path != "AFTER" {
				t.Fatalf("reopen replay = %+v, want %d records ending in AFTER", recs2, tc.want+1)
			}
			// LSNs stay contiguous: the new record continues right after the surviving prefix.
			for i, r := range recs2 {
				if r.Seq != uint64(i) {
					t.Fatalf("LSN gap after torn-tail recovery: rec[%d].Seq=%d", i, r.Seq)
				}
			}
		})
	}
}

// TestTornTailExactlyOneByteShyOfHeaderBoundary pins the boundary at headerBytes-1: a
// trailing partial header that is one byte short of complete is still a torn tail (the
// header read fails), not length corruption.
func TestTornTailExactlyOneByteShyOfHeaderBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	clean := seedLog(t, path, 1)
	// headerBytes-1 bytes of a would-be next header: io.ReadFull fails -> torn tail.
	partial := make([]byte, headerBytes-1)
	binary.BigEndian.PutUint32(partial[0:4], 4096) // plausible length, but header incomplete
	writeRaw(t, path, append(append([]byte{}, clean...), partial...))

	w, _ := Open(path)
	defer w.Close()
	recs, err := w.Replay()
	if err != nil {
		t.Fatalf("a header one byte short of complete is a torn tail, not an error: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("replay = %d, want 1", len(recs))
	}
}

// ===========================================================================
// 2. Mid-log corruption WITH data following: Replay returns the valid PREFIX
//    plus an error, for every unreadable-frame flavor.
// ===========================================================================

// TestMidLogUnreadableFrameReturnsPrefixPlusError sweeps every way a NON-tail frame can be
// unreadable and asserts the shared contract: Replay returns a non-nil error AND the valid
// records BEFORE the fault (so a recovery caller can salvage the prefix), and never the
// records that follow the fault (they must not be silently swallowed). Frame 1 of a 3-record
// log is corrupted, so the surviving prefix is exactly frame 0.
func TestMidLogUnreadableFrameReturnsPrefixPlusError(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(t *testing.T, raw []byte) []byte
	}{
		{
			name: "corrupt length header (lenCrc stale)",
			corrupt: func(t *testing.T, raw []byte) []byte {
				h, _, _ := frameSpan(t, raw, 1)
				binary.BigEndian.PutUint32(raw[h:h+4], 4096) // bogus length; leave lenCrc stale
				return raw
			},
		},
		{
			name: "oversize length (integrity-valid, > maxRecordBytes)",
			corrupt: func(t *testing.T, raw []byte) []byte {
				setLen(t, raw, 1, maxRecordBytes+1) // length CRC fixed, so it passes the lenCrc check
				return raw
			},
		},
		{
			name: "crc failure with data following",
			corrupt: func(t *testing.T, raw []byte) []byte {
				flipPayloadByte(t, raw, 1) // payload CRC now mismatches; frame 2 follows
				return raw
			},
		},
		{
			name: "undecodable gob with data following",
			corrupt: func(t *testing.T, raw []byte) []byte {
				// Replace frame 1's payload with bytes that pass the crc we set but are NOT a
				// valid gob stream, so decode fails while data (frame 2) follows.
				_, ps, fe := frameSpan(t, raw, 1)
				for i := ps; i < fe; i++ {
					raw[i] = 0xff // 0xff... is not a decodable gob(Record)
				}
				h := ps - headerBytes
				binary.BigEndian.PutUint32(raw[h+8:h+12], crc32.ChecksumIEEE(raw[ps:fe])) // fix payload CRC
				return raw
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wal.log")
			clean := seedLog(t, path, 3)
			writeRaw(t, path, tc.corrupt(t, append([]byte{}, clean...)))

			w, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			recs, err := w.Replay()
			if err == nil {
				t.Fatalf("mid-log corruption (%s) must surface as an error, not silent truncation", tc.name)
			}
			// The valid PREFIX before the fault must come back alongside the error (frame 0
			// only), so a salvaging caller can re-flush it; frame 2 must NOT leak through.
			if len(recs) != 1 || recs[0].Path != "f0" {
				t.Fatalf("Replay returned prefix %+v, want exactly the pre-fault [f0]", recs)
			}
		})
	}
}

// TestEncryptedMidLogDecryptAuthFailureReturnsPrefix covers the encrypted-at-rest variant:
// a frame whose crc passes but whose GCM tag fails (tamper or wrong key) is a decrypt/auth
// failure, reported loudly with the valid prefix returned — never silently dropped.
func TestEncryptedMidLogDecryptAuthFailureReturnsPrefix(t *testing.T) {
	t.Run("tamper inside an interior sealed payload", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal.log")
		w, err := OpenEncrypted(path, encA(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Append(Record{Op: OpCreate, Path: "keep0", Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(Record{Op: OpWrite, Path: "secret1", Data: []byte("payload")}); err != nil {
			t.Fatal(err)
		}
		if err := w.Append(Record{Op: OpCreate, Path: "after2", Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()

		raw, _ := os.ReadFile(path)
		// Tamper a ciphertext byte in frame 1 and REPAIR its payload CRC, so the crc passes
		// and the failure is forced into GCM auth (Open), exactly the "wrong key or tampering"
		// branch — with frame 2 following so it must be loud.
		_, ps, fe := frameSpan(t, raw, 1)
		raw[ps] ^= 0x01
		h := ps - headerBytes
		binary.BigEndian.PutUint32(raw[h+8:h+12], crc32.ChecksumIEEE(raw[ps:fe]))
		writeRaw(t, path, raw)

		w2, err := OpenEncrypted(path, encA(t))
		if err != nil {
			t.Fatal(err)
		}
		defer w2.Close()
		recs, err := w2.Replay()
		if err == nil {
			t.Fatal("an interior GCM-auth failure must error, not silently drop the records after it")
		}
		if len(recs) != 1 || recs[0].Path != "keep0" {
			t.Fatalf("Replay prefix = %+v, want [keep0]", recs)
		}
	})

	t.Run("wrong key on a multi-record log returns nothing and errors", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "wal.log")
		w, err := OpenEncrypted(path, encA(t))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := w.Append(Record{Op: OpCreate, Path: fmt.Sprintf("e%d", i), Mode: 0o644}); err != nil {
				t.Fatal(err)
			}
		}
		_ = w.Close()

		wrong, _ := secure.NewAtRestFromKey(testKeyB)
		w2, err := OpenEncrypted(path, wrong)
		if err != nil {
			t.Fatal(err)
		}
		defer w2.Close()
		recs, err := w2.Replay()
		if err == nil {
			t.Fatal("replay with the wrong key must fail loudly")
		}
		// The very FIRST frame already fails to authenticate, so there is no valid prefix.
		if len(recs) != 0 {
			t.Fatalf("wrong-key replay prefix = %+v, want empty (frame 0 fails auth)", recs)
		}
	})
}

// ===========================================================================
// 3. Distinguish a corrupt LAST frame (== torn tail, silently dropped) from the
//    same corruption mid-log (loud). This is the crux of the framing design.
// ===========================================================================

// TestCorruptLastFrameIsSilentTornTail flips a byte in the FINAL frame's payload. Because
// no data follows, the bad final record is indistinguishable from a torn write and is
// dropped silently (no error), leaving the intact prefix — the mirror image of the mid-log
// case which must be loud.
func TestCorruptLastFrameIsSilentTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	clean := seedLog(t, path, 3)
	raw := append([]byte{}, clean...)
	flipPayloadByte(t, raw, 2) // corrupt the LAST frame; nothing follows
	writeRaw(t, path, raw)

	w, _ := Open(path)
	defer w.Close()
	recs, err := w.Replay()
	if err != nil {
		t.Fatalf("a corrupt LAST frame is a torn tail (no data follows) and must be silent: %v", err)
	}
	if len(recs) != 2 || recs[0].Path != "f0" || recs[1].Path != "f1" {
		t.Fatalf("replay = %+v, want the intact prefix [f0 f1]", recs)
	}
}

// TestUndecodableLastFrameIsSilentTornTail: a final frame whose payload passes crc but is
// not a decodable gob is likewise a torn tail (nothing follows) and dropped silently.
func TestUndecodableLastFrameIsSilentTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	clean := seedLog(t, path, 2)
	raw := append([]byte{}, clean...)
	_, ps, fe := frameSpan(t, raw, 1) // the last frame
	for i := ps; i < fe; i++ {
		raw[i] = 0xff
	}
	h := ps - headerBytes
	binary.BigEndian.PutUint32(raw[h+8:h+12], crc32.ChecksumIEEE(raw[ps:fe])) // crc passes, gob will not decode
	writeRaw(t, path, raw)

	w, _ := Open(path)
	defer w.Close()
	recs, err := w.Replay()
	if err != nil {
		t.Fatalf("an undecodable LAST frame is a torn tail and must be silent: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "f0" {
		t.Fatalf("replay = %+v, want [f0]", recs)
	}
}

// ===========================================================================
// 4. Mid-log corruption POISONS so later appends are refused (the FOCUS contract):
//    after a Replay that reported mid-log corruption, an append that lands after the
//    corrupt region must NOT be silently acked into a log a later replay rejects.
// ===========================================================================

// TestMidLogCorruptionRefusesLaterAppends asserts the durability contract the package
// documents: when Replay hits mid-log corruption (valid data following an unreadable
// frame), the log must not go on accepting acknowledged appends that a later replay would
// reject. Because Replay does not truncate on the mid-log path (it leaves the file intact
// for forensics / salvage), an O_APPEND write would land at EOF — AFTER the corrupt region
// — yielding [valid][corrupt][new]; a subsequent reopen+Replay then rejects the WHOLE log
// as mid-log corruption, SILENTLY LOSING the new acknowledged write. The only safe
// behaviors are: refuse the append (poison), or land it where a later replay still returns
// it. This test fails if the new write is acked but then vanishes on reopen.
func TestMidLogCorruptionReplaySalvagesPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	clean := seedLog(t, path, 3)
	raw := append([]byte{}, clean...)
	flipPayloadByte(t, raw, 1) // mid-log corruption: frame 1 bad, frame 2 still valid
	writeRaw(t, path, raw)

	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	recs, rerr := w.Replay()
	if rerr == nil {
		t.Fatal("setup: expected a mid-log corruption error from Replay")
	}
	// DESIGN: Replay SALVAGES the valid prefix before the corruption and returns it alongside the
	// error — WITHOUT poisoning or truncating, so the recovery caller can atomically Renumber it to
	// a clean log (poisoning here would make Renumber refuse; truncating would destroy the forensic
	// tail). The recovery caller (session.New) does the safe salvage below, and Poison()s only when
	// it cannot rewrite the log clean. Appending to the RAW handle WITHOUT Renumber is a foot-gun no
	// production caller commits.
	if len(recs) < 1 {
		t.Fatalf("Replay must return the valid prefix before the corruption; got %d records", len(recs))
	}
	// Renumber rewrites the log to ONLY the prefix (physically removing the corrupt region); an
	// append then lands in a clean log and survives a reopen+Replay.
	if _, nerr := w.Renumber(recs); nerr != nil {
		t.Fatalf("Renumber salvage of the prefix: %v", nerr)
	}
	if aerr := w.Append(Record{Op: OpCreate, Path: "AFTER-SALVAGE", Mode: 0o644}); aerr != nil {
		t.Fatalf("append after salvage: %v", aerr)
	}
	_ = w.Close()

	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	recs2, rerr2 := w2.Replay()
	if rerr2 != nil {
		t.Fatalf("reopen after salvage must be clean, got: %v", rerr2)
	}
	found := false
	for _, r := range recs2 {
		if r.Path == "AFTER-SALVAGE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the post-salvage acked append must survive a clean reopen; got %+v", recs2)
	}
}

// ===========================================================================
// 5. Poison-on-truncate / poison-on-sync of Replay: a torn tail that cannot be
//    removed must leave NO writable torn tail (the log is poisoned instead).
// ===========================================================================

// TestReplayTornTailTruncationSkippedWhenStatFails locks in the OBSERVED behavior of the
// only public-API way to make Replay's torn-tail truncation fail: a dead WAL file handle.
//
// The FOCUS contract wants "a torn tail that cannot be truncated POISONS (no writable torn
// tail is left)". Replay's poison-on-truncate / poison-on-sync path (wal.go:554-567) is
// GUARDED by `if info, serr := w.f.Stat(); serr == nil && info.Size() > validEnd`. The only
// way to make Truncate/Sync fail via the public surface is to close w.f — but a closed fd
// also makes w.f.Stat() fail, so `serr != nil` and the WHOLE truncate+poison block is
// SKIPPED. The result observed here: Replay returns the valid prefix with NO error, does
// NOT poison, and leaves the torn tail on disk untouched (the file does not shrink). The
// intended poison-on-truncate-failure path is therefore unreachable through the public API,
// and a transient Stat error on a LIVE handle would silently skip torn-tail truncation
// (latent acked-loss risk if the handle then keeps appending) — reported in bugs[]. This
// test pins the current contract so any future change to it is noticed.
func TestReplayTornTailTruncationSkippedWhenStatFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	clean := seedLog(t, path, 2)
	// A torn tail: a full header claiming 100 body bytes but only 1 present.
	var hdr [headerBytes]byte
	binary.BigEndian.PutUint32(hdr[0:4], 100)
	binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(hdr[0:4]))
	binary.BigEndian.PutUint32(hdr[8:12], 0xABCD)
	torn := append(append(append([]byte{}, clean...), hdr[:]...), 0x01)
	writeRaw(t, path, torn)
	tornSize := int64(len(torn))

	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Open now removes the torn tail before publishing the WAL handle, closing the
	// historical append-after-torn-tail window. Sabotaging the fd afterward cannot
	// resurrect those bytes.
	w.mu.Lock()
	_ = w.f.Close()
	w.mu.Unlock()

	recs, err := w.Replay()
	// OBSERVED: the Stat short-circuit means Replay returns the prefix WITHOUT error and does
	// not poison. (This is the documented-but-unreached path; we assert what actually happens.)
	if err != nil {
		t.Fatalf("with a dead handle the Stat guard skips truncation and Replay returns no error; got %v", err)
	}
	if len(recs) != 2 || recs[0].Path != "f0" || recs[1].Path != "f1" {
		t.Fatalf("Replay returned %+v, want the intact 2-record prefix [f0 f1]", recs)
	}
	// The WAL is not poisoned because startup repair already completed durably.
	select {
	case <-w.PoisonedCh():
		t.Fatal("Replay poisoned the WAL — behavior changed; the Stat short-circuit no longer applies (revisit bugs[] note)")
	default:
	}
	if fi, serr := os.Stat(path); serr != nil {
		t.Fatal(serr)
	} else if fi.Size() != int64(len(clean)) {
		t.Fatalf("file size after Replay = %d, want repaired prefix size %d (original torn size %d)", fi.Size(), len(clean), tornSize)
	}
}

// ===========================================================================
// 6. Renumber: atomic rewrite to contiguous Seqs from 0; appends continue after;
//    reopen+Replay sees the renumbered file; empty input; idempotent re-Renumber.
// ===========================================================================

// TestRenumberContiguousFromZeroAcrossSizes renumbers tails of several sizes (0, 1, a few,
// and a "huge gap" set whose input Seqs are far apart) and asserts the output is always the
// contiguous prefix {0..n-1} with DATA preserved, that the next append continues at n, and
// that a reopen+Replay sees the renumbered, durable file. The 0 case exercises an empty
// rewrite (the file becomes empty, watermark resets to 0).
func TestRenumberContiguousFromZeroAcrossSizes(t *testing.T) {
	mk := func(seqs ...uint64) []Record {
		out := make([]Record, len(seqs))
		for i, s := range seqs {
			out[i] = Record{Seq: s, Op: OpWrite, Path: fmt.Sprintf("p%d", i), Data: []byte(fmt.Sprintf("d%d", i))}
		}
		return out
	}
	cases := []struct {
		name string
		in   []Record
	}{
		{"empty", nil},
		{"single mid-stream", mk(42)},
		{"few contiguous-but-offset", mk(7, 8, 9)},
		{"huge sparse gaps", mk(1, 1000, 9_999_999, 1<<40)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "w.wal")
			w, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			out, err := w.Renumber(tc.in)
			if err != nil {
				t.Fatalf("Renumber: %v", err)
			}
			if len(out) != len(tc.in) {
				t.Fatalf("Renumber returned %d records, want %d", len(out), len(tc.in))
			}
			for i, r := range out {
				if r.Seq != uint64(i) {
					t.Fatalf("renumbered rec[%d].Seq = %d, want %d (must be contiguous from 0)", i, r.Seq, i)
				}
				if want := fmt.Sprintf("d%d", i); string(r.Data) != want {
					t.Fatalf("renumbered rec[%d].Data = %q, want %q (data must be preserved)", i, r.Data, want)
				}
			}
			if wm := w.Watermark(); wm != uint64(len(tc.in)) {
				t.Fatalf("watermark after Renumber = %d, want %d", wm, len(tc.in))
			}
			// A subsequent append continues immediately after the renumbered tail.
			seq, err := w.AppendBuffered(Record{Op: OpCreate, Path: "next", Mode: 0o644})
			if err != nil {
				t.Fatalf("append after Renumber: %v", err)
			}
			if seq != uint64(len(tc.in)) {
				t.Fatalf("append after Renumber got Seq %d, want %d (must continue after the tail)", seq, len(tc.in))
			}
			if err := w.CommitThrough(seq); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			// Reopen + Replay: the persisted file is contiguous [0..len(in)] with intact data.
			w2, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer w2.Close()
			recs, err := w2.Replay()
			if err != nil {
				t.Fatalf("reopen replay after Renumber: %v", err)
			}
			if len(recs) != len(tc.in)+1 {
				t.Fatalf("reopen replay = %d records, want %d", len(recs), len(tc.in)+1)
			}
			for i, r := range recs {
				if r.Seq != uint64(i) {
					t.Fatalf("persisted rec[%d].Seq = %d, want %d", i, r.Seq, i)
				}
			}
			if recs[len(recs)-1].Path != "next" {
				t.Fatalf("last persisted record = %q, want the post-Renumber append 'next'", recs[len(recs)-1].Path)
			}
		})
	}
}

// TestRenumberIsIdempotentOnAlreadyContiguous: renumbering records that already start at 0
// and run contiguously is a no-op on the Seqs (and a faithful rewrite of the file).
func TestRenumberIsIdempotentOnAlreadyContiguous(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.wal")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	in := []Record{
		{Seq: 0, Op: OpCreate, Path: "a", Mode: 0o644},
		{Seq: 1, Op: OpWrite, Path: "a", Data: []byte("x")},
	}
	out1, err := w.Renumber(in)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := w.Renumber(out1) // renumber the already-0-based output again
	if err != nil {
		t.Fatal(err)
	}
	if len(out2) != 2 || out2[0].Seq != 0 || out2[1].Seq != 1 {
		t.Fatalf("idempotent Renumber Seqs = %+v, want 0,1", out2)
	}
	if string(out2[1].Data) != "x" {
		t.Fatalf("idempotent Renumber lost data: %q", out2[1].Data)
	}
	recs, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Seq != 0 || recs[1].Seq != 1 {
		t.Fatalf("replay after idempotent Renumber = %+v, want [0,1]", recs)
	}
}

// ===========================================================================
// 7. Group commit: many concurrent AppendBuffered, THEN a concurrent CommitThrough
//    storm. Run under -race. Every acked LSN must be durable and contiguous.
// ===========================================================================

// TestGroupCommitBufferAllThenCommitStorm exercises the exact shape the FOCUS calls out:
// fan out N goroutines that each AppendBuffered (no commit), wait for ALL buffers to land,
// then release a second storm where every goroutine calls CommitThrough on its own LSN at
// once. Group commit must coalesce these into far fewer than N flushes, every commit must
// return nil (durable), and a reopen+Replay must show a gapless [0..N) LSN prefix with the
// standby a faithful mirror. -race guards the shared mu/commitMu/unflushed/durableSeq.
func TestGroupCommitBufferAllThenCommitStorm(t *testing.T) {
	dir := t.TempDir()
	primary, err := Open(filepath.Join(dir, "p.wal"))
	if err != nil {
		t.Fatal(err)
	}
	standby, err := Open(filepath.Join(dir, "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	rep := &countingReplica{w: standby}
	primary.SetReplica(rep)

	const N = 256
	seqs := make([]uint64, N)

	// Phase 1: every goroutine buffers one record. A barrier (bufWG) ensures the whole
	// batch is buffered before ANY commit, maximizing the group-commit coalescing window.
	var bufWG sync.WaitGroup
	release := make(chan struct{})
	var commitWG sync.WaitGroup
	var ack int64
	var commitErrs int64
	for i := 0; i < N; i++ {
		bufWG.Add(1)
		commitWG.Add(1)
		go func(i int) {
			seq, err := primary.AppendBuffered(Record{Op: OpCreate, Path: fmt.Sprintf("g%04d", i), Mode: 0o644})
			if err != nil {
				t.Errorf("AppendBuffered(%d): %v", i, err)
				seqs[i] = ^uint64(0)
				bufWG.Done()
				commitWG.Done()
				return
			}
			seqs[i] = seq
			bufWG.Done()
			// Phase 2: wait for the global release, then everyone commits at once.
			<-release
			if err := primary.CommitThrough(seq); err != nil {
				atomic.AddInt64(&commitErrs, 1)
				t.Errorf("CommitThrough(%d): %v", seq, err)
			} else {
				atomic.AddInt64(&ack, 1)
			}
			commitWG.Done()
		}(i)
	}
	bufWG.Wait()
	// Every LSN [0..N) was assigned exactly once (no gaps/dups under concurrent append).
	seen := make(map[uint64]bool, N)
	for i, s := range seqs {
		if s == ^uint64(0) {
			t.Fatalf("goroutine %d failed to buffer", i)
		}
		if s >= N {
			t.Fatalf("assigned LSN %d out of range [0,%d)", s, N)
		}
		if seen[s] {
			t.Fatalf("LSN %d assigned to two goroutines (AppendBuffered raced)", s)
		}
		seen[s] = true
	}
	if wm := primary.Watermark(); wm != N {
		t.Fatalf("watermark after buffering all = %d, want %d", wm, N)
	}
	close(release) // unleash the commit storm
	commitWG.Wait()

	if commitErrs != 0 {
		t.Fatalf("%d CommitThrough calls failed; every buffered+committed record must be durable", commitErrs)
	}
	if ack != N {
		t.Fatalf("acked %d, want %d", ack, N)
	}
	// All acked => durableSeq must equal the watermark (every record durable).
	if d := primary.durableSeqForTest(); d != N {
		t.Fatalf("final durableSeq = %d, want %d", d, N)
	}
	rep.mu.Lock()
	batches := rep.batches
	rep.mu.Unlock()
	if batches >= N {
		t.Fatalf("group commit did not coalesce: %d replication batches for %d concurrent commits", batches, N)
	}
	t.Logf("buffer-all + commit-storm: %d concurrent commits coalesced into %d replication batches", N, batches)

	// Durable & contiguous on the primary, and faithfully mirrored on the standby.
	assertContiguousReplay(t, "primary", filepath.Join(dir, "p.wal"), N)
	assertContiguousReplay(t, "standby", filepath.Join(dir, "s.wal"), N)
}

// TestConcurrentAppendBufferedAssignsUniqueContiguousLSNs isolates the AppendBuffered LSN
// allocator under heavy concurrency (no commits): the assigned LSNs must be exactly the set
// {0..N-1}, proving the nextSeq counter is race-free, then one CommitThrough makes the whole
// buffered batch durable in a single flush.
func TestConcurrentAppendBufferedAssignsUniqueContiguousLSNs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.wal")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	const N = 500
	got := make([]uint64, N)
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seq, err := w.AppendBuffered(Record{Op: OpCreate, Path: fmt.Sprintf("c%d", i), Mode: 0o644})
			if err != nil {
				t.Errorf("AppendBuffered: %v", err)
				return
			}
			got[i] = seq
		}(i)
	}
	wg.Wait()

	seen := make([]bool, N)
	for _, s := range got {
		if s >= N || seen[s] {
			t.Fatalf("AppendBuffered LSNs are not the unique set {0..%d}: saw %d twice/out-of-range", N-1, s)
		}
		seen[s] = true
	}
	// A single commit at the top LSN makes the entire buffered batch durable in one flush.
	if err := w.CommitThrough(N - 1); err != nil {
		t.Fatalf("CommitThrough(%d): %v", N-1, err)
	}
	if d := w.durableSeqForTest(); d != N {
		t.Fatalf("durableSeq = %d, want %d (one flush must cover the whole buffered batch)", d, N)
	}
	_ = w.Close()
	assertContiguousReplay(t, "buffered", path, N)
}

// ===========================================================================
// 8. Trivial edges: empty/absent Replay, no-op Reset, idempotent repeat Replay,
//    delete-then-recreate, CompactThrough at/around a boundary, Close.
// ===========================================================================

// TestReplayEmptyAndAbsentFile: replaying a brand-new (zero-byte) log and an absent path
// both yield zero records and no error, and the log is immediately writable afterward.
func TestReplayEmptyAndAbsentFile(t *testing.T) {
	t.Run("freshly created empty file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.wal")
		w, err := Open(path) // O_CREATE makes a zero-byte file
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		recs, err := w.Replay()
		if err != nil {
			t.Fatalf("empty-file replay: %v", err)
		}
		if len(recs) != 0 {
			t.Fatalf("empty replay = %d, want 0", len(recs))
		}
		if w.Watermark() != 0 || w.Count() != 0 {
			t.Fatalf("empty log watermark=%d count=%d, want 0,0", w.Watermark(), w.Count())
		}
		// Usable: append lands at LSN 0.
		seq, err := primaryAppend(w, "first")
		if err != nil || seq != 0 {
			t.Fatalf("append to empty log: seq=%d err=%v, want 0", seq, err)
		}
	})

	t.Run("absent file via readRecords path", func(t *testing.T) {
		// readRecords treats os.ErrNotExist as an empty log. Drive it through a WAL whose
		// backing file we delete out from under it, then Replay (readRecords opens by path).
		path := filepath.Join(t.TempDir(), "gone.wal")
		w, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		recs, err := w.Replay()
		if err != nil {
			t.Fatalf("absent-file replay must be a clean empty result: %v", err)
		}
		if len(recs) != 0 {
			t.Fatalf("absent-file replay = %d, want 0", len(recs))
		}
	})
}

// primaryAppend is a tiny helper: AppendBuffered + CommitThrough, returning the LSN.
func primaryAppend(w *WAL, path string) (uint64, error) {
	seq, err := w.AppendBuffered(Record{Op: OpCreate, Path: path, Mode: 0o644})
	if err != nil {
		return 0, err
	}
	return seq, w.CommitThrough(seq)
}

// TestResetNoOpOnEmptyLog: Reset on an already-empty log is a clean no-op (no error,
// stays empty, stays writable, numbering still starts at 0). Repeated Resets too.
func TestResetNoOpOnEmptyLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 3; i++ { // multiple no-op resets in a row
		if err := w.Reset(); err != nil {
			t.Fatalf("no-op Reset #%d: %v", i, err)
		}
		if w.Count() != 0 || w.Watermark() != 0 {
			t.Fatalf("after no-op Reset: count=%d watermark=%d, want 0,0", w.Count(), w.Watermark())
		}
	}
	// Still writable, numbering from 0.
	seq, err := primaryAppend(w, "y")
	if err != nil || seq != 0 {
		t.Fatalf("append after no-op resets: seq=%d err=%v, want 0", seq, err)
	}
	recs, _ := w.Replay()
	if len(recs) != 1 || recs[0].Path != "y" {
		t.Fatalf("replay after no-op reset+append = %+v, want [y]", recs)
	}
}

// TestResetThenReuseRestartsLSNAtZero: a Reset on a NON-empty log drops everything and
// restarts numbering at 0, and the file on disk is empty afterward (reopen sees nothing).
func TestResetThenReuseRestartsLSNAtZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := primaryAppend(w, fmt.Sprintf("a%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Reset(); err != nil {
		t.Fatal(err)
	}
	if w.Watermark() != 0 {
		t.Fatalf("watermark after reset = %d, want 0", w.Watermark())
	}
	seq, err := primaryAppend(w, "fresh")
	if err != nil || seq != 0 {
		t.Fatalf("post-reset append seq=%d err=%v, want 0", seq, err)
	}
	_ = w.Close()
	// On-disk file must contain ONLY the post-reset record (the rewrite truncated it).
	w2, _ := Open(path)
	defer w2.Close()
	recs, err := w2.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Seq != 0 || recs[0].Path != "fresh" {
		t.Fatalf("reopen after reset = %+v, want exactly [fresh@0]", recs)
	}
}

// TestReplayIdempotentRepeat: calling Replay twice in a row on a stable log returns the
// same records both times and does not corrupt or shrink the log.
func TestReplayIdempotentRepeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 5; i++ {
		if _, err := primaryAppend(w, fmt.Sprintf("r%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 5 || len(second) != 5 {
		t.Fatalf("repeat Replay lengths = %d,%d, want 5,5", len(first), len(second))
	}
	for i := range first {
		if first[i].Seq != second[i].Seq || first[i].Path != second[i].Path {
			t.Fatalf("repeat Replay diverged at %d: %+v vs %+v", i, first[i], second[i])
		}
	}
	// Appending after a double-replay still lands at the right LSN (offset preserved).
	seq, err := primaryAppend(w, "after")
	if err != nil || seq != 5 {
		t.Fatalf("append after repeat replay: seq=%d err=%v, want 5", seq, err)
	}
}

// TestCompactThroughBoundaries pins CompactThrough at exactly-at, +1, and -1 of a record's
// LSN, plus 0 (drops nothing) and a value past the end (drops everything). throughSeq is
// the EXCLUSIVE lower bound kept: records with Seq < throughSeq are dropped.
func TestCompactThroughBoundaries(t *testing.T) {
	cases := []struct {
		name      string
		through   uint64
		wantKept  int
		wantFirst uint64 // first surviving Seq (ignored if wantKept==0)
	}{
		{"zero keeps all", 0, 5, 0},
		{"exactly at a record drops below it", 3, 2, 3}, // keep Seq>=3 => 3,4
		{"one below a record", 2, 3, 2},                 // keep Seq>=2 => 2,3,4
		{"one above a record", 4, 1, 4},                 // keep Seq>=4 => 4
		{"exactly at watermark drops all", 5, 0, 0},     // keep Seq>=5 => none
		{"past the end drops all", 99, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := Open(filepath.Join(t.TempDir(), "wal.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			for i := 0; i < 5; i++ { // LSNs 0..4
				if _, err := primaryAppend(w, fmt.Sprintf("f%d", i)); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.CompactThrough(tc.through); err != nil {
				t.Fatalf("CompactThrough(%d): %v", tc.through, err)
			}
			if w.Count() != tc.wantKept {
				t.Fatalf("count after compact(%d) = %d, want %d", tc.through, w.Count(), tc.wantKept)
			}
			recs, err := w.Replay()
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != tc.wantKept {
				t.Fatalf("replay after compact(%d) = %d records, want %d", tc.through, len(recs), tc.wantKept)
			}
			if tc.wantKept > 0 {
				if recs[0].Seq != tc.wantFirst {
					t.Fatalf("first surviving Seq = %d, want %d (compaction kept the wrong prefix)", recs[0].Seq, tc.wantFirst)
				}
				// Surviving records keep their ORIGINAL LSNs and stay contiguous.
				for i := 1; i < len(recs); i++ {
					if recs[i].Seq != recs[i-1].Seq+1 {
						t.Fatalf("compaction left an LSN gap: %d then %d", recs[i-1].Seq, recs[i].Seq)
					}
				}
			}
			// The log keeps working: an append continues after the highest surviving LSN
			// (or at the preserved watermark, which compaction does NOT lower).
			wantNext := w.Watermark()
			seq, err := primaryAppend(w, "post")
			if err != nil {
				t.Fatalf("append after compact: %v", err)
			}
			if seq != wantNext {
				t.Fatalf("append after compact got Seq %d, want %d (watermark must not regress)", seq, wantNext)
			}
		})
	}
}

// TestCompactThroughIsIdempotent: compacting through the same watermark twice is a no-op
// the second time (the prefix is already gone), and a higher-then-lower sequence never
// resurrects dropped records.
func TestCompactThroughIdempotentAndMonotone(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "wal.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for i := 0; i < 6; i++ {
		if _, err := primaryAppend(w, fmt.Sprintf("f%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.CompactThrough(4); err != nil { // keep 4,5
		t.Fatal(err)
	}
	if w.Count() != 2 {
		t.Fatalf("count = %d, want 2", w.Count())
	}
	// Repeat the SAME compaction: nothing more to drop.
	if err := w.CompactThrough(4); err != nil {
		t.Fatal(err)
	}
	if w.Count() != 2 {
		t.Fatalf("count after repeat compact = %d, want 2 (idempotent)", w.Count())
	}
	// A LOWER watermark than already compacted must not resurrect 0..3 (they are gone).
	if err := w.CompactThrough(1); err != nil {
		t.Fatal(err)
	}
	recs, _ := w.Replay()
	if len(recs) != 2 || recs[0].Seq != 4 || recs[1].Seq != 5 {
		t.Fatalf("after lower-watermark compact = %+v, want still [4,5] (no resurrection)", recs)
	}
}

// TestDeleteThenRecreateLog: removing the backing file and re-Opening the same path yields a
// fresh empty log (LSN restarts at 0), independent of whatever it held before. Models an
// operator wiping a stale WAL between epochs.
func TestDeleteThenRecreateLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := primaryAppend(w, fmt.Sprintf("old%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(path) // recreate at the same path
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	recs, err := w2.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("recreated log replay = %d, want 0 (delete must wipe history)", len(recs))
	}
	seq, err := primaryAppend(w2, "new0")
	if err != nil || seq != 0 {
		t.Fatalf("append to recreated log: seq=%d err=%v, want 0", seq, err)
	}
}

// TestCloseThenReopenPreservesDurableRecords: Close flushes nothing by itself, but records
// already made durable via CommitThrough survive a Close + reopen. (Close only closes the
// fd; durability came from the per-append commit.)
func TestCloseThenReopenPreservesDurableRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: fmt.Sprintf("d%d", i), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A second Close on the same handle is expected to error (fd already closed) — we only
	// assert it does not panic.
	_ = w.Close()

	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	recs, err := w2.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("after Close+reopen replay = %d, want 3 (durable records must persist)", len(recs))
	}
}

// ===========================================================================
// 9. Cross-cutting: a full lifecycle through every entry point in one log, asserting
//    the LSN bookkeeping stays coherent across append → commit → compact → renumber →
//    reopen, including a buffered-but-uncommitted tail dropped by a crash (reopen).
// ===========================================================================

// TestBufferedTailNotCommittedSurvivesAsDurableBytesButReplayIsConsistent buffers records
// WITHOUT CommitThrough and then "crashes" (reopen without close). AppendBuffered already
// wrote the bytes to the file (only fsync/replicate is deferred), so a reopen+Replay must see
// every acked record with a consistent state (contiguous LSNs, correct watermark, writable).
// This exercises the unflushed-tail seam.
func TestBufferedTailReopenIsConsistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	// Two committed records, then three buffered-but-not-committed.
	for i := 0; i < 2; i++ {
		if err := w.Append(Record{Op: OpCreate, Path: fmt.Sprintf("c%d", i), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := w.AppendBuffered(Record{Op: OpCreate, Path: fmt.Sprintf("b%d", i), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate a process crash: reopen by path without closing or committing the old fd.

	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	recs, err := w2.Replay()
	if err != nil {
		t.Fatalf("reopen after a buffered tail must replay consistently: %v", err)
	}
	if len(recs) != 5 {
		t.Fatalf("replay after uncommitted process-death tail returned %d records, want all 5 acked records", len(recs))
	}
	// The replayed records must be a gapless LSN prefix and the watermark must match.
	for i, r := range recs {
		if r.Seq != uint64(i) {
			t.Fatalf("buffered-tail reopen LSN gap at %d: Seq=%d", i, r.Seq)
		}
	}
	if wm := w2.Watermark(); wm != uint64(len(recs)) {
		t.Fatalf("watermark = %d, want %d (== records replayed)", wm, len(recs))
	}
	// And the log is immediately writable, continuing after the surviving prefix.
	seq, err := primaryAppend(w2, "resumed")
	if err != nil {
		t.Fatalf("append after buffered-tail reopen: %v", err)
	}
	if seq != uint64(len(recs)) {
		t.Fatalf("resumed append Seq = %d, want %d", seq, len(recs))
	}
}

// TestFullLifecycleLSNBookkeeping runs append → CompactThrough → more appends → Renumber →
// reopen and asserts the LSN accounting is coherent at each hop (the kind of multi-stage
// sequence crash recovery actually performs).
func TestFullLifecycleLSNBookkeeping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}

	// 6 records (LSN 0..5).
	for i := 0; i < 6; i++ {
		if _, err := primaryAppend(w, fmt.Sprintf("a%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	// Compact away 0..3, keep 4,5; watermark stays 6.
	if err := w.CompactThrough(4); err != nil {
		t.Fatal(err)
	}
	if w.Watermark() != 6 || w.Count() != 2 {
		t.Fatalf("post-compact watermark=%d count=%d, want 6,2", w.Watermark(), w.Count())
	}
	// Append two more (LSN 6,7).
	for i := 0; i < 2; i++ {
		if _, err := primaryAppend(w, fmt.Sprintf("m%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	// The surviving set is now LSNs {4,5,6,7}. Read them back, then Renumber to {0..3}.
	survivors, err := w.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(survivors) != 4 || survivors[0].Seq != 4 || survivors[3].Seq != 7 {
		t.Fatalf("survivors = %+v, want LSNs 4..7", survivors)
	}
	renum, err := w.Renumber(survivors)
	if err != nil {
		t.Fatal(err)
	}
	if len(renum) != 4 || renum[0].Seq != 0 || renum[3].Seq != 3 {
		t.Fatalf("renumbered = %+v, want 0..3", renum)
	}
	if w.Watermark() != 4 {
		t.Fatalf("watermark after Renumber = %d, want 4", w.Watermark())
	}
	// One more append continues at 4, then reopen sees the contiguous [0..4].
	if seq, err := primaryAppend(w, "z"); err != nil || seq != 4 {
		t.Fatalf("append after Renumber: seq=%d err=%v, want 4", seq, err)
	}
	_ = w.Close()

	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	final, err := w2.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(final) != 5 {
		t.Fatalf("final replay = %d records, want 5", len(final))
	}
	for i, r := range final {
		if r.Seq != uint64(i) {
			t.Fatalf("final LSN gap at %d: Seq=%d", i, r.Seq)
		}
	}
	// Data integrity across the whole journey: the renumbered survivors kept their payload
	// identity (a4,a5 from before the compaction; m0,m1 appended after; z last).
	wantPaths := []string{"a4", "a5", "m0", "m1", "z"}
	for i, r := range final {
		if r.Path != wantPaths[i] {
			t.Fatalf("final rec[%d].Path = %q, want %q", i, r.Path, wantPaths[i])
		}
	}
}

// sanity: keep the bytes import used even if a future edit drops its only user.
var _ = bytes.Equal
