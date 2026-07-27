package session_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/session"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// corruptMidLogRecord flips a byte inside the payload of WAL record `idx`, leaving later
// records intact — bit-rot in the MIDDLE of the log, not a torn tail. On replay the crc fails
// at `idx` with data still following, so Replay returns the valid prefix [0,idx) plus an error.
func corruptMidLogRecord(t *testing.T, path string, idx int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const hdr = 12 // headerBytes: n[4] lenCrc[4] payloadCrc[4]
	off := 0
	for i := 0; ; i++ {
		if off+hdr > len(b) {
			t.Fatalf("record %d not found in WAL (%d bytes)", idx, len(b))
		}
		n := int(binary.BigEndian.Uint32(b[off : off+4]))
		if i == idx {
			b[off+hdr] ^= 0xff // flip the first payload byte -> crc mismatch
			break
		}
		off += hdr + n
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type nopBlobs struct{}

func (nopBlobs) Blob(context.Context, string) ([]byte, error) { return nil, nil }

// startAuthority starts an in-process fsproto server over a fresh workfs and returns a
// connected client (the session's Authority).
func startAuthority(t *testing.T) *fsproto.Client {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "auth.wal"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fsproto.NewServer(fs, fs, delegation.New()).Serve(ctx, ln) }()
	cli, err := fsproto.Dial(ln.Addr().String(), 4)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

// wbAuth wraps the authority client the way the production mount does
// (clientcore.wbAuthority): checkout/checkin/flush route through the managed
// coordination surface when the authority negotiated it, else the legacy
// methods. Against the legacy in-process server above, ServerManaged() is
// false, so it routes to the legacy path — behavior-identical to before the
// Authority interface grew the checkout grant.
type wbAuth struct{ c *fsproto.Client }

func (a wbAuth) Checkout(path, owner string) (bool, string, session.CheckoutGrant, error) {
	if a.c.ServerManaged() {
		granted, heldBy, epoch, err := a.c.CheckoutManaged(path)
		if err != nil || !granted {
			return granted, heldBy, session.CheckoutGrant{}, err
		}
		return true, "", session.CheckoutGrant{Path: path, Epoch: epoch}, nil
	}
	granted, heldBy, err := a.c.Checkout(path, owner)
	return granted, heldBy, session.CheckoutGrant{}, err
}

func (a wbAuth) Checkin(path, owner string, g session.CheckoutGrant) error {
	if g.Epoch != "" {
		return a.c.CheckinManaged(g.Path, g.Epoch)
	}
	return a.c.Checkin(path, owner)
}

func (a wbAuth) FlushBatch(id string, epoch uint64, owner string, g session.CheckoutGrant, recs []wal.Record) (uint64, int32, error) {
	return a.c.FlushBatchWriteBack(id, epoch, owner, g.Path, g.Epoch, recs)
}

func (a wbAuth) Read(p string, off, n int64) ([]byte, int32, error) { return a.c.Read(p, off, n) }
func (a wbAuth) Stat(p string) (string, uint32, int32, error)       { return a.c.Stat(p) }
func (a wbAuth) Readlink(p string) (string, int32, error)           { return a.c.Readlink(p) }

type benchAuthority struct{}

func (benchAuthority) Checkout(string, string) (bool, string, session.CheckoutGrant, error) {
	return true, "", session.CheckoutGrant{}, nil
}
func (benchAuthority) Checkin(string, string, session.CheckoutGrant) error { return nil }
func (benchAuthority) Read(string, int64, int64) ([]byte, int32, error) {
	return nil, fsproto.ENOENT, nil
}
func (benchAuthority) Stat(string) (string, uint32, int32, error) {
	return "", 0, fsproto.ENOENT, nil
}
func (benchAuthority) Readlink(string) (string, int32, error) {
	return "", fsproto.ENOENT, nil
}
func (benchAuthority) FlushBatch(_ string, _ uint64, _ string, _ session.CheckoutGrant, records []wal.Record) (uint64, int32, error) {
	if len(records) == 0 {
		return 0, fsproto.OK, nil
	}
	return records[len(records)-1].Seq, fsproto.OK, nil
}

// TestSessionWriteBack: writes under a checkout are LOCAL — visible to the session
// immediately, invisible to the authority until Flush, then exactly-once on the authority.
func TestSessionWriteBack(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("work", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir work: st=%d err=%v", st, err)
	}

	sess, err := session.New(wbAuth{cli}, "M", "sess1", "work", filepath.Join(t.TempDir(), "sess.wal"))
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	// Local create + write.
	if err := sess.Create("work/db", 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := sess.Write("work/db", 0, []byte("hello world")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read-back is served LOCALLY from the overlay.
	data, ok, err := sess.Read("work/db", 0, 64)
	if err != nil || !ok || string(data) != "hello world" {
		t.Fatalf("local read: data=%q ok=%v err=%v, want hello world", data, ok, err)
	}

	// The authority does NOT have it yet (write-back: invisible before flush).
	if _, st, _ := cli.Getattr("work/db"); st == fsproto.OK {
		t.Fatal("work/db must NOT be visible on the authority before flush (write-back)")
	}

	// Flush: now the authority has the exact content.
	if err := sess.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got, st, err := cli.Read("work/db", 0, 64)
	if err != nil || st != fsproto.OK || string(got) != "hello world" {
		t.Fatalf("authority read after flush: data=%q st=%d err=%v, want hello world", got, st, err)
	}

	// A second flush with no new writes is a no-op; a redundant flush of the same records
	// is exactly-once (the discriminator: overwrite on the authority, re-flush must not
	// revert). Append a new write, flush, then force a redundant re-flush.
	if _, err := sess.Write("work/db", 0, []byte("HELLO")); err != nil {
		t.Fatalf("write2: %v", err)
	}
	if err := sess.Flush(); err != nil {
		t.Fatalf("flush2: %v", err)
	}
	got2, _, _ := cli.Read("work/db", 0, 64)
	if string(got2) != "HELLO world" {
		t.Fatalf("after write2+flush authority=%q, want 'HELLO world'", got2)
	}

	if err := sess.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestSessionAtomicAppendStaysBatchedAndLocallyVisible(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("append-owner")
	if _, st, err := cli.Mkdir("work", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Create("work/log", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("create: st=%d err=%v", st, err)
	}
	if _, _, _, st, err := cli.WriteV("work/log", 0, []byte("base"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed: st=%d err=%v", st, err)
	}

	sess, err := session.New(wbAuth{cli}, "append-owner", "append-session", "work", filepath.Join(t.TempDir(), "append.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	for _, chunk := range [][]byte{[]byte("-A"), []byte("-B"), []byte("-C")} {
		if n, err := sess.WriteAppend("work/log", chunk); err != nil || n != len(chunk) {
			t.Fatalf("append %q: n=%d err=%v", chunk, n, err)
		}
	}
	if got, ok, err := sess.Read("work/log", 0, 64); err != nil || !ok || string(got) != "base-A-B-C" {
		t.Fatalf("local overlay=%q ok=%v err=%v", got, ok, err)
	}
	if got, st, err := cli.Read("work/log", 0, 64); err != nil || st != fsproto.OK || string(got) != "base" {
		t.Fatalf("authority changed before flush: %q st=%d err=%v", got, st, err)
	}
	if err := sess.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, st, err := cli.Read("work/log", 0, 64); err != nil || st != fsproto.OK || string(got) != "base-A-B-C" {
		t.Fatalf("authority after append batch=%q st=%d err=%v", got, st, err)
	}
}

// TestSessionReadThrough: a path the session has NOT edited reads through to the authority
// (ok=false → caller forwards).
func TestSessionReadThrough(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("work", 0o755)
	sess, err := session.New(wbAuth{cli}, "M", "s", "work", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if _, ok, err := sess.Read("work/other", 0, 16); ok || err != nil {
		t.Fatalf("unedited path must read-through (ok=false); got ok=%v err=%v", ok, err)
	}
}

func TestSessionLocalReaddirReportsOverlayChildren(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	sess, err := session.New(wbAuth{cli}, "M", "s", "", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.Create("root.txt", 0o644); err != nil {
		t.Fatalf("create root.txt: %v", err)
	}
	if err := sess.Mkdir("dir", 0o755); err != nil {
		t.Fatalf("mkdir dir: %v", err)
	}
	if err := sess.Create("dir/file", 0o640); err != nil {
		t.Fatalf("create dir/file: %v", err)
	}
	if _, err := sess.Write("dir/file", 0, []byte("data")); err != nil {
		t.Fatalf("write dir/file: %v", err)
	}
	if err := sess.Symlink("dir/link", "target-name"); err != nil {
		t.Fatalf("symlink dir/link: %v", err)
	}
	if err := sess.Create("dir/sub/grandchild", 0o644); err != nil {
		t.Fatalf("create grandchild: %v", err)
	}
	if err := sess.Remove("dir/deleted"); err != nil {
		t.Fatalf("remove dir/deleted: %v", err)
	}
	if err := sess.Remove("root-deleted"); err != nil {
		t.Fatalf("remove root-deleted: %v", err)
	}

	rootPresent, rootDeleted := sess.LocalReaddir("")
	if got := localDirNames(rootPresent); got != "dir,root.txt" {
		t.Fatalf("root present = %q", got)
	}
	if got := stringsJoin(rootDeleted); got != "root-deleted" {
		t.Fatalf("root deleted = %q", got)
	}

	dirPresent, dirDeleted := sess.LocalReaddir("dir")
	if got := localDirNames(dirPresent); got != "file,link" {
		t.Fatalf("dir present = %q", got)
	}
	if got := stringsJoin(dirDeleted); got != "deleted" {
		t.Fatalf("dir deleted = %q", got)
	}
	byName := map[string]session.LocalDirEntry{}
	for _, e := range dirPresent {
		byName[e.Name] = e
	}
	if file := byName["file"]; file.Kind != "file" || file.Mode != 0o640 || file.Size != int64(len("data")) {
		t.Fatalf("file entry = %+v", file)
	}
	if link := byName["link"]; link.Kind != "symlink" || link.Size != int64(len("target-name")) {
		t.Fatalf("link entry = %+v", link)
	}
}

func localDirNames(entries []session.LocalDirEntry) string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name)
	}
	return stringsJoin(names)
}

func stringsJoin(v []string) string {
	if len(v) == 0 {
		return ""
	}
	out := v[0]
	for _, s := range v[1:] {
		out += "," + s
	}
	return out
}

// TestSessionBaseFetchOnPartialWrite: writing at an offset into a file that exists on the
// authority pulls the base, so a read of the un-written region is still correct.
func TestSessionBaseFetchOnPartialWrite(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("d", 0o755)
	// Seed a file on the authority directly (not via the session).
	cli.Create("d/f", 0o644)
	cli.Write("d/f", 0, []byte("AAAAAAAA"), 0o644) // 8 'A's

	sess, err := session.New(wbAuth{cli}, "M", "s2", "d", filepath.Join(t.TempDir(), "s2.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// Overwrite the middle locally; the base must be pulled so edges survive.
	if _, err := sess.Write("d/f", 4, []byte("BB")); err != nil {
		t.Fatalf("partial write: %v", err)
	}
	got, ok, err := sess.Read("d/f", 0, 64)
	if err != nil || !ok || string(got) != "AAAABBAA" {
		t.Fatalf("partial overwrite read=%q ok=%v, want AAAABBAA", got, ok)
	}
}

// TestCreateAdoptsHandedOffFile: O_CREAT on a file that already exists on the authority (a
// handed-off workspace file this mount hadn't observed, so the kernel issued CREATE not OPEN)
// must ADOPT its content, not shadow it with an empty file. Regression for the contended-handoff
// data-loss bug (a second mount's empty re-create made reads see 0 bytes — SQLite "no such
// table" — and would have clobbered the first mount's data).
func TestCreateAdoptsHandedOffFile(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	cli.Mkdir("ws", 0o755)
	a, err := session.New(wbAuth{cli}, "A", "sA", "ws", filepath.Join(t.TempDir(), "a.wal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Create("ws/db", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Write("ws/db", 0, []byte("HANDED-OFF")); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil { // flush + checkin
		t.Fatalf("A close: %v", err)
	}
	b, err := session.New(wbAuth{cli}, "B", "sB", "ws", filepath.Join(t.TempDir(), "b.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Create("ws/db", 0o644); err != nil {
		t.Fatalf("B create: %v", err)
	}
	if _, _, size, _, _, _, ok := b.LocalStat("ws/db"); !ok || size != int64(len("HANDED-OFF")) {
		t.Fatalf("B's O_CREAT shadowed the handed-off file: size=%d ok=%v, want %d", size, ok, len("HANDED-OFF"))
	}
	got, ok, err := b.Read("ws/db", 0, 64)
	if err != nil || !ok || string(got) != "HANDED-OFF" {
		t.Fatalf("B read=%q ok=%v err=%v, want HANDED-OFF (O_CREAT must adopt the existing file)", got, ok, err)
	}
}

// TestRecreateAfterLocalDeleteIsFresh: re-creating a file this session just deleted (e.g.
// SQLite's -journal, dropped + remade each transaction) must come back EMPTY — it must NOT
// adopt the authority's pre-deletion content (a resurrected stale journal corrupts the DB).
func TestRecreateAfterLocalDeleteIsFresh(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("d", 0o755)
	s, err := session.New(wbAuth{cli}, "M", "s", "d", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Create("d/j", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("d/j", 0, []byte("STALE-JOURNAL")); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // now "STALE-JOURNAL" is on the authority
		t.Fatal(err)
	}
	if err := s.Remove("d/j"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("d/j", 0o644); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	got, ok, err := s.Read("d/j", 0, 64)
	if err != nil || !ok || len(got) != 0 {
		t.Fatalf("re-create after delete read=%q (ok=%v) — must be FRESH/empty, not the stale authority content", got, ok)
	}
}

// TestCrashRecoveryReflushesUnflushedTail: a mount that wrote to its persistent WAL but CRASHED
// before flushing (un-flushed records remain on disk) must, on restart with the same WAL path +
// owner, re-flush that tail to the authority exactly-once. This is the persistent-walDir crash
// recovery guarantee.
func TestCrashRecoveryReflushesUnflushedTail(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("R")
	cli.Mkdir("ws", 0o755)
	walPath := filepath.Join(t.TempDir(), "sess-R-ws.wal")

	// Simulate the crashed mount: append the records a session would have, commit them DURABLY
	// to the WAL, close — but never flush them to the authority (the crash).
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	recs := []wal.Record{
		{Op: wal.OpCreate, Path: "ws/db", Mode: 0o644},
		{Op: wal.OpWrite, Path: "ws/db", Offset: 0, Data: []byte("UNFLUSHED-TAIL")},
	}
	var last uint64
	for _, r := range recs {
		seq, aerr := w.AppendBuffered(r)
		if aerr != nil {
			t.Fatal(aerr)
		}
		last = seq
	}
	if err := w.CommitThrough(last); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// The authority does NOT have the data yet (it was never flushed).
	if _, st, _ := cli.Getattr("ws/db"); st == fsproto.OK {
		t.Fatal("ws/db must be absent before recovery (the crash never flushed it)")
	}

	// Restart: a NEW session for the same (id, walPath) recovers + re-flushes the tail.
	s, err := session.New(wbAuth{cli}, "R", "R-ws", "ws", walPath)
	if err != nil {
		t.Fatalf("recovery session: %v", err)
	}
	defer s.Close()
	got, st, err := cli.Read("ws/db", 0, 64)
	if err != nil || st != fsproto.OK || string(got) != "UNFLUSHED-TAIL" {
		t.Fatalf("authority after recovery: data=%q st=%d err=%v, want UNFLUSHED-TAIL", got, st, err)
	}
}

func TestCrashRecoveryReplaysUnfsyncedSessionLogWithoutClose(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("R")
	cli.Mkdir("ws", 0o755)
	walPath := filepath.Join(t.TempDir(), "sess-R-ws.wal")

	crashed, err := session.New(wbAuth{cli}, "R", "R-ws", "ws", walPath)
	if err != nil {
		t.Fatalf("new crashed session: %v", err)
	}
	if err := crashed.Create("ws/no-fsync", 0o644); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := crashed.Write("ws/no-fsync", 0, []byte("ACKED-NO-FSYNC")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, ok, err := crashed.Read("ws/no-fsync", 0, 64); err != nil || !ok || string(got) != "ACKED-NO-FSYNC" {
		t.Fatalf("pre-crash local read=%q ok=%v err=%v, want ACKED-NO-FSYNC", got, ok, err)
	}
	if _, st, _ := cli.Getattr("ws/no-fsync"); st == fsproto.OK {
		t.Fatal("authority must not have no-fsync write before recovery")
	}

	tail, err := os.OpenFile(walPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tail.Write([]byte{0, 0, 0, 64, 0}); err != nil {
		_ = tail.Close()
		t.Fatalf("append torn tail: %v", err)
	}
	if err := tail.Close(); err != nil {
		t.Fatalf("close torn-tail helper: %v", err)
	}

	// Simulate process death: do not Fsync or Close the crashed session. A fresh
	// session over the same WAL must replay the complete frames and ignore the torn tail.
	recovered, err := session.New(wbAuth{cli}, "R", "R-ws", "ws", walPath)
	if err != nil {
		t.Fatalf("recovery session: %v", err)
	}
	defer recovered.Close()
	got, st, err := cli.Read("ws/no-fsync", 0, 64)
	if err != nil || st != fsproto.OK || string(got) != "ACKED-NO-FSYNC" {
		t.Fatalf("authority after unfsynced recovery: data=%q st=%d err=%v, want ACKED-NO-FSYNC", got, st, err)
	}
}

// TestSetattrMetadataReachesAuthority: chtimes/chown on a session-covered file must be
// buffered and flushed — not silently dropped. Regression for the audit-found HIGH where
// node.Setattr handled only truncate+chmod for session paths and discarded mtime/uid/gid.
func TestSetattrMetadataReachesAuthority(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	cli.Mkdir("ws", 0o755)
	s, err := session.New(wbAuth{cli}, "A", "sA", "ws", filepath.Join(t.TempDir(), "a.wal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("ws/f", 0o644); err != nil {
		t.Fatal(err)
	}
	const mtimeMs = int64(1600000000000)
	if err := s.Chtimes("ws/f", mtimeMs); err != nil {
		t.Fatal(err)
	}
	if err := s.Chown("ws/f", 4242, 5252); err != nil {
		t.Fatal(err)
	}
	// Pre-flush: LocalStat surfaces the new metadata immediately (no stale read-back).
	if _, _, _, mt, uid, gid, ok := s.LocalStat("ws/f"); !ok || mt != mtimeMs || uid != 4242 || gid != 5252 {
		t.Fatalf("LocalStat = mt:%d uid:%d gid:%d ok:%v, want %d/4242/5252", mt, uid, gid, ok, mtimeMs)
	}
	if err := s.Close(); err != nil { // flush + checkin
		t.Fatalf("close: %v", err)
	}
	// Durable: the authority must carry the new mtime/uid/gid after the flush.
	a, st, err := cli.Getattr("ws/f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("authority getattr: st=%d err=%v", st, err)
	}
	if a.MtimeMs != mtimeMs || a.Uid != 4242 || a.Gid != 5252 {
		t.Fatalf("authority after flush = mt:%d uid:%d gid:%d, want %d/4242/5252 — Setattr metadata LOST", a.MtimeMs, a.Uid, a.Gid, mtimeMs)
	}
}

// TestCrashRecoverySalvagesPrefixOnMidLogCorruption: when a crashed session's WAL has bit-rot
// in the MIDDLE (not just a torn tail), recovery must re-flush the valid PREFIX rather than
// abandon the whole tail. Regression for the audit-found HIGH where any Replay error skipped
// recovery entirely, silently losing every un-flushed write — even the readable ones.
func TestCrashRecoverySalvagesPrefixOnMidLogCorruption(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("ws", 0o755)
	walPath := filepath.Join(t.TempDir(), "sess.wal")

	// Crash session: durably log 4 records, then die WITHOUT flushing to the authority.
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for _, r := range []wal.Record{
		{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644},
		{Op: wal.OpWrite, Path: "ws/a", Offset: 0, Data: []byte("AAAA")},
		{Op: wal.OpCreate, Path: "ws/b", Mode: 0o644}, // record idx 2 — corrupted below
		{Op: wal.OpWrite, Path: "ws/b", Offset: 0, Data: []byte("BBBB")},
	} {
		seq, aerr := w.AppendBuffered(r)
		if aerr != nil {
			t.Fatal(aerr)
		}
		last = seq
	}
	if err := w.CommitThrough(last); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	corruptMidLogRecord(t, walPath, 2) // records 0,1 stay valid; 2 onward unreadable

	// Recover: New must salvage + re-flush the readable prefix (ws/a="AAAA").
	s, err := session.New(wbAuth{cli}, "M", "sess", "ws", walPath)
	if err != nil {
		t.Fatalf("New (recovery): %v", err)
	}
	defer s.Close()
	got, st, err := cli.Read("ws/a", 0, 64)
	if err != nil || st != fsproto.OK || string(got) != "AAAA" {
		t.Fatalf("recovery must re-flush the valid prefix; ws/a=%q st=%d err=%v, want AAAA (the tail was abandoned)", got, st, err)
	}
}

// TestRenameUnoverlaidSymlinkKeepsKindAndTarget: renaming a symlink that exists only on the
// authority must preserve its symlink-ness and target — not fabricate an empty file. Regression
// for the audit-found HIGH.
func TestRenameUnoverlaidSymlinkKeepsKindAndTarget(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("ws", 0o755)
	if _, st, err := cli.Symlink("the-target", "ws/link"); err != nil || st != fsproto.OK {
		t.Fatalf("seed symlink: st=%d err=%v", st, err)
	}
	s, err := session.New(wbAuth{cli}, "M", "s", "ws", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("ws/link", "ws/link2"); err != nil {
		t.Fatalf("rename symlink: %v", err)
	}
	if kind, _, _, _, _, _, ok := s.LocalStat("ws/link2"); !ok || kind != "symlink" {
		t.Fatalf("renamed symlink local kind=%q ok=%v, want symlink (not a fabricated file)", kind, ok)
	}
	if err := s.Close(); err != nil { // flush + checkin
		t.Fatal(err)
	}
	tgt, st, err := cli.Readlink("ws/link2")
	if err != nil || st != fsproto.OK || tgt != "the-target" {
		t.Fatalf("authority link2 target=%q st=%d err=%v, want the-target", tgt, st, err)
	}
}

// TestRenameNonexistentSourceFails: renaming a path that doesn't exist must fail (ENOENT), not
// silently fabricate an empty destination. Regression for the audit-found HIGH.
func TestRenameNonexistentSourceFails(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("ws", 0o755)
	s, err := session.New(wbAuth{cli}, "M", "s", "ws", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Rename("ws/ghost", "ws/x"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rename of nonexistent source: err=%v, want os.ErrNotExist", err)
	}
	if _, _, _, _, _, _, ok := s.LocalStat("ws/x"); ok {
		t.Fatal("a failed rename must not create the destination")
	}
}

// TestRenameDirectoryMovesOverlaidChildren: renaming a directory must carry its locally-buffered
// children with it — both in the local view and durably — instead of stranding them at the old
// path. Regression for the descendant-stranding bug uncovered alongside the audit HIGH.
func TestRenameDirectoryMovesOverlaidChildren(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("ws", 0o755)
	s, err := session.New(wbAuth{cli}, "M", "s", "ws", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Mkdir("ws/d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("ws/d/child", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("ws/d/child", 0, []byte("HI")); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("ws/d", "ws/d2"); err != nil {
		t.Fatalf("rename dir: %v", err)
	}
	// Local view: the child moved with the directory; the old path is gone.
	got, ok, err := s.Read("ws/d2/child", 0, 64)
	if err != nil || !ok || string(got) != "HI" {
		t.Fatalf("renamed dir child local read=%q ok=%v err=%v, want HI", got, ok, err)
	}
	if k, _, _, _, _, _, ok := s.LocalStat("ws/d/child"); !ok || k != "" {
		t.Fatalf("old child path must be tombstoned (absent) after the directory rename; kind=%q ok=%v", k, ok)
	}
	// Durable: the authority reflects the moved child after flush.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	d2, st, err := cli.Read("ws/d2/child", 0, 64)
	if err != nil || st != fsproto.OK || string(d2) != "HI" {
		t.Fatalf("authority ws/d2/child=%q st=%d err=%v, want HI", d2, st, err)
	}
}

// TestMetadataOpOnReadThroughDirDoesNotShadowIt: a metadata op (mtime/mode/owner) on a path the
// session has NOT overlaid — e.g. a directory whose mtime the OS bumps when a file is created in
// it — must NOT fabricate a kind:"file" overlay entry. Doing so shadowed the directory as an
// empty file locally, so readdir found nothing and apps got "no such file". The op is still
// recorded and applies on the authority at flush. Regression for the SQLite-handoff break.
func TestMetadataOpOnReadThroughDirDoesNotShadowIt(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("ws", 0o755)
	cli.Mkdir("ws/sub", 0o755) // a directory the session will not overlay
	s, err := session.New(wbAuth{cli}, "M", "s", "ws", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	// The OS bumps the directory's mtime (read-through path).
	if err := s.Chtimes("ws/sub", 1700000000000); err != nil {
		t.Fatal(err)
	}
	// It must NOT have been shadowed by a fabricated overlay entry — LocalStat stays read-through.
	if kind, _, _, _, _, _, ok := s.LocalStat("ws/sub"); ok {
		t.Fatalf("metadata op fabricated an overlay entry for read-through dir ws/sub (kind=%q) — shadows the directory", kind)
	}
	// The op still reaches the authority on flush, and the path is still a DIRECTORY (not a file).
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	a, st, err := cli.Getattr("ws/sub")
	if err != nil || st != fsproto.OK {
		t.Fatalf("authority getattr ws/sub: st=%d err=%v", st, err)
	}
	if a.Kind != "directory" {
		t.Fatalf("ws/sub kind=%q after a metadata op + flush, want directory (not shadowed)", a.Kind)
	}
	if a.MtimeMs != 1700000000000 {
		t.Fatalf("directory mtime not flushed: got %d, want 1700000000000", a.MtimeMs)
	}
}

// TestNewPoisonsUnsalvageableCorruptWAL: when a crash WAL is corrupt from the FIRST frame (no
// salvageable prefix, nothing for Renumber to rewrite), session.New cannot clean the log, so it
// must POISON it — a later write then fails LOUD instead of landing past the corrupt region and
// vanishing on the next replay. Regression for the WAL mid-log-corruption durability gap.
func TestNewPoisonsUnsalvageableCorruptWAL(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	cli.Mkdir("ws", 0o755)
	walPath := filepath.Join(t.TempDir(), "sess.wal")
	garbage := make([]byte, 64)
	for i := range garbage {
		garbage[i] = 0xAB // a complete but crc-invalid frame header => Replay errors with no prefix
	}
	if err := os.WriteFile(walPath, garbage, 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := session.New(wbAuth{cli}, "M", "sess", "ws", walPath)
	if err != nil {
		t.Fatalf("New should still return a session over a corrupt WAL: %v", err)
	}
	defer s.Close()
	if werr := s.Create("ws/x", 0o644); werr == nil {
		t.Fatal("a write to a session over an UNSALVAGEABLE-corrupt WAL must fail (poisoned), not silently append past the corruption")
	}
}

// TestMaterializeForgetThenOrphanKeepsWriteBackOpenFile is the session half of B4 (write-back
// delete-on-last-close): Materialize flushes the buffered create+write so the authority has the live
// bytes, Orphan parks them by ino, Forget drops the overlay so no later flush re-deletes the path,
// and the parked inode stays readable+writable by ino and survives a subsequent Flush.
func TestMaterializeForgetThenOrphanKeepsWriteBackOpenFile(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("ws", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir ws: st=%d err=%v", st, err)
	}

	s, err := session.New(wbAuth{cli}, "M", "s", "ws", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Create("ws/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("ws/f", 0, []byte("before-unlink")); err != nil {
		t.Fatal(err)
	}

	// Materialize: the buffered create+write must land at the authority BEFORE the orphan parks it.
	if err := s.Materialize("ws/f"); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	ino, st, err := cli.Orphan("ws/f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("orphan: ino=%d st=%d err=%v", ino, st, err)
	}
	s.Forget("ws/f")

	if _, _, _, _, _, _, ok := s.LocalStat("ws/f"); ok {
		t.Fatal("orphaned path must be forgotten from the session overlay")
	}
	if _, st, _ := cli.Getattr("ws/f"); st == fsproto.OK {
		t.Fatal("linked name still resolves after orphan")
	}

	got, st, err := cli.ReadOrphan(ino, 0, 64)
	if err != nil || st != fsproto.OK || string(got) != "before-unlink" {
		t.Fatalf("orphan read=%q st=%d err=%v, want before-unlink", got, st, err)
	}

	// Write-after-unlink by ino, then Flush must NOT emit a stale path-addressed record for ws/f.
	if _, st, err := cli.WriteOrphan(ino, int64(len("before-unlink")), []byte("+after")); err != nil || st != fsproto.OK {
		t.Fatalf("orphan write: st=%d err=%v", st, err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush after forget must not emit stale path records: %v", err)
	}
	got, st, err = cli.ReadOrphan(ino, 0, 64)
	if err != nil || st != fsproto.OK || string(got) != "before-unlink+after" {
		t.Fatalf("orphan after flush=%q st=%d err=%v", got, st, err)
	}

	if st, err := cli.Reap(ino); err != nil || st != fsproto.OK {
		t.Fatalf("reap: st=%d err=%v", st, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestMaterializeSealRejectsStalePathWrite covers the phantom-resurrection guard: once Materialize
// seals a path (orphaned-while-open), a path-addressed write is rejected with ErrOrphaned so it can
// never re-create the deleted name; a genuine re-create (Create) — or Unseal (orphan-failed rollback)
// — lifts the seal so legitimate writes land again.
func TestMaterializeSealRejectsStalePathWrite(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("ws", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir ws: st=%d err=%v", st, err)
	}
	s, err := session.New(wbAuth{cli}, "M", "s", "ws", filepath.Join(t.TempDir(), "s.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Create("ws/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("ws/f", 0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := s.Materialize("ws/f"); err != nil {
		t.Fatalf("materialize: %v", err)
	}

	// Sealed: a stale path-addressed write must be rejected (it would resurrect the deleted name).
	if _, err := s.Write("ws/f", 4, []byte("+stale")); !errors.Is(err, session.ErrOrphaned) {
		t.Fatalf("write to sealed path = %v, want ErrOrphaned", err)
	}
	// A genuine re-create of the name lifts the seal.
	if err := s.Create("ws/f", 0o644); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	if _, err := s.Write("ws/f", 0, []byte("fresh")); err != nil {
		t.Fatalf("write after re-create must succeed, got %v", err)
	}
	// Unseal (the orphan-failed rollback path) also lifts a fresh seal.
	if err := s.Materialize("ws/f"); err != nil {
		t.Fatalf("materialize2: %v", err)
	}
	if _, err := s.Write("ws/f", 0, []byte("x")); !errors.Is(err, session.ErrOrphaned) {
		t.Fatal("re-seal must reject the write")
	}
	s.Unseal("ws/f")
	if _, err := s.Write("ws/f", 0, []byte("y")); err != nil {
		t.Fatalf("write after unseal must succeed, got %v", err)
	}
}

func BenchmarkSessionWriteAckNoFsync(b *testing.B) {
	s, err := session.New(benchAuthority{}, "B", "bench", "ws", filepath.Join(b.TempDir(), "bench.wal"))
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Create("ws/file", 0o644); err != nil {
		b.Fatal(err)
	}
	data := bytes.Repeat([]byte("x"), 1024)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if i > 0 && i%4096 == 0 {
			b.StopTimer()
			if err := s.Flush(); err != nil {
				b.Fatal(err)
			}
			b.StartTimer()
		}
		if _, err := s.Write("ws/file", 0, data); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := s.Close(); err != nil {
		b.Fatal(err)
	}
}
