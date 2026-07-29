package fsproto

import (
	"encoding/binary"
	"io"
	"sync"
	"testing"
)

// TestAtomicAppendAcrossClients exercises the entire wire/exact/WAL path.
// Every request is one RPC and the authority returns the offset it selected
// in sequencer order. Fixed-size unique records make overlap, loss, or
// duplication observable without assuming goroutine scheduling order.
func TestAtomicAppendAcrossClients(t *testing.T) {
	fs, addr := serveFS(t)
	const (
		clientsN  = 8
		perClient = 32
		recordLen = 16
	)
	clients := make([]*Client, clientsN)
	for i := range clients {
		cli, err := Dial(addr, 4)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cli.Close() })
		cli.SetOwner("append-client")
		if _, err := cli.EnsureExactSession(); err != nil {
			t.Fatal(err)
		}
		clients[i] = cli
	}
	if _, st, err := clients[0].Create("log", 0o644); err != nil || st != OK {
		t.Fatalf("create: status=%d err=%v", st, err)
	}

	offsets := make(chan int64, clientsN*perClient)
	errs := make(chan error, clientsN)
	var wg sync.WaitGroup
	for writer := 0; writer < clientsN; writer++ {
		writer := writer
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := 0; seq < perClient; seq++ {
				record := make([]byte, recordLen)
				binary.BigEndian.PutUint32(record[0:4], uint32(writer))
				binary.BigEndian.PutUint32(record[4:8], uint32(seq))
				copy(record[8:], "PFSAPPND")
				n, off, _, _, st, err := clients[writer].AppendVHandle("log", 0, record, 0o644)
				if err != nil {
					errs <- err
					return
				}
				if st != OK || n != len(record) {
					errs <- &appendTestError{status: st, count: n}
					return
				}
				offsets <- off
			}
		}()
	}
	wg.Wait()
	close(errs)
	close(offsets)
	for err := range errs {
		t.Fatal(err)
	}

	wantRecords := clientsN * perClient
	seenOffsets := make(map[int64]bool, wantRecords)
	for off := range offsets {
		if off < 0 || off%recordLen != 0 {
			t.Fatalf("authority returned unaligned append offset %d", off)
		}
		if seenOffsets[off] {
			t.Fatalf("authority returned duplicate append offset %d", off)
		}
		seenOffsets[off] = true
	}
	if len(seenOffsets) != wantRecords {
		t.Fatalf("returned offsets=%d, want %d", len(seenOffsets), wantRecords)
	}

	f, err := fs.Open("log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != wantRecords*recordLen {
		t.Fatalf("file length=%d, want %d", len(data), wantRecords*recordLen)
	}
	seenRecords := make(map[uint64]bool, wantRecords)
	for off := 0; off < len(data); off += recordLen {
		record := data[off : off+recordLen]
		if string(record[8:]) != "PFSAPPND" {
			t.Fatalf("corrupt/overlapped record at offset %d: %x", off, record)
		}
		key := uint64(binary.BigEndian.Uint32(record[0:4]))<<32 |
			uint64(binary.BigEndian.Uint32(record[4:8]))
		if seenRecords[key] {
			t.Fatalf("duplicate record key %#x", key)
		}
		seenRecords[key] = true
	}
	if len(seenRecords) != wantRecords {
		t.Fatalf("records=%d, want %d", len(seenRecords), wantRecords)
	}
}

type appendTestError struct {
	status int32
	count  int
}

func (e *appendTestError) Error() string {
	return "append returned non-OK status or short count"
}
