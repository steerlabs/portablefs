package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type v7Commands struct {
	Pause, Resume, Epoch, Gateway string
}

func allCases() []coherenceCase {
	cases := baselineCases()
	loss := cases[len(cases)-1]
	cases = append(cases[:len(cases)-1], v7Cases()...)
	return append(cases, loss)
}

func (c *caseRun) barrier(who actor) {
	handle := c.ok(who, request{Op: "open", Flags: []string{"rdonly"}}).Handle
	c.ok(who, request{Op: "fsync", Handle: handle})
	c.ok(who, request{Op: "closehandle", Handle: handle})
}

func (c *caseRun) errno(who actor, req request, want syscall.Errno) {
	out := c.do(who, req)
	if out.Errno != int(want) {
		c.fail("%s %s errno=%d (%s), want %v", who.name(), req.Op, out.Errno, out.Err, want)
	}
}

func shellArgument(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func v7Cases() []coherenceCase {
	return []coherenceCase{
		{name: "peer_cached_handle_forces_writethrough", what: "a preexisting cached read descriptor sees each peer write before that write returns", run: func(c *caseRun) {
			target := c.p("cached")
			c.writeFile(c.a, target, []byte("initial"), 0o600)
			c.barrier(c.a)
			reader := c.ok(c.b, request{Op: "open", Path: target, Flags: []string{"rdonly"}}).Handle
			c.ok(c.b, request{Op: "pread", Handle: reader, Len: 7})
			writer := c.ok(c.a, request{Op: "open", Path: target, Flags: []string{"rdwr"}}).Handle
			for i := 0; i < 24; i++ {
				want := []byte(fmt.Sprintf("%07d", i))
				c.ok(c.a, request{Op: "pwrite", Handle: writer, Data: want})
				got := c.ok(c.b, request{Op: "pread", Handle: reader, Len: len(want)}).Data
				if !bytes.Equal(got, want) {
					c.fail("retained cacheable fd saw %q after peer wrote %q", got, want)
				}
			}
			c.barrier(c.a)
			c.ok(c.a, request{Op: "closehandle", Handle: writer})
			c.ok(c.b, request{Op: "closehandle", Handle: reader})
		}},
		{name: "git_index_lock_protocol", what: "cross-mount exclusive index.lock has one winner and publishes each index replacement to the peer", run: func(c *caseRun) {
			c.ok(c.a, request{Op: "mkdirall", Path: c.p(".git"), Mode: 0o700})
			index, lock := c.p(".git", "index"), c.p(".git", "index.lock")
			c.writeFile(c.a, index, []byte("initial index"), 0o600)
			c.expectBytes(c.a, index, []byte("initial index"), "prime index before lock competition")
			actors := []actor{c.a, c.b}
			var results [2]response
			var wg sync.WaitGroup
			for i := range actors {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					results[i] = c.do(actors[i], request{Op: "open", Path: lock, Flags: []string{"rdwr", "create", "excl"}, Mode: 0o600})
				}(i)
			}
			wg.Wait()
			winner, winners := -1, 0
			for i, out := range results {
				if out.Err == "" {
					winner = i
					winners++
				} else if out.Errno != int(syscall.EEXIST) {
					c.fail("lock contender %d: %s", i, out.Err)
				}
			}
			if winners != 1 {
				c.abort("exclusive lock winners=%d, want exactly one", winners)
			}
			handle := results[winner].Handle
			for round := 0; round < 2; round++ {
				want := []byte(fmt.Sprintf("index generation %d", round))
				c.ok(actors[winner], request{Op: "pwrite", Handle: handle, Data: want})
				c.ok(actors[winner], request{Op: "fsync", Handle: handle})
				c.ok(actors[winner], request{Op: "rename", Path: lock, To: index})
				c.ok(actors[winner], request{Op: "closehandle", Handle: handle})
				for _, who := range actors {
					c.expectBytes(who, index, want, "published git index")
				}
				c.barrier(actors[winner])
				if round == 0 {
					winner = 1 - winner
					handle = c.ok(actors[winner], request{Op: "open", Path: lock, Flags: []string{"rdwr", "create", "excl"}, Mode: 0o600}).Handle
				}
			}
		}},
		{name: "write_then_rename_flushes_before_visibility", what: "rename publishes buffered bytes to the peer while the writer fd stays open without prior fsync", run: func(c *caseRun) {
			target, temporary := c.p("published"), c.p("temporary")
			c.writeFile(c.a, target, []byte("old"), 0o600)
			c.expectBytes(c.a, target, []byte("old"), "prime rename destination")
			writer := c.ok(c.b, request{Op: "open", Path: temporary, Flags: []string{"rdwr", "create", "excl"}, Mode: 0o600}).Handle
			want := bytes.Repeat([]byte("buffered replacement"), 4096)
			c.ok(c.b, request{Op: "pwrite", Handle: writer, Data: want})
			c.ok(c.b, request{Op: "rename", Path: temporary, To: target})
			c.expectBytes(c.a, target, want, "first peer read after unsynced rename")
			c.barrier(c.b)
			c.ok(c.b, request{Op: "closehandle", Handle: writer})
		}},
		{name: "gateway_reads_delegated_data_without_obstructing_writer", what: "an authenticated cacheless gateway lists and reads buffered data while the writer remains responsive", run: func(c *caseRun) {
			if c.commands.Gateway == "" {
				c.skipCase("no --gateway-command supplied")
			}
			out := c.ok(c.a, request{Op: "run", Tag: c.commands.Gateway + " --gateway-probe-path " + shellArgument(c.p("gateway-data"))})
			observed := parseSummary(out.Str)
			for _, key := range []string{"listing_matches", "reads_match", "writer_remained_open"} {
				if observed[key] != "true" {
					c.fail("gateway %s=%q", key, observed[key])
				}
			}
			rounds, err := strconv.Atoi(observed["rounds"])
			if err != nil || rounds < 3 {
				c.fail("gateway rounds=%q", observed["rounds"])
			}
			elapsed, err := strconv.ParseInt(observed["maximum_write_millis"], 10, 64)
			if err != nil || elapsed >= 1000 {
				c.fail("gateway obstructed writer: maximum_write_millis=%q", observed["maximum_write_millis"])
			}
			c.barrier(c.a)
		}},
		{name: "recall_budget_loss_fails_barrier", what: "a holder missing recall reports EIO and a failed old-root barrier while the peer and fresh handles keep serving", run: func(c *caseRun) {
			if c.commands.Pause == "" || c.commands.Resume == "" {
				c.skipCase("pause and resume commands are required")
			}
			target := c.p("recalled")
			root := c.ok(c.b, request{Op: "open", Flags: []string{"rdonly"}}).Handle
			writer := c.ok(c.b, request{Op: "open", Path: target, Flags: []string{"rdwr", "create", "excl"}, Mode: 0o600}).Handle
			c.ok(c.b, request{Op: "pwrite", Handle: writer, Data: []byte("holder")})
			defer c.do(c.a, request{Op: "run", Tag: c.commands.Resume})
			c.ok(c.a, request{Op: "run", Tag: c.commands.Pause})
			start := time.Now()
			peer := c.ok(c.a, request{Op: "open", Path: target, Flags: []string{"rdwr"}}).Handle
			elapsed := time.Since(start)
			if elapsed < 4*time.Second || elapsed > 9*time.Second {
				c.fail("conflicting open waited %s, want recall-budget interval", elapsed)
			}
			c.ok(c.a, request{Op: "pwrite", Handle: peer, Data: []byte("winner")})
			c.barrier(c.a)
			c.errno(c.b, request{Op: "fsync", Handle: writer}, syscall.EIO)
			c.errno(c.b, request{Op: "fsync", Handle: root}, syscall.EIO)
			c.expectBytes(c.b, target, []byte("winner"), "fresh read after recall loss")
			c.barrier(c.b)
			c.ok(c.a, request{Op: "closehandle", Handle: peer})
			c.note("peer acquired after %s; old holder and run barrier reported EIO", elapsed.Round(time.Millisecond))
		}},
		{name: "epoch_change_stales_handles_and_new_barrier_passes", what: "Authority replacement stales old file/root handles and admits fresh durable work without remounting", run: func(c *caseRun) {
			if c.commands.Epoch == "" {
				c.skipCase("no --epoch-command supplied")
			}
			target := c.p("epoch-file")
			c.writeFile(c.a, target, []byte("durable epoch data"), 0o600)
			root := c.ok(c.a, request{Op: "open", Flags: []string{"rdonly"}}).Handle
			file := c.ok(c.a, request{Op: "open", Path: target, Flags: []string{"rdwr"}}).Handle
			c.ok(c.a, request{Op: "fsync", Handle: root})
			c.ok(c.a, request{Op: "run", Tag: c.commands.Epoch})
			deadline := time.Now().Add(30 * time.Second)
			recovered := false
			for time.Now().Before(deadline) {
				fresh := c.do(c.a, request{Op: "open", Flags: []string{"rdonly"}})
				if fresh.Err == "" {
					synced := c.do(c.a, request{Op: "fsync", Handle: fresh.Handle})
					c.do(c.a, request{Op: "closehandle", Handle: fresh.Handle})
					if synced.Err == "" {
						recovered = true
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !recovered {
				c.abort("new root barrier did not recover within 30s")
			}
			for _, req := range []request{{Op: "pread", Handle: file, Len: 1}, {Op: "pwrite", Handle: file, Data: []byte("x")}, {Op: "fstat", Handle: file}, {Op: "fsync", Handle: file}, {Op: "fsync", Handle: root}} {
				c.errno(c.a, req, syscall.EIO)
			}
			c.expectBytes(c.a, target, []byte("durable epoch data"), "fresh file after epoch replacement")
			freshName := c.p("new-epoch-write")
			c.writeFile(c.a, freshName, []byte("new epoch data"), 0o600)
			c.expectBytes(c.b, freshName, []byte("new epoch data"), "peer reads new epoch mutation")
			c.barrier(c.a)
			c.barrier(c.b)
		}},
	}
}
