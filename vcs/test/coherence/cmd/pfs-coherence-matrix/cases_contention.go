package main

import (
	"bytes"
	"sync"
)

func ordinaryContentionCases() []coherenceCase {
	return []coherenceCase{
		{name: "same_mount_editor_save_with_reader", what: "an editor save races a reader on its own mount and publishes the final generation to the peer", run: func(c *caseRun) {
			target := c.p("document")
			c.writeFile(c.b, target, bytes.Repeat([]byte("."), 4096), 0o600)
			c.expectBytes(c.a, target, bytes.Repeat([]byte("."), 4096), "initial editor generation")
			c.ok(c.b, request{Op: "burst_editor_save", Path: target, Count: 400, Size: 4096})
			want := bytes.Repeat([]byte("B"), 4096)
			c.expectBytes(c.a, target, want, "final editor generation on peer")
			c.expectBytes(c.b, target, want, "final editor generation on source")
			c.barrier(c.a)
			c.barrier(c.b)
		}},
		{name: "two_local_truncating_writers_and_peer", what: "two in-place writers sharing a mount compete with a peer without stalling the volume", run: func(c *caseRun) {
			target := c.p("overwrite")
			initial := bytes.Repeat([]byte("."), 4096)
			c.writeFile(c.a, target, initial, 0o600)
			c.expectBytes(c.a, target, initial, "initial overwrite generation")
			var results [2]response
			var joined sync.WaitGroup
			joined.Add(2)
			go func() {
				defer joined.Done()
				results[0] = c.do(c.a, request{Op: "burst_truncate_overwrite", Path: target, Count: 200, Size: 4096, Len: 2, Fill: 'A'})
			}()
			go func() {
				defer joined.Done()
				results[1] = c.do(c.b, request{Op: "burst_truncate_overwrite", Path: target, Count: 200, Size: 4096, Len: 1, Fill: 'C'})
			}()
			joined.Wait()
			for index, result := range results {
				if result.Err != "" {
					c.abort("overwrite group %d: %s", index, result.Err)
				}
			}
			data, err := c.readBytes(c.a, target)
			if err != "" || len(data) != 4096 {
				c.abort("final overwrite bytes=%d error=%s", len(data), err)
			}
			valid := false
			for _, fill := range []byte{'A', 'B', 'C'} {
				valid = valid || bytes.Equal(data, bytes.Repeat([]byte{fill}, 4096))
			}
			if !valid {
				c.fail("final overwrite mixed writer records")
			}
			c.expectBytes(c.b, target, data, "same overwrite record on peer")
			c.barrier(c.a)
			c.barrier(c.b)
		}},
	}
}
