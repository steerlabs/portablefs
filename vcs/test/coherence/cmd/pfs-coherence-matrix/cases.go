package main

import (
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// A coherenceCase is one named POSIX semantic that the product claims to
// provide across mounts. The name is the contract identifier: the Linux matrix
// and the macOS matrix run the same names so their results are directly
// comparable, and a case that cannot be honestly asserted on a platform must
// skip with a stated reason rather than pass.
type coherenceCase struct {
	name string
	// what states the product promise in one line, so a report is readable
	// without the source.
	what string
	// destructive marks a case that leaves a mount unusable. Those run last.
	destructive bool
	run         func(*caseRun)
}

type caseRun struct {
	a, b actor
	dir  string
	// mu guards the recorded results. A case that exceeds its wall clock bound
	// is reported while its goroutine may still be running, so the reader and
	// the case body genuinely race without it.
	mu       sync.Mutex
	notes    []string
	failures []string
	skip     string
	altGID   int
	fenceCmd string
	replaces int
	// localRoute is the workspace-relative directory the two mounts were told to
	// serve from their own machine-local backing. Empty means the harness was
	// not told about one, and the route cases skip loudly rather than assert a
	// property nobody configured.
	localRoute string
	// routesContract is a shell command that attaches with a deliberately stale
	// routing revision WITHOUT adopting, then adopts and retries, and prints a
	// key=value summary of what it observed. The mount binary adopts and retries
	// by itself, so asserting the refusal needs a client that does not. Empty
	// means the same loud skip.
	routesContract string
}

// sameDirToleratedFencedMounts is deliberately zero. The frontend reports a
// blocked repair only when its exact cached-binding and parked-directory
// registries prove the i_rwsem cycle, and racing reads leave Stabilize at apply
// rather than holding the directory lock until COMPLETE. Fencing either healthy
// participant is therefore a regression, not a tolerated liveness outcome.
const sameDirToleratedFencedMounts = 0

// sameDirStormBound is how long the two storms get before the case calls it a
// deadlock. It is not a settling delay and nothing is retried inside it: it is
// the bound that turns "this hangs forever" into a reported failure instead of a
// harness that never returns.
const sameDirStormBound = 3 * time.Minute

type abortCase struct{ reason string }

func (c *caseRun) note(format string, arguments ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notes = append(c.notes, fmt.Sprintf(format, arguments...))
}

// fail records a semantic violation and keeps going, so one run reports every
// way a case is broken rather than only the first.
func (c *caseRun) fail(format string, arguments ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = append(c.failures, fmt.Sprintf(format, arguments...))
}

func (c *caseRun) snapshot() (notes, failures []string, skip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.notes...), append([]string{}, c.failures...), c.skip
}

func (c *caseRun) setSkip(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.skip = reason
}

// abort ends the case immediately. Used when the harness itself cannot proceed
// (a setup step failed), never to hide a semantic failure.
func (c *caseRun) abort(format string, arguments ...any) {
	panic(abortCase{reason: fmt.Sprintf(format, arguments...)})
}

func (c *caseRun) skipCase(format string, arguments ...any) {
	c.setSkip(fmt.Sprintf(format, arguments...))
	panic(abortCase{reason: ""})
}

func (c *caseRun) p(elements ...string) string {
	return path.Join(append([]string{c.dir}, elements...)...)
}

// do executes an operation and returns the reply, including an operation-level
// error. A transport failure aborts: the harness has lost the ability to
// observe anything, which is not the same as an assertion failing.
func (c *caseRun) do(who actor, req request) response {
	out, err := who.exec(req)
	if err != nil {
		c.abort("%s: %s %s: transport failure: %v", who.name(), req.Op, req.Path, err)
	}
	return out
}

// ok executes an operation that must succeed for the case to mean anything.
func (c *caseRun) ok(who actor, req request) response {
	out := c.do(who, req)
	if out.Err != "" {
		c.abort("%s: %s %s: %s", who.name(), req.Op, req.Path, out.Err)
	}
	return out
}

// mustFail asserts that an operation is refused. Used for the negative half of
// the namespace contract, where a quiet success is the bug.
func (c *caseRun) mustFail(who actor, req request, what string) {
	out := c.do(who, req)
	if out.Err == "" {
		c.fail("%s: %s %s unexpectedly succeeded; %s", who.name(), req.Op, req.Path, what)
	}
}

func (c *caseRun) writeFile(who actor, relative string, data []byte, mode uint32) {
	c.ok(who, request{Op: "writefile", Path: relative, Data: data, Mode: mode})
}

// readBytes returns the bytes a mount can actually read from a name, by reading
// an open descriptor to EOF. It never trusts a size attribute.
func (c *caseRun) readBytes(who actor, relative string) ([]byte, string) {
	out := c.do(who, request{Op: "readfile", Path: relative})
	if out.Err != "" {
		return nil, out.Err
	}
	return out.Data, ""
}

func (c *caseRun) stat(who actor, relative string) (*statInfo, string) {
	out := c.do(who, request{Op: "stat", Path: relative})
	if out.Err != "" {
		return nil, out.Err
	}
	return out.Stat, ""
}

func (c *caseRun) names(who actor, relative string) []string {
	out := c.ok(who, request{Op: "readdir", Path: relative})
	names := append([]string{}, out.Names...)
	sort.Strings(names)
	return names
}

func (c *caseRun) expectBytes(who actor, relative string, want []byte, what string) {
	got, err := c.readBytes(who, relative)
	if err != "" {
		c.fail("%s: reading %s (%s) failed: %s", who.name(), relative, what, err)
		return
	}
	if !bytes.Equal(got, want) {
		c.fail("%s: %s (%s) has %d readable bytes %q, want %d bytes %q",
			who.name(), relative, what, len(got), preview(got), len(want), preview(want))
	}
}

// parseSummary reads the key=value report a harness helper prints. Anything
// that is not a key=value line is ignored, so a helper may also write prose for
// a human without the parse having to know about it.
func parseSummary(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || key == "" {
			continue
		}
		out[key] = value
	}
	return out
}

// mountFenced reports whether this mount has revoked itself. A strict frontend
// that misses its declared repair budget withdraws every binding it published
// and aborts its kernel connection, after which the kernel answers every request
// with ENOTCONN. That is a definite answer, not a hang, so the harness can tell
// "fenced" apart from "wedged" without any privileged inspection.
func (c *caseRun) mountFenced(who actor) bool {
	out := c.do(who, request{Op: "stat", Path: c.dir})
	return out.Errno == int(syscall.ENOTCONN)
}

// stillServes proves this mount can still complete a full create/read/unlink
// round trip. It is the difference between "the volume kept serving" and "every
// request happened to return an error quickly".
func (c *caseRun) stillServes(who actor, tag string) (bool, string) {
	relative := c.p("liveness-" + tag)
	payload := []byte("liveness-" + tag + "\n")
	if out := c.do(who, request{Op: "writefile", Path: relative, Data: payload, Mode: 0o644}); out.Err != "" {
		return false, "create: " + out.Err
	}
	got, err := c.readBytes(who, relative)
	if err != "" {
		return false, "read: " + err
	}
	if !bytes.Equal(got, payload) {
		return false, fmt.Sprintf("read back %q, want %q", preview(got), preview(payload))
	}
	if out := c.do(who, request{Op: "remove", Path: relative}); out.Err != "" {
		return false, "unlink: " + out.Err
	}
	return true, ""
}

func preview(data []byte) string {
	const limit = 48
	if len(data) <= limit {
		return string(data)
	}
	return string(data[:limit]) + fmt.Sprintf("...(+%d)", len(data)-limit)
}

// ---------------------------------------------------------------------------
// the matrix
// ---------------------------------------------------------------------------

func allCases() []coherenceCase {
	return []coherenceCase{
		{
			name: "remote_create_visible",
			what: "a file created on one mount is visible and readable on the other with no polling",
			run: func(c *caseRun) {
				payload := []byte("created-on-B\n")
				c.writeFile(c.b, c.p("created.txt"), payload, 0o644)
				got := c.names(c.a, c.dir)
				if !contains(got, "created.txt") {
					c.fail("%s: first readdir after the remote create returned %v, want it to contain created.txt", c.a.name(), got)
				}
				c.expectBytes(c.a, c.p("created.txt"), payload, "remote create")
				if info, err := c.stat(c.a, c.p("created.txt")); err != "" {
					c.fail("%s: stat after the remote create failed: %s", c.a.name(), err)
				} else if info.Size != int64(len(payload)) {
					c.fail("%s: stat size %d disagrees with the %d bytes written remotely", c.a.name(), info.Size, len(payload))
				}
			},
		},
		{
			name: "remote_unlink_name_gone",
			what: "a name unlinked on one mount stops resolving on the other, including reopen",
			run: func(c *caseRun) {
				payload := []byte("doomed\n")
				c.writeFile(c.a, c.p("doomed.txt"), payload, 0o644)
				c.expectBytes(c.b, c.p("doomed.txt"), payload, "pre-unlink")
				// Observe the positive binding on the mount that must later drop
				// it. Besides matching the kernel-cache contract exactly, this
				// gives the falsifiability control a real pre-unlink answer to
				// freeze instead of letting its first stat happen after removal.
				if _, err := c.stat(c.a, c.p("doomed.txt")); err != "" {
					c.abort("%s: stat before remote unlink: %s", c.a.name(), err)
				}
				c.ok(c.b, request{Op: "remove", Path: c.p("doomed.txt")})
				if _, err := c.stat(c.a, c.p("doomed.txt")); err == "" {
					c.fail("%s: stat still resolves a name unlinked on %s", c.a.name(), c.b.name())
				}
				c.mustFail(c.a, request{Op: "open", Path: c.p("doomed.txt"), Flags: []string{"rdonly"}},
					"a deleted file must not be reopenable")
				if got := c.names(c.a, c.dir); contains(got, "doomed.txt") {
					c.fail("%s: directory listing still contains the unlinked name: %v", c.a.name(), got)
				}
			},
		},
		{
			name: "remote_unlink_open_fd_posix",
			what: "an fd open across a remote unlink keeps reading and writing the unlinked inode",
			run: func(c *caseRun) {
				payload := []byte("open-unlinked-payload\n")
				c.writeFile(c.a, c.p("held.txt"), payload, 0o644)
				handle := c.ok(c.a, request{Op: "open", Path: c.p("held.txt"), Flags: []string{"rdwr"}}).Handle
				c.ok(c.b, request{Op: "remove", Path: c.p("held.txt")})

				after := c.do(c.a, request{Op: "readall", Handle: handle})
				if after.Err != "" {
					c.fail("%s: reading the retained descriptor after the remote unlink failed: %s", c.a.name(), after.Err)
				} else if !bytes.Equal(after.Data, payload) {
					c.fail("%s: retained descriptor read %d bytes %q, want the %d unlinked bytes %q",
						c.a.name(), len(after.Data), preview(after.Data), len(payload), preview(payload))
				}
				extra := []byte("still-writable\n")
				if out := c.do(c.a, request{Op: "pwrite", Handle: handle, Off: int64(len(payload)), Data: extra}); out.Err != "" {
					c.fail("%s: writing the retained descriptor after the remote unlink failed: %s", c.a.name(), out.Err)
				} else if reread := c.do(c.a, request{Op: "readall", Handle: handle}); reread.Err != "" {
					c.fail("%s: re-reading the retained descriptor failed: %s", c.a.name(), reread.Err)
				} else if want := append(append([]byte{}, payload...), extra...); !bytes.Equal(reread.Data, want) {
					c.fail("%s: retained descriptor read back %q, want %q", c.a.name(), preview(reread.Data), preview(want))
				}
				if out := c.do(c.a, request{Op: "fstat", Handle: handle}); out.Err == "" && out.Stat != nil {
					c.note("retained descriptor reports nlink=%d size=%d", out.Stat.Nlink, out.Stat.Size)
				}
				c.mustFail(c.a, request{Op: "open", Path: c.p("held.txt"), Flags: []string{"rdonly"}},
					"the name is unlinked, so only the retained descriptor may reach the inode")
				c.ok(c.a, request{Op: "closehandle", Handle: handle})
			},
		},
		{
			name: "atomic_replace_new_inode",
			what: "create-temp/write/rename-over is observed on the other mount as the new inode with the new bytes",
			run: func(c *caseRun) {
				target := c.p("config.json")
				c.writeFile(c.a, target, []byte("generation-0"), 0o644)
				previous, err := c.stat(c.a, target)
				if err != "" {
					c.abort("%s: stat the initial target: %s", c.a.name(), err)
				}
				rounds := c.replaces
				good := 0
				for round := 1; round <= rounds; round++ {
					payload := []byte(fmt.Sprintf("generation-%d-%s", round, strings.Repeat("x", round)))
					produced := c.ok(c.b, request{Op: "atomic_replace", Path: target, Data: payload, Mode: 0o644})
					observed, statErr := c.stat(c.a, target)
					if statErr != "" {
						c.fail("round %d: %s cannot stat the replaced target: %s", round, c.a.name(), statErr)
						continue
					}
					data, readErr := c.readBytes(c.a, target)
					roundOK := true
					if readErr != "" {
						c.fail("round %d: %s cannot read the replaced target: %s", round, c.a.name(), readErr)
						roundOK = false
					} else if !bytes.Equal(data, payload) {
						c.fail("round %d: %s read %q, want %q (stale binding to the replaced inode)",
							round, c.a.name(), preview(data), preview(payload))
						roundOK = false
					}
					if observed.Ino == previous.Ino {
						c.fail("round %d: %s still resolves the old inode %d after the rename-over; %s created inode %d",
							round, c.a.name(), observed.Ino, c.b.name(), produced.Stat.Ino)
						roundOK = false
					}
					if observed.Size != int64(len(payload)) {
						c.fail("round %d: %s reports size %d for a %d byte replacement", round, c.a.name(), observed.Size, len(payload))
						roundOK = false
					}
					if roundOK {
						good++
					}
					previous = observed
				}
				c.note("atomic replacement observed correctly in %d/%d rounds", good, rounds)
			},
		},
		{
			name: "rename_old_gone_new_present_same_inode",
			what: "after a remote rename the old name is gone, the new name resolves, and the inode is unchanged",
			run: func(c *caseRun) {
				payload := []byte("renamed-content\n")
				c.writeFile(c.a, c.p("old-name"), payload, 0o644)
				before, err := c.stat(c.a, c.p("old-name"))
				if err != "" {
					c.abort("%s: stat before rename: %s", c.a.name(), err)
				}
				c.ok(c.b, request{Op: "rename", Path: c.p("old-name"), To: c.p("new-name")})
				if _, err := c.stat(c.a, c.p("old-name")); err == "" {
					c.fail("%s: the old name still resolves after the remote rename", c.a.name())
				}
				after, err := c.stat(c.a, c.p("new-name"))
				if err != "" {
					c.fail("%s: the new name does not resolve after the remote rename: %s", c.a.name(), err)
				} else if after.Ino != before.Ino {
					c.fail("%s: rename changed the inode from %d to %d; a rename must preserve inode identity",
						c.a.name(), before.Ino, after.Ino)
				}
				c.expectBytes(c.a, c.p("new-name"), payload, "post-rename")
				got := c.names(c.a, c.dir)
				if contains(got, "old-name") || !contains(got, "new-name") {
					c.fail("%s: listing after the remote rename is %v, want exactly the new name", c.a.name(), got)
				}
			},
		},
		{
			name: "remote_chmod_visible",
			what: "mode bits changed on one mount are observed on the other, not served from a stale attribute cache",
			run: func(c *caseRun) {
				c.writeFile(c.a, c.p("modes"), []byte("m"), 0o644)
				if _, err := c.stat(c.a, c.p("modes")); err != "" {
					c.abort("%s: prime the attribute cache: %s", c.a.name(), err)
				}
				for _, mode := range []uint32{0o600, 0o705, 0o640} {
					c.ok(c.b, request{Op: "chmod", Path: c.p("modes"), Mode: mode})
					info, err := c.stat(c.a, c.p("modes"))
					if err != "" {
						c.fail("%s: stat after remote chmod %04o: %s", c.a.name(), mode, err)
						continue
					}
					if info.Perm != mode {
						c.fail("%s: observed mode %04o after a remote chmod to %04o (stale mode bits)", c.a.name(), info.Perm, mode)
					}
				}
			},
		},
		{
			name: "remote_chown_visible",
			what: "an ownership change made on one mount is observed on the other",
			run: func(c *caseRun) {
				if c.altGID <= 0 {
					c.skipCase("no alternate GID supplied (--alt-gid); an unprivileged process cannot make an ownership change that is observable, and asserting a chown to the identity it already has would be vacuous")
				}
				c.writeFile(c.a, c.p("owned"), []byte("o"), 0o644)
				before, err := c.stat(c.a, c.p("owned"))
				if err != "" {
					c.abort("%s: stat before chown: %s", c.a.name(), err)
				}
				if int(before.GID) == c.altGID {
					c.skipCase("the file already has GID %d, so changing to it would assert nothing", c.altGID)
				}
				out := c.do(c.b, request{Op: "chown", Path: c.p("owned"), UID: -1, GID: c.altGID})
				if out.Errno == int(syscall.EPERM) {
					// Not a coherence failure. The v3 volume model is
					// deliberately single-principal (see the ownership section
					// of docs/xfs-authority-architecture.md): every inode is
					// owned by the volume worker's service identity, each mount
					// projects that principal to its local user, and a chown to
					// any other principal is refused with EPERM by design.
					// There is therefore no ownership change that could be
					// observed, and pretending otherwise would be a pass this
					// case did not earn.
					c.skipCase("the volume refused the ownership change with EPERM. The v3 volume model is single-principal by design, so no cross-principal ownership change exists to observe. If multiple POSIX principals are ever supported, this case becomes assertable and must be re-enabled.")
				}
				if out.Err != "" {
					c.abort("%s: chown to GID %d: %s", c.b.name(), c.altGID, out.Err)
				}
				after, err := c.stat(c.a, c.p("owned"))
				if err != "" {
					c.fail("%s: stat after the remote chown: %s", c.a.name(), err)
				} else if int(after.GID) != c.altGID {
					c.fail("%s: observed GID %d after a remote chown to %d (stale ownership)", c.a.name(), after.GID, c.altGID)
				}
			},
		},
		{
			name: "remote_utimes_visible",
			what: "timestamps set on one mount are observed exactly on the other",
			run: func(c *caseRun) {
				c.writeFile(c.a, c.p("stamped"), []byte("t"), 0o644)
				if _, err := c.stat(c.a, c.p("stamped")); err != "" {
					c.abort("%s: prime the attribute cache: %s", c.a.name(), err)
				}
				wantMtime := time.Date(2001, time.February, 3, 4, 5, 6, 123456789, time.UTC).UnixNano()
				wantAtime := time.Date(2002, time.March, 4, 5, 6, 7, 987654321, time.UTC).UnixNano()
				c.ok(c.b, request{Op: "utimes", Path: c.p("stamped"), AtimeNs: wantAtime, MtimeNs: wantMtime})
				info, err := c.stat(c.a, c.p("stamped"))
				if err != "" {
					c.fail("%s: stat after remote utimes: %s", c.a.name(), err)
					return
				}
				if info.MtimeNs != wantMtime {
					c.fail("%s: observed mtime %d after a remote utimes to %d (delta %dns)",
						c.a.name(), info.MtimeNs, wantMtime, info.MtimeNs-wantMtime)
				}
				if info.AtimeNs != wantAtime {
					c.fail("%s: observed atime %d after a remote utimes to %d (delta %dns)",
						c.a.name(), info.AtimeNs, wantAtime, info.AtimeNs-wantAtime)
				}
			},
		},
		{
			name: "remote_truncate_grow_readable_eof",
			what: "a remote grow is observed as readable bytes to the new EOF, not only as a larger stat size",
			run: func(c *caseRun) {
				original := bytes.Repeat([]byte("a"), 1000)
				c.writeFile(c.a, c.p("grow"), original, 0o644)
				c.expectBytes(c.a, c.p("grow"), original, "before the remote grow")
				c.ok(c.b, request{Op: "truncate", Path: c.p("grow"), Size: 5000})
				want := append(append([]byte{}, original...), make([]byte, 4000)...)
				got, err := c.readBytes(c.a, c.p("grow"))
				if err != "" {
					c.fail("%s: read after the remote grow: %s", c.a.name(), err)
					return
				}
				if len(got) != 5000 {
					c.fail("%s: %d bytes are readable after a remote grow to 5000", c.a.name(), len(got))
				}
				if !bytes.Equal(got, want) {
					c.fail("%s: readable content after the remote grow is not the original 1000 bytes followed by 4000 zero bytes", c.a.name())
				}
				if info, statErr := c.stat(c.a, c.p("grow")); statErr == "" && info.Size != int64(len(got)) {
					c.fail("%s: stat size %d disagrees with the %d readable bytes", c.a.name(), info.Size, len(got))
				}
			},
		},
		{
			name: "remote_truncate_shrink_readable_eof",
			what: "a remote shrink is observed as a shorter readable EOF, not a stale tail",
			run: func(c *caseRun) {
				original := bytes.Repeat([]byte("b"), 4096)
				c.writeFile(c.a, c.p("shrink"), original, 0o644)
				c.expectBytes(c.a, c.p("shrink"), original, "before the remote shrink")
				c.ok(c.b, request{Op: "truncate", Path: c.p("shrink"), Size: 400})
				got, err := c.readBytes(c.a, c.p("shrink"))
				if err != "" {
					c.fail("%s: read after the remote shrink: %s", c.a.name(), err)
					return
				}
				if len(got) != 400 || !bytes.Equal(got, original[:400]) {
					c.fail("%s: %d bytes readable after a remote shrink to 400 (stale tail retained)", c.a.name(), len(got))
				}
				if info, statErr := c.stat(c.a, c.p("shrink")); statErr == "" && info.Size != int64(len(got)) {
					c.fail("%s: stat size %d disagrees with the %d readable bytes", c.a.name(), info.Size, len(got))
				}
			},
		},
		{
			name: "dir_listing_reflects_remote_creates_and_deletes",
			what: "an enumeration on one mount reflects creates and deletes performed on the other",
			run: func(c *caseRun) {
				for _, name := range []string{"keep-1", "keep-2", "drop-1", "drop-2"} {
					c.writeFile(c.a, c.p(name), []byte(name), 0o644)
				}
				for _, name := range []string{"remote-1", "remote-2", "remote-3"} {
					c.writeFile(c.b, c.p(name), []byte(name), 0o644)
				}
				c.ok(c.b, request{Op: "remove", Path: c.p("drop-1")})
				c.ok(c.b, request{Op: "remove", Path: c.p("drop-2")})
				want := []string{"keep-1", "keep-2", "remote-1", "remote-2", "remote-3"}
				got := c.names(c.a, c.dir)
				if strings.Join(got, ",") != strings.Join(want, ",") {
					c.fail("%s: listing is %v, want exactly %v", c.a.name(), got, want)
				}
				for _, name := range want {
					c.expectBytes(c.a, c.p(name), []byte(name), "listed entry")
				}
			},
		},
		{
			name: "concurrent_writers_distinct_files",
			what: "both mounts writing distinct files concurrently lose nothing and both see the full result",
			run: func(c *caseRun) {
				const perSide = 150
				var wait sync.WaitGroup
				results := make([]response, 2)
				wait.Add(2)
				go func() {
					defer wait.Done()
					results[0] = c.do(c.a, request{Op: "burst_create", Path: c.dir, Count: perSide, Tag: "aa"})
				}()
				go func() {
					defer wait.Done()
					results[1] = c.do(c.b, request{Op: "burst_create", Path: c.dir, Count: perSide, Tag: "bb"})
				}()
				wait.Wait()
				for index, out := range results {
					if out.Err != "" {
						c.fail("burst %d wrote %d/%d files then failed: %s", index, out.N, perSide, out.Err)
					}
				}
				want := make([]string, 0, 2*perSide)
				for i := range perSide {
					want = append(want, fmt.Sprintf("aa-%08d", i), fmt.Sprintf("bb-%08d", i))
				}
				sort.Strings(want)
				for _, who := range []actor{c.a, c.b} {
					got := c.names(who, c.dir)
					if strings.Join(got, ",") != strings.Join(want, ",") {
						c.fail("%s: sees %d entries, want %d (missing or extra names after concurrent creates)", who.name(), len(got), len(want))
					}
				}
				for i := range perSide {
					c.expectBytes(c.a, c.p(fmt.Sprintf("bb-%08d", i)), record("bb", i), "written by the other mount")
					c.expectBytes(c.b, c.p(fmt.Sprintf("aa-%08d", i)), record("aa", i), "written by the other mount")
				}
			},
		},
		{
			name: "concurrent_same_file_append_atomicity",
			what: "concurrent O_APPEND writers to one file lose no record and tear no record; the interleaving is free",
			run: func(c *caseRun) {
				const perSide = 250
				target := c.p("shared-append")
				c.writeFile(c.a, target, nil, 0o644)
				var wait sync.WaitGroup
				results := make([]response, 2)
				wait.Add(2)
				go func() {
					defer wait.Done()
					results[0] = c.do(c.a, request{Op: "burst_append", Path: target, Count: perSide, Tag: "AAA"})
				}()
				go func() {
					defer wait.Done()
					results[1] = c.do(c.b, request{Op: "burst_append", Path: target, Count: perSide, Tag: "BBB"})
				}()
				wait.Wait()
				for index, out := range results {
					if out.Err != "" {
						c.abort("append burst %d appended %d/%d records then failed: %s", index, out.N, perSide, out.Err)
					}
				}
				data, err := c.readBytes(c.a, target)
				if err != "" {
					c.abort("%s: read the shared append file: %s", c.a.name(), err)
				}
				if len(data) != 2*perSide*recordSize {
					c.fail("%s: the shared file holds %d bytes, want %d (%d records lost or overwritten)",
						c.a.name(), len(data), 2*perSide*recordSize, (2*perSide*recordSize-len(data))/recordSize)
				}
				seen := map[string]int{}
				torn := 0
				for offset := 0; offset+recordSize <= len(data); offset += recordSize {
					entry := data[offset : offset+recordSize]
					if entry[recordSize-1] != '\n' {
						torn++
						continue
					}
					seen[string(bytes.TrimRight(entry[:recordSize-1], "."))]++
				}
				if torn != 0 {
					c.fail("%s: %d of %d record slots are torn; a single append write must be atomic", c.a.name(), torn, len(data)/recordSize)
				}
				missing, duplicated := 0, 0
				for _, tag := range []string{"AAA", "BBB"} {
					for i := range perSide {
						key := fmt.Sprintf("%s-%08d", tag, i)
						switch count := seen[key]; {
						case count == 0:
							missing++
						case count > 1:
							duplicated++
						}
					}
				}
				if missing != 0 || duplicated != 0 {
					c.fail("%s: %d records missing and %d duplicated after concurrent cross-mount appends", c.a.name(), missing, duplicated)
				}
				// Read from the other mount too: both must observe the same file.
				c.expectBytes(c.b, target, data, "the same shared append file seen from the other mount")
			},
		},
		{
			name: "concurrent_same_file_overwrite_integrity",
			what: "concurrent whole-record overwrites of one file leave one writer's record, never a mixture",
			run: func(c *caseRun) {
				const (
					size   = 4096
					rounds = 60
				)
				target := c.p("shared-overwrite")
				initial := bytes.Repeat([]byte("."), size)
				c.writeFile(c.a, target, initial, 0o644)
				// Establish the exact pre-storm generation before either writer
				// starts. Without this observation the stale-view control races the
				// B burst and can freeze a completed, valid B record, making the
				// deliberately broken run nondeterministically pass.
				c.expectBytes(c.a, target, initial, "initial generation before concurrent overwrites")
				var wait sync.WaitGroup
				results := make([]response, 2)
				wait.Add(2)
				go func() {
					defer wait.Done()
					results[0] = c.do(c.a, request{Op: "burst_overwrite", Path: target, Count: rounds, Size: size, Fill: 'A'})
				}()
				go func() {
					defer wait.Done()
					results[1] = c.do(c.b, request{Op: "burst_overwrite", Path: target, Count: rounds, Size: size, Fill: 'B'})
				}()
				wait.Wait()
				for index, out := range results {
					if out.Err != "" {
						c.abort("overwrite burst %d failed: %s", index, out.Err)
					}
				}
				data, err := c.readBytes(c.a, target)
				if err != "" {
					c.abort("%s: read the shared overwrite file: %s", c.a.name(), err)
				}
				if len(data) != size {
					c.fail("%s: the shared file holds %d bytes, want %d", c.a.name(), len(data), size)
				}
				if !bytes.Equal(data, bytes.Repeat([]byte{'A'}, len(data))) && !bytes.Equal(data, bytes.Repeat([]byte{'B'}, len(data))) {
					aCount := bytes.Count(data, []byte{'A'})
					bCount := bytes.Count(data, []byte{'B'})
					c.fail("%s: the file is not one complete writer record (%d A bytes, %d B bytes, %d other bytes); one %d byte write must replace the prior generation atomically",
						c.a.name(), aCount, bCount, len(data)-aCount-bCount, size)
				}
				c.expectBytes(c.b, target, data, "the same shared file seen from the other mount")
			},
		},
		{
			name: "hardlink_visible_same_inode",
			what: "a hard link made on one mount is observed on the other as the same inode with the right link count",
			run: func(c *caseRun) {
				payload := []byte("linked\n")
				c.writeFile(c.a, c.p("link-source"), payload, 0o644)
				original, err := c.stat(c.a, c.p("link-source"))
				if err != "" {
					c.abort("%s: stat the link source: %s", c.a.name(), err)
				}
				c.ok(c.b, request{Op: "link", Path: c.p("link-source"), To: c.p("link-alias")})
				alias, err := c.stat(c.a, c.p("link-alias"))
				if err != "" {
					c.fail("%s: the hard link made on %s does not resolve: %s", c.a.name(), c.b.name(), err)
					return
				}
				if alias.Ino != original.Ino {
					c.fail("%s: the hard link resolves to inode %d, want the source inode %d", c.a.name(), alias.Ino, original.Ino)
				}
				if alias.Nlink != 2 {
					c.fail("%s: link count is %d after a remote link, want 2", c.a.name(), alias.Nlink)
				}
				c.expectBytes(c.a, c.p("link-alias"), payload, "hard link")
				c.ok(c.b, request{Op: "remove", Path: c.p("link-source")})
				remaining, err := c.stat(c.a, c.p("link-alias"))
				if err != "" {
					c.fail("%s: unlinking one name removed the other: %s", c.a.name(), err)
					return
				}
				if remaining.Nlink != 1 {
					c.fail("%s: link count is %d after one name was unlinked remotely, want 1", c.a.name(), remaining.Nlink)
				}
				c.expectBytes(c.a, c.p("link-alias"), payload, "surviving hard link")
			},
		},
		{
			name: "symlink_visible_and_resolves",
			what: "a symlink created and atomically replaced on one mount is observed on the other with its exact current target and bytes",
			run: func(c *caseRun) {
				firstPayload := []byte("symlink-target-one\n")
				secondPayload := []byte("symlink-target-two-is-different\n")
				c.writeFile(c.a, c.p("sym-target-1"), firstPayload, 0o644)
				c.writeFile(c.a, c.p("sym-target-2"), secondPayload, 0o644)
				if got := c.names(c.a, c.dir); contains(got, "sym-link") {
					c.abort("%s: sym-link unexpectedly exists before the remote symlink: %v", c.a.name(), got)
				}
				c.ok(c.b, request{Op: "symlink", Path: c.p("sym-link"), To: "sym-target-1"})
				if got := c.names(c.a, c.dir); !contains(got, "sym-link") {
					c.fail("%s: directory listing after the remote symlink returned %v, want it to contain sym-link", c.a.name(), got)
				}
				before := c.do(c.a, request{Op: "lstat", Path: c.p("sym-link")})
				if before.Err != "" {
					c.fail("%s: the remote symlink does not resolve: %s", c.a.name(), before.Err)
					return
				}
				if !before.Stat.IsLink {
					c.fail("%s: %s is not reported as a symlink (mode %#o)", c.a.name(), c.p("sym-link"), before.Stat.Mode)
				}
				target := c.do(c.a, request{Op: "readlink", Path: c.p("sym-link")})
				if target.Err != "" {
					c.fail("%s: readlink failed: %s", c.a.name(), target.Err)
				} else if target.Str != "sym-target-1" {
					c.fail("%s: readlink returned %q, want %q", c.a.name(), target.Str, "sym-target-1")
				}
				c.expectBytes(c.a, c.p("sym-link"), firstPayload, "reading through the remote symlink")

				// Replace the link inode remotely and repeat the exact same A-side
				// observations. This catches stale lstat, readlink, and content
				// answers independently of the initial missing-to-present lookup.
				c.ok(c.b, request{Op: "symlink", Path: c.p("sym-link-next"), To: "sym-target-2"})
				c.ok(c.b, request{Op: "rename", Path: c.p("sym-link-next"), To: c.p("sym-link")})
				after := c.do(c.a, request{Op: "lstat", Path: c.p("sym-link")})
				if after.Err != "" {
					c.fail("%s: the remotely replaced symlink does not resolve: %s", c.a.name(), after.Err)
				} else {
					if !after.Stat.IsLink {
						c.fail("%s: the replacement at %s is not reported as a symlink", c.a.name(), c.p("sym-link"))
					}
					if after.Stat.Ino == before.Stat.Ino {
						c.fail("%s: symlink replacement still resolves inode %d", c.a.name(), after.Stat.Ino)
					}
				}
				target = c.do(c.a, request{Op: "readlink", Path: c.p("sym-link")})
				if target.Err != "" {
					c.fail("%s: readlink after remote replacement failed: %s", c.a.name(), target.Err)
				} else if target.Str != "sym-target-2" {
					c.fail("%s: readlink after remote replacement returned %q, want %q", c.a.name(), target.Str, "sym-target-2")
				}
				c.expectBytes(c.a, c.p("sym-link"), secondPayload, "reading through the remotely replaced symlink")
			},
		},
		{
			name: "deep_nesting",
			what: "a deep tree created and rewritten on one mount is fully traversable and mutable from the other",
			run: func(c *caseRun) {
				const depth = 24
				elements := make([]string, 0, depth)
				for i := range depth {
					elements = append(elements, fmt.Sprintf("d%02d", i))
				}
				nested := path.Join(elements...)
				if got := c.names(c.a, c.dir); len(got) != 0 {
					c.abort("%s: deep-tree case root is not empty before remote creation: %v", c.a.name(), got)
				}
				c.ok(c.b, request{Op: "mkdirall", Path: c.p(nested), Mode: 0o755})
				payload := []byte("bottom-of-the-tree\n")
				c.writeFile(c.b, c.p(nested, "leaf.txt"), payload, 0o644)
				if got := c.names(c.a, c.dir); len(got) != 1 || got[0] != elements[0] {
					c.fail("%s: deep-tree root lists %v, want exactly [%s]", c.a.name(), got, elements[0])
				}
				c.expectBytes(c.a, c.p(nested, "leaf.txt"), payload, "deeply nested file")
				for i := range depth - 1 {
					partial := path.Join(elements[:i+1]...)
					got := c.names(c.a, c.p(partial))
					if len(got) != 1 || got[0] != elements[i+1] {
						c.fail("%s: %s lists %v, want exactly [%s]", c.a.name(), partial, got, elements[i+1])
					}
				}
				replacement := []byte("bottom-of-the-tree-generation-two-is-longer\n")
				c.writeFile(c.b, c.p(nested, "leaf.txt"), replacement, 0o644)
				c.expectBytes(c.a, c.p(nested, "leaf.txt"), replacement, "remotely rewritten deeply nested file")
				if info, err := c.stat(c.a, c.p(nested, "leaf.txt")); err != "" {
					c.fail("%s: stat after the remote deep rewrite failed: %s", c.a.name(), err)
				} else if info.Size != int64(len(replacement)) {
					c.fail("%s: deep leaf reports size %d after remote rewrite, want %d", c.a.name(), info.Size, len(replacement))
				}
				c.ok(c.a, request{Op: "rename", Path: c.p(nested, "leaf.txt"), To: c.p(nested, "leaf-renamed.txt")})
				c.expectBytes(c.b, c.p(nested, "leaf-renamed.txt"), replacement, "renamed deeply nested file")
				if _, err := c.stat(c.b, c.p(nested, "leaf.txt")); err == "" {
					c.fail("%s: the pre-rename deep name still resolves", c.b.name())
				}
			},
		},
		{
			name: "open_after_unlink_cross_mount_contents",
			what: "a descriptor held across a remote unlink AND a remote replacement keeps reading the original bytes, while the name resolves the replacement",
			run: func(c *caseRun) {
				// remote_unlink_open_fd_posix asserts the descriptor stays usable
				// and that its link count moved. That is not enough: a frontend
				// that quietly re-resolved the name would also stay usable and
				// would also report the right nlink, while serving somebody else's
				// bytes. This case asserts the BYTES on both sides of the split -
				// the retained inode through the fd, the replacement through the
				// path - which is the only pair of observations a re-resolution
				// cannot satisfy at the same time.
				target := c.p("held-then-replaced.txt")
				original := bytes.Repeat([]byte("original-generation\n"), 64)
				c.writeFile(c.a, target, original, 0o644)
				before, err := c.stat(c.a, target)
				if err != "" {
					c.abort("%s: stat the original: %s", c.a.name(), err)
				}
				handle := c.ok(c.a, request{Op: "open", Path: target, Flags: []string{"rdonly"}}).Handle
				defer func() { _ = c.do(c.a, request{Op: "closehandle", Handle: handle}) }()

				// Phase 1: remote unlink. The inode has no name anywhere now.
				c.ok(c.b, request{Op: "remove", Path: target})
				afterUnlink := c.do(c.a, request{Op: "readall", Handle: handle})
				if afterUnlink.Err != "" {
					c.fail("%s: reading the retained descriptor after the remote unlink failed: %s", c.a.name(), afterUnlink.Err)
				} else if !bytes.Equal(afterUnlink.Data, original) {
					c.fail("%s: after the remote unlink the retained descriptor read %d bytes %q, want the %d original bytes %q",
						c.a.name(), len(afterUnlink.Data), preview(afterUnlink.Data), len(original), preview(original))
				}

				// Phase 2: remote replacement at the same name. A different
				// inode, different length, different bytes.
				replacement := bytes.Repeat([]byte("replacement\n"), 8)
				c.writeFile(c.b, target, replacement, 0o644)

				afterReplace := c.do(c.a, request{Op: "readall", Handle: handle})
				switch {
				case afterReplace.Err != "":
					c.fail("%s: reading the retained descriptor after the remote replacement failed: %s", c.a.name(), afterReplace.Err)
				case bytes.Equal(afterReplace.Data, replacement):
					c.fail("%s: the retained descriptor now reads the REPLACEMENT bytes; the fd was re-resolved to the new inode instead of holding the unlinked one", c.a.name())
				case !bytes.Equal(afterReplace.Data, original):
					c.fail("%s: after the remote replacement the retained descriptor read %d bytes %q, want the %d original bytes %q",
						c.a.name(), len(afterReplace.Data), preview(afterReplace.Data), len(original), preview(original))
				}

				// The name must resolve the replacement, on the same mount that
				// is holding the old inode open. Both halves are true at once or
				// the frontend has conflated name and inode.
				c.expectBytes(c.a, target, replacement, "the name after the remote replacement")
				if after, statErr := c.stat(c.a, target); statErr != "" {
					c.fail("%s: the replaced name does not resolve: %s", c.a.name(), statErr)
				} else {
					if after.Ino == before.Ino {
						c.fail("%s: the replaced name still resolves the original inode %d", c.a.name(), after.Ino)
					}
					if after.Size != int64(len(replacement)) {
						c.fail("%s: the replaced name reports size %d for a %d byte replacement", c.a.name(), after.Size, len(replacement))
					}
				}
			},
		},
		{
			name: "rename_over_open_fd",
			what: "a remote rename-over while a descriptor is open leaves the fd on the displaced inode's bytes and the name on the replacement's",
			run: func(c *caseRun) {
				target := c.p("renamed-over.txt")
				displaced := bytes.Repeat([]byte("displaced-inode\n"), 48)
				c.writeFile(c.a, target, displaced, 0o644)
				before, err := c.stat(c.a, target)
				if err != "" {
					c.abort("%s: stat the soon-to-be-displaced target: %s", c.a.name(), err)
				}
				handle := c.ok(c.a, request{Op: "open", Path: target, Flags: []string{"rdonly"}}).Handle
				defer func() { _ = c.do(c.a, request{Op: "closehandle", Handle: handle}) }()

				// A rename-over from the other mount: a distinct source inode
				// takes the name atomically.
				source := c.p("rename-source.txt")
				replacement := bytes.Repeat([]byte("replacement-inode\n"), 12)
				c.writeFile(c.b, source, replacement, 0o644)
				sourceStat, err := c.stat(c.b, source)
				if err != "" {
					c.abort("%s: stat the rename source: %s", c.b.name(), err)
				}
				c.ok(c.b, request{Op: "rename", Path: source, To: target})

				held := c.do(c.a, request{Op: "readall", Handle: handle})
				switch {
				case held.Err != "":
					c.fail("%s: reading the descriptor across the remote rename-over failed: %s", c.a.name(), held.Err)
				case bytes.Equal(held.Data, replacement):
					c.fail("%s: the open descriptor followed the NAME to the replacement inode; a rename-over must not move an open file description",
						c.a.name())
				case !bytes.Equal(held.Data, displaced):
					c.fail("%s: the open descriptor read %d bytes %q, want the %d displaced bytes %q",
						c.a.name(), len(held.Data), preview(held.Data), len(displaced), preview(displaced))
				}

				c.expectBytes(c.a, target, replacement, "the name after the remote rename-over")
				after, statErr := c.stat(c.a, target)
				if statErr != "" {
					c.fail("%s: the renamed-over name does not resolve: %s", c.a.name(), statErr)
					return
				}
				if after.Ino == before.Ino {
					c.fail("%s: the name still resolves the displaced inode %d after the rename-over", c.a.name(), after.Ino)
				}
				if after.Ino != sourceStat.Ino {
					c.fail("%s: the name resolves inode %d, want the source inode %d the rename moved", c.a.name(), after.Ino, sourceStat.Ino)
				}
				if _, sourceErr := c.stat(c.a, source); sourceErr == "" {
					c.fail("%s: the rename source name still resolves after the remote rename-over", c.a.name())
				}
			},
		},
		{
			name: "same_dir_concurrent_mutations",
			what: "both mounts running create/rename/unlink storms in the SAME directory finish in bounded time, wedge no mount, and leave both mounts enumerating the identical surviving set",
			run: func(c *caseRun) {
				const perSide = 200
				started := time.Now()
				var wait sync.WaitGroup
				results := make([]response, 2)
				wait.Add(2)
				go func() {
					defer wait.Done()
					results[0] = c.do(c.a, request{Op: "burst_churn", Path: c.dir, Count: perSide, Tag: "aa"})
				}()
				go func() {
					defer wait.Done()
					results[1] = c.do(c.b, request{Op: "burst_churn", Path: c.dir, Count: perSide, Tag: "bb"})
				}()
				finished := make(chan struct{})
				go func() { wait.Wait(); close(finished) }()

				deadlocked := false
				select {
				case <-finished:
					c.note("both same-directory storms completed in %s", time.Since(started).Round(time.Millisecond))
				case <-time.After(sameDirStormBound):
					deadlocked = true
					c.fail("neither storm completed within %s; a mount that never answers a same-directory mutation is a deadlock, not a slow run",
						sameDirStormBound)
				}

				// Fencing is measured separately from a transport failure so the
				// report names the violated invariant, but the allowed count is zero.
				fenced := 0
				for _, who := range []actor{c.a, c.b} {
					if c.mountFenced(who) {
						fenced++
						c.note("%s revoked itself during the storm (ENOTCONN); the authority fenced this participant", who.name())
					} else {
						c.note("%s was not fenced during the storm", who.name())
					}
				}
				c.note("fenced participants: %d of 2 (allowed: %d)",
					fenced, sameDirToleratedFencedMounts)
				if fenced > sameDirToleratedFencedMounts {
					c.fail("%d of 2 mounts were fenced during a same-directory mutation storm; the tolerated number is %d",
						fenced, sameDirToleratedFencedMounts)
				}

				// The liveness probe runs LAST, after every assertion that reads
				// this directory. It creates and removes a file in the same
				// directory, and doing that first would put its own entry into the
				// exact surviving set the enumeration below compares.
				defer func() {
					serving := 0
					for index, who := range []actor{c.a, c.b} {
						alive, why := c.stillServes(who, fmt.Sprintf("%d", index))
						if alive {
							serving++
						} else {
							c.note("%s cannot serve after the storm: %s", who.name(), why)
						}
					}
					if serving == 0 {
						c.fail("no mount can serve a create/read/unlink after the storm; the volume stopped serving")
					}
				}()
				if deadlocked {
					// The surviving-set assertion below reads a directory whose
					// storms never finished. Anything it reported would be noise.
					return
				}
				for index, out := range results {
					if out.Err != "" {
						c.fail("storm %d completed %d/%d iterations then failed: %s", index, out.N, perSide, out.Err)
					}
				}

				// The exact surviving set: burst_churn renames every name and
				// unlinks the odd-numbered ones, so what must remain is the
				// even-numbered renamed names from both mounts and nothing else.
				want := make([]string, 0, perSide)
				for _, tag := range []string{"AA", "BB"} {
					for i := 0; i < perSide; i += 2 {
						want = append(want, fmt.Sprintf("%s-%08d", tag, i))
					}
				}
				sort.Strings(want)
				for _, who := range []actor{c.a, c.b} {
					if c.mountFenced(who) {
						c.note("%s is fenced, so its enumeration is not asserted; a revoked mount answering ENOTCONN is correct behaviour", who.name())
						continue
					}
					got := c.names(who, c.dir)
					if strings.Join(got, ",") != strings.Join(want, ",") {
						c.fail("%s enumerates %d entries after the storm, want exactly %d; the two mounts do not agree on what survived a same-directory storm",
							who.name(), len(got), len(want))
					}
				}
				// Content, not just names: a surviving name must still hold the
				// record its creator wrote.
				for _, sample := range []struct {
					tag   string
					index int
				}{{"aa", 0}, {"bb", 0}, {"aa", perSide - 2}, {"bb", perSide - 2}} {
					name := fmt.Sprintf("%s-%08d", strings.ToUpper(sample.tag), sample.index)
					for _, who := range []actor{c.a, c.b} {
						if c.mountFenced(who) {
							continue
						}
						c.expectBytes(who, c.p(name), record(sample.tag, sample.index), "survivor of the same-directory storm")
					}
				}
			},
		},
		{
			name: "local_route_isolation",
			what: "a route-configured directory is machine-local: files created under it on one mount are invisible on the other while shared siblings stay coherent",
			run: func(c *caseRun) {
				if c.localRoute == "" {
					c.skipCase("SKIP (not a pass): the harness was not told which directory name the volume routes " +
						"machine-local (--local-route), so no assertion here would be about routing.")
				}
				route := c.p(c.localRoute)

				// Each mount materializes the route root on its OWN backing. A route
				// rule owns the name but synthesizes nothing, so the root does not
				// exist until an ordinary mkdir creates it - on each machine
				// separately, which is the whole point.
				c.ok(c.a, request{Op: "mkdirall", Path: route, Mode: 0o755})
				c.ok(c.b, request{Op: "mkdirall", Path: route, Mode: 0o755})

				// Support probe. Two mounts resolving the route root to the SAME
				// inode are both being served the shared volume, so routing is not in
				// effect and an isolation assertion would pass or fail for reasons
				// that have nothing to do with routing.
				aRoot, aErr := c.stat(c.a, route)
				bRoot, bErr := c.stat(c.b, route)
				if aErr != "" || bErr != "" {
					c.skipCase("SKIP (not a pass): the route root %q does not resolve on both mounts (%s: %s, %s: %s); "+
						"machine-local routing is not in effect in this run", route, c.a.name(), aErr, c.b.name(), bErr)
				}
				if aRoot.Ino == bRoot.Ino {
					c.skipCase("SKIP (not a pass): the route root %q resolves to the same inode %d on both mounts, so it is "+
						"being served from the shared volume rather than from per-machine backing; machine-local "+
						"routing is not in effect in this run", route, aRoot.Ino)
				}
				c.note("route root %s resolves to inode %d on %s and %d on %s - two backings, as routing requires",
					route, aRoot.Ino, c.a.name(), bRoot.Ino, c.b.name())

				local := path.Join(route, "route-local.txt")
				payload := []byte("machine-local-only\n")
				c.writeFile(c.a, local, payload, 0o644)
				c.expectBytes(c.a, local, payload, "read back on the mount that created it")
				if _, err := c.stat(c.b, local); err == "" {
					c.fail("%s can see %s, created under a machine-local route on %s; routed content must never cross mounts",
						c.b.name(), local, c.a.name())
				}
				if got := c.names(c.b, route); contains(got, "route-local.txt") {
					c.fail("%s enumerates route-local.txt under the route root; its listing is %v", c.b.name(), got)
				}
				// The reverse direction, with different bytes, so a symmetric defect
				// cannot cancel out.
				remote := path.Join(route, "route-remote.txt")
				other := []byte("the-other-machines-copy\n")
				c.writeFile(c.b, remote, other, 0o644)
				c.expectBytes(c.b, remote, other, "read back on the mount that created it")
				if _, err := c.stat(c.a, remote); err == "" {
					c.fail("%s can see %s, created under the machine-local route on %s", c.a.name(), remote, c.b.name())
				}
				// Same name, different bytes, on both mounts at once: each must keep
				// its own. This is the case a shared directory cannot satisfy.
				contested := path.Join(route, "same-name.txt")
				mine, theirs := []byte("written-by-A\n"), []byte("written-by-B\n")
				c.writeFile(c.a, contested, mine, 0o644)
				c.writeFile(c.b, contested, theirs, 0o644)
				c.expectBytes(c.a, contested, mine, "one name, two backings")
				c.expectBytes(c.b, contested, theirs, "one name, two backings")

				// ── shared siblings of a routed directory stay fully coherent ────
				//
				// Written as an observe-then-change assertion rather than a single
				// read, because a single read would survive a frozen view: routing one
				// name must not quarantine its neighbours, and this is the half of the
				// case the falsifiability controls have to be able to turn red.
				sibling := c.p("shared-sibling.txt")
				first := []byte("sibling-generation-1\n")
				c.writeFile(c.a, sibling, first, 0o644)
				c.expectBytes(c.a, sibling, first, "the shared sibling before the peer changes it")
				second := []byte("sibling-generation-2-written-by-the-peer\n")
				c.writeFile(c.b, sibling, second, 0o644)
				c.expectBytes(c.a, sibling, second, "the shared sibling after the peer changed it")
			},
		},
		{
			name: "routes_revision_mismatch",
			what: "an attach carrying a stale routing revision is refused with both revisions and the volume's canonical rules, and adopting them lets the same capability attach on the second attempt",
			run: func(c *caseRun) {
				if c.routesContract == "" {
					c.skipCase("SKIP (not a pass): the harness was not given a command that attaches with a deliberately " +
						"stale routing revision (--routes-contract-command). The mount binary adopts the volume's " +
						"declaration from the refusal and retries, so asserting the refusal itself needs a client " +
						"that does not adopt.")
				}
				out := c.do(c.a, request{Op: "run", Tag: c.routesContract})
				report := strings.TrimSpace(out.Str)
				if out.Err != "" {
					c.abort("the routing-contract command could not run: %s (%s)", out.Err, report)
				}
				summary := parseSummary(report)
				if len(summary) == 0 {
					c.abort("the routing-contract command produced no summary: %s", report)
				}
				for _, note := range []string{"refusal_presented", "refusal_active", "refusal_canonical_patterns", "attempts"} {
					if value, ok := summary[note]; ok {
						c.note("%s=%s", note, value)
					}
				}

				// 1. The stale revision must be refused at all.
				if summary["stale_attach_refused"] != "true" {
					c.fail("an attach carrying a routing revision this volume does not run was ACCEPTED; " +
						"a mount that routes a subtree to local disk hides it from every peer, so the topology " +
						"cannot be the mount's to choose")
					return
				}
				if summary["refusal_is_routing_mismatch"] != "true" {
					c.fail("the attach was refused, but not as a routing mismatch, so an operator is not told which two "+
						"configurations disagreed: %s", summary["refusal_detail"])
					return
				}

				// 2. The refusal must name BOTH sides. An errno cannot say which two
				//    configurations disagreed, and that is exactly the thing a human
				//    has to reconcile.
				if summary["refusal_declared"] != "true" {
					c.fail("the refusal does not record that a revision was presented at all")
				}
				if summary["presented_is_the_stale_one"] != "true" {
					c.fail("the refusal reports presented revision %s, which is not the stale one that was sent",
						summary["refusal_presented"])
				}
				if summary["refusal_active"] == "" || summary["refusal_active"] == summary["refusal_presented"] {
					c.fail("the refusal reports active=%q and presented=%q; a mismatch must name two different revisions",
						summary["refusal_active"], summary["refusal_presented"])
				}

				// 3. It must carry the canonical rules. Without them a mount that has
				//    never seen this volume can never attach: it cannot read the
				//    declaration without a session and cannot get a session without
				//    declaring the revision.
				if bytes := summary["refusal_canonical_bytes"]; bytes == "" || bytes == "0" {
					c.fail("the refusal carries no canonical rules, so a mount that has never seen this volume has " +
						"nothing to adopt and could never attach")
				}
				if summary["refusal_canonical_matches_active"] != "true" {
					c.fail("the canonical rules the refusal carries do not hash to the revision it calls active; " +
						"a mount adopting them would attach claiming a topology it did not derive from what it was handed")
				}

				// 4. Adopting them must work ON THE SAME CAPABILITY, in exactly one
				//    more attempt. A routing refusal that spent the single-use token
				//    would make every first mount of a declaring volume need two
				//    credentials to complete a handshake it was just taught.
				if summary["adopt_succeeded"] != "true" {
					c.fail("adopting the rules the refusal carried did not let the same capability attach: %s",
						summary["adopt_error"])
				}
				if summary["attempts"] != "2" {
					c.fail("the adopt-and-retry took %q attach attempts, want exactly 2 (one refusal that teaches, one attach that works)",
						summary["attempts"])
				}

				// 5. And the real mount binary is living proof of the same path: both
				//    mounts under test attached to this declaring volume on one
				//    capability each, which is only possible through adopt-and-retry.
				//    The probe is a stat of each mount ROOT rather than work inside
				//    this case's directory: what is being asserted is that the mount
				//    attached and answers, which is true of a mount whether or not it
				//    shares a namespace with its peer.
				for _, who := range []actor{c.a, c.b} {
					if out := c.do(who, request{Op: "stat", Path: ""}); out.Err != "" {
						c.fail("%s does not answer at its own root, so it is not an attached mount: %s", who.name(), out.Err)
					}
				}
				c.note("both mounts under test are the real mount binary and are answering, each having attached on one capability")
			},
		},
		{
			name:        "peer_loss_does_not_break_surviving_mount",
			what:        "one mount dying uncleanly must not stop the other mount from serving",
			destructive: true,
			run: func(c *caseRun) {
				if c.fenceCmd == "" {
					c.skipCase("no --fence-command supplied; this case must actually kill the second mount uncleanly, and asserting it without doing so would prove nothing")
				}
				payload := []byte("written-before-the-peer-died\n")
				c.writeFile(c.a, c.p("survivor.txt"), payload, 0o644)
				c.expectBytes(c.b, c.p("survivor.txt"), payload, "before the peer is fenced")

				out := c.do(c.a, request{Op: "run", Tag: c.fenceCmd})
				if out.Err != "" {
					c.abort("fence command %q failed: %s (%s)", c.fenceCmd, out.Err, strings.TrimSpace(out.Str))
				}
				c.note("fence command output: %s", strings.TrimSpace(out.Str))

				started := time.Now()
				c.expectBytes(c.a, c.p("survivor.txt"), payload, "after the peer died uncleanly")
				fresh := []byte("written-after-the-peer-died\n")
				c.writeFile(c.a, c.p("after-death.txt"), fresh, 0o644)
				c.expectBytes(c.a, c.p("after-death.txt"), fresh, "created after the peer died")
				c.ok(c.a, request{Op: "rename", Path: c.p("after-death.txt"), To: c.p("after-death-renamed.txt")})
				c.ok(c.a, request{Op: "remove", Path: c.p("after-death-renamed.txt")})
				got := c.names(c.a, c.dir)
				if !contains(got, "survivor.txt") {
					c.fail("%s: listing after the peer died is %v", c.a.name(), got)
				}
				c.note("the surviving mount completed read, create, write, rename, unlink and readdir in %s after the peer was killed", time.Since(started).Round(time.Millisecond))
			},
		},
	}
}

func contains(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}
