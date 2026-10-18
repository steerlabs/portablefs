package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// recordingActor wraps a real local actor, records which operations reached
// it, and can refuse mutations the way writer exclusion does.
type recordingActor struct {
	inner  actor
	label  string
	ops    []string
	refuse func(request) (response, bool)
}

func (a *recordingActor) name() string { return a.label }
func (a *recordingActor) close() error { return a.inner.close() }
func (a *recordingActor) exec(req request) (response, error) {
	a.ops = append(a.ops, req.Op)
	if a.refuse != nil {
		if out, refused := a.refuse(req); refused {
			return out, nil
		}
	}
	return a.inner.exec(req)
}

// refuseMutations models the authority's writer exclusion on the reader.
func refuseMutations(req request) (response, bool) {
	if mutates(req) {
		return response{Err: "device or resource busy", Errno: int(syscall.EBUSY)}, true
	}
	return response{}, false
}

// sharedVolume returns a writer and a reader over one directory, so the two
// actors observe one namespace the way two mounts of one volume do.
func sharedVolume(t *testing.T, refuse func(request) (response, bool)) (*recordingActor, *recordingActor) {
	t.Helper()
	root := t.TempDir()
	w, err := newLocalActor("writer", root)
	if err != nil {
		t.Fatal(err)
	}
	r, err := newLocalActor("reader", root)
	if err != nil {
		t.Fatal(err)
	}
	return &recordingActor{inner: w, label: "writer"}, &recordingActor{inner: r, label: "reader", refuse: refuse}
}

func TestRouterSendsMutationsToTheWriterAndObservationsToTheReader(t *testing.T) {
	writer, reader := sharedVolume(t, refuseMutations)
	routes := newRouter(writer, reader)
	a, b := routes.view("a"), routes.view("b")
	steps := []struct {
		who  actor
		req  request
		want *recordingActor
	}{
		{a, request{Op: "writefile", Path: "f", Data: []byte("x"), Mode: 0o644}, writer},
		{b, request{Op: "stat", Path: "f"}, reader},
		{b, request{Op: "rename", Path: "f", To: "g"}, writer},
		{a, request{Op: "readdir", Path: ""}, reader},
		{a, request{Op: "readfile", Path: "g"}, reader},
		{b, request{Op: "open", Path: "g", Flags: []string{"rdonly"}}, reader},
		{a, request{Op: "open", Path: "g", Flags: []string{"rdwr"}}, writer},
	}
	for i, step := range steps {
		before := len(step.want.ops)
		out, err := step.who.exec(step.req)
		if err != nil || out.Err != "" {
			t.Fatalf("step %d %s: %v %s", i, step.req.Op, err, out.Err)
		}
		if len(step.want.ops) != before+1 {
			t.Fatalf("step %d %s did not reach %s", i, step.req.Op, step.want.label)
		}
	}
}

func TestRouterKeepsDescriptorsOnTheirOpeningMount(t *testing.T) {
	writer, reader := sharedVolume(t, refuseMutations)
	if err := os.WriteFile(filepath.Join(writer.inner.(*localActor).root, "f"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	routes := newRouter(writer, reader)
	a, b := routes.view("a"), routes.view("b")
	readHandle, _ := b.exec(request{Op: "open", Path: "f", Flags: []string{"rdonly"}})
	writeHandle, _ := a.exec(request{Op: "open", Path: "f", Flags: []string{"rdwr"}})
	if readHandle.Handle == 0 || writeHandle.Handle == 0 || readHandle.Handle == writeHandle.Handle {
		t.Fatalf("router handles %d and %d", readHandle.Handle, writeHandle.Handle)
	}
	readerOps, writerOps := len(reader.ops), len(writer.ops)
	if out, _ := a.exec(request{Op: "pwrite", Handle: writeHandle.Handle, Data: []byte("z")}); out.Err != "" {
		t.Fatal(out.Err)
	}
	if out, _ := b.exec(request{Op: "pread", Handle: readHandle.Handle, Len: 3}); out.Err != "" || string(out.Data) != "zbc" {
		t.Fatalf("reader descriptor read %q %s", out.Data, out.Err)
	}
	if len(writer.ops) != writerOps+1 || len(reader.ops) != readerOps+1 {
		t.Fatalf("descriptor operations ran on the wrong mount: writer %v reader %v", writer.ops, reader.ops)
	}
	for _, h := range []int{readHandle.Handle, writeHandle.Handle} {
		if out, _ := a.exec(request{Op: "closehandle", Handle: h}); out.Err != "" {
			t.Fatal(out.Err)
		}
		if out, _ := a.exec(request{Op: "closehandle", Handle: h}); out.Err == "" {
			t.Fatalf("closed handle %d still routed", h)
		}
	}
}

func runExclusion(t *testing.T, refuse func(request) (response, bool)) outcome {
	t.Helper()
	writer, reader := sharedVolume(t, refuse)
	routes := newRouter(writer, reader)
	entry := exclusiveCases()[0]
	return executeCaseDirect(entry, routes.view("a"), routes.view("b"), "run", caseInputs{writer: writer, reader: reader})
}

func TestWriterExclusionCase(t *testing.T) {
	t.Run("every reader mutation refused with EBUSY passes", func(t *testing.T) {
		if got := runExclusion(t, refuseMutations); got.Status != statusPass {
			t.Fatalf("status %s failures %v reason %q", got.Status, got.Failures, got.Reason)
		}
	})
	t.Run("a reader mutation that succeeds fails", func(t *testing.T) {
		got := runExclusion(t, func(req request) (response, bool) {
			if req.Op == "chmod" {
				return response{}, false
			}
			return refuseMutations(req)
		})
		if got.Status != statusFail {
			t.Fatalf("status %s, want FAIL", got.Status)
		}
	})
	t.Run("a refusal with the wrong errno fails", func(t *testing.T) {
		got := runExclusion(t, func(req request) (response, bool) {
			if mutates(req) {
				return response{Err: "input/output error", Errno: int(syscall.EIO)}, true
			}
			return response{}, false
		})
		if got.Status != statusFail {
			t.Fatalf("status %s, want FAIL", got.Status)
		}
	})
	t.Run("a partial effect behind an EBUSY fails", func(t *testing.T) {
		var reader *recordingActor
		got := func() outcome {
			writer, r := sharedVolume(t, nil)
			reader = r
			reader.refuse = func(req request) (response, bool) {
				if req.Op == "truncate" {
					// Apply the change, then report EBUSY: the snapshot,
					// not the errno, must catch it.
					_, _ = reader.inner.exec(req)
					return response{Err: "device or resource busy", Errno: int(syscall.EBUSY)}, true
				}
				return refuseMutations(req)
			}
			routes := newRouter(writer, reader)
			return executeCaseDirect(exclusiveCases()[0], routes.view("a"), routes.view("b"), "run", caseInputs{writer: writer, reader: reader})
		}()
		if got.Status != statusFail {
			t.Fatalf("status %s, want FAIL", got.Status)
		}
	})
	t.Run("without exclusive-writer actors the case skips", func(t *testing.T) {
		writer, reader := sharedVolume(t, nil)
		got := executeCaseDirect(exclusiveCases()[0], writer, reader, "run", caseInputs{})
		if got.Status != statusSkip {
			t.Fatalf("status %s, want SKIP", got.Status)
		}
	})
}

func TestExclusiveCasesOnlyInExclusiveMode(t *testing.T) {
	has := func(cases []coherenceCase) bool {
		for _, c := range cases {
			if c.name == "writer_exclusion_refuses_reader_mutations" {
				return true
			}
		}
		return false
	}
	if has(casesFor(false)) || !has(casesFor(true)) {
		t.Fatal("the writer-exclusion case must run only in exclusive-writer mode")
	}
	if len(casesFor(true)) != len(casesFor(false))+1 {
		t.Fatal("exclusive-writer mode must add exactly the exclusion case")
	}
	last := casesFor(true)[len(casesFor(true))-1]
	if last.name != allCases()[len(allCases())-1].name {
		t.Fatal("the destructive peer-loss case must stay last")
	}
}
