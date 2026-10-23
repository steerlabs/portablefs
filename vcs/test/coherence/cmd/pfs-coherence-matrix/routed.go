package main

import (
	"fmt"
	"sync"
)

// Exclusive-writer mode measures a volume whose mount A is its only writer (a
// macOS FSKit mount) and whose mount B is a reader (a Linux peer whose visible
// mutations the authority refuses with EBUSY). The shared cases are written
// for two writers, so in this mode both case actors are views of one router:
// every mutation runs on the writer, every pathname observation runs on the
// reader, and an operation on a descriptor runs on the mount that opened it.
// Each retained case therefore becomes "the writer mutates, the reader
// observes", which is the direction the profile promises; the refusal of the
// reader's own mutations is asserted separately and positively by the
// writer_exclusion_refuses_reader_mutations case. Nothing here turns an error
// into a pass: a failed mutation, observation or descriptor operation fails
// the case exactly as it would on two writers.

// mutatingOps are the operations a reader may not perform under writer
// exclusion. "run" executes a harness command in the actor's mount and is
// treated as mutating because its effects are not known to the router.
var mutatingOps = map[string]bool{
	"mkdirall": true, "mkdir": true, "removeall": true, "remove": true,
	"writefile": true, "rename": true, "chmod": true, "chown": true,
	"utimes": true, "truncate": true, "symlink": true, "link": true,
	"burst_create": true, "burst_churn": true, "burst_append": true,
	"burst_overwrite": true, "atomic_replace": true, "run": true,
	"burst_editor_save": true, "burst_truncate_overwrite": true,
}

// mutates reports whether req changes the volume (or, for open, requests write
// access or creation, which the authority treats as a write-intent open).
func mutates(req request) bool {
	if req.Op == "open" {
		for _, flag := range req.Flags {
			switch flag {
			case "wronly", "rdwr", "create", "trunc", "append":
				return true
			}
		}
		return false
	}
	return mutatingOps[req.Op]
}

type routedHandle struct {
	target actor
	inner  int
}

// router is the state shared by the two case-actor views. Its descriptor table
// maps the router's own handle numbers to the opening mount's numbers, so a
// descriptor opened through either view keeps running on the mount that owns
// it and handle numbers from the two mounts never collide.
type router struct {
	writer, reader actor
	mu             sync.Mutex
	handles        map[int]routedHandle
	next           int
}

func newRouter(writer, reader actor) *router {
	return &router{writer: writer, reader: reader, handles: map[int]routedHandle{}, next: 1}
}

// view returns a case actor with its own label over the shared router.
func (r *router) view(label string) actor { return &routedActor{label: label, router: r} }

type routedActor struct {
	label  string
	router *router
}

func (a *routedActor) name() string { return a.label }

// close is a no-op: the router owns no mount; the worker closes the two real
// actors itself.
func (a *routedActor) close() error { return nil }

func (a *routedActor) exec(req request) (response, error) {
	r := a.router
	if req.Handle != 0 {
		r.mu.Lock()
		route, ok := r.handles[req.Handle]
		if ok && req.Op == "closehandle" {
			delete(r.handles, req.Handle)
		}
		r.mu.Unlock()
		if !ok {
			return response{Err: fmt.Sprintf("unknown handle %d", req.Handle)}, nil
		}
		req.Handle = route.inner
		return route.target.exec(req)
	}
	target := r.reader
	if mutates(req) {
		target = r.writer
	}
	out, err := target.exec(req)
	if err != nil || out.Handle == 0 {
		return out, err
	}
	r.mu.Lock()
	id := r.next
	r.next++
	r.handles[id] = routedHandle{target: target, inner: out.Handle}
	r.mu.Unlock()
	out.Handle = id
	return out, nil
}
