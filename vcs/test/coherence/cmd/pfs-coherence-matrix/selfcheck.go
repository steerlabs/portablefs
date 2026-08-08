package main

import (
	"path"
	"sync"
)

// staleActor is the harness's own falsifiability control.
//
// An assertion nobody has watched fail is not evidence. This wrapper makes one
// mount answer every repeated observation of a name with the first answer it
// ever gave, which is exactly the defect class the hand-run macOS matrix found:
// a create that is never seen, mode bits that never change, an atomic
// replacement that keeps resolving the old inode, an EOF that never moves.
// Running the matrix with --self-check-stale must turn every case that repeats
// one of those pathname observations across a remote mutation red. Stateful
// handle contracts intentionally survive this fault model and are falsified by
// different controls. If a declared stale-sensitive case stays green here, its
// observation sequence must be fixed before it is trusted.
//
// It is reachable only through that explicit flag and is never part of a real
// measurement run.
type staleActor struct {
	inner actor
	mu    sync.Mutex
	seen  map[string]response
}

func newStaleActor(inner actor) *staleActor {
	return &staleActor{inner: inner, seen: map[string]response{}}
}

func (a *staleActor) name() string { return a.inner.name() + "(stale-cache-injected)" }

func (a *staleActor) close() error { return a.inner.close() }

// mutating lists the operations after which a real stale cache would still be
// holding whatever it had already seen. Freezing the view at that instant is
// what turns "the other mount changed it afterwards" into an observable defect.
var mutating = map[string]bool{
	"mkdir": true, "mkdirall": true, "writefile": true, "remove": true, "removeall": true,
	"rename": true, "chmod": true, "chown": true, "utimes": true, "truncate": true,
	"symlink": true, "link": true, "burst_create": true, "burst_append": true,
	"burst_overwrite": true, "atomic_replace": true, "burst_churn": true,
}

func (a *staleActor) exec(req request) (response, error) {
	switch req.Op {
	case "stat", "lstat", "readdir", "readfile", "readlink":
	default:
		if mutating[req.Op] && req.Path != "" {
			// Take the view now, before this mount's own change, so that a
			// later observation is answered from a genuinely older state.
			for _, probe := range []request{
				{Op: "readdir", Path: path.Dir(req.Path)},
				{Op: "stat", Path: req.Path},
				{Op: "readfile", Path: req.Path},
			} {
				_, _ = a.exec(probe)
			}
			out, err := a.inner.exec(req)
			if (req.Op == "mkdir" || req.Op == "mkdirall") && err == nil && out.Err == "" {
				// A directory that did not exist a moment ago has nothing to
				// freeze, so take its (empty) listing immediately afterwards.
				_, _ = a.exec(request{Op: "readdir", Path: req.Path})
			}
			return out, err
		}
		return a.inner.exec(req)
	}
	key := req.Op + "\x00" + req.Path
	a.mu.Lock()
	cached, ok := a.seen[key]
	a.mu.Unlock()
	if ok {
		return cached, nil
	}
	out, err := a.inner.exec(req)
	// Only a successful observation is retained. A cached failure would make
	// the negative half of the namespace contract pass for the wrong reason,
	// which is the opposite of what this control is for.
	if err != nil || out.Err != "" {
		return out, err
	}
	a.mu.Lock()
	a.seen[key] = out
	a.mu.Unlock()
	return out, nil
}
