package main

import "github.com/trendup-ai/portablefs/vcs/internal/clientcore"

type openTracker struct {
	*clientcore.OpenTracker
}

var opens = &openTracker{OpenTracker: clientcore.NewOpenTracker()}

func (t *openTracker) inc(p string)               { t.Inc(p) }
func (t *openTracker) dec(p string)               { t.Dec(p) }
func (t *openTracker) busyUnder(root string) bool { return t.BusyUnder(root) }
