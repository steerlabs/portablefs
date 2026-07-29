package writeback

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkLookupNegativeUnderDelegation(b *testing.B) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	dir := b.TempDir()
	e, err := Open(context.Background(), Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		if _, handled, err := e.Create(ctx, fmt.Sprintf("d/f%03d", i), 0o644, false, false); err != nil || !handled {
			b.Fatal(handled, err)
		}
	}
	// Pin the delegation active across the measurement loop (the idle
	// voluntary release would otherwise fire mid-loop).
	e.mu.Lock()
	for _, d := range e.delegations {
		d.lastActive = d.lastActive.Add(time.Hour)
	}
	e.mu.Unlock()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, res := e.Lookup("d/missing.json"); res != LookupNegative {
			b.Fatal(res)
		}
	}
}

func BenchmarkLookupNoDelegations(b *testing.B) {
	auth := newFakeAuthority()
	dir := b.TempDir()
	e, err := Open(context.Background(), Config{StateDir: dir, VolumeID: "vol", Branch: "main", Remote: auth, BudgetBytes: 1 << 30})
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _, _ = e.ForceClose("teardown") }()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, res := e.Lookup("d/missing.json"); res != LookupUndecided {
			b.Fatal(res)
		}
	}
}
