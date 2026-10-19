package continuous

import (
	"math"
	"testing"
	"time"
)

func TestTimespecRejectsUnrepresentablePermissionClock(t *testing.T) {
	for _, tt := range []struct {
		name      string
		sec, nsec int64
		want      time.Duration
		valid     bool
	}{
		{"zero", 0, 0, 0, true}, {"fraction", 3, 125, 3*time.Second + 125, true},
		{"limit", 9_223_372_036, 854_775_807, time.Duration(math.MaxInt64), true},
		{"negative-seconds", -1, 0, 0, false}, {"negative-nanos", 0, -1, 0, false},
		{"nanos-overflow", 0, 1_000_000_000, 0, false},
		{"duration-overflow", 9_223_372_036, 854_775_808, 0, false},
		{"seconds-overflow", math.MaxInt64, 0, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := timespec(tt.sec, tt.nsec)
			if (err == nil) != tt.valid || tt.valid && got != tt.want {
				t.Fatalf("time=%v err=%v", got, err)
			}
		})
	}
}

func TestTimeUsesTheContinuousDomain(t *testing.T) {
	before, err := Now()
	if err != nil {
		t.Fatal(err)
	}
	sampled := Time()
	after, err := Now()
	if err != nil {
		t.Fatal(err)
	}
	if sampled.Before(time.Unix(0, int64(before))) || sampled.After(time.Unix(0, int64(after))) {
		t.Fatalf("continuous time outside samples: %v <= %v <= %v", before, sampled, after)
	}
	// Serialization strips Go's private active-time reading. A continuous time
	// must already be identical to that representation before serialization.
	if sampled != sampled.Round(0) {
		t.Fatal("continuous timestamp retained a Go active-time reading")
	}
}
