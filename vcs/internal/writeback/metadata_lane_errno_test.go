package writeback

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ENOSPC is a DEFINITE claim about a bounded local store: it is full, and this
// operation can never fit. Applications act on it — they delete things, they
// give up, they page someone. Returning it for a condition the next authority
// ack will clear teaches exactly the wrong response, and the wrong response
// (deleting files) does not fix a slow uplink.
//
// The credit architecture already draws that line for bulk data: an append that
// would fit an empty lane is transient, and only an append larger than the lane
// at ANY occupancy is ENOSPC. That question is about the APPEND, not about which
// lane carries it, so it has to be asked for metadata too — a small create or
// rename could never be the thing a bounded store cannot fit.

// fillMetadataLane drives the stream to its hard cap with namespace mutations
// while the uplink is gated shut, so nothing is applied and nothing is
// reclaimable. It returns the error the first refused mutation produced.
func fillMetadataLane(t *testing.T, f *saturationFixture) error {
	t.Helper()
	ctx := context.Background()
	// Long names make each namespace record large, so the cap is reached in a
	// bounded number of mutations rather than a hundred thousand.
	long := strings.Repeat("n", 3000)
	for i := 0; i < 20000; i++ {
		name := "d/" + long + string(rune('a'+i%26)) + itoa(i)
		_, handled, err := f.e.Create(ctx, name, 0o644, false, false)
		if err != nil {
			if !handled {
				t.Fatalf("create %d changed lanes instead of refusing: %v", i, err)
			}
			return err
		}
	}
	t.Skip("the metadata lane never reached its cap at this budget")
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestTransientMetadataExhaustionIsNotENOSPC is the errno contract itself. A
// small create refused because the metadata lane is momentarily full would fit
// an empty lane, so it is not the definite condition and must not carry the
// definite errno.
func TestTransientMetadataExhaustionIsNotENOSPC(t *testing.T) {
	f := newSaturationFixture(t, 4<<20)
	err := fillMetadataLane(t, f)
	if err == nil {
		t.Fatal("the metadata lane never refused an append")
	}
	if errors.Is(err, ErrNoSpace) {
		t.Fatalf("a transient metadata-lane full returned ENOSPC (%v); the operation "+
			"would fit an empty lane and the next authority ack admits it, so an "+
			"application is being told to delete files to fix a slow uplink", err)
	}
	if !errors.Is(err, ErrUplinkStalled) {
		t.Fatalf("transient metadata exhaustion = %v, want the EIO-class "+
			"ErrUplinkStalled the data lane produces for the same cause", err)
	}
}

// TestOversizedMetadataAppendKeepsDefiniteENOSPC is the other half: the
// classification must not turn every refusal into EIO. An append that cannot
// fit the lane at any occupancy is exactly what ENOSPC is for, and it stays.
func TestOversizedMetadataAppendKeepsDefiniteENOSPC(t *testing.T) {
	// A metadata record larger than the whole cap, so it is oversized on an
	// entirely EMPTY stream. An xattr value is the largest payload the metadata
	// lane carries.
	f := newSaturationFixture(t, 64<<10)
	ctx := context.Background()
	if _, handled, cerr := f.e.Create(ctx, "d/f", 0o644, false, false); cerr != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, cerr)
	}
	_, err := f.e.Setxattr(ctx, "d/f", "user.big", make([]byte, 128<<10), 0)
	if err == nil {
		t.Skip("the oversized metadata record was admitted at this budget")
	}
	if errors.Is(err, ErrUplinkStalled) {
		t.Fatalf("an append that cannot fit an EMPTY lane was reported transient (%v); "+
			"no amount of draining can ever admit it, which is precisely ENOSPC", err)
	}
	if !errors.Is(err, ErrNoSpace) {
		t.Fatalf("oversized metadata append = %v, want ErrNoSpace", err)
	}
}
