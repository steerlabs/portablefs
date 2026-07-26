package histstore_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/histstore"
	"github.com/trendup-ai/portablefs/vcs/internal/histstore/s3double"
)

func hexDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func newS3(t *testing.T, pathStyle bool) (*histstore.S3Store, *s3double.Double) {
	t.Helper()
	double := s3double.New("history", "auto", "AKTEST", "secretsecret")
	t.Cleanup(double.Close)
	store, err := histstore.NewS3Store(histstore.S3Config{
		Domain:           "s3-a",
		Endpoint:         double.URL(),
		Region:           "auto",
		Bucket:           "history",
		Prefix:           "pfx",
		PathStyle:        pathStyle,
		AccessKeyID:      "AKTEST",
		SecretAccessKey:  "secretsecret",
		OperationTimeout: 5 * time.Second,
		Transport:        double.Transport(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, double
}

func TestS3RoundTripBothStyles(t *testing.T) {
	for _, pathStyle := range []bool{true, false} {
		store, double := newS3(t, pathStyle)
		ctx := context.Background()
		data := bytes.Repeat([]byte("s3-bytes"), 1000)
		id := histstore.ObjectID{
			Tenant: "ten/ant", Kind: "pft2",
			DigestHex: hexDigest(data), Incarnation: 2,
		}
		key, err := store.ExactKey(id)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(key, "pfx/t/") || !strings.HasSuffix(key, "/i2") {
			t.Fatalf("exact key shape: %q", key)
		}
		if err := store.Put(ctx, key, int64(len(data)), hexDigest(data), bytes.NewReader(data)); err != nil {
			t.Fatalf("pathStyle=%v put: %v", pathStyle, err)
		}
		if _, ok := double.GetObject(key); !ok {
			t.Fatalf("pathStyle=%v: object not stored at exact key %q (stored: %v)",
				pathStyle, key, double.Keys())
		}
		got, err := histstore.ReadVerified(ctx, store, key, int64(len(data)), hexDigest(data))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("pathStyle=%v read: %v", pathStyle, err)
		}
		size, err := store.Head(ctx, key)
		if err != nil || size != int64(len(data)) {
			t.Fatalf("pathStyle=%v head: %d %v", pathStyle, size, err)
		}
		if err := store.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Head(ctx, key); !errors.Is(err, histstore.ErrNotFound) {
			t.Fatalf("pathStyle=%v after delete: %v", pathStyle, err)
		}
		// Idempotent delete of an absent key.
		if err := store.Delete(ctx, key); err != nil {
			t.Fatal(err)
		}
		if double.UnsignedRejects != 0 {
			t.Fatalf("%d requests failed signature verification", double.UnsignedRejects)
		}
	}
}

func TestS3RejectsBadCredentials(t *testing.T) {
	double := s3double.New("history", "auto", "AKTEST", "rightsecret")
	defer double.Close()
	store, err := histstore.NewS3Store(histstore.S3Config{
		Domain: "s3-a", Endpoint: double.URL(), Region: "auto",
		Bucket: "history", PathStyle: true,
		AccessKeyID: "AKTEST", SecretAccessKey: "wrongsecret",
		Transport: double.Transport(),
	})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("x")
	err = store.Put(context.Background(), "a/b", 1, hexDigest(data), bytes.NewReader(data))
	if err == nil {
		t.Fatal("bad signature accepted")
	}
	if double.UnsignedRejects == 0 {
		t.Fatal("double did not reject the signature")
	}
}

func TestS3ShortReadDetected(t *testing.T) {
	store, double := newS3(t, true)
	ctx := context.Background()
	data := bytes.Repeat([]byte{9}, 64<<10)
	key := "pfx/short/" + hexDigest(data)
	double.PutObject(key, data, nil)
	double.InjectFault(s3double.Fault{Method: "GET", KeySuffix: hexDigest(data), TruncateBody: true, Remaining: 1})
	if _, err := histstore.ReadVerified(ctx, store, key, int64(len(data)), hexDigest(data)); err == nil {
		t.Fatal("short read verified")
	}
	// Next read (no fault) succeeds.
	if _, err := histstore.ReadVerified(ctx, store, key, int64(len(data)), hexDigest(data)); err != nil {
		t.Fatal(err)
	}
}

func TestS3HashMismatchDetected(t *testing.T) {
	store, double := newS3(t, true)
	data := bytes.Repeat([]byte{3}, 4096)
	key := "pfx/corrupt/" + hexDigest(data)
	double.PutObject(key, data, nil)
	double.InjectFault(s3double.Fault{Method: "GET", CorruptBody: true, Remaining: -1})
	if _, err := histstore.ReadVerified(context.Background(), store, key, int64(len(data)), hexDigest(data)); err == nil {
		t.Fatal("corrupted body verified")
	}
	if err := histstore.VerifyStream(context.Background(), store, key, int64(len(data)), hexDigest(data)); err == nil {
		t.Fatal("corrupted body stream-verified")
	}
}

func TestS3DeadlineAndCancel(t *testing.T) {
	double := s3double.New("history", "auto", "AKTEST", "secretsecret")
	defer double.Close()
	store, err := histstore.NewS3Store(histstore.S3Config{
		Domain: "s3-a", Endpoint: double.URL(), Region: "auto",
		Bucket: "history", PathStyle: true,
		AccessKeyID: "AKTEST", SecretAccessKey: "secretsecret",
		OperationTimeout: 150 * time.Millisecond,
		Transport:        double.Transport(),
	})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("slow")
	key := "slow/object"
	double.PutObject(key, data, nil)
	double.InjectFault(s3double.Fault{Method: "GET", Delay: 2 * time.Second, Remaining: 1})
	start := time.Now()
	if _, err := histstore.ReadVerified(context.Background(), store, key, int64(len(data)), hexDigest(data)); err == nil {
		t.Fatal("deadline did not fire")
	}
	if time.Since(start) > time.Second {
		t.Fatalf("deadline took %v", time.Since(start))
	}

	// Caller-side cancellation aborts a PUT mid-stream.
	ctx, cancel := context.WithCancel(context.Background())
	big := bytes.Repeat([]byte{1}, 1<<20)
	pr, pw := io.Pipe()
	go func() {
		pw.Write(big[:64<<10])
		cancel()
		pw.CloseWithError(context.Canceled)
	}()
	if err := store.Put(ctx, "abort/object", int64(len(big)), hexDigest(big), pr); err == nil {
		t.Fatal("aborted put succeeded")
	}
}

func TestS3ServerErrorSurfacesTyped(t *testing.T) {
	store, double := newS3(t, true)
	data := []byte("y")

	// 503 is S3 flow control (SlowDown): typed as ErrThrottled so the cut
	// pipeline can back off per object instead of failing the attempt.
	double.InjectFault(s3double.Fault{Method: "PUT", Status: 503, Remaining: 1})
	err := store.Put(context.Background(), "err/object", 1, hexDigest(data), bytes.NewReader(data))
	if !errors.Is(err, histstore.ErrThrottled) {
		t.Fatalf("want ErrThrottled for 503, got %v", err)
	}
	double.InjectFault(s3double.Fault{Method: "PUT", Status: 429, Remaining: 1})
	err = store.Put(context.Background(), "err/object", 1, hexDigest(data), bytes.NewReader(data))
	if !errors.Is(err, histstore.ErrThrottled) {
		t.Fatalf("want ErrThrottled for 429, got %v", err)
	}

	// A genuine server error stays untyped (attempt-level handling).
	double.InjectFault(s3double.Fault{Method: "PUT", Status: 500, Remaining: 1})
	err = store.Put(context.Background(), "err/object", 1, hexDigest(data), bytes.NewReader(data))
	if err == nil || errors.Is(err, histstore.ErrNotFound) || errors.Is(err, histstore.ErrThrottled) {
		t.Fatalf("want untyped server error for 500, got %v", err)
	}

	if _, err := store.Head(context.Background(), "missing/object"); !errors.Is(err, histstore.ErrNotFound) {
		t.Fatalf("missing head: %v", err)
	}
}

func TestS3LostPutCaughtByReadback(t *testing.T) {
	store, double := newS3(t, true)
	ctx := context.Background()
	data := []byte("will be dropped")
	key := "pfx/dropped/" + hexDigest(data)
	double.InjectFault(s3double.Fault{Method: "PUT", DropPut: true, Remaining: 1})
	// The PUT "succeeds" (200) but stored nothing; only read-after-write
	// catches it — exactly why receipts require the readback proof.
	if err := store.Put(ctx, key, int64(len(data)), hexDigest(data), bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := histstore.ReadVerified(ctx, store, key, int64(len(data)), hexDigest(data)); err == nil {
		t.Fatal("lost write passed readback")
	}
}
