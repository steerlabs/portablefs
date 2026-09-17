package authorityrpc

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// The production request reader hashes payload bytes while reading them. Keep
// that cost separate from canonicalizing metadata with its retained digest.
func BenchmarkReadRequestRetainedBulkFrame1MiB(b *testing.B) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
		Handle: bytes.Repeat([]byte{1}, 16), Size: 1 << 20, Data: make([]byte, 1<<20),
	}}}
	var encoded bytes.Buffer
	if err := writeFrame(&encoded, 2<<20, request); err != nil {
		b.Fatal(err)
	}
	wire := encoded.Bytes()
	b.ReportAllocs()
	b.SetBytes(1 << 20)
	for b.Loop() {
		var got authoritypb.Request
		release, digest, err := readRequestFrameRetained(bytes.NewReader(wire), 2<<20, nil, 0, &got)
		if err != nil {
			b.Fatal(err)
		}
		if digest == nil {
			b.Fatal("request reader omitted replay digest")
		}
		benchmarkValue = *digest
		release()
	}
}

func BenchmarkFrameReplayFingerprint1MiB(b *testing.B) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
		Handle: bytes.Repeat([]byte{1}, 16), Position: 4096, Size: 1 << 20, Data: make([]byte, 1<<20),
	}}}
	runtime, err := volumeserver.New("fingerprint-benchmark", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 1, MaxSessions: 1, MaxLockRecords: 1,
	})
	if err != nil {
		b.Fatal(err)
	}
	digest := sha256.Sum256(request.GetWrite().GetData())
	b.ReportAllocs()
	for b.Loop() {
		fingerprint, err := canonicalFingerprintWithWriteDataDigest(runtime, request, digest)
		if err != nil {
			b.Fatal(err)
		}
		benchmarkValue = fingerprint
	}
}
