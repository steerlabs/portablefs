package archiveverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/archive"
	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

const (
	testBucket = "portablefs-archive"
	testPrefix = "archives"
	volumeUUID = "0f0e0d0c-0b0a-4908-8706-050403020100"
	attempt    = "11111111-2222-4333-8444-555555555555"
	epoch      = uint64(3)
)

// fakeStore is a minimal unauthenticated byte-map store: signature
// verification is archivestore's own concern (its suite verifies with an
// independent implementation); this test only needs object semantics.
type fakeStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (s *fakeStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/"+testBucket+"/")
	switch r.Method {
	case http.MethodGet:
		payload, ok := s.objects[key]
		if !ok {
			http.Error(w, "<Error><Code>NoSuchKey</Code><Message>absent</Message></Error>", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	case http.MethodHead:
		payload, ok := s.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(payload)))
		w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		delete(s.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func rawUUID(t *testing.T, value string) [16]byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(decoded) != 16 {
		t.Fatalf("uuid %q", value)
	}
	var raw [16]byte
	copy(raw[:], decoded)
	return raw
}

type memorySink struct{ packs map[uint32]*bytes.Buffer }

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }

func (s *memorySink) OpenPack(index uint32) (io.WriteCloser, error) {
	buffer := &bytes.Buffer{}
	s.packs[index] = buffer
	return nopCloser{buffer}, nil
}

func sealedFixture(t *testing.T) (*fakeStore, *archivestore.Client, controlplane.ArchiveRecord) {
	t.Helper()
	config := archive.DefaultBuilderConfig()
	config.VolumeID = rawUUID(t, volumeUUID)
	config.SealedEpoch = epoch
	config.Attempt = rawUUID(t, attempt)
	content := bytes.Repeat([]byte("tiered storage round trip "), 512)
	source := archive.NewSliceSource([]archive.SourceEntry{
		{ParentIndex: 0, Name: nil, Type: archive.TypeDirectory, Mode: 0o700, MTimeNanos: 1},
		{ParentIndex: 0, Name: []byte("file.txt"), Type: archive.TypeRegular, Size: uint64(len(content)),
			Mode: 0o600, MTimeNanos: 2, Nlink: 1, InodeKey: 1,
			Open: func() (archive.SourceFile, error) {
				return &archive.MemoryFile{Logical: content, Data: []archive.Extent{{Offset: 0, Length: uint64(len(content))}}}, nil
			}},
	})
	sink := &memorySink{packs: map[uint32]*bytes.Buffer{}}
	manifest, err := archive.Build(config, source, sink)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	encoded, err := archive.Encode(manifest)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	store := &fakeStore{objects: map[string][]byte{}}
	server := httptest.NewServer(store)
	t.Cleanup(server.Close)
	client, err := archivestore.New(archivestore.Config{
		Endpoint: server.URL, Region: "us-east-1", Bucket: testBucket, KeyPrefix: testPrefix,
		AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret", PathStyle: true,
		ChecksumCapability: archivestore.ChecksumCRC64NVMEFullObject, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	manifestKey, err := client.KeyFor(volumeUUID, epoch, attempt, "manifest")
	if err != nil {
		t.Fatal(err)
	}
	store.objects[manifestKey] = encoded
	manifestDigest := sha256.Sum256(encoded)
	record := controlplane.ArchiveRecord{
		FormatVersion: manifest.Header.FormatVersion, ChunkSizeBytes: manifest.Header.ChunkSizeBytes,
		Attempt: attempt, SealedEpoch: epoch, SealedUnix: 1,
		Manifest: controlplane.ObjectRef{Key: manifestKey, SizeBytes: uint64(len(encoded)),
			SHA256: hex.EncodeToString(manifestDigest[:]), CRC64NVME: archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(encoded))},
		RootDigest:   archive.RootDigestHex(manifest),
		LogicalBytes: manifest.Header.LogicalBytes, LogicalInodes: manifest.Header.LogicalInodes,
		SealedAllocatedBytes: manifest.Header.SealedAllocatedBytes, SealedInodes: manifest.Header.SealedInodes,
		KeyVersion: "default",
	}
	for index, pack := range manifest.Header.Packs {
		key, err := client.KeyFor(volumeUUID, epoch, attempt, fmt.Sprintf("pack-%d", index))
		if err != nil {
			t.Fatal(err)
		}
		payload := sink.packs[uint32(index)].Bytes()
		store.objects[key] = payload
		record.Packs = append(record.Packs, controlplane.ObjectRef{
			Key: key, SizeBytes: pack.SizeBytes,
			SHA256: hex.EncodeToString(pack.SHA256[:]), CRC64NVME: archivestore.CRC64Hex(pack.CRC64NVME),
		})
	}
	return store, client, record
}

func TestVerifyAcceptsASealedArchiveAndPurgeIsIdempotent(t *testing.T) {
	store, client, record := sealedFixture(t)
	verify, err := New(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify.Verify(record); err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if err := verify.Purge(record); err != nil {
		t.Fatalf("Purge = %v", err)
	}
	if len(store.objects) != 0 {
		t.Fatalf("purge left objects: %v", store.objects)
	}
	if err := verify.Purge(record); err != nil {
		t.Fatalf("second Purge = %v", err)
	}
}

func TestVerifyRefusesEveryMismatch(t *testing.T) {
	_, client, good := sealedFixture(t)
	verify, err := New(client)
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(name string, change func(record *controlplane.ArchiveRecord)) {
		t.Run(name, func(t *testing.T) {
			record := good
			record.Packs = append([]controlplane.ObjectRef(nil), good.Packs...)
			change(&record)
			if err := verify.Verify(record); err == nil {
				t.Fatal("Verify accepted a corrupted record")
			}
		})
	}
	mutate("manifest digest", func(record *controlplane.ArchiveRecord) { record.Manifest.SHA256 = strings.Repeat("0", 64) })
	mutate("manifest size", func(record *controlplane.ArchiveRecord) { record.Manifest.SizeBytes-- })
	mutate("wrong attempt", func(record *controlplane.ArchiveRecord) {
		record.Attempt = "99999999-9999-4999-8999-999999999999"
	})
	mutate("wrong epoch", func(record *controlplane.ArchiveRecord) { record.SealedEpoch++ })
	mutate("root digest", func(record *controlplane.ArchiveRecord) { record.RootDigest = strings.Repeat("1", 64) })
	mutate("totals", func(record *controlplane.ArchiveRecord) { record.SealedAllocatedBytes++ })
	mutate("foreign manifest key", func(record *controlplane.ArchiveRecord) {
		record.Manifest.Key = record.Manifest.Key + "x"
	})
	mutate("pack size", func(record *controlplane.ArchiveRecord) { record.Packs[0].SizeBytes++ })
	mutate("pack digest", func(record *controlplane.ArchiveRecord) { record.Packs[0].SHA256 = strings.Repeat("2", 64) })
	mutate("pack checksum", func(record *controlplane.ArchiveRecord) { record.Packs[0].CRC64NVME = strings.Repeat("3", 16) })
	mutate("missing pack list entry", func(record *controlplane.ArchiveRecord) { record.Packs = record.Packs[:0] })
}

func TestVerifyRefusesAMissingPackObject(t *testing.T) {
	store, client, record := sealedFixture(t)
	verify, err := New(client)
	if err != nil {
		t.Fatal(err)
	}
	delete(store.objects, record.Packs[0].Key)
	if err := verify.Verify(record); err == nil {
		t.Fatal("Verify accepted an archive whose pack object is absent")
	}
}
