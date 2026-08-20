package archivestore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

// TestIntegrationAgainstARealStore is opt-in. It runs the whole archive object
// lifecycle against a real S3-compatible endpoint (MinIO in CI, S3 by hand) so
// the fake-server suite is checked against an actual implementation now and
// then. The fake-server suite remains the requirement; this test is never part
// of the default gate because it needs credentials and a network.
//
// To run it, point PORTABLEFS_ARCHIVE_INTEGRATION_CONFIG at a config file in
// the same format LoadConfigFile expects (root-owned or owned by the test user,
// mode 0600), whose bucket already exists and whose prefix is disposable:
//
//	PORTABLEFS_ARCHIVE_INTEGRATION_CONFIG=/etc/portablefs/minio-test.env \
//	    go test ./internal/archivestore/... -run TestIntegration -v
//
// A local MinIO is enough:
//
//	docker run -p 9000:9000 -e MINIO_ROOT_USER=minioadmin \
//	    -e MINIO_ROOT_PASSWORD=minioadmin minio/minio server /data
//	mc alias set local http://127.0.0.1:9000 minioadmin minioadmin
//	mc mb local/portablefs-archive
//
// MinIO needs PORTABLEFS_ARCHIVE_PATH_STYLE=true, and declares
// crc64nvme-full-object only on releases that support full-object checksums;
// set the capability to "none" otherwise and the checksum assertions relax.
func TestIntegrationAgainstARealStore(t *testing.T) {
	path := os.Getenv("PORTABLEFS_ARCHIVE_INTEGRATION_CONFIG")
	if path == "" {
		t.Skip("set PORTABLEFS_ARCHIVE_INTEGRATION_CONFIG to run the live archive-store test")
	}
	config, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFile(%s): %v", path, err)
	}
	client, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// A fresh epoch per run keeps concurrent runs from colliding, exactly as
	// the attempt discipline does in production.
	epoch := uint64(time.Now().UnixNano())
	manifestKey, err := client.KeyFor(testVolumeID, epoch, testAttempt, "manifest")
	if err != nil {
		t.Fatalf("KeyFor: %v", err)
	}
	packKey, err := client.KeyFor(testVolumeID, epoch, testAttempt, "pack-000001")
	if err != nil {
		t.Fatalf("KeyFor: %v", err)
	}
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		for _, key := range []string{manifestKey, packKey} {
			if err := client.DeleteObject(cleanupContext, key); err != nil {
				t.Logf("cleanup of %s failed: %v", key, err)
			}
		}
	})

	// Conditional create, then a lost race on the same key.
	manifest := bytes.Repeat([]byte("manifest\n"), 4096)
	manifestChecksum := ""
	if client.ChecksumsEnabled() {
		manifestChecksum = CRC64Hex(ChecksumCRC64NVME(manifest))
	}
	if _, err := client.PutObject(ctx, manifestKey, manifest, PutOptions{IfNoneMatch: true, ChecksumCRC64NVMEHex: manifestChecksum}); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if _, err := client.PutObject(ctx, manifestKey, manifest, PutOptions{IfNoneMatch: true}); err != nil && !errors.Is(err, ErrPreconditionFailed) {
		t.Logf("conditional create returned %v; some stores do not implement If-None-Match", err)
	}

	fetched, err := client.GetObject(ctx, manifestKey, 1<<20)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	if !bytes.Equal(fetched, manifest) {
		t.Fatal("the manifest round trip changed bytes")
	}

	// Multipart: two parts, the smaller of which is still above S3's 5 MiB
	// non-final-part minimum.
	partOne := bytes.Repeat([]byte("P"), 6<<20)
	partTwo := bytes.Repeat([]byte("Q"), 1<<20)
	options := CreateMultipartOptions{FullObjectChecksum: client.ChecksumsEnabled()}
	uploadID, err := client.CreateMultipartUpload(ctx, packKey, options)
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	sealed := false
	defer func() {
		if !sealed {
			if err := client.AbortMultipartUpload(ctx, packKey, uploadID); err != nil {
				t.Logf("abort failed: %v", err)
			}
		}
	}()
	var parts []UploadedPart
	for index, payload := range [][]byte{partOne, partTwo} {
		checksum := ""
		if client.ChecksumsEnabled() {
			checksum = CRC64Hex(ChecksumCRC64NVME(payload))
		}
		part, err := client.UploadPart(ctx, packKey, uploadID, index+1, PartBodyFromBytes(payload), checksum)
		if err != nil {
			t.Fatalf("UploadPart %d: %v", index+1, err)
		}
		parts = append(parts, part)
	}
	result, err := client.CompleteMultipartUpload(ctx, packKey, uploadID, parts)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	sealed = true

	assembled := append(append([]byte{}, partOne...), partTwo...)
	wantChecksum := CRC64Hex(ChecksumCRC64NVME(assembled))
	if client.ChecksumsEnabled() && result.ChecksumCRC64NVMEHex != wantChecksum {
		t.Fatalf("sealed checksum = %q, want %q", result.ChecksumCRC64NVMEHex, wantChecksum)
	}

	info, err := client.HeadObject(ctx, packKey)
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if info.Size != int64(len(assembled)) {
		t.Fatalf("sealed size = %d, want %d", info.Size, len(assembled))
	}
	if client.ChecksumsEnabled() && info.CRC64NVMEHex != wantChecksum {
		t.Fatalf("HeadObject checksum = %q, want %q", info.CRC64NVMEHex, wantChecksum)
	}

	// One contiguous ranged GET spanning the part boundary.
	const offset = (6 << 20) - 1024
	const length = 4096
	stream, err := client.GetObjectRange(ctx, packKey, offset, length)
	if err != nil {
		t.Fatalf("GetObjectRange: %v", err)
	}
	ranged := make([]byte, length)
	if _, err := io.ReadFull(stream, ranged); err != nil {
		t.Fatalf("read range: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("close range: %v", err)
	}
	if !bytes.Equal(ranged, assembled[offset:offset+length]) {
		t.Fatal("the ranged read returned the wrong bytes across the part boundary")
	}

	if err := client.DeleteObject(ctx, packKey); err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	if _, err := client.HeadObject(ctx, packKey); !errors.Is(err, ErrNotFound) {
		t.Fatalf("HeadObject after delete = %v, want ErrNotFound", err)
	}
}
