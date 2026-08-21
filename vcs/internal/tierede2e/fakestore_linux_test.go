//go:build linux

package tierede2e

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/archivestore"
)

// A minimal in-memory S3-compatible store, the same shape the archiver's own
// suite uses (vcs/internal/archiver/fakestore_test.go). Signatures are not
// verified — archivestore proves its signer against an independent fake — but
// everything this flow depends on is real: conditional create, multipart part
// ordering and ETags, full-object checksums, and exact ranged reads, because a
// ranged read of a pack frame is how every recall and every drain fetch is
// actually served.
//
// The one addition over the archiver's copy is rangeGets: a demand recall that
// never issued a ranged GET was not a cold recall, and the serve-while-cold
// assertions have to be able to say so.

const (
	storeBucket = "portablefs-archive"
	storePrefix = "archives"
)

type fakeUpload struct {
	key        string
	fullObject bool
	parts      map[int][]byte
	checksums  map[int]string
}

type fakeStore struct {
	mutex      sync.Mutex
	objects    map[string][]byte
	uploads    map[string]*fakeUpload
	nextUpload int
	rangeGET   int
}

func newFakeStore() *fakeStore {
	return &fakeStore{objects: map[string][]byte{}, uploads: map[string]*fakeUpload{}}
}

func (s *fakeStore) object(key string) ([]byte, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	payload, ok := s.objects[key]
	return payload, ok
}

// rangeGets is the number of ranged GETs the store has answered. It is the
// evidence that a read was served from the archive rather than from XFS.
func (s *fakeStore) rangeGets() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.rangeGET
}

func (s *fakeStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<26))
	if err != nil {
		writeStoreError(w, http.StatusBadRequest, "InvalidRequest", "unreadable body")
		return
	}
	prefix := "/" + storeBucket + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		writeStoreError(w, http.StatusNotFound, "NoSuchBucket", "unknown bucket")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	query := r.URL.Query()
	switch {
	case r.Method == http.MethodPost && query.Has("uploads"):
		s.createMultipart(w, r, key)
	case r.Method == http.MethodPut && query.Has("uploadId"):
		s.uploadPart(w, key, query.Get("uploadId"), query.Get("partNumber"), r.Header.Get("x-amz-checksum-crc64nvme"), body)
	case r.Method == http.MethodPost && query.Has("uploadId"):
		s.completeMultipart(w, key, query.Get("uploadId"), body)
	case r.Method == http.MethodDelete && query.Has("uploadId"):
		s.abortMultipart(w, query.Get("uploadId"))
	case r.Method == http.MethodPut:
		s.putObject(w, r, key, body)
	case r.Method == http.MethodGet:
		s.getObject(w, r, key)
	case r.Method == http.MethodHead:
		s.headObject(w, key)
	case r.Method == http.MethodDelete:
		s.deleteObject(w, key)
	default:
		writeStoreError(w, http.StatusMethodNotAllowed, "MethodNotAllowed", r.Method)
	}
}

func (s *fakeStore) putObject(w http.ResponseWriter, r *http.Request, key string, body []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if r.Header.Get("If-None-Match") == "*" {
		if _, exists := s.objects[key]; exists {
			writeStoreError(w, http.StatusPreconditionFailed, "PreconditionFailed", "object already exists")
			return
		}
	}
	if supplied := r.Header.Get("x-amz-checksum-crc64nvme"); supplied != "" {
		if want := archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(body)); supplied != want {
			writeStoreError(w, http.StatusBadRequest, "BadDigest", "crc64nvme mismatch")
			return
		}
	}
	s.objects[key] = body
	w.Header().Set("ETag", "\""+storeETag(body)+"\"")
	w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(body)))
	w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
	w.WriteHeader(http.StatusOK)
}

func (s *fakeStore) createMultipart(w http.ResponseWriter, r *http.Request, key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	fullObject := false
	if algorithm := r.Header.Get("x-amz-checksum-algorithm"); algorithm != "" {
		if algorithm != "CRC64NVME" || r.Header.Get("x-amz-checksum-type") != "FULL_OBJECT" {
			writeStoreError(w, http.StatusBadRequest, "InvalidRequest", "unsupported checksum declaration")
			return
		}
		fullObject = true
	}
	s.nextUpload++
	uploadID := fmt.Sprintf("upload-%d", s.nextUpload)
	s.uploads[uploadID] = &fakeUpload{key: key, fullObject: fullObject, parts: map[int][]byte{}, checksums: map[int]string{}}
	writeStoreXML(w, fmt.Sprintf(
		"<InitiateMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId></InitiateMultipartUploadResult>",
		storeBucket, key, uploadID))
}

func (s *fakeStore) uploadPart(w http.ResponseWriter, key, uploadID, partNumber, checksum string, body []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	upload, ok := s.uploads[uploadID]
	if !ok || upload.key != key {
		writeStoreError(w, http.StatusNotFound, "NoSuchUpload", "unknown upload")
		return
	}
	number, err := strconv.Atoi(partNumber)
	if err != nil || number < 1 || number > 10000 {
		writeStoreError(w, http.StatusBadRequest, "InvalidPart", "bad part number")
		return
	}
	if checksum != "" {
		if want := archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(body)); checksum != want {
			writeStoreError(w, http.StatusBadRequest, "BadDigest", "part crc64nvme mismatch")
			return
		}
	}
	upload.parts[number] = body
	upload.checksums[number] = checksum
	w.Header().Set("ETag", "\""+storeETag(body)+"\"")
	if checksum != "" {
		w.Header().Set("x-amz-checksum-crc64nvme", checksum)
	}
	w.WriteHeader(http.StatusOK)
}

type completionDocument struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber        int    `xml:"PartNumber"`
		ETag              string `xml:"ETag"`
		ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME"`
	} `xml:"Part"`
}

func (s *fakeStore) completeMultipart(w http.ResponseWriter, key, uploadID string, body []byte) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	upload, ok := s.uploads[uploadID]
	if !ok || upload.key != key {
		writeStoreError(w, http.StatusNotFound, "NoSuchUpload", "unknown upload")
		return
	}
	var document completionDocument
	if err := xml.Unmarshal(body, &document); err != nil || len(document.Parts) == 0 {
		writeStoreError(w, http.StatusBadRequest, "MalformedXML", "bad completion body")
		return
	}
	var assembled []byte
	previous := 0
	for _, part := range document.Parts {
		stored, ok := upload.parts[part.PartNumber]
		if !ok || part.PartNumber <= previous {
			writeStoreError(w, http.StatusBadRequest, "InvalidPart", "unknown or misordered part")
			return
		}
		if strings.Trim(part.ETag, "\"") != storeETag(stored) {
			writeStoreError(w, http.StatusBadRequest, "InvalidPart", "etag mismatch")
			return
		}
		if part.ChecksumCRC64NVME != "" && part.ChecksumCRC64NVME != upload.checksums[part.PartNumber] {
			writeStoreError(w, http.StatusBadRequest, "InvalidPart", "part checksum mismatch")
			return
		}
		previous = part.PartNumber
		assembled = append(assembled, stored...)
	}
	s.objects[key] = assembled
	delete(s.uploads, uploadID)
	checksum := ""
	if upload.fullObject {
		checksum = fmt.Sprintf("<ChecksumCRC64NVME>%s</ChecksumCRC64NVME><ChecksumType>FULL_OBJECT</ChecksumType>",
			archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(assembled)))
	}
	writeStoreXML(w, fmt.Sprintf(
		"<CompleteMultipartUploadResult><Bucket>%s</Bucket><Key>%s</Key><ETag>&quot;%s-%d&quot;</ETag>%s</CompleteMultipartUploadResult>",
		storeBucket, key, storeETag(assembled), len(document.Parts), checksum))
}

func (s *fakeStore) abortMultipart(w http.ResponseWriter, uploadID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.uploads, uploadID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *fakeStore) getObject(w http.ResponseWriter, r *http.Request, key string) {
	s.mutex.Lock()
	payload, ok := s.objects[key]
	s.mutex.Unlock()
	if !ok {
		writeStoreError(w, http.StatusNotFound, "NoSuchKey", "unknown key")
		return
	}
	w.Header().Set("ETag", "\""+storeETag(payload)+"\"")
	rangeHeader := r.Header.Get("Range")
	if rangeHeader == "" {
		w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(payload)))
		w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return
	}
	first, last, err := parseStoreRange(rangeHeader, int64(len(payload)))
	if err != nil {
		writeStoreError(w, http.StatusRequestedRangeNotSatisfiable, "InvalidRange", err.Error())
		return
	}
	s.mutex.Lock()
	s.rangeGET++
	s.mutex.Unlock()
	slice := payload[first : last+1]
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(payload)))
	w.Header().Set("Content-Length", strconv.Itoa(len(slice)))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(slice)
}

func (s *fakeStore) headObject(w http.ResponseWriter, key string) {
	s.mutex.Lock()
	payload, ok := s.objects[key]
	s.mutex.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", "\""+storeETag(payload)+"\"")
	w.Header().Set("x-amz-checksum-crc64nvme", archivestore.CRC64Base64(archivestore.ChecksumCRC64NVME(payload)))
	w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(http.StatusOK)
}

func (s *fakeStore) deleteObject(w http.ResponseWriter, key string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.objects[key]; !ok {
		writeStoreError(w, http.StatusNotFound, "NoSuchKey", "unknown key")
		return
	}
	delete(s.objects, key)
	w.WriteHeader(http.StatusNoContent)
}

func parseStoreRange(value string, size int64) (int64, int64, error) {
	span, ok := strings.CutPrefix(value, "bytes=")
	if !ok || strings.Contains(span, ",") {
		return 0, 0, fmt.Errorf("unsupported range %q", value)
	}
	firstText, lastText, ok := strings.Cut(span, "-")
	if !ok {
		return 0, 0, fmt.Errorf("unsupported range %q", value)
	}
	first, err := strconv.ParseInt(firstText, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	last, err := strconv.ParseInt(lastText, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if first < 0 || first > last || first >= size {
		return 0, 0, fmt.Errorf("range %q outside object", value)
	}
	if last >= size {
		last = size - 1
	}
	return first, last, nil
}

func storeETag(payload []byte) string {
	return archivestore.CRC64Hex(archivestore.ChecksumCRC64NVME(payload))
}

func writeStoreError(w http.ResponseWriter, status int, code, message string) {
	body := fmt.Sprintf("<?xml version=\"1.0\"?><Error><Code>%s</Code><Message>%s</Message><RequestId>fake</RequestId></Error>", code, message)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func writeStoreXML(w http.ResponseWriter, body string) {
	document := "<?xml version=\"1.0\"?>" + body
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("Content-Length", strconv.Itoa(len(document)))
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, document)
}

// newTestStore starts the fake and returns a client addressed at it.
func newTestStore(t *testing.T) (*archivestore.Client, *fakeStore) {
	t.Helper()
	store := newFakeStore()
	server := httptest.NewServer(store)
	t.Cleanup(server.Close)
	client, err := archivestore.New(archivestore.Config{
		Endpoint:           server.URL,
		Region:             "us-east-1",
		Bucket:             storeBucket,
		KeyPrefix:          storePrefix,
		AccessKeyID:        "AKIAEXAMPLE",
		SecretAccessKey:    "secret-example",
		ChecksumCapability: archivestore.ChecksumCRC64NVMEFullObject,
		PathStyle:          true,
		MaxAttempts:        1,
	})
	if err != nil {
		t.Fatalf("build store client: %v", err)
	}
	return client, store
}
