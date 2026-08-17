package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
	"github.com/steerlabs/portablefs/vcs/readonlyfs"
	"golang.org/x/sys/unix"
)

const (
	maximumBodyBytes     = 2 << 20
	maximumCursors       = 4096
	maximumVolumeCursors = 128
	cursorLifetime       = 2 * time.Minute
	sessionIdleTime      = 15 * time.Minute
	grantRefreshMargin   = 30 * time.Second
	previewMaximum       = 512 << 10
	maximumDownloads     = 16
	maximumOperations    = 64
)

type options struct {
	requestPublicKey string
	requestIssuer    string
	identityDir      string
	listen           string
	maxSessions      int
}

type identity struct {
	csrPEM     string
	keyID      string
	privatePEM []byte
}

type readGrant struct {
	Access                    []string `json:"access"`
	AuthorityAddress          string   `json:"authorityAddress"`
	AuthorityCACertificatePEM string   `json:"authorityCaCertificatePem"`
	AuthorityGeneration       uint64   `json:"authorityGeneration"`
	AuthorityServerName       string   `json:"authorityServerName"`
	Capability                string   `json:"capability"`
	CertificateExpiresAt      string   `json:"certificateExpiresAt"`
	ClientCertificatePEM      string   `json:"clientCertificatePem"`
	ExpiresAt                 string   `json:"expiresAt"`
	ManagerReleaseID          string   `json:"managerReleaseId"`
	VolumeID                  string   `json:"volumeId"`
}

type volumeSession struct {
	client       *readonlyfs.Client
	expiresAt    time.Time
	generation   uint64
	lastUsedUnix atomic.Int64
	managerBuild string
	mu           sync.RWMutex
}

type cursorRecord struct {
	cursor    *readonlyfs.Cursor
	expiresAt time.Time
	parentKey string
	session   *volumeSession
	volumeID  string
}

type server struct {
	requestKey  ed25519.PublicKey
	issuer      string
	identity    identity
	maxSessions int
	downloads   chan struct{}
	operations  chan struct{}
	mu          sync.Mutex
	sessions    map[string]*volumeSession
	cursors     map[string]cursorRecord
}

func main() {
	var configured options
	flag.StringVar(&configured.requestPublicKey, "request-public-key", "", "trusted request-signer Ed25519 public key PEM")
	flag.StringVar(&configured.requestIssuer, "request-issuer", "", "exact trusted request-token issuer")
	flag.StringVar(&configured.identityDir, "identity-dir", "", "private Files service identity directory")
	flag.StringVar(&configured.listen, "listen", "127.0.0.1:4315", "private HTTP listen address")
	flag.IntVar(&configured.maxSessions, "max-sessions", 128, "maximum live volume sessions")
	flag.Parse()
	if configured.requestPublicKey == "" || configured.requestIssuer == "" || configured.identityDir == "" || configured.maxSessions < 1 || configured.maxSessions > 4096 {
		log.Fatal("portablefs-files: --request-public-key, --request-issuer, --identity-dir, and a bounded --max-sessions are required")
	}
	requestKey, err := loadRequestPublicKey(configured.requestPublicKey)
	if err != nil {
		log.Fatalf("portablefs-files: request public key: %v", err)
	}
	serviceIdentity, err := loadOrCreateIdentity(configured.identityDir)
	if err != nil {
		log.Fatalf("portablefs-files: identity: %v", err)
	}
	service := &server{
		requestKey: requestKey, issuer: configured.requestIssuer, identity: serviceIdentity, maxSessions: configured.maxSessions,
		downloads: make(chan struct{}, maximumDownloads), operations: make(chan struct{}, maximumOperations),
		sessions: make(map[string]*volumeSession), cursors: make(map[string]cursorRecord),
	}
	stop := make(chan struct{})
	go service.sweep(stop)
	httpServer := &http.Server{
		Addr: configured.listen, Handler: service.routes(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10,
	}
	log.Printf("portablefs-files: listening on %s", configured.listen)
	shutdownContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	shutdownFinished := make(chan struct{})
	go func() {
		defer close(shutdownFinished)
		<-shutdownContext.Done()
		deadline, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(deadline); err != nil {
			_ = httpServer.Close()
		}
	}()
	serveErr := httpServer.ListenAndServe()
	if shutdownContext.Err() != nil {
		<-shutdownFinished
	}
	close(stop)
	service.close()
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		log.Fatal(serveErr)
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /v1/volumes/{volume}/identity", s.handleIdentity)
	mux.HandleFunc("GET /v1/volumes/{volume}/session", s.handleSessionStatus)
	mux.HandleFunc("PUT /v1/volumes/{volume}/session", s.handleSessionInstall)
	mux.HandleFunc("GET /v1/volumes/{volume}/entries", s.handleEntries)
	mux.HandleFunc("GET /v1/volumes/{volume}/content", s.handleContent)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(writer, request)
	})
}

func (s *server) handleIdentity(writer http.ResponseWriter, request *http.Request) {
	volumeID := request.PathValue("volume")
	if !s.authorize(writer, request, expectedClaims{Operation: "identity", VolumeID: volumeID}) {
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"csrPem": s.identity.csrPEM, "keyId": s.identity.keyID})
}

func (s *server) handleSessionStatus(writer http.ResponseWriter, request *http.Request) {
	volumeID := request.PathValue("volume")
	if !s.authorize(writer, request, expectedClaims{Operation: "session.status", VolumeID: volumeID}) {
		return
	}
	session := s.lockCurrentSession(volumeID)
	if session == nil {
		writeJSON(writer, http.StatusOK, map[string]any{"ready": false})
		return
	}
	defer session.mu.RUnlock()
	ready := time.Now().Add(grantRefreshMargin).Before(session.expiresAt) && session.client.Err() == nil
	writeJSON(writer, http.StatusOK, map[string]any{
		"authorityGeneration": session.generation, "expiresAt": session.expiresAt.Format(time.RFC3339Nano),
		"managerReleaseId": session.managerBuild, "ready": ready,
	})
}

func (s *server) handleSessionInstall(writer http.ResponseWriter, request *http.Request) {
	volumeID := request.PathValue("volume")
	body, err := readBoundedBody(request)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	digest := sha256.Sum256(body)
	if !s.authorize(writer, request, expectedClaims{
		Operation: "session.install", VolumeID: volumeID,
		BodySHA256: base64.RawURLEncoding.EncodeToString(digest[:]),
	}) {
		return
	}
	var grant readGrant
	if err := decodeJSON(body, &grant); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if grant.VolumeID != volumeID || len(grant.Access) != 1 || grant.Access[0] != "read" {
		writeError(writer, http.StatusBadRequest, "invalid_grant", "grant does not authorize this read-only volume session")
		return
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, grant.ExpiresAt)
	certificateExpiresAt, certificateErr := time.Parse(time.RFC3339Nano, grant.CertificateExpiresAt)
	if certificateErr == nil && certificateExpiresAt.Before(expiresAt) {
		expiresAt = certificateExpiresAt
	}
	if err != nil || certificateErr != nil || grant.AuthorityGeneration == 0 || grant.ManagerReleaseID == "" || !expiresAt.After(time.Now().Add(grantRefreshMargin)) {
		writeError(writer, http.StatusBadRequest, "invalid_grant", "grant is expired or too close to expiry")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	client, err := readonlyfs.Dial(ctx, readonlyfs.Config{
		Address: grant.AuthorityAddress, AuthorityCAPEM: []byte(grant.AuthorityCACertificatePEM),
		AuthorityServerName: grant.AuthorityServerName, Capability: []byte(grant.Capability),
		ClientCertificatePEM: []byte(grant.ClientCertificatePEM), ClientPrivateKeyPEM: s.identity.privatePEM,
		VolumeID: volumeID,
	})
	if err != nil {
		writeError(writer, http.StatusBadGateway, "authority_unavailable", "PortableFS authority session could not be established")
		return
	}
	installed := &volumeSession{client: client, expiresAt: expiresAt, generation: grant.AuthorityGeneration, managerBuild: grant.ManagerReleaseID}
	installed.lastUsedUnix.Store(time.Now().UnixNano())
	var prior *volumeSession
	var evicted *volumeSession
	s.mu.Lock()
	if len(s.sessions) >= s.maxSessions && s.sessions[volumeID] == nil {
		var evictedVolume string
		var oldest int64 = 1<<63 - 1
		for candidateVolume, candidate := range s.sessions {
			if used := candidate.lastUsedUnix.Load(); used < oldest {
				oldest = used
				evicted = candidate
				evictedVolume = candidateVolume
			}
		}
		if evicted != nil {
			delete(s.sessions, evictedVolume)
		}
	}
	prior = s.sessions[volumeID]
	s.sessions[volumeID] = installed
	stale := s.removeVolumeCursorsLocked(volumeID)
	if evicted != nil {
		for token, record := range s.cursors {
			if record.session == evicted {
				stale = append(stale, record)
				delete(s.cursors, token)
			}
		}
	}
	s.mu.Unlock()
	closeCursors(stale)
	for _, retired := range []*volumeSession{prior, evicted} {
		if retired != nil {
			closeSessionWhenIdle(retired)
		}
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"expiresAt": expiresAt.Format(time.RFC3339Nano), "ready": true})
}

func (s *server) handleEntries(writer http.ResponseWriter, request *http.Request) {
	volumeID := request.PathValue("volume")
	parentKey := request.URL.Query().Get("parent")
	cursorToken := request.URL.Query().Get("cursor")
	knownRevision := request.URL.Query().Get("revision")
	retainedCursor := request.URL.Query().Get("retain")
	limit, err := parseBoundedInt(request.URL.Query().Get("limit"), 200, 1, 500)
	if err != nil || cursorToken != "" && (knownRevision != "" || retainedCursor != "") || retainedCursor != "" && knownRevision == "" || !validOpaqueToken(knownRevision, 16, 128) || !validOpaqueToken(retainedCursor, 22, 256) {
		if err != nil {
			writeError(writer, http.StatusBadRequest, "invalid_request", "directory page limit is invalid")
		} else {
			writeError(writer, http.StatusBadRequest, "invalid_request", "directory revalidation is invalid")
		}
		return
	}
	if !s.authorize(writer, request, expectedClaims{
		Operation: "list", VolumeID: volumeID, PathKey: parentKey, Cursor: cursorToken,
		KnownRevision: knownRevision, RetainedCursor: retainedCursor, Limit: uint64(limit),
	}) {
		return
	}
	if _, err := readonlyfs.DecodePath(parentKey); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_path", "directory key is invalid")
		return
	}
	session, release := s.acquireSession(writer, volumeID)
	if session == nil {
		return
	}
	defer release()
	if !acquireOperation(request.Context(), s.operations) {
		writeError(writer, http.StatusServiceUnavailable, "busy", "Files service is busy")
		return
	}
	defer releaseOperation(s.operations)
	var cursor *readonlyfs.Cursor
	if cursorToken != "" {
		var ok bool
		cursor, ok = s.takeCursor(cursorToken, volumeID, parentKey, session)
		if !ok {
			writeError(writer, http.StatusConflict, "cursor_expired", "directory cursor expired; list the directory again")
			return
		}
	}
	page, err := session.client.List(request.Context(), parentKey, limit, cursor)
	if err != nil {
		s.handleFileError(writer, volumeID, session, err)
		return
	}
	revision := pageRevision(parentKey, page)
	unchanged := false
	next := ""
	if knownRevision == revision {
		switch {
		case retainedCursor != "" && page.Next != nil && s.renewCursor(retainedCursor, volumeID, parentKey, session):
			_ = page.Next.Close(context.Background())
			page.Next = nil
			next = retainedCursor
			unchanged = true
		case retainedCursor == "" && page.Next == nil:
			unchanged = true
		}
	}
	entries := make([]map[string]any, 0, len(page.Entries))
	if !unchanged {
		if retainedCursor != "" {
			s.dropCursor(retainedCursor, volumeID, parentKey, session)
		}
		for _, entry := range page.Entries {
			key, keyErr := readonlyfs.AppendPath(parentKey, entry.Name)
			if keyErr != nil {
				if page.Next != nil {
					_ = page.Next.Close(context.Background())
				}
				s.handleFileError(writer, volumeID, session, keyErr)
				return
			}
			modified := any(nil)
			if !entry.Attr.ModifiedAt.IsZero() {
				modified = entry.Attr.ModifiedAt.Format(time.RFC3339Nano)
			}
			entries = append(entries, map[string]any{
				"executable": entry.Attr.Mode&0o111 != 0, "hidden": len(entry.Name) > 0 && entry.Name[0] == '.',
				"key": key, "kind": entry.Attr.Kind, "mode": entry.Attr.Mode & 0o7777,
				"modifiedAt": modified, "name": displayName(entry.Name),
				"nameBytes": base64.RawURLEncoding.EncodeToString(entry.Name), "sizeBytes": entry.Attr.Size,
			})
		}
		if page.Next != nil {
			next, err = s.storeCursor(volumeID, parentKey, session, page.Next)
			if err != nil {
				_ = page.Next.Close(context.Background())
				writeError(writer, http.StatusServiceUnavailable, "cursor_capacity", err.Error())
				return
			}
		}
	}
	payload := map[string]any{"cursor": nil, "entries": entries, "parentKey": parentKey, "revision": revision}
	if next != "" {
		payload["cursor"] = next
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (s *server) handleContent(writer http.ResponseWriter, request *http.Request) {
	volumeID := request.PathValue("volume")
	fileKey := request.URL.Query().Get("file")
	offset, offsetErr := parseUint(request.URL.Query().Get("offset"), 0)
	length, lengthErr := parseUint(request.URL.Query().Get("length"), 0)
	mode := request.URL.Query().Get("mode")
	if (mode != "preview" && mode != "download") || offsetErr != nil || lengthErr != nil || mode == "preview" && (length == 0 || length > previewMaximum) {
		writeError(writer, http.StatusBadRequest, "invalid_request", "content range is invalid")
		return
	}
	if !s.authorize(writer, request, expectedClaims{Operation: mode, VolumeID: volumeID, PathKey: fileKey, Offset: offset, Length: length}) {
		return
	}
	if _, err := readonlyfs.DecodePath(fileKey); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_path", "file key is invalid")
		return
	}
	session, release := s.acquireSession(writer, volumeID)
	if session == nil {
		return
	}
	defer release()
	pool := s.operations
	if mode == "download" {
		pool = s.downloads
	}
	if !acquireOperation(request.Context(), pool) {
		writeError(writer, http.StatusServiceUnavailable, "busy", "Files service is busy")
		return
	}
	defer releaseOperation(pool)
	file, err := session.client.OpenFile(request.Context(), fileKey)
	if err != nil {
		s.handleFileError(writer, volumeID, session, err)
		return
	}
	defer func() { _ = file.Close(context.Background()) }()
	attr := file.Attr()
	if offset > attr.Size {
		writeError(writer, http.StatusRequestedRangeNotSatisfiable, "invalid_range", "content offset exceeds file size")
		return
	}
	remaining := attr.Size - offset
	if length != 0 && length < remaining {
		remaining = length
	}
	firstSize := min(remaining, 32<<10)
	first := make([]byte, firstSize)
	read, readErr := file.ReadAt(request.Context(), first, offset)
	first = first[:read]
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		s.handleFileError(writer, volumeID, session, readErr)
		return
	}
	contentType := http.DetectContentType(first)
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("ETag", fileETag(attr))
	writer.Header().Set("X-Opensteer-File-Size", strconv.FormatUint(attr.Size, 10))
	writer.Header().Set("X-Opensteer-File-Truncated", strconv.FormatBool(offset+remaining < attr.Size))
	if !attr.ModifiedAt.IsZero() {
		writer.Header().Set("Last-Modified", attr.ModifiedAt.Format(http.TimeFormat))
	}
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(first); err != nil {
		return
	}
	position := offset + uint64(len(first))
	buffer := make([]byte, 64<<10)
	for position < offset+remaining {
		want := min(uint64(len(buffer)), offset+remaining-position)
		read, err = file.ReadAt(request.Context(), buffer[:want], position)
		if read > 0 {
			if _, writeErr := writer.Write(buffer[:read]); writeErr != nil {
				return
			}
			position += uint64(read)
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil || read == 0 {
			return
		}
	}
}

func (s *server) acquireSession(writer http.ResponseWriter, volumeID string) (*volumeSession, func()) {
	session := s.lockCurrentSession(volumeID)
	if session == nil || !time.Now().Add(grantRefreshMargin).Before(session.expiresAt) || session.client.Err() != nil {
		if session != nil {
			session.mu.RUnlock()
		}
		writeError(writer, http.StatusConflict, "session_required", "a current read-only PortableFS session is required")
		return nil, nil
	}
	session.lastUsedUnix.Store(time.Now().UnixNano())
	return session, session.mu.RUnlock
}

// lockCurrentSession never waits on a session lock while holding the global
// registry lock. Directory operations hold the session read lock while briefly
// entering the registry for cursor updates, so the opposite order could
// deadlock behind an installer waiting for the session write lock.
func (s *server) lockCurrentSession(volumeID string) *volumeSession {
	s.mu.Lock()
	session := s.sessions[volumeID]
	s.mu.Unlock()
	if session == nil {
		return nil
	}
	session.mu.RLock()
	s.mu.Lock()
	current := s.sessions[volumeID] == session
	s.mu.Unlock()
	if !current {
		session.mu.RUnlock()
		return nil
	}
	return session
}

func (s *server) handleFileError(writer http.ResponseWriter, volumeID string, session *volumeSession, err error) {
	if session.client.Err() != nil {
		s.retireSession(volumeID, session)
		writeError(writer, http.StatusConflict, "session_required", "PortableFS authority session ended")
		return
	}
	status := http.StatusBadGateway
	code := "filesystem_error"
	switch {
	case errors.Is(err, syscall.ENOENT):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, syscall.ENOTDIR), errors.Is(err, syscall.EISDIR), errors.Is(err, syscall.EINVAL):
		status, code = http.StatusBadRequest, "invalid_path"
	case errors.Is(err, syscall.ESTALE):
		status, code = http.StatusConflict, "directory_changed"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status, code = http.StatusGatewayTimeout, "timeout"
	}
	writeError(writer, status, code, "PortableFS could not complete the file request")
}

func (s *server) retireSession(volumeID string, target *volumeSession) {
	s.mu.Lock()
	if s.sessions[volumeID] != target {
		s.mu.Unlock()
		return
	}
	delete(s.sessions, volumeID)
	stale := s.removeVolumeCursorsLocked(volumeID)
	s.mu.Unlock()
	closeCursors(stale)
	// The caller may still hold the session read lock. The writer lock waits
	// for every in-flight operation before closing the shared authority client.
	closeSessionWhenIdle(target)
}

func acquireOperation(ctx context.Context, pool chan struct{}) bool {
	select {
	case pool <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func releaseOperation(pool chan struct{}) { <-pool }

func (s *server) storeCursor(volumeID, parentKey string, session *volumeSession, cursor *readonlyfs.Cursor) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cursors) >= maximumCursors {
		return "", errors.New("Files service directory-cursor capacity reached")
	}
	volumeCursors := 0
	for _, record := range s.cursors {
		if record.volumeID == volumeID {
			volumeCursors++
		}
	}
	if volumeCursors >= maximumVolumeCursors {
		return "", errors.New("Workspace directory-cursor capacity reached")
	}
	for {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return "", err
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		if _, exists := s.cursors[token]; exists {
			continue
		}
		s.cursors[token] = cursorRecord{cursor: cursor, expiresAt: time.Now().Add(cursorLifetime), parentKey: parentKey, session: session, volumeID: volumeID}
		return token, nil
	}
}

func (s *server) takeCursor(token, volumeID, parentKey string, session *volumeSession) (*readonlyfs.Cursor, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.cursors[token]
	if !ok || record.volumeID != volumeID || record.parentKey != parentKey || record.session != session {
		return nil, false
	}
	delete(s.cursors, token)
	if !time.Now().Before(record.expiresAt) {
		go func() { _ = record.cursor.Close(context.Background()) }()
		return nil, false
	}
	return record.cursor, true
}

func (s *server) renewCursor(token, volumeID, parentKey string, session *volumeSession) bool {
	var stale *readonlyfs.Cursor
	s.mu.Lock()
	record, ok := s.cursors[token]
	if !ok || record.volumeID != volumeID || record.parentKey != parentKey || record.session != session {
		s.mu.Unlock()
		return false
	}
	if !time.Now().Before(record.expiresAt) {
		delete(s.cursors, token)
		stale = record.cursor
		s.mu.Unlock()
		_ = stale.Close(context.Background())
		return false
	}
	record.expiresAt = time.Now().Add(cursorLifetime)
	s.cursors[token] = record
	s.mu.Unlock()
	return true
}

func (s *server) dropCursor(token, volumeID, parentKey string, session *volumeSession) {
	var dropped *readonlyfs.Cursor
	s.mu.Lock()
	if record, ok := s.cursors[token]; ok && record.volumeID == volumeID && record.parentKey == parentKey && record.session == session {
		delete(s.cursors, token)
		dropped = record.cursor
	}
	s.mu.Unlock()
	if dropped != nil {
		_ = dropped.Close(context.Background())
	}
}

func (s *server) removeVolumeCursorsLocked(volumeID string) []cursorRecord {
	var removed []cursorRecord
	for token, record := range s.cursors {
		if record.volumeID == volumeID {
			removed = append(removed, record)
			delete(s.cursors, token)
		}
	}
	return removed
}

func (s *server) sweep(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			var staleCursors []cursorRecord
			var staleSessions []*volumeSession
			s.mu.Lock()
			for token, record := range s.cursors {
				if !now.Before(record.expiresAt) {
					staleCursors = append(staleCursors, record)
					delete(s.cursors, token)
				}
			}
			for volumeID, session := range s.sessions {
				lastUsed := time.Unix(0, session.lastUsedUnix.Load())
				if !now.Before(session.expiresAt) || now.Sub(lastUsed) >= sessionIdleTime || session.client.Err() != nil {
					staleSessions = append(staleSessions, session)
					delete(s.sessions, volumeID)
					staleCursors = append(staleCursors, s.removeVolumeCursorsLocked(volumeID)...)
				}
			}
			s.mu.Unlock()
			closeCursors(staleCursors)
			for _, session := range staleSessions {
				session.mu.Lock()
				_ = session.client.Close()
				session.mu.Unlock()
			}
		}
	}
}

func (s *server) close() {
	s.mu.Lock()
	cursors := make([]cursorRecord, 0, len(s.cursors))
	for _, cursor := range s.cursors {
		cursors = append(cursors, cursor)
	}
	sessions := make([]*volumeSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}
	s.cursors = make(map[string]cursorRecord)
	s.sessions = make(map[string]*volumeSession)
	s.mu.Unlock()
	closeCursors(cursors)
	for _, session := range sessions {
		session.mu.Lock()
		_ = session.client.Close()
		session.mu.Unlock()
	}
}

func closeCursors(records []cursorRecord) {
	for _, record := range records {
		_ = record.cursor.Close(context.Background())
	}
}

func closeSessionWhenIdle(session *volumeSession) {
	go func() {
		session.mu.Lock()
		_ = session.client.Close()
		session.mu.Unlock()
	}()
}

type expectedClaims struct {
	Operation      string
	VolumeID       string
	PathKey        string
	Cursor         string
	Limit          uint64
	Offset         uint64
	Length         uint64
	BodySHA256     string
	KnownRevision  string
	RetainedCursor string
}

type tokenClaims struct {
	Audience       string `json:"aud"`
	Expires        int64  `json:"exp"`
	Issued         int64  `json:"iat"`
	Issuer         string `json:"iss"`
	Operation      string `json:"operation"`
	VolumeID       string `json:"volumeId"`
	PathKey        string `json:"pathKey"`
	Cursor         string `json:"cursor"`
	Limit          uint64 `json:"limit"`
	Offset         uint64 `json:"offset"`
	Length         uint64 `json:"length"`
	BodySHA256     string `json:"bodySha256"`
	KnownRevision  string `json:"knownRevision"`
	RetainedCursor string `json:"retainedCursor"`
}

func (s *server) authorize(writer http.ResponseWriter, request *http.Request, expected expectedClaims) bool {
	value := request.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") || !verifyToken(s.requestKey, s.issuer, strings.TrimPrefix(value, "Bearer "), expected) {
		writeError(writer, http.StatusUnauthorized, "unauthorized", "valid request authorization is required")
		return false
	}
	return true
}

func verifyToken(key ed25519.PublicKey, issuer, token string, expected expectedClaims) bool {
	if len(token) > 64<<10 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(header) != `{"alg":"EdDSA","typ":"JWT","v":1}` {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims tokenClaims
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	now := time.Now().Unix()
	return claims.Audience == "portablefs-files" && claims.Issuer == issuer && claims.Expires > now && claims.Expires <= now+60 && claims.Issued <= now+5 && claims.Issued >= now-60 &&
		claims.Operation == expected.Operation && claims.VolumeID == expected.VolumeID && claims.PathKey == expected.PathKey && claims.Cursor == expected.Cursor && claims.Limit == expected.Limit && claims.Offset == expected.Offset && claims.Length == expected.Length &&
		claims.BodySHA256 == expected.BodySHA256 && claims.KnownRevision == expected.KnownRevision && claims.RetainedCursor == expected.RetainedCursor
}

func loadRequestPublicKey(path string) (ed25519.PublicKey, error) {
	cleaned := filepath.Clean(path)
	fd, err := unix.Open(cleaned, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), cleaned)
	if file == nil {
		_ = unix.Close(fd)
		return nil, syscall.EBADF
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, errors.New("request public key must be a bounded regular file")
	}
	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected one PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("request public key must be Ed25519")
	}
	return key, nil
}

func loadOrCreateIdentity(directory string) (identity, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return identity{}, err
	}
	absolute = filepath.Clean(absolute)
	if err := privatepath.EnsureDir(absolute); err != nil {
		return identity{}, err
	}
	parent, err := privatepath.OpenExistingDir(absolute)
	if err != nil {
		return identity{}, err
	}
	defer parent.Close()
	lock, err := privatepath.OpenLockFile(parent, absolute, "files-identity.lock")
	if err != nil {
		return identity{}, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return identity{}, fmt.Errorf("lock Files identity: %w", err)
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
	path := filepath.Join(absolute, "files-private.pem")
	raw, err := privatepath.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, private, generateErr := ed25519.GenerateKey(rand.Reader)
		if generateErr != nil {
			return identity{}, generateErr
		}
		der, marshalErr := x509.MarshalPKCS8PrivateKey(private)
		if marshalErr != nil {
			return identity{}, marshalErr
		}
		raw = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := privatepath.WriteFileAtomic(path, raw); err != nil {
			return identity{}, err
		}
		raw, err = privatepath.ReadFile(path)
		if err != nil {
			return identity{}, err
		}
	} else if err != nil {
		return identity{}, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return identity{}, errors.New("Files identity must contain one PRIVATE KEY PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return identity{}, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return identity{}, errors.New("Files identity must be Ed25519")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return identity{}, err
	}
	digest := sha256.Sum256(publicDER)
	keyID := base64.RawURLEncoding.EncodeToString(digest[:])
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "portablefs-files:" + keyID}}, private)
	if err != nil {
		return identity{}, err
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return identity{csrPEM: string(csr), keyID: keyID, privatePEM: append([]byte(nil), raw...)}, nil
}

func readBoundedBody(request *http.Request) ([]byte, error) {
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, maximumBodyBytes+1))
	if err != nil {
		return nil, errors.New("request body could not be read")
	}
	if len(body) > maximumBodyBytes {
		return nil, errors.New("request body exceeds its byte limit")
	}
	return body, nil
}

func decodeJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("request body is not valid JSON")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("request body contains trailing data")
	}
	return nil
}

func parseBoundedInt(value string, fallback, minimum, maximum int) (int, error) {
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, syscall.EINVAL
	}
	return parsed, nil
}

func parseUint(value string, fallback uint64) (uint64, error) {
	if value == "" {
		return fallback, nil
	}
	return strconv.ParseUint(value, 10, 63)
}

func validOpaqueToken(value string, minimum, maximum int) bool {
	if value == "" {
		return true
	}
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func displayName(raw []byte) string {
	if !utf8.Valid(raw) {
		return fmt.Sprintf("[%s]", base64.RawURLEncoding.EncodeToString(raw))
	}
	return strings.Map(func(value rune) rune {
		if unicode.IsControl(value) || unicode.Is(unicode.Bidi_Control, value) {
			return unicode.ReplacementChar
		}
		return value
	}, string(raw))
}

func pageRevision(parent string, page readonlyfs.Page) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(parent))
	writeAttrDigest(digest, page.Directory)
	for _, entry := range page.Entries {
		_, _ = digest.Write(entry.Name)
		writeAttrDigest(digest, entry.Attr)
	}
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func fileETag(attr readonlyfs.Attr) string {
	digest := sha256.New()
	writeAttrDigest(digest, attr)
	return `"` + base64.RawURLEncoding.EncodeToString(digest.Sum(nil)) + `"`
}

func writeAttrDigest(writer io.Writer, attr readonlyfs.Attr) {
	var values [40]byte
	binary.BigEndian.PutUint64(values[0:8], attr.Inode)
	binary.BigEndian.PutUint64(values[8:16], attr.Size)
	binary.BigEndian.PutUint64(values[16:24], uint64(attr.ModifiedAt.UnixNano()))
	binary.BigEndian.PutUint64(values[24:32], uint64(attr.ChangedAt.UnixNano()))
	binary.BigEndian.PutUint32(values[32:36], attr.Mode)
	_, _ = writer.Write(values[:])
	_, _ = writer.Write([]byte(attr.Kind))
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
