package main

import (
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"
)

func startTestExpiryOwner(t *testing.T, s *server) {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); s.sweep(stop) }()
	t.Cleanup(func() { close(stop); <-done })
	synctest.Wait()
}

func TestExpiryOwnerWakesFromEmptyRegistryAtTheActualDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestServer(t, nil, nil)
		startTestExpiryOwner(t, s)
		client := newFakeAuthority()
		session := &volumeSession{client: client, expiresAt: time.Now().Add(10 * time.Second)}
		session.lastUsedUnix.Store(time.Now().UnixNano())
		s.mu.Lock()
		s.sessions[testVolume] = session
		s.signalExpiryChangedLocked()
		s.mu.Unlock()
		synctest.Wait()
		time.Sleep(10*time.Second - time.Nanosecond)
		select {
		case <-client.closed:
			t.Fatal("session expired before its real deadline")
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case <-client.closed:
		default:
			t.Fatal("session waited for a periodic sweep after its real deadline")
		}
	})
}

func TestExpiryOwnerHonorsIdleRefreshAndFenceRetention(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := newTestServer(t, nil, nil)
		client := newFakeAuthority()
		session := &volumeSession{client: client, expiresAt: time.Now().Add(2 * time.Hour)}
		session.lastUsedUnix.Store(time.Now().UnixNano())
		s.sessions[testVolume] = session
		s.raiseFence(testVolume, 9)
		startTestExpiryOwner(t, s)
		time.Sleep(14 * time.Minute)
		if got, release := s.acquireSession(httptest.NewRecorder(), testVolume); got != session {
			t.Fatal("session expired before idle refresh")
		} else {
			release()
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		select {
		case <-client.closed:
			t.Fatal("idle refresh did not move the expiry deadline")
		default:
		}
		time.Sleep(14 * time.Minute)
		synctest.Wait()
		select {
		case <-client.closed:
		default:
			t.Fatal("idle session was not closed at its refreshed deadline")
		}
		time.Sleep(31*time.Minute - time.Nanosecond)
		synctest.Wait()
		s.mu.Lock()
		floor := s.fences[testVolume].value
		s.mu.Unlock()
		if floor != 9 {
			t.Fatal("fence expired before its retention deadline")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		s.mu.Lock()
		remaining := len(s.fences)
		s.mu.Unlock()
		if remaining != 0 {
			t.Fatal("fence waited for a periodic sweep after retention")
		}
	})
}

func TestEndedSessionRetiresFromItsOwnEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		public, private := testKeys(t)
		dialer := &fakeDialer{}
		s := newTestServer(t, public, dialer.dial)
		if response := installSession(t, s, private, testVolume, 0); response.Code != 201 {
			t.Fatalf("install = %d: %s", response.Code, response.Body.String())
		}
		_ = dialer.last().Close()
		synctest.Wait()
		s.mu.Lock()
		remaining := len(s.sessions)
		s.mu.Unlock()
		if remaining != 0 {
			t.Fatal("ended session retained registry capacity until an expiry timer")
		}
	})
}
