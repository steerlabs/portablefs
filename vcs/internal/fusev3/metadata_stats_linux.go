//go:build linux

package fusev3

import (
	"os"
	"strconv"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountlog"
)

var metadataProcessStart = strconv.FormatInt(time.Now().UnixNano(), 10)

func (m *Mount) MetadataStats() *mountlog.MetadataStats {
	if m == nil || m.raw == nil {
		return nil
	}
	r := m.raw
	r.mu.RLock()
	c := &r.directories
	stats := &mountlog.MetadataStats{PID: os.Getpid(), ProcessStart: metadataProcessStart,
		FUSEOperations: m.metadataFUSE.snapshot(), Notifications: m.metadataFUSE.notifications.Load(), NotificationNanos: m.metadataFUSE.notificationNanos.Load(), NotificationFailures: m.metadataFUSE.notificationFailures.Load(), MetadataHits: c.metadataHits, MetadataMisses: c.metadataMisses,
		PageHits: c.hits, PageMisses: c.misses, OpenHits: c.openHits, OpenMisses: c.openMisses,
		MissAbsent: c.missReasons["absent"], MissAttributes: c.missReasons["child-attributes"], MissWithdrawn: c.missReasons["withdrawn"], MissOwnership: c.missReasons["ownership"], MissFinalPublication: c.missReasons["final-publication"],
		SingleFlightWaits: c.singleFlightWaits, CapacityEvictions: c.capacityEvictions, Invalidations: c.invalidations, PayloadBytes: r.metadataBytesLocked(), PayloadLimit: c.limit,
		Names: r.cachedNameTotalLocked(), Pages: len(c.pages), Backings: len(c.proofs), PendingFills: len(c.fills), Withdrawals: c.withdrawals, WithdrawalNanos: c.withdrawalNanos, Terminal: r.replyTerminal || r.replyTerminalizing || m.revoked.Load()}
	r.mu.RUnlock()
	m.subscription.mu.RLock()
	stats.ColdInstalls, stats.Incarnation = m.subscription.coldInstalls, m.subscription.incarnation
	m.subscription.mu.RUnlock()
	if rtc, ok := m.workspaceRTC.(interface {
		RTCStats() (uint64, uint64, uint64)
	}); ok {
		stats.RTCReads, stats.RTCNanos, stats.RTCFailures = rtc.RTCStats()
	}
	return stats
}

func (r *rawFileSystem) recordMetadataMiss() {
	r.mu.Lock()
	r.directories.metadataMisses++
	r.mu.Unlock()
}
