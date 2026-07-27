package histworker

import (
	"context"
	"encoding/json"

	"github.com/steerlabs/portablefs/vcs/internal/historycut"
)

// repoSources adapts the Repository onto the reducer's claim-fenced source
// interfaces for one claimed cut.
type repoSources struct {
	repo  Repository
	claim CutClaim
}

var (
	_ historycut.JournalSource = (*repoSources)(nil)
	_ historycut.LegacySource  = (*repoSources)(nil)
)

// ReadPage implements historycut.JournalSource.
func (s *repoSources) ReadPage(ctx context.Context, fromSeq uint64, maxRecords int, maxBytes int64) ([]historycut.PageRecord, error) {
	return s.repo.ReadJournalPage(ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch, fromSeq, maxRecords, maxBytes)
}

// EntriesPage implements historycut.LegacySource.
func (s *repoSources) EntriesPage(ctx context.Context, afterOrd int64, limit int) ([]historycut.LegacyEntry, error) {
	return s.repo.LegacyEntriesPage(ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch, afterOrd, limit)
}

// ImportCursor implements historycut.LegacySource.
func (s *repoSources) ImportCursor(ctx context.Context) (json.RawMessage, error) {
	return s.repo.LegacyGetImportCursor(ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch)
}

// PutImportCursor implements historycut.LegacySource.
func (s *repoSources) PutImportCursor(ctx context.Context, cursor json.RawMessage) error {
	return s.repo.LegacyPutImportCursor(ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch, cursor)
}

// VerifyTreeHash implements historycut.LegacySource: the database compares
// against the pinned anchor commit and raises on mismatch.
func (s *repoSources) VerifyTreeHash(ctx context.Context, treeHash string) error {
	return s.repo.LegacyVerifyTreeHash(ctx, s.claim.Facts.CutID, s.claim.ClaimEpoch, treeHash)
}
