package histworker

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/steerlabs/portablefs/vcs/internal/historycut"
)

func TestMapPgErrorTaxonomy(t *testing.T) {
	for _, code := range []string{"PF002", "PF004", "PF005", "PF007", "PF008", "PF009", "PF010", "PF011"} {
		t.Run(code+"-definite", func(t *testing.T) {
			err := mapPgError(&pgconn.PgError{Code: code, Message: "definite"})
			if !errors.Is(err, historycut.ErrCorrupt) {
				t.Fatalf("%s mapped to %v", code, err)
			}
		})
	}
	if err := mapPgError(&pgconn.PgError{Code: "PF001", Message: "stale"}); !errors.Is(err, ErrFenced) {
		t.Fatalf("PF001 mapped to %v", err)
	}
	if err := mapPgError(&pgconn.PgError{Code: "PF015", Message: "missing"}); !errors.Is(err, ErrPolicyMissing) {
		t.Fatalf("PF015 mapped to %v", err)
	}
	transient := &pgconn.PgError{Code: "08006", Message: "connection failure"}
	if err := mapPgError(transient); !errors.Is(err, transient) {
		t.Fatalf("transient error was reclassified: %v", err)
	}
}
