package remotejournal

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPoolConfigDirectConnectionKeepsTimeoutStartupParameters(t *testing.T) {
	pc, err := poolConfig(Config{
		DSN:             "postgres://authority@db.internal/portablefs",
		ApplicationName: "journal-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if pc.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Fatalf("query exec mode = %v, want QueryExecModeExec", pc.ConnConfig.DefaultQueryExecMode)
	}
	want := map[string]string{
		"application_name":                    "journal-test",
		"statement_timeout":                   "30000",
		"lock_timeout":                        "5000",
		"idle_in_transaction_session_timeout": "60000",
	}
	for name, value := range want {
		if got := pc.ConnConfig.RuntimeParams[name]; got != value {
			t.Errorf("runtime parameter %s = %q, want %q", name, got, value)
		}
	}
}

func TestPoolConfigTransactionPoolerOmitsTimeoutStartupParameters(t *testing.T) {
	pc, err := poolConfig(Config{
		DSN: "postgres://authority@pooler.internal/portablefs" +
			"?statement_timeout=1&lock_timeout=2&idle_in_transaction_session_timeout=3",
		ApplicationName:   "journal-pooler-test",
		TransactionPooler: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pc.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Fatalf("query exec mode = %v, want QueryExecModeExec", pc.ConnConfig.DefaultQueryExecMode)
	}
	if got := pc.ConnConfig.RuntimeParams["application_name"]; got != "journal-pooler-test" {
		t.Fatalf("application_name = %q, want journal-pooler-test", got)
	}
	for _, name := range []string{
		"statement_timeout",
		"lock_timeout",
		"idle_in_transaction_session_timeout",
	} {
		if value, ok := pc.ConnConfig.RuntimeParams[name]; ok {
			t.Errorf("pooled mode retained runtime parameter %s=%q", name, value)
		}
	}
}
