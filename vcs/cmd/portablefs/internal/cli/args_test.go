package cli

import (
	"testing"
)

func TestParseArgsInterleavedPositionalsAndFlags(t *testing.T) {
	fs := newFlagSet("test")
	branch := fs.String("branch", "main", "")
	pos, err := parseArgs(fs, []string{"vol_1", "--branch", "dev", "extra"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if len(pos) != 2 || pos[0] != "vol_1" || pos[1] != "extra" {
		t.Fatalf("positionals = %v", pos)
	}
	if *branch != "dev" {
		t.Fatalf("branch = %q", *branch)
	}

	fs2 := newFlagSet("test")
	branch2 := fs2.String("branch", "main", "")
	pos2, err := parseArgs(fs2, []string{"--branch", "dev", "vol_1"})
	if err != nil {
		t.Fatalf("parseArgs flags-first: %v", err)
	}
	if len(pos2) != 1 || pos2[0] != "vol_1" || *branch2 != "dev" {
		t.Fatalf("flags-first parse wrong: %v %q", pos2, *branch2)
	}
}

func TestParseArgsUnknownFlag(t *testing.T) {
	fs := newFlagSet("test")
	if _, err := parseArgs(fs, []string{"vol", "--bogus"}); err == nil {
		t.Fatal("unknown flag must error")
	}
}
