package cli

import (
	"strings"
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

func TestParseExecArgsSplitting(t *testing.T) {
	flagArgs, command, err := parseExecArgs([]string{"vol_1", "--branch", "dev", "--", "npm", "test", "--", "-v"})
	if err != nil {
		t.Fatalf("parseExecArgs: %v", err)
	}
	if len(flagArgs) != 3 || flagArgs[0] != "vol_1" {
		t.Fatalf("flagArgs = %v", flagArgs)
	}
	// Only the FIRST -- splits; later ones belong to the remote command.
	if command != "npm test -- -v" {
		t.Fatalf("command = %q", command)
	}
}

func TestParseExecArgsFlagLikeCommandTokensSurvive(t *testing.T) {
	_, command, err := parseExecArgs([]string{"vol_1", "--", "ls", "-la", "--color=never"})
	if err != nil {
		t.Fatalf("parseExecArgs: %v", err)
	}
	if command != "ls -la --color=never" {
		t.Fatalf("command = %q", command)
	}
}

func TestParseExecArgsQuotesShellWords(t *testing.T) {
	// Each argv word must survive the remote shell as ONE word: `sh -c 'find . | wc -l'`
	// stays a single -c argument instead of piping the CLI's remote sh.
	_, command, err := parseExecArgs([]string{"vol_1", "--", "sh", "-c", "find . | wc -l"})
	if err != nil {
		t.Fatalf("parseExecArgs: %v", err)
	}
	if command != `sh -c 'find . | wc -l'` {
		t.Fatalf("command = %q", command)
	}

	_, command, err = parseExecArgs([]string{"vol_1", "--", "echo", "it's", "$HOME", "a b"})
	if err != nil {
		t.Fatalf("parseExecArgs: %v", err)
	}
	if command != `echo 'it'\''s' '$HOME' 'a b'` {
		t.Fatalf("command = %q", command)
	}

	// Env assignments and flag=value words stay unquoted so they keep meaning.
	_, command, err = parseExecArgs([]string{"vol_1", "--", "FOO=bar", "ls", "--color=never"})
	if err != nil {
		t.Fatalf("parseExecArgs: %v", err)
	}
	if command != "FOO=bar ls --color=never" {
		t.Fatalf("command = %q", command)
	}
}

func TestParseExecArgsErrors(t *testing.T) {
	if _, _, err := parseExecArgs([]string{"vol_1", "ls"}); err == nil || !strings.Contains(err.Error(), "--") {
		t.Fatalf("missing -- must be a usage error, got %v", err)
	}
	if _, _, err := parseExecArgs([]string{"vol_1", "--"}); err == nil || !strings.Contains(err.Error(), "no command") {
		t.Fatalf("empty command must be a usage error, got %v", err)
	}
}

func TestExecUsageErrorExitCode(t *testing.T) {
	e, _, stderr := testEnv(t)
	if rc := e.run([]string{"exec", "vol_1", "ls"}); rc != 2 {
		t.Fatalf("rc = %d, want usage error 2", rc)
	}
	if !strings.Contains(stderr.String(), "--") {
		t.Fatalf("stderr must explain the -- convention: %q", stderr.String())
	}
}
