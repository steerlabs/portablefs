package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// parseExecArgs splits an exec invocation into its flag/positional part and
// the remote command tail after "--". The tail arrives as argv words already
// parsed by the LOCAL shell; the server runs one shell command line, so each
// word must be re-quoted or `sh -c 'find . | wc -l'` degrades to
// `sh -c find . | wc -l` remotely. Split out for testing.
func parseExecArgs(args []string) (flagArgs []string, command string, err error) {
	before, after, found := splitDoubleDash(args)
	if !found {
		return nil, "", fmt.Errorf("missing `--`: usage is `portablefs exec <volumeId> [flags] -- <command...>`")
	}
	if len(after) == 0 {
		return nil, "", fmt.Errorf("no command after `--`")
	}
	quoted := make([]string, len(after))
	for i, word := range after {
		quoted[i] = shellQuote(word)
	}
	return before, strings.Join(quoted, " "), nil
}

// shellQuote makes one argv word safe to embed in a POSIX shell command line.
// Safe words pass through untouched so simple commands stay readable in logs
// and so `FOO=bar cmd` assignments and `--flag=value` words keep their
// unquoted meaning. A leading ~ is quoted (remote tilde expansion would
// substitute the server's HOME); `=` is deliberately not an unsafe character.
func shellQuote(word string) string {
	const unsafe = " \t\n\r\"'`$\\|&;<>()*?[]#"
	if word != "" && !strings.ContainsAny(word, unsafe) && !strings.HasPrefix(word, "~") {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
}

func cmdExec(e *cmdEnv, args []string) int {
	flagArgs, command, err := parseExecArgs(args)
	if err != nil {
		return e.usageError("exec", err)
	}
	fs := newFlagSet("exec")
	var o commonOpts
	addCommonFlags(fs, &o)
	branch := fs.String("branch", "main", "branch to run against")
	write := fs.Bool("write", false, "commit filesystem changes made by the command back to the branch")
	timeout := fs.Duration("timeout", 60*time.Second, "remote command timeout")
	positionals, err := parseArgs(fs, flagArgs)
	if err != nil {
		return e.handleParseError("exec", err)
	}
	if len(positionals) != 1 {
		return e.usageError("exec", fmt.Errorf("expected exactly one volume id before `--`"))
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("exec", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("exec", err)
	}
	res, err := e.apiClient(s.apiURL, s.apiToken).exec(context.Background(), positionals[0], *branch, command, *write, *timeout)
	if err != nil {
		return e.fail("exec", err)
	}
	if o.jsonOut {
		if rc := e.printJSON(res); rc != 0 {
			return rc
		}
		return res.ExitCode
	}
	_, _ = io.WriteString(e.stdout, res.Stdout)
	_, _ = io.WriteString(e.stderr, res.Stderr)
	if res.Signal != "" {
		fmt.Fprintf(e.stderr, "portablefs exec: remote command killed by %s (likely the %s timeout)\n", res.Signal, *timeout)
	}
	if res.Committed {
		fmt.Fprintf(e.stderr, "portablefs exec: committed changes as %s\n", res.HeadCommitID)
	}
	return res.ExitCode
}

func cmdGrep(e *cmdEnv, args []string) int {
	fs := newFlagSet("grep")
	var o commonOpts
	addCommonFlags(fs, &o)
	dir := fs.String("dir", "", "restrict the search to a directory")
	branch := fs.String("branch", "main", "branch to search")
	max := fs.Int("max", 1000, "maximum number of matches")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("grep", err)
	}
	if len(positionals) != 2 {
		return e.usageError("grep", fmt.Errorf("expected <volumeId> <pattern>"))
	}
	s, err := e.resolveSettings(&o)
	if err != nil {
		return e.fail("grep", err)
	}
	if err := s.requireAPI(); err != nil {
		return e.fail("grep", err)
	}
	res, err := e.apiClient(s.apiURL, s.apiToken).grep(context.Background(), positionals[0], *branch, *dir, positionals[1], *max)
	if err != nil {
		return e.fail("grep", err)
	}
	if o.jsonOut {
		if rc := e.printJSON(res); rc != 0 {
			return rc
		}
		if len(res.Matches) == 0 {
			return 1
		}
		return 0
	}
	for _, m := range res.Matches {
		fmt.Fprintf(e.stdout, "%s:%d:%s\n", m.File, m.Line, m.Text)
	}
	switch res.StoppedReason {
	case "max_results":
		fmt.Fprintf(e.stderr, "portablefs grep: truncated at %d matches (raise --max)\n", *max)
	case "deadline":
		fmt.Fprintln(e.stderr, "portablefs grep: stopped at the server-side deadline; results are partial")
	}
	// grep(1) semantics: 0 = matches found, 1 = none.
	if len(res.Matches) == 0 {
		return 1
	}
	return 0
}
