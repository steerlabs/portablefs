package cli

import (
	"context"
	"fmt"
)

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
