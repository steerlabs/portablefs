package cli

import (
	"flag"
	"io"
	"strings"
)

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseArgs parses fs over args while collecting positional arguments, so
// `portablefs status vol --branch dev` and `portablefs status --branch dev vol`
// both work (stdlib flag stops at the first non-flag token; we resume after it).
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	rest := fs.Args()
	for len(rest) > 0 {
		positionals = append(positionals, rest[0])
		if err := fs.Parse(rest[1:]); err != nil {
			return nil, err
		}
		rest = fs.Args()
	}
	return positionals, nil
}

// stringListFlag is a repeatable string flag (flag.Var), e.g. --local-dir a
// --local-dir b.
type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }

func (f *stringListFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// splitDoubleDash splits args at the first standalone "--". Everything after it
// is an opaque command tail that must not be flag-parsed (portablefs exec).
func splitDoubleDash(args []string) (before, after []string, found bool) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:], true
		}
	}
	return args, nil, false
}
