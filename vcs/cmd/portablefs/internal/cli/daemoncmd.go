package cli

import (
	"fmt"
	"time"
)

func cmdDaemon(e *cmdEnv, args []string) int {
	fs := newFlagSet("daemon")
	var o commonOpts
	addCommonFlags(fs, &o)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("daemon", err)
	}
	if len(positionals) != 1 || positionals[0] != "stop" {
		return e.usageError("daemon", fmt.Errorf("expected `stop`"))
	}
	if err := daemonStopPolicy(); err != nil {
		return e.fail("daemon stop", err)
	}
	cfg, err := fskitConfigFromEnv(e.getenv)
	if err != nil {
		return e.fail("daemon stop", err)
	}
	ctl, err := connectCompatiblePortablefsd(cfg, e.version)
	if err != nil {
		return e.fail("daemon stop", err)
	}
	if err := ctl.stopIfIdle(); err != nil {
		return e.fail("daemon stop", err)
	}
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if !ctl.healthy() {
			if o.jsonOut {
				return e.printJSON(map[string]any{"stopped": true})
			}
			fmt.Fprintln(e.stdout, "portablefsd stopped")
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	return e.fail("daemon stop", fmt.Errorf("portablefsd accepted the idle stop but did not exit within its 30-second drain budget"))
}
