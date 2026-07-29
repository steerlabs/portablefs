package cli

import (
	"fmt"
	"time"
)

func cmdDaemon(e *cmdEnv, args []string) int {
	if len(args) != 1 || args[0] != "stop" {
		return e.usageError("daemon", fmt.Errorf("expected `stop`"))
	}
	cfg := fskitConfigFromEnv(e.getenv)
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
			fmt.Fprintln(e.stdout, "portablefsd stopped")
			return 0
		}
		time.Sleep(100 * time.Millisecond)
	}
	return e.fail("daemon stop", fmt.Errorf("portablefsd accepted the idle stop but did not exit within its 30-second drain budget"))
}
