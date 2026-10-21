package cli

import (
	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"testing"
	"time"
)

func TestHostedReadyRequiresInstalledRenewalAndExactDeadline(t *testing.T) {
	now := time.Now()
	deadline := now.Add(time.Minute)
	installed := mountenrollment.RenewalReadiness{State: "installed", InstalledSequence: 1, SessionID: "session", AuthorizationDeadline: deadline}
	for _, tc := range []struct {
		name     string
		hosted   bool
		proof    mountenrollment.RenewalReadiness
		deadline time.Time
		want     bool
	}{
		{"pending", true, mountenrollment.RenewalReadiness{State: "pending"}, deadline, false},
		{"installed", true, installed, deadline, true},
		{"unequal", true, installed, deadline.Add(time.Nanosecond), false},
		{"zero-deadline", true, installed, time.Time{}, false},
		{"hosted-not-required", true, mountenrollment.RenewalReadiness{State: "not-required"}, deadline, false},
		{"standalone", false, mountenrollment.RenewalReadiness{State: "not-required"}, time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateFUSERenewalReadiness(tc.proof, tc.hosted, "session", tc.deadline, now) == nil; got != tc.want {
				t.Fatal(got)
			}
		})
	}
	installed.InstalledSequence = 0
	if validateFUSERenewalReadiness(installed, true, "session", deadline, now) == nil {
		t.Fatal("sequence zero ready")
	}
}
