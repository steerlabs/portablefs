// nts-reference is a read-only, test-only RFC 8915 reference for the workspace
// qualification harness. It never disciplines a clock or persists NTS keys.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/beevik/ntp"
)

type reference struct {
	Operator      string `json:"operator,omitempty"`
	Server        string `json:"server"`
	Protocol      string `json:"protocol"`
	Authenticated bool   `json:"authenticated"`
	UnixNS        int64  `json:"unix_ns"`
	UncertaintyNS int64  `json:"uncertainty_ns"`
	QueryBeganNS  int64  `json:"query_began_ns,omitempty"`
	QueryEndedNS  int64  `json:"query_ended_ns,omitempty"`
}

type observation struct {
	References []reference `json:"references"`
	Clock      string      `json:"clock,omitempty"`
	Policy     string      `json:"policy,omitempty"`
	Exchanges  []exchange  `json:"exchanges,omitempty"`
}

func authenticatedReference(server string, response *ntp.Response) (reference, error) {
	if response == nil {
		return reference{}, errors.New("missing authenticated NTP response")
	}
	if err := response.Validate(); err != nil {
		return reference{}, fmt.Errorf("validate NTS response: %w", err)
	}
	if response.Version != 4 || response.RootDispersion < 0 || response.Precision < 0 {
		return reference{}, errors.New("invalid NTPv4 uncertainty")
	}
	// Use authenticated server transmit time, never host wall + estimated offset.
	// Its sample is inside the bracketed NTP exchange. The Python harness charges
	// the complete NTP and SSH transit interval, including path asymmetry;
	// adding RTT again here would double charge it. Round half root delay upward.
	delay := max(response.RootDelay, 0)
	if delay > 2*time.Second || response.RootDispersion > time.Second || response.Precision > time.Second {
		return reference{}, errors.New("server uncertainty exceeds one-second allocation")
	}
	uncertainty := response.RootDispersion + (delay+1)/2 + max(response.Precision, time.Nanosecond)
	stamp := response.Timestamps.ServerXmit
	if uncertainty > time.Second || stamp.Before(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)) ||
		!stamp.Before(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)) {
		return reference{}, errors.New("timestamp or uncertainty outside source allocation")
	}
	return reference{Server: server, Protocol: "NTS", Authenticated: true, UnixNS: stamp.UnixNano(), UncertaintyNS: int64(uncertainty)}, nil
}

// Each operator gets two attempts, with both address families in each attempt.
// All attempts share one deadline; no failed path extends the slot's budget.
type queryFunc func(context.Context, string, string) ([]reference, []exchange)

type exchange struct {
	Server  string `json:"server"`
	Family  string `json:"family"`
	Stage   string `json:"stage"`
	BeganNS int64  `json:"began_ns"`
	EndedNS int64  `json:"ended_ns"`
	Error   string `json:"error,omitempty"`
}

//go:embed policy.json
var policyBytes []byte

var policy struct {
	ID        string              `json:"id"`
	Operators map[string][]string `json:"operators"`
}

func init() {
	if err := json.Unmarshal(policyBytes, &policy); err != nil {
		panic(err)
	}
}

func collect(servers []string, timeout time.Duration, probe queryFunc, diagnostic io.Writer) (observation, error) {
	allowed := map[string]string{}
	for operator, hosts := range policy.Operators {
		for _, host := range hosts {
			allowed[host] = operator
		}
	}
	groups := map[string][]string{}
	seen := map[string]bool{}
	for _, host := range servers {
		operator, ok := allowed[host]
		if !ok || seen[host] {
			return observation{}, fmt.Errorf("duplicate or unsupported server %q", host)
		}
		seen[host] = true
		groups[operator] = append(groups[operator], host)
	}
	if len(groups) < 2 {
		return observation{}, errors.New("at least two approved operators required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), min(timeout, 9*time.Second))
	defer cancel()
	type outcome struct {
		refs      []reference
		exchanges []exchange
	}
	outcomes := make(chan outcome, len(groups))
	var group sync.WaitGroup
	for operator, hosts := range groups {
		group.Go(func() {
			var result outcome
			for attempt := 0; attempt < 2 && ctx.Err() == nil; attempt++ {
				// The first attempt cannot consume the retry's aggregate budget.
				attemptCtx, done := context.WithTimeout(ctx, 4400*time.Millisecond)
				paths := make(chan outcome, 2)
				var families sync.WaitGroup
				for _, family := range []string{"4", "6"} {
					families.Go(func() {
						refs, exchanges := probe(attemptCtx, hosts[attempt%len(hosts)], family)
						paths <- outcome{refs, exchanges}
					})
				}
				families.Wait()
				close(paths)
				done()
				for path := range paths {
					for i := range path.refs {
						path.refs[i].Operator = operator
					}
					result.refs = append(result.refs, path.refs...)
					result.exchanges = append(result.exchanges, path.exchanges...)
				}
				// Retain every authenticated response, including disagreements.
				// A successful operator is never retried to find a nicer answer.
				if len(result.refs) != 0 {
					break
				}
			}
			outcomes <- result
		})
	}
	group.Wait()
	close(outcomes)
	result := observation{References: []reference{}, Clock: referenceClock, Policy: policy.ID}
	for outcome := range outcomes {
		result.References = append(result.References, outcome.refs...)
		result.Exchanges = append(result.Exchanges, outcome.exchanges...)
	}
	sort.Slice(result.References, func(i, j int) bool { return result.References[i].QueryBeganNS < result.References[j].QueryBeganNS })
	for _, item := range result.Exchanges {
		if item.Error != "" {
			fmt.Fprintf(diagnostic, "%s %s %s: %s\n", item.Server, item.Family, item.Stage, item.Error)
		}
	}
	return result, nil
}

func main() {
	defaults := []string{}
	for _, name := range []string{"Cloudflare", "Netnod", "PTB", "SIDN/TimeNL", "NIC.br/NTP.br"} {
		defaults = append(defaults, policy.Operators[name]...)
	}
	servers := flag.String("servers", strings.Join(defaults, ","), "approved NTS hosts, grouped by operator")
	timeout := flag.Duration("timeout", 9*time.Second, "aggregate collection deadline (maximum 9s)")
	flag.Parse()
	if flag.NArg() != 0 || *timeout <= 0 || *timeout > 9*time.Second {
		fmt.Fprintln(os.Stderr, "expected no positional arguments and aggregate timeout in (0,9s]")
		os.Exit(2)
	}
	result, err := collect(strings.Split(*servers, ","), *timeout, query, os.Stderr)
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(result)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "NTS reference:", err)
		os.Exit(1)
	}
}
