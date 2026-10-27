// nts-reference is a read-only, test-only RFC 8915 reference for the workspace
// qualification harness. It never disciplines a clock or persists NTS keys.
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/beevik/ntp"
	"github.com/beevik/nts"
)

type reference struct {
	Server        string `json:"server"`
	Protocol      string `json:"protocol"`
	Authenticated bool   `json:"authenticated"`
	UnixNS        int64  `json:"unix_ns"`
	UncertaintyNS int64  `json:"uncertainty_ns"`
}

type observation struct {
	References []reference `json:"references"`
}

// Authentication is established by NewSession's verified TLS 1.3 NTS-KE and
// QueryWithOptions' NTS extension (unique-ID and AEAD verification). Validate
// must still be called: ntp deliberately returns invalid/auth-failed responses
// for diagnostic consumers. Never mark such a response authenticated.
func query(server string, timeout time.Duration) (*ntp.Response, error) {
	session, err := nts.NewSessionWithOptions(server, &nts.SessionOptions{Timeout: timeout,
		Dialer: func(network, address string, config *tls.Config) (*tls.Conn, error) {
			deadline := time.Now().Add(timeout)
			conn, err := tls.DialWithDialer(&net.Dialer{Deadline: deadline}, network, address, config)
			if err != nil {
				return nil, err
			}
			if err := conn.SetDeadline(deadline); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		}})
	if err != nil {
		return nil, fmt.Errorf("NTS-KE: %w", err)
	}
	return session.QueryWithOptions(&ntp.QueryOptions{Version: 4, Timeout: timeout})
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
	// Its sample is inside this command's invocation. The Python harness charges
	// the complete invocation and SSH transit interval, including path asymmetry;
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
	return reference{server, "NTS", true, stamp.UnixNano(), int64(uncertainty)}, nil
}

type queryFunc func(string, time.Duration) (*ntp.Response, error)

func collect(servers []string, timeout time.Duration, probe queryFunc, diagnostic io.Writer) (observation, error) {
	// A fixed operator-diverse allowlist prevents aliases from manufacturing
	// independence. Each entry is a different operator: Cloudflare, Netnod, PTB.
	allowed := map[string]bool{"time.cloudflare.com": true, "nts.netnod.se": true, "ptbtime1.ptb.de": true}
	seen := make(map[string]bool)
	for _, server := range servers {
		if !allowed[server] || seen[server] {
			return observation{}, fmt.Errorf("duplicate or unsupported independent server %q", server)
		}
		seen[server] = true
	}
	if len(servers) < 2 {
		return observation{}, errors.New("at least two independent NTS servers required")
	}
	refs := make([]reference, len(servers))
	errs := make([]error, len(servers))
	var group sync.WaitGroup
	for i, server := range servers {
		group.Go(func() {
			response, err := probe(server, timeout)
			if err == nil {
				refs[i], err = authenticatedReference(server, response)
			}
			errs[i] = err
		})
	}
	group.Wait()
	result := observation{References: make([]reference, 0, len(servers))}
	for i, err := range errs {
		if err != nil {
			fmt.Fprintf(diagnostic, "%s: %v\n", servers[i], err)
		} else {
			result.References = append(result.References, refs[i])
		}
	}
	if len(result.References) < 2 {
		return observation{}, errors.New("fewer than two authenticated independent NTS responses")
	}
	return result, nil
}

func main() {
	servers := flag.String("servers", "time.cloudflare.com,nts.netnod.se,ptbtime1.ptb.de", "independent NTS operators (comma separated)")
	timeout := flag.Duration("timeout", 3*time.Second, "timeout for each NTS-KE and NTP exchange")
	flag.Parse()
	if flag.NArg() != 0 || *timeout <= 0 || *timeout > 4*time.Second {
		fmt.Fprintln(os.Stderr, "expected no positional arguments and timeout in (0,4s]")
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
