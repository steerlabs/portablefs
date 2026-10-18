package readonlyfs

import "time"

// Compiled only by the HTTP regression overlay; never part of the library.
func ReviewNewClient(rpc authorityClient, timeout time.Duration) *Client {
	return newClient(rpc, timeout)
}
