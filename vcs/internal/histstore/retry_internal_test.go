package histstore

import (
	"fmt"
	"net"
	"testing"
)

func TestRetriableTransportErrorIncludesClosedNetworkConnection(t *testing.T) {
	err := fmt.Errorf("HTTP transport: %w", net.ErrClosed)
	if !retriableTransportError(err) {
		t.Fatalf("closed network connection was not classified as transient: %v", err)
	}
}
