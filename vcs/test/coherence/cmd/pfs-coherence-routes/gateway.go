package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/readonlyfs"
)

// probeGateway holds one real kernel writer across the lifetime of the actual
// files-gateway client. It reports observations for the matrix to judge.
func probeGateway(o options, root, path string) error {
	if root == "" {
		return errors.New("gateway probe requires --gateway-mount-root")
	}
	parts := strings.Split(path, "/")
	components := make([][]byte, len(parts))
	for i, part := range parts {
		components[i] = []byte(part)
	}
	key, err := readonlyfs.EncodePath(components)
	if err != nil {
		return err
	}
	parent, err := readonlyfs.EncodePath(components[:len(components)-1])
	if err != nil {
		return err
	}
	cfg := readonlyfs.Config{Address: o.address, AuthorityServerName: o.serverName, VolumeID: o.volumeID}
	for _, pair := range []struct {
		path  string
		value *[]byte
	}{{o.serverCA, &cfg.AuthorityCAPEM}, {o.clientCert, &cfg.ClientCertificatePEM}, {o.clientKey, &cfg.ClientPrivateKeyPEM}, {o.tokenFile, &cfg.Capability}} {
		data, err := os.ReadFile(pair.path)
		if err != nil {
			return fmt.Errorf("read gateway credential: %w", err)
		}
		*pair.value = data
	}
	writer, err := os.OpenFile(filepath.Join(root, path), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open delegated writer: %w", err)
	}
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	gateway, err := readonlyfs.Dial(ctx, cfg)
	if err != nil {
		return fmt.Errorf("attach cacheless gateway: %w", err)
	}
	defer gateway.Close()
	listingMatches, readsMatch := true, true
	var maximum time.Duration
	const rounds = 8
	for round := 0; round < rounds; round++ {
		want := bytes.Repeat([]byte{byte('a' + round)}, 4096+round*257)
		start := time.Now()
		if _, err := writer.WriteAt(want, 0); err != nil {
			return fmt.Errorf("write beside gateway: %w", err)
		}
		maximum = max(maximum, time.Since(start))
		page, err := gateway.List(ctx, parent, 100, nil)
		if err != nil {
			return fmt.Errorf("gateway listing: %w", err)
		}
		found := false
		for _, entry := range page.Entries {
			if bytes.Equal(entry.Name, components[len(components)-1]) {
				found = true
				listingMatches = listingMatches && entry.Attr.Size == uint64(len(want))
			}
		}
		listingMatches = listingMatches && found
		file, err := gateway.OpenFile(ctx, key)
		if err != nil {
			return fmt.Errorf("gateway open: %w", err)
		}
		got := make([]byte, len(want)+1)
		n, readErr := file.ReadAt(ctx, got, 0)
		closeErr := file.Close(ctx)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("gateway read: %w", readErr)
		}
		if closeErr != nil {
			return closeErr
		}
		readsMatch = readsMatch && bytes.Equal(got[:n], want)
	}
	fmt.Printf("listing_matches=%t\nreads_match=%t\nwriter_remained_open=true\nrounds=%d\nmaximum_write_millis=%d\n", listingMatches, readsMatch, rounds, maximum.Milliseconds())
	return nil
}
